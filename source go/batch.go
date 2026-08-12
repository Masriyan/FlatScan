package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// batchScan is the per-file scan entry point used by the batch worker. It is a
// variable only so the panic-isolation test can inject a scanner that fails
// deterministically; production code always runs RunConfiguredScan.
var batchScan = RunConfiguredScan

// batchPanicLog is where the batch worker reports a recovered panic. Split out
// from os.Stderr so tests can assert the diagnostic without polluting output.
var batchPanicLog io.Writer = os.Stderr

// batchResult holds the summary of one file's scan in batch mode.
type batchResult struct {
	FileName string
	Verdict  string
	Score    int
	FileType string
	SHA256   string
	Duration string
	Findings int
	IOCs     int
	Size     int64
	Error    string
}

// RunBatchScan scans all regular files in a directory and prints a
// colorized summary table. Each file is scanned independently using
// the same Config (mode, rules, etc.), with per-file progress shown.
func RunBatchScan(cfg Config) error {
	stat, err := os.Stat(cfg.DirPath)
	if err != nil {
		return fmt.Errorf("directory scan: %w", err)
	}
	if !stat.IsDir() {
		return fmt.Errorf("--dir target is not a directory: %s", cfg.DirPath)
	}

	entries, err := os.ReadDir(cfg.DirPath)
	if err != nil {
		return fmt.Errorf("directory scan: %w", err)
	}

	// Filter to regular files only
	var files []string
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.Size() == 0 {
			continue
		}
		files = append(files, filepath.Join(cfg.DirPath, entry.Name()))
	}

	if len(files) == 0 {
		return fmt.Errorf("no scannable files found in %s", cfg.DirPath)
	}

	useColor := !cfg.NoColor && stderrColorEnabled()
	start := time.Now()

	// Print batch header
	if useColor {
		fmt.Fprintf(os.Stderr, "\n%s\n", bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
		fmt.Fprintf(os.Stderr, "%s  Batch scan: %d files in %s\n",
			bold("FlatScan"), len(files), dim(cfg.DirPath))
		fmt.Fprintf(os.Stderr, "%s  Mode: %s\n",
			bold("        "), colorize(colorCyan, cfg.Mode))
		fmt.Fprintf(os.Stderr, "%s\n\n", bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
	} else {
		fmt.Fprintf(os.Stderr, "\nFlatScan batch scan: %d files in %s (mode: %s)\n\n",
			len(files), cfg.DirPath, cfg.Mode)
	}

	// Parallel worker pool — limit concurrency to number of CPU cores.
	workers := runtime.NumCPU()
	if workers > len(files) {
		workers = len(files)
	}

	// Each worker owns exactly one index of resultSlots, which is allocated at
	// full length up front. Disjoint element writes need no synchronization,
	// and wg.Wait provides the happens-before edge for the reader below.
	sem := make(chan struct{}, workers)
	resultSlots := make([]batchResult, len(files))
	var wg sync.WaitGroup

	for i, filePath := range files {
		// Acquire the slot before spawning. Blocking here caps the number of
		// live goroutines at `workers`; acquiring inside the goroutine would
		// cap concurrent scans but still create one goroutine per file up
		// front — hundreds of thousands of them on a large sample directory.
		sem <- struct{}{}
		wg.Add(1)
		go func(idx int, fp string) {
			defer wg.Done()
			defer func() { <-sem }()

			name := filepath.Base(fp)

			// Defense in depth. batchScan recovers panics internally and
			// returns them as an error, so this should never fire — but "should
			// never" is not a guarantee worth betting an overnight 10,000-sample
			// run on. A panic that escapes here would kill the process and
			// discard every result already collected, so the batch worker keeps
			// its own guard and degrades to a single error row instead.
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(batchPanicLog,
						"[flatscan] BUG: recovered panic scanning %q in batch worker: %v\n%s\n",
						fp, r, debug.Stack())
					resultSlots[idx] = batchResult{
						FileName: name,
						Error:    fmt.Sprintf("panic: %v", r),
					}
					if useColor {
						progressLine(fmt.Sprintf("%s [%d/%d] %s  %s %s\n",
							dim("→"), idx+1, len(files), name,
							colorize(colorRed, "✗"), dim(fmt.Sprintf("panic: %v", r))))
					} else {
						progressLine(fmt.Sprintf("[%d/%d] %s  ERROR: panic: %v\n",
							idx+1, len(files), name, r))
					}
				}
			}()

			fileCfg := cfg
			fileCfg.FilePath = fp
			fileCfg.NoSplash = true
			fileCfg.NoProgress = true
			fileCfg.DirPath = ""
			fileCfg.Quiet = true // suppress per-file report; only the summary is printed

			result, err := batchScan(fileCfg)
			if err != nil {
				br := batchResult{FileName: name, Error: err.Error()}
				if useColor {
					progressLine(fmt.Sprintf("%s [%d/%d] %s  %s %s\n",
						dim("→"), idx+1, len(files), name,
						colorize(colorRed, "✗"), dim(err.Error())))
				} else {
					progressLine(fmt.Sprintf("[%d/%d] %s  ERROR: %s\n",
						idx+1, len(files), name, err.Error()))
				}
				resultSlots[idx] = br
				return
			}

			br := batchResult{
				FileName: result.FileName,
				Verdict:  result.Verdict,
				Score:    result.RiskScore,
				FileType: result.FileType,
				SHA256:   result.Hashes.SHA256,
				Duration: result.Duration,
				Findings: len(result.Findings),
				// Report the actionable IOC count (build-artifact / source-path /
				// namespace noise excluded) so the triage column reflects
				// operational indicators, not registry/PKI/library artifacts.
				IOCs: IOCCount(actionableIOCs(result.IOCs)),
				Size: result.Size,
			}
			if useColor {
				progressLine(fmt.Sprintf("%s [%d/%d] %s  %s %s score=%s findings=%d\n",
					dim("→"), idx+1, len(files), name,
					colorize(colorGreen, "✓"),
					colorize(verdictColor(br.Verdict), br.Verdict),
					colorize(verdictColor(br.Verdict), fmt.Sprintf("%d", br.Score)),
					br.Findings))
			} else {
				progressLine(fmt.Sprintf("[%d/%d] %s  %s score=%d findings=%d\n",
					idx+1, len(files), name, br.Verdict, br.Score, br.Findings))
			}
			resultSlots[idx] = br
		}(i, filePath)
	}
	wg.Wait()

	// Every slot is filled by its worker — successful scans carry the result,
	// failed ones carry FileName plus Error — so the slice is used as-is.
	results := resultSlots

	elapsed := time.Since(start)

	// The summary table is the batch deliverable, so it goes to STDOUT where it
	// can be redirected/captured. Per-file progress lines above stay on stderr.
	fmt.Fprintln(os.Stdout)
	if useColor {
		printColorBatchSummary(os.Stdout, results, elapsed)
	} else {
		printPlainBatchSummary(os.Stdout, results, elapsed)
	}

	// Write JSON batch summary if requested
	if cfg.BatchJSONPath != "" {
		if err := writeBatchJSON(cfg.BatchJSONPath, results, elapsed); err != nil {
			fmt.Fprintf(os.Stderr, "batch-json write failed: %v\n", err)
		}
	}

	// Risk-based exit code mirrors the single-file matrix: 20 if any file is
	// malicious, 10 if any is suspicious/over CI threshold, else 0.
	worst := 0
	for _, r := range results {
		if r.Error == "" && r.Score > worst {
			worst = r.Score
		}
	}
	switch {
	case worst >= 80:
		batchExitCode = 20
	case cfg.CI && worst >= cfg.CIThreshold:
		batchExitCode = 10
	case !cfg.CI && worst >= 30:
		batchExitCode = 10
	}

	return nil
}

// batchExitCode carries the risk-based exit code out of RunBatchScan so main()
// can apply the same 0/10/20 matrix used for single-file scans.
var batchExitCode int

// progressMu serializes batch progress output. Workers finish out of order, so
// each one emits a single self-describing line naming the file it reports on,
// written under the lock — previously the "scanning X" header and the "✓ score"
// result were two separate writes that other workers could interleave between,
// which attributed verdicts to the wrong file in the transcript.
var progressMu sync.Mutex

func progressLine(s string) {
	progressMu.Lock()
	fmt.Fprint(os.Stderr, s)
	progressMu.Unlock()
}

type batchJSONSummary struct {
	Scanned    int           `json:"scanned"`
	Malicious  int           `json:"malicious"`
	Suspicious int           `json:"suspicious"`
	Clean      int           `json:"clean"`
	Errors     int           `json:"errors"`
	Duration   string        `json:"duration"`
	Results    []batchResult `json:"results"`
}

func writeBatchJSON(path string, results []batchResult, elapsed time.Duration) error {
	malicious, suspicious, clean, errCount := 0, 0, 0, 0
	for _, r := range results {
		if r.Error != "" {
			errCount++
		} else if r.Score >= 80 {
			malicious++
		} else if r.Score >= 30 {
			suspicious++
		} else {
			clean++
		}
	}
	summary := batchJSONSummary{
		Scanned:    len(results),
		Malicious:  malicious,
		Suspicious: suspicious,
		Clean:      clean,
		Errors:     errCount,
		Duration:   elapsed.Round(time.Millisecond).String(),
		Results:    results,
	}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func printColorBatchSummary(w io.Writer, results []batchResult, elapsed time.Duration) {
	const rule = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	fmt.Fprintf(w, "%s\n", bold(rule))
	fmt.Fprintf(w, "%s  %s\n",
		bold("Batch Summary"),
		dim(fmt.Sprintf("(%d files  %s)", len(results), elapsed.Round(time.Millisecond))))
	fmt.Fprintf(w, "%s\n", bold(rule))

	fmt.Fprintf(w, "  %-28s %-20s %5s %6s %5s %5s  %s\n",
		dim("File"), dim("Verdict"), dim("Score"), dim("Size"), dim("Finds"), dim("IOCs"), dim("Type"))
	fmt.Fprintf(w, "  %s\n", dim(strings.Repeat("─", 90)))

	malicious := 0
	suspicious := 0
	clean := 0
	errCount := 0

	for _, r := range results {
		if r.Error != "" {
			errCount++
			fmt.Fprintf(w, "  %-28s %s\n",
				truncStr(r.FileName, 28),
				colorize(colorRed, "ERROR: "+truncStr(r.Error, 50)))
			continue
		}

		vColor := verdictColor(r.Verdict)
		row := fmt.Sprintf("  %-28s %s %s %6s %5d %5d  %s\n",
			truncStr(r.FileName, 28),
			colorize(vColor, padRight(r.Verdict, 20)),
			colorize(vColor, padLeft(fmt.Sprintf("%d", r.Score), 5)),
			formatBytes(r.Size),
			r.Findings,
			r.IOCs,
			dim(truncStr(r.FileType, 16)))
		if r.Score >= 80 {
			fmt.Fprint(w, colorize(colorBold, row))
		} else {
			fmt.Fprint(w, row)
		}

		switch {
		case r.Score >= 80:
			malicious++
		case r.Score >= 30:
			suspicious++
		default:
			clean++
		}
	}

	fmt.Fprintf(w, "  %s\n", dim(strings.Repeat("─", 90)))
	fmt.Fprintf(w, "  Scanned %s in %s  —  %s  %s  %s  %s\n",
		bold(fmt.Sprintf("%d files", len(results))),
		elapsed.Round(time.Millisecond),
		colorize(colorRed, fmt.Sprintf("%d malicious", malicious)),
		colorize(colorOrange, fmt.Sprintf("%d suspicious", suspicious)),
		colorize(colorGreen, fmt.Sprintf("%d clean", clean)),
		dim(fmt.Sprintf("%d errors", errCount)))
	fmt.Fprintln(w)
}

func printPlainBatchSummary(w io.Writer, results []batchResult, elapsed time.Duration) {
	fmt.Fprintf(w, "Batch Summary (%d files in %s)\n",
		len(results), elapsed.Round(time.Millisecond))
	fmt.Fprintf(w, "%-28s %-20s %5s %6s %5s %5s  %s\n",
		"File", "Verdict", "Score", "Size", "Finds", "IOCs", "Type")
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", 90))

	malicious, suspicious, clean, errCount := 0, 0, 0, 0
	for _, r := range results {
		if r.Error != "" {
			errCount++
			fmt.Fprintf(w, "%-28s ERROR: %s\n",
				truncStr(r.FileName, 28), truncStr(r.Error, 50))
			continue
		}
		fmt.Fprintf(w, "%-28s %-20s %5d %6s %5d %5d  %s\n",
			truncStr(r.FileName, 28),
			r.Verdict,
			r.Score,
			formatBytes(r.Size),
			r.Findings,
			r.IOCs,
			truncStr(r.FileType, 16))
		switch {
		case r.Score >= 80:
			malicious++
		case r.Score >= 30:
			suspicious++
		default:
			clean++
		}
	}
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", 90))
	fmt.Fprintf(w, "Scanned %d files in %s — %d malicious, %d suspicious, %d clean, %d errors\n",
		len(results), elapsed.Round(time.Millisecond), malicious, suspicious, clean, errCount)
}

// truncStr limits a string to n runes with an ellipsis. Rune-aware so
// multibyte filenames (UTF-8 malware names) never slice mid-codepoint or panic.
func truncStr(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 3 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

// padRight pads a string to width runes with trailing spaces.
func padRight(s string, width int) string {
	n := len([]rune(s))
	if n >= width {
		return s
	}
	return s + strings.Repeat(" ", width-n)
}

// padLeft pads a string to width runes with leading spaces.
func padLeft(s string, width int) string {
	n := len([]rune(s))
	if n >= width {
		return s
	}
	return strings.Repeat(" ", width-n) + s
}
