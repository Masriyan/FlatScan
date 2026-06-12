package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

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

	useColor := !cfg.NoColor && colorEnabled()
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

	type indexedResult struct {
		idx int
		br  batchResult
	}

	sem := make(chan struct{}, workers)
	var mu sync.Mutex
	resultSlots := make([]batchResult, len(files))
	var wg sync.WaitGroup

	for i, filePath := range files {
		wg.Add(1)
		go func(idx int, fp string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			name := filepath.Base(fp)
			if useColor {
				fmt.Fprintf(os.Stderr, "%s [%d/%d] %s\n", dim("→"), idx+1, len(files), name)
			} else {
				fmt.Fprintf(os.Stderr, "[%d/%d] scanning %s\n", idx+1, len(files), name)
			}

			fileCfg := cfg
			fileCfg.FilePath = fp
			fileCfg.NoSplash = true
			fileCfg.NoProgress = true
			fileCfg.DirPath = ""

			result, err := RunConfiguredScan(fileCfg)
			if err != nil {
				br := batchResult{FileName: name, Error: err.Error()}
				if useColor {
					fmt.Fprintf(os.Stderr, "  %s %s\n", colorize(colorRed, "✗"), dim(err.Error()))
				} else {
					fmt.Fprintf(os.Stderr, "  ERROR: %s\n", err.Error())
				}
				mu.Lock()
				resultSlots[idx] = br
				mu.Unlock()
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
				fmt.Fprintf(os.Stderr, "  %s %s score=%s findings=%d\n",
					colorize(colorGreen, "✓"),
					colorize(verdictColor(br.Verdict), br.Verdict),
					colorize(verdictColor(br.Verdict), fmt.Sprintf("%d", br.Score)),
					br.Findings)
			} else {
				fmt.Fprintf(os.Stderr, "  %s score=%d findings=%d\n", br.Verdict, br.Score, br.Findings)
			}
			mu.Lock()
			resultSlots[idx] = br
			mu.Unlock()
		}(i, filePath)
	}
	wg.Wait()

	// Filter out zero-value placeholders (files with errors already have FileName set)
	var results []batchResult
	for _, r := range resultSlots {
		results = append(results, r)
	}

	elapsed := time.Since(start)

	// Print summary table
	fmt.Fprintln(os.Stderr)
	if useColor {
		printColorBatchSummary(results, elapsed)
	} else {
		printPlainBatchSummary(results, elapsed)
	}

	// Write JSON batch summary if requested
	if cfg.BatchJSONPath != "" {
		if err := writeBatchJSON(cfg.BatchJSONPath, results, elapsed); err != nil {
			fmt.Fprintf(os.Stderr, "batch-json write failed: %v\n", err)
		}
	}

	return nil
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

func printColorBatchSummary(results []batchResult, elapsed time.Duration) {
	const rule = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	fmt.Fprintf(os.Stderr, "%s\n", bold(rule))
	fmt.Fprintf(os.Stderr, "%s  %s\n",
		bold("Batch Summary"),
		dim(fmt.Sprintf("(%d files  %s)", len(results), elapsed.Round(time.Millisecond))))
	fmt.Fprintf(os.Stderr, "%s\n", bold(rule))

	fmt.Fprintf(os.Stderr, "  %-28s %-20s %5s %6s %5s %5s  %s\n",
		dim("File"), dim("Verdict"), dim("Score"), dim("Size"), dim("Finds"), dim("IOCs"), dim("Type"))
	fmt.Fprintf(os.Stderr, "  %s\n", dim(strings.Repeat("─", 90)))

	malicious := 0
	suspicious := 0
	clean := 0
	errCount := 0

	for _, r := range results {
		if r.Error != "" {
			errCount++
			fmt.Fprintf(os.Stderr, "  %-28s %s\n",
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
			fmt.Fprint(os.Stderr, colorize(colorBold, row))
		} else {
			fmt.Fprint(os.Stderr, row)
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

	fmt.Fprintf(os.Stderr, "  %s\n", dim(strings.Repeat("─", 90)))
	fmt.Fprintf(os.Stderr, "  Scanned %s in %s  —  %s  %s  %s  %s\n",
		bold(fmt.Sprintf("%d files", len(results))),
		elapsed.Round(time.Millisecond),
		colorize(colorRed, fmt.Sprintf("%d malicious", malicious)),
		colorize(colorOrange, fmt.Sprintf("%d suspicious", suspicious)),
		colorize(colorGreen, fmt.Sprintf("%d clean", clean)),
		dim(fmt.Sprintf("%d errors", errCount)))
	fmt.Fprintln(os.Stderr)
}

func printPlainBatchSummary(results []batchResult, elapsed time.Duration) {
	fmt.Fprintf(os.Stderr, "Batch Summary (%d files in %s)\n",
		len(results), elapsed.Round(time.Millisecond))
	fmt.Fprintf(os.Stderr, "%-28s %-20s %5s %6s %5s %5s  %s\n",
		"File", "Verdict", "Score", "Size", "Finds", "IOCs", "Type")
	fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("-", 90))

	malicious, suspicious, clean, errCount := 0, 0, 0, 0
	for _, r := range results {
		if r.Error != "" {
			errCount++
			fmt.Fprintf(os.Stderr, "%-28s ERROR: %s\n",
				truncStr(r.FileName, 28), truncStr(r.Error, 50))
			continue
		}
		fmt.Fprintf(os.Stderr, "%-28s %-20s %5d %6s %5d %5d  %s\n",
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
	fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("-", 90))
	fmt.Fprintf(os.Stderr, "Scanned %d files in %s — %d malicious, %d suspicious, %d clean, %d errors\n",
		len(results), elapsed.Round(time.Millisecond), malicious, suspicious, clean, errCount)
}

// truncStr limits a string to n characters with an ellipsis.
func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// padRight pads a string to width with spaces.
func padRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

// padLeft pads a string to width with leading spaces.
func padLeft(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return strings.Repeat(" ", width-len(s)) + s
}
