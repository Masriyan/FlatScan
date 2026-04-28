package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

	var results []batchResult

	for i, filePath := range files {
		fileCfg := cfg
		fileCfg.FilePath = filePath
		fileCfg.NoSplash = true
		fileCfg.DirPath = "" // prevent recursion

		if useColor {
			fmt.Fprintf(os.Stderr, "%s [%d/%d] %s\n",
				dim("→"),
				i+1, len(files),
				filepath.Base(filePath))
		} else {
			fmt.Fprintf(os.Stderr, "[%d/%d] scanning %s\n",
				i+1, len(files), filepath.Base(filePath))
		}

		result, err := RunConfiguredScan(fileCfg)
		if err != nil {
			results = append(results, batchResult{
				FileName: filepath.Base(filePath),
				Error:    err.Error(),
			})
			if useColor {
				fmt.Fprintf(os.Stderr, "  %s %s\n",
					colorize(colorRed, "✗"),
					dim(err.Error()))
			} else {
				fmt.Fprintf(os.Stderr, "  ERROR: %s\n", err.Error())
			}
			continue
		}

		br := batchResult{
			FileName: result.FileName,
			Verdict:  result.Verdict,
			Score:    result.RiskScore,
			FileType: result.FileType,
			SHA256:   result.Hashes.SHA256,
			Duration: result.Duration,
			Findings: len(result.Findings),
			IOCs:     IOCCount(result.IOCs),
		}
		results = append(results, br)

		if useColor {
			fmt.Fprintf(os.Stderr, "  %s %s score=%s findings=%d\n",
				colorize(colorGreen, "✓"),
				colorize(verdictColor(br.Verdict), br.Verdict),
				colorize(verdictColor(br.Verdict), fmt.Sprintf("%d", br.Score)),
				br.Findings)
		} else {
			fmt.Fprintf(os.Stderr, "  %s score=%d findings=%d\n",
				br.Verdict, br.Score, br.Findings)
		}
	}

	elapsed := time.Since(start)

	// Print summary table
	fmt.Fprintln(os.Stderr)
	if useColor {
		printColorBatchSummary(results, elapsed)
	} else {
		printPlainBatchSummary(results, elapsed)
	}

	return nil
}

func printColorBatchSummary(results []batchResult, elapsed time.Duration) {
	fmt.Fprintf(os.Stderr, "%s\n", bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
	fmt.Fprintf(os.Stderr, "%s  %s\n",
		bold("📊 Batch Summary"),
		dim(fmt.Sprintf("(%d files in %s)", len(results), elapsed.Round(time.Millisecond))))
	fmt.Fprintf(os.Stderr, "%s\n", bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))

	// Table header
	fmt.Fprintf(os.Stderr, "  %-30s %-22s %6s %8s %5s  %s\n",
		dim("File"), dim("Verdict"), dim("Score"), dim("Finds"), dim("IOCs"), dim("Type"))
	fmt.Fprintf(os.Stderr, "  %s\n",
		dim(strings.Repeat("─", 78)))

	malicious := 0
	suspicious := 0
	clean := 0
	errors := 0

	for _, r := range results {
		if r.Error != "" {
			errors++
			fmt.Fprintf(os.Stderr, "  %-30s %s\n",
				truncStr(r.FileName, 30),
				colorize(colorRed, "ERROR: "+truncStr(r.Error, 45)))
			continue
		}

		name := truncStr(r.FileName, 30)
		vColor := verdictColor(r.Verdict)
		fmt.Fprintf(os.Stderr, "  %-30s %s %s %8d %5d  %s\n",
			name,
			colorize(vColor, padRight(r.Verdict, 22)),
			colorize(vColor, padLeft(fmt.Sprintf("%d", r.Score), 6)),
			r.Findings,
			r.IOCs,
			dim(truncStr(r.FileType, 18)))

		switch {
		case r.Score >= 80:
			malicious++
		case r.Score >= 30:
			suspicious++
		default:
			clean++
		}
	}

	fmt.Fprintf(os.Stderr, "  %s\n", dim(strings.Repeat("─", 78)))
	fmt.Fprintf(os.Stderr, "  %s  %s  %s  %s\n",
		colorize(colorRed, fmt.Sprintf("🔴 Malicious: %d", malicious)),
		colorize(colorOrange, fmt.Sprintf("🟠 Suspicious: %d", suspicious)),
		colorize(colorGreen, fmt.Sprintf("🟢 Clean: %d", clean)),
		dim(fmt.Sprintf("Errors: %d", errors)))
	fmt.Fprintln(os.Stderr)
}

func printPlainBatchSummary(results []batchResult, elapsed time.Duration) {
	fmt.Fprintf(os.Stderr, "Batch Summary (%d files in %s)\n",
		len(results), elapsed.Round(time.Millisecond))
	fmt.Fprintf(os.Stderr, "%-30s %-22s %6s %8s %5s  %s\n",
		"File", "Verdict", "Score", "Finds", "IOCs", "Type")
	fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("-", 78))

	for _, r := range results {
		if r.Error != "" {
			fmt.Fprintf(os.Stderr, "%-30s ERROR: %s\n",
				truncStr(r.FileName, 30), truncStr(r.Error, 45))
			continue
		}
		fmt.Fprintf(os.Stderr, "%-30s %-22s %6d %8d %5d  %s\n",
			truncStr(r.FileName, 30),
			r.Verdict,
			r.Score,
			r.Findings,
			r.IOCs,
			truncStr(r.FileType, 18))
	}
	fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("-", 78))
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
