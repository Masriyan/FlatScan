package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RunWatchMode monitors a directory for new files and auto-scans them.
// It uses a polling approach with configurable interval to stay within
// the zero-dependency constraint (no fsnotify/inotify required).
//
// Usage: ./flatscan --watch ./inbox -m deep
func RunWatchMode(cfg Config) error {
	dir := cfg.DirPath
	stat, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("watch: %w", err)
	}
	if !stat.IsDir() {
		return fmt.Errorf("watch: %s is not a directory", dir)
	}

	interval := time.Duration(cfg.WatchIntervalSec) * time.Second
	if interval < 1*time.Second {
		interval = 3 * time.Second
	}

	useColor := !cfg.NoColor && colorEnabled()
	seen := make(map[string]time.Time)

	// Initial population — mark existing files as seen
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.Size() == 0 {
			continue
		}
		seen[entry.Name()] = info.ModTime()
	}

	if useColor {
		fmt.Fprintf(os.Stderr, "\n%s\n", bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
		fmt.Fprintf(os.Stderr, "%s  Watch mode active\n", bold("FlatScan"))
		fmt.Fprintf(os.Stderr, "%s  Directory: %s\n", bold("        "), dim(dir))
		fmt.Fprintf(os.Stderr, "%s  Mode: %s  Interval: %s\n",
			bold("        "), colorize(colorCyan, cfg.Mode), dim(interval.String()))
		fmt.Fprintf(os.Stderr, "%s  Existing files: %s (skipped)\n",
			bold("        "), dim(fmt.Sprintf("%d", len(seen))))
		fmt.Fprintf(os.Stderr, "%s\n", bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
		fmt.Fprintf(os.Stderr, "%s Waiting for new files...\n\n", dim("👁"))
	} else {
		fmt.Fprintf(os.Stderr, "\nFlatScan watch mode: monitoring %s (mode: %s, interval: %s)\n",
			dir, cfg.Mode, interval)
		fmt.Fprintf(os.Stderr, "Existing files: %d (skipped). Waiting for new files...\n\n", len(seen))
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	scanned := 0
	for range ticker.C {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if useColor {
				fmt.Fprintf(os.Stderr, "  %s %s\n", colorize(colorRed, "✗"), dim(err.Error()))
			}
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			info, err := entry.Info()
			if err != nil || info.Size() == 0 {
				continue
			}

			name := entry.Name()
			modTime := info.ModTime()

			// Check if file is new or modified
			if prevMod, exists := seen[name]; exists && prevMod.Equal(modTime) {
				continue
			}

			// Wait briefly to ensure the file is fully written
			time.Sleep(500 * time.Millisecond)

			// Re-stat to confirm size is stable
			info2, err := os.Stat(filepath.Join(dir, name))
			if err != nil || info2.Size() != info.Size() {
				continue // file is still being written
			}

			seen[name] = modTime
			scanned++

			filePath := filepath.Join(dir, name)
			if useColor {
				fmt.Fprintf(os.Stderr, "%s [%s] New file detected: %s (%s)\n",
					colorize(colorCyan, "📄"),
					dim(time.Now().Format("15:04:05")),
					bold(name),
					dim(formatBytes(info.Size())))
			} else {
				fmt.Fprintf(os.Stderr, "[%s] new file: %s (%d bytes)\n",
					time.Now().Format("15:04:05"), name, info.Size())
			}

			// Scan the file
			fileCfg := cfg
			fileCfg.FilePath = filePath
			fileCfg.NoSplash = true
			fileCfg.DirPath = ""

			result, err := RunConfiguredScan(fileCfg)
			if err != nil {
				if useColor {
					fmt.Fprintf(os.Stderr, "  %s %s\n",
						colorize(colorRed, "✗"),
						dim(err.Error()))
				} else {
					fmt.Fprintf(os.Stderr, "  ERROR: %s\n", err.Error())
				}
				continue
			}

			if useColor {
				hashPreview := result.Hashes.SHA256
				if len(hashPreview) > 16 {
					hashPreview = hashPreview[:16] + "..."
				}
				fmt.Fprintf(os.Stderr, "  %s %s score=%s findings=%d sha256=%s\n",
					colorize(colorGreen, "✓"),
					colorize(verdictColor(result.Verdict), result.Verdict),
					colorize(verdictColor(result.Verdict), fmt.Sprintf("%d", result.RiskScore)),
					len(result.Findings),
					dim(hashPreview))

				if result.RiskScore >= 80 {
					fmt.Fprintf(os.Stderr, "  %s %s\n",
						colorize(colorRed+colorBold, "⚠ ALERT:"),
						colorize(colorRed, "Malicious file detected! Immediate action recommended."))
				}
			} else {
				hashPreview := result.Hashes.SHA256
				if len(hashPreview) > 16 {
					hashPreview = hashPreview[:16] + "..."
				}
				fmt.Fprintf(os.Stderr, "  %s score=%d findings=%d sha256=%s\n",
					result.Verdict, result.RiskScore,
					len(result.Findings), hashPreview)
			}

			if useColor {
				fmt.Fprintf(os.Stderr, "%s Total scanned: %d | Waiting...\n\n",
					dim("👁"), scanned)
			}
		}
	}
	return nil
}
