package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// watchOutputPath turns a configured output path into a per-sample one by
// keeping the template's directory and suffix and substituting the sample name.
//
//	--json reports/out.json   + evil.exe -> reports/evil.exe.json
//	--stix reports/a.stix.json + evil.exe -> reports/evil.exe.stix.json
//
// The suffix runs from the first dot of the template's base name, so
// multi-part extensions like .stix.json survive intact. This matches how web
// mode names its per-job artifacts (<sample><suffix>), so the two modes agree.
//
// "" and "-" pass through untouched: the first means "not requested", the
// second means stdout.
func watchOutputPath(template, sampleName string) string {
	if template == "" || template == "-" {
		return template
	}
	base := filepath.Base(template)
	suffix := ""
	if i := strings.Index(base, "."); i >= 0 {
		suffix = base[i:]
	}
	return filepath.Join(filepath.Dir(template), sampleName+suffix)
}

// applyWatchOutputPaths rewrites every per-scan output path in dst so this
// sample's artifacts do not overwrite the previous sample's.
//
// Watch mode used to carry the single configured --json/--report/--html/--pdf
// path into every scan, so each new file silently clobbered the last and an
// inbox that received ten samples left exactly one set of artifacts behind.
//
// Deliberately untouched:
//   - ReportPackPath already collides safely. WriteReportPack names every file
//     "<sample>_<hash8>.<kind>", so two samples never overwrite each other
//     inside one pack directory. Rewriting it here would change working
//     behaviour and break existing scripts for no benefit.
//   - CaseDBPath is an append-only case ledger; appending every scan to one
//     file is the intended behaviour, not a collision.
//   - RulePaths, PluginPaths, IntelDBPath, SimilarityDBPath and
//     IOCAllowlistPath are inputs, not outputs.
func applyWatchOutputPaths(dst *Config, template Config, sampleName string) {
	dst.ReportPath = watchOutputPath(template.ReportPath, sampleName)
	dst.JSONPath = watchOutputPath(template.JSONPath, sampleName)
	dst.HTMLPath = watchOutputPath(template.HTMLPath, sampleName)
	dst.PDFPath = watchOutputPath(template.PDFPath, sampleName)
	dst.YARAPath = watchOutputPath(template.YARAPath, sampleName)
	dst.SigmaPath = watchOutputPath(template.SigmaPath, sampleName)
	dst.STIXPath = watchOutputPath(template.STIXPath, sampleName)
	dst.IOCPath = watchOutputPath(template.IOCPath, sampleName)
}

// watchWritesPerFile reports whether any per-scan artifact is configured, so
// watch can tell the operator where output is going.
func watchWritesPerFile(cfg Config) bool {
	return cfg.ReportPath != "" || cfg.JSONPath != "" || cfg.HTMLPath != "" ||
		cfg.PDFPath != "" || cfg.YARAPath != "" || cfg.SigmaPath != "" ||
		cfg.STIXPath != "" || cfg.IOCPath != "" || cfg.ReportPackPath != ""
}

// firstConfiguredOutput returns one configured output path, for use as an
// example in the startup notice. Order matches the flag list in --help.
func firstConfiguredOutput(cfg Config) string {
	for _, p := range []string{
		cfg.ReportPath, cfg.JSONPath, cfg.HTMLPath, cfg.PDFPath,
		cfg.YARAPath, cfg.SigmaPath, cfg.STIXPath, cfg.IOCPath, cfg.ReportPackPath,
	} {
		if p != "" && p != "-" {
			return p
		}
	}
	return ""
}

// RunWatchMode monitors a directory for new files and auto-scans them.
// It uses a polling approach with configurable interval to stay within
// the zero-dependency constraint (no fsnotify/inotify required).
//
// Usage: ./flatscan --watch ./inbox -m deep
//
// It returns when ctx is cancelled (Ctrl-C or SIGTERM), printing a final
// tally. Previously the ticker loop had no exit path at all, so the trailing
// return was unreachable and the process could only be killed mid-scan.
func RunWatchMode(ctx context.Context, cfg Config) error {
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

	useColor := !cfg.NoColor && stderrColorEnabled()
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

	// Each scan writes its own artifacts, named after the sample. Say so at
	// startup so nobody expects the single path they typed on the command line.
	if watchWritesPerFile(cfg) {
		example := firstConfiguredOutput(cfg)
		if useColor {
			fmt.Fprintf(os.Stderr, "%s  Outputs are written per file, e.g. %s\n\n",
				dim("        "), dim(watchOutputPath(example, "<sample>")))
		} else {
			fmt.Fprintf(os.Stderr, "Outputs are written per file, e.g. %s\n\n",
				watchOutputPath(example, "<sample>"))
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	scanned := 0
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr, "\nWatch stopped. Scanned %d file(s).\n", scanned)
			return nil
		case <-ticker.C:
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			if useColor {
				fmt.Fprintf(os.Stderr, "  %s %s\n", colorize(colorRed, "✗"), dim(err.Error()))
			}
			continue
		}

		for _, entry := range entries {
			// A directory drop of many files can keep this loop busy for a
			// while; check for cancellation between files so Ctrl-C is
			// responsive rather than waiting for the batch to drain.
			if ctx.Err() != nil {
				break
			}
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
			fileCfg.Quiet = true // suppress the full per-file report; watch prints its own one-line summary
			applyWatchOutputPaths(&fileCfg, cfg, name)

			// In alert-only mode, suppress file-detected message until result known
			alertThreshold := 55
			if cfg.WatchAlertOnly {
				fileCfg.NoProgress = true
			}

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

			// In alert-only mode, skip clean/low files silently
			// scanned was already incremented when the file was accepted above;
			// incrementing again here double-counted every below-threshold file,
			// which is the common case in alert-only mode.
			if cfg.WatchAlertOnly && result.RiskScore < alertThreshold {
				if useColor {
					fmt.Fprintf(os.Stderr, "\r%s Monitored: %d  Alerts: skip clean files  Last: %s (%s)  %s    ",
						dim("👁"), scanned, name, dim(fmt.Sprintf("score=%d", result.RiskScore)),
						dim(time.Now().Format("15:04:05")))
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
}
