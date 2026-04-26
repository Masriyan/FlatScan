package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func ShouldShowSplash(cfg Config, stderr *os.File) bool {
	if cfg.NoProgress || cfg.NoSplash || cfg.SplashSeconds <= 0 {
		return false
	}
	info, err := stderr.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func RunStartupSplash(enabled bool, out io.Writer, cfg Config) {
	if !enabled {
		return
	}

	fmt.Fprintln(out)
	PrintASCIIBanner(out)
	fmt.Fprintln(out, "  FlatScan :: Static Malware Analysis Engine")
	fmt.Fprintf(out, "  Target   :: %s\n", filepath.Base(cfg.FilePath))
	fmt.Fprintf(out, "  Mode     :: %s | Report :: %s\n", strings.ToUpper(cfg.Mode), strings.ToUpper(cfg.ReportMode))

	steps := cfg.SplashSeconds * 10
	if steps < 1 {
		steps = 1
	}
	barWidth := 34
	tick := time.Duration(cfg.SplashSeconds) * time.Second / time.Duration(steps)
	labels := []string{
		"loading signature modules",
		"initializing IOC extractors",
		"preparing entropy analyzers",
		"warming decoder pipeline",
		"arming report engine",
	}

	for step := 0; step <= steps; step++ {
		percent := int(float64(step) / float64(steps) * 100)
		filled := int(float64(barWidth) * float64(percent) / 100.0)
		if filled > barWidth {
			filled = barWidth
		}
		label := labels[(step*len(labels))/(steps+1)]
		bar := strings.Repeat("#", filled) + strings.Repeat("-", barWidth-filled)
		fmt.Fprintf(out, "\r  [%s] %3d%%  %s", bar, percent, label)
		if step < steps {
			time.Sleep(tick)
		}
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out)
}

func PrintASCIIBanner(out io.Writer) {
	lines := []string{
		"░▒▓████████▓▒░▒▓█▓▒░       ░▒▓██████▓▒░▒▓████████▓▒░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░",
		"░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░  ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ",
		"░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░  ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ",
		"░▒▓██████▓▒░ ░▒▓█▓▒░      ░▒▓████████▓▒░ ░▒▓█▓▒░   ░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░ ",
		"░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░         ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ",
		"░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░         ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ",
		"░▒▓█▓▒░      ░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░  ░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ",
		"",
		"        FlatScan..!! by sudo3rs",
		"",
	}
	for _, line := range lines {
		fmt.Fprintln(out, line)
	}
}
