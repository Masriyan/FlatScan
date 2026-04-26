package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const version = "0.1.0"

type Config struct {
	Mode            string
	FilePath        string
	IOCPath         string
	ReportMode      string
	ReportPath      string
	PDFPath         string
	JSONPath        string
	YARAPath        string
	Debug           bool
	NoProgress      bool
	NoSplash        bool
	SplashSeconds   int
	MinStringLen    int
	MaxDecodeDepth  int
	MaxAnalyzeBytes int64
	MaxArchiveFiles int
}

func main() {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	progress := NewProgress(!cfg.NoProgress, os.Stderr)
	defer func() {
		if recovered := recover(); recovered != nil {
			progress.Done()
			fmt.Fprintln(os.Stderr, "fatal scanner error:", recovered)
			if cfg.Debug {
				fmt.Fprintf(os.Stderr, "debug: recovered panic while scanning %q\n", cfg.FilePath)
			}
			os.Exit(1)
		}
	}()

	RunStartupSplash(ShouldShowSplash(cfg, os.Stderr), os.Stderr, cfg)

	start := time.Now()
	result, err := ScanFile(cfg, progress)
	progress.Done()
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan failed:", err)
		os.Exit(1)
	}
	result.Duration = time.Since(start).String()

	if cfg.IOCPath != "" {
		if err := WriteIOCFile(cfg.IOCPath, result); err != nil {
			fmt.Fprintln(os.Stderr, "ioc export failed:", err)
			os.Exit(1)
		}
	}

	report := RenderReport(result, cfg.ReportMode)
	if cfg.ReportPath != "" {
		if err := os.WriteFile(cfg.ReportPath, []byte(report), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "report write failed:", err)
			os.Exit(1)
		}
	} else {
		fmt.Print(report)
	}

	if cfg.JSONPath != "" {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "json render failed:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(cfg.JSONPath, append(data, '\n'), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "json write failed:", err)
			os.Exit(1)
		}
	}

	if cfg.PDFPath != "" {
		if err := WritePDFReport(cfg.PDFPath, result); err != nil {
			fmt.Fprintln(os.Stderr, "pdf report write failed:", err)
			os.Exit(1)
		}
	}

	if cfg.YARAPath != "" {
		if err := WriteYARARule(cfg.YARAPath, result); err != nil {
			fmt.Fprintln(os.Stderr, "yara rule write failed:", err)
			os.Exit(1)
		}
	}
}

func parseFlags(args []string) (Config, error) {
	cfg := Config{
		Mode:            "quick",
		ReportMode:      "summary",
		SplashSeconds:   20,
		MinStringLen:    5,
		MaxDecodeDepth:  2,
		MaxAnalyzeBytes: 256 * 1024 * 1024,
		MaxArchiveFiles: 500,
	}

	fs := flag.NewFlagSet("flatscan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&cfg.Mode, "m", cfg.Mode, "scan mode: quick, standard, or deep")
	fs.StringVar(&cfg.Mode, "mode", cfg.Mode, "scan mode: quick, standard, or deep")
	fs.StringVar(&cfg.FilePath, "f", "", "file to scan")
	fs.StringVar(&cfg.FilePath, "file", "", "file to scan")
	fs.StringVar(&cfg.IOCPath, "extract-ioc", "", "write extracted IOCs to a text file")
	fs.StringVar(&cfg.ReportMode, "report-mode", cfg.ReportMode, "report mode: Full, Summary, or minimal")
	fs.StringVar(&cfg.ReportPath, "report", "", "optional path to write the text report")
	fs.StringVar(&cfg.PDFPath, "pdf", "", "optional path to write a professional PDF report")
	fs.StringVar(&cfg.JSONPath, "json", "", "optional path to write a machine-readable JSON report")
	fs.StringVar(&cfg.YARAPath, "yara", "", "optional path to write a generated YARA hunting rule")
	fs.BoolVar(&cfg.Debug, "debug", false, "enable scanner debug logs")
	fs.BoolVar(&cfg.NoProgress, "no-progress", false, "disable progress percentage output")
	fs.BoolVar(&cfg.NoSplash, "no-splash", false, "disable startup splash loading bar")
	fs.IntVar(&cfg.SplashSeconds, "splash-seconds", cfg.SplashSeconds, "startup splash loading duration in seconds")
	fs.IntVar(&cfg.MinStringLen, "min-string", cfg.MinStringLen, "minimum string length to extract")
	fs.IntVar(&cfg.MaxDecodeDepth, "decode-depth", cfg.MaxDecodeDepth, "maximum nested decode depth")
	fs.Int64Var(&cfg.MaxAnalyzeBytes, "max-analyze-bytes", cfg.MaxAnalyzeBytes, "maximum bytes retained for in-memory analysis")
	fs.IntVar(&cfg.MaxArchiveFiles, "max-archive-files", cfg.MaxArchiveFiles, "maximum archive entries inspected")
	showVersion := fs.Bool("version", false, "print FlatScan version")

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "FlatScan %s - static malicious file scanner\n\n", version)
		fmt.Fprintln(fs.Output(), "Usage:")
		fmt.Fprintln(fs.Output(), `  ./flatscan -m "quick" -f "sample.bin" --extract-ioc "iocs.txt" --report-mode Full`)
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if *showVersion {
		fmt.Println("FlatScan", version)
		os.Exit(0)
	}

	cfg.Mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
	switch cfg.Mode {
	case "quick", "standard", "deep":
	default:
		return cfg, errors.New("invalid mode: use quick, standard, or deep")
	}

	cfg.ReportMode = normalizeReportMode(cfg.ReportMode)
	if cfg.ReportMode == "" {
		return cfg, errors.New("invalid report mode: use Full, Summary, or minimal")
	}

	if cfg.FilePath == "" {
		return cfg, errors.New("missing required -f/--file path")
	}
	clean, err := filepath.Abs(cfg.FilePath)
	if err != nil {
		return cfg, err
	}
	cfg.FilePath = clean

	if cfg.MinStringLen < 3 {
		return cfg, errors.New("--min-string must be at least 3")
	}
	if cfg.MaxDecodeDepth < 0 || cfg.MaxDecodeDepth > 5 {
		return cfg, errors.New("--decode-depth must be between 0 and 5")
	}
	if cfg.MaxAnalyzeBytes < 1024 {
		return cfg, errors.New("--max-analyze-bytes must be at least 1024")
	}
	if cfg.MaxArchiveFiles < 1 {
		return cfg, errors.New("--max-archive-files must be at least 1")
	}
	if cfg.SplashSeconds < 0 || cfg.SplashSeconds > 120 {
		return cfg, errors.New("--splash-seconds must be between 0 and 120")
	}
	return cfg, nil
}

func normalizeReportMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "full":
		return "full"
	case "summary":
		return "summary"
	case "minimal", "minimum", "min":
		return "minimal"
	default:
		return ""
	}
}
