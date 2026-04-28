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

const defaultVersion = "0.2.0"

// version can be overridden at build time via:
//   go build -ldflags "-X main.version=1.0.0" .
var version = defaultVersion

type Config struct {
	Mode             string
	FilePath         string
	DirPath          string
	IOCPath          string
	ReportMode       string
	ReportPath       string
	PDFPath          string
	JSONPath         string
	HTMLPath         string
	YARAPath         string
	SigmaPath        string
	STIXPath         string
	ReportPackPath   string
	RulePaths        string
	PluginPaths      string
	IOCAllowlistPath string
	CaseID           string
	CaseDBPath       string
	Debug            bool
	Interactive      bool
	CommandShell     bool
	EnableCarving    bool
	ExternalTools    bool
	NoProgress       bool
	NoSplash         bool
	NoColor          bool
	WatchMode        bool
	WatchIntervalSec int
	SplashSeconds    int
	MinStringLen     int
	MaxDecodeDepth   int
	MaxAnalyzeBytes  int64
	MaxArchiveFiles  int
	MaxCarves        int
}

func main() {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	if cfg.Interactive {
		if err := RunInteractive(os.Stdin, os.Stdout, os.Stderr, cfg); err != nil {
			fmt.Fprintln(os.Stderr, "interactive mode failed:", err)
			os.Exit(1)
		}
		return
	}
	if cfg.CommandShell {
		if err := RunCommandShell(os.Stdin, os.Stdout, os.Stderr, cfg); err != nil {
			fmt.Fprintln(os.Stderr, "command shell failed:", err)
			os.Exit(1)
		}
		return
	}

	if cfg.DirPath != "" && cfg.WatchMode {
		if err := RunWatchMode(cfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if cfg.DirPath != "" {
		if err := RunBatchScan(cfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if _, err := RunConfiguredScan(cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func RunConfiguredScan(cfg Config) (result ScanResult, err error) {
	progress := NewProgress(!cfg.NoProgress, os.Stderr)
	defer func() {
		if recovered := recover(); recovered != nil {
			progress.Done()
			err = fmt.Errorf("fatal scanner error: %v", recovered)
			if cfg.Debug {
				err = fmt.Errorf("%w; debug: recovered panic while scanning %q", err, cfg.FilePath)
			}
		}
	}()

	RunStartupSplash(ShouldShowSplash(cfg, os.Stderr), os.Stderr, cfg)

	start := time.Now()
	result, err = ScanFile(cfg, progress)
	progress.Done()
	if err != nil {
		return result, fmt.Errorf("scan failed: %w", err)
	}
	result.Duration = time.Since(start).String()

	if cfg.CaseID != "" || cfg.CaseDBPath != "" {
		if err := StoreCaseRecord(cfg, &result); err != nil {
			return result, fmt.Errorf("case database write failed: %w", err)
		}
	}

	if cfg.IOCPath != "" {
		if err := WriteIOCFile(cfg.IOCPath, result); err != nil {
			return result, fmt.Errorf("ioc export failed: %w", err)
		}
	}

	report := renderReportForTerminal(result, cfg)
	if cfg.ReportPath != "" {
		// File output always uses plain text (no ANSI)
		plainReport := RenderReport(result, cfg.ReportMode)
		if err := os.WriteFile(cfg.ReportPath, []byte(plainReport), 0o644); err != nil {
			return result, fmt.Errorf("report write failed: %w", err)
		}
	} else {
		fmt.Print(report)
	}

	if cfg.JSONPath == "-" {
		// JSON to stdout for scripting: ./flatscan -f sample.bin --json -
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return result, fmt.Errorf("json render failed: %w", err)
		}
		fmt.Println(string(data))
	} else if cfg.JSONPath != "" {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return result, fmt.Errorf("json render failed: %w", err)
		}
		if err := os.WriteFile(cfg.JSONPath, append(data, '\n'), 0o644); err != nil {
			return result, fmt.Errorf("json write failed: %w", err)
		}
	}

	if cfg.PDFPath != "" {
		if err := WritePDFReport(cfg.PDFPath, result); err != nil {
			return result, fmt.Errorf("pdf report write failed: %w", err)
		}
	}

	if cfg.YARAPath != "" {
		if err := WriteYARARule(cfg.YARAPath, result); err != nil {
			return result, fmt.Errorf("yara rule write failed: %w", err)
		}
	}

	if cfg.SigmaPath != "" {
		if err := WriteSigmaRule(cfg.SigmaPath, result); err != nil {
			return result, fmt.Errorf("sigma rule write failed: %w", err)
		}
	}

	if cfg.HTMLPath != "" {
		if err := WriteHTMLReport(cfg.HTMLPath, result); err != nil {
			return result, fmt.Errorf("html report write failed: %w", err)
		}
	}

	if cfg.STIXPath != "" {
		if err := WriteSTIXBundle(cfg.STIXPath, result); err != nil {
			return result, fmt.Errorf("stix export failed: %w", err)
		}
	}

	if cfg.ReportPackPath != "" {
		if err := WriteReportPack(cfg.ReportPackPath, result, cfg); err != nil {
			return result, fmt.Errorf("report pack write failed: %w", err)
		}
	}
	return result, nil
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
		MaxCarves:       80,
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
	fs.StringVar(&cfg.HTMLPath, "html", "", "optional path to write an interactive HTML analyst report")
	fs.StringVar(&cfg.YARAPath, "yara", "", "optional path to write a generated YARA hunting rule")
	fs.StringVar(&cfg.SigmaPath, "sigma", "", "optional path to write a generated Sigma hunting rule")
	fs.StringVar(&cfg.STIXPath, "stix", "", "optional path to write a STIX 2.1 JSON bundle for threat intel sharing")
	fs.StringVar(&cfg.ReportPackPath, "report-pack", "", "optional directory to write PDF, HTML, JSON, IOC, YARA, Sigma, STIX, and text reports")
	fs.StringVar(&cfg.RulePaths, "rules", "", "comma-separated files or directories containing FlatScan JSON/rule-pack rules")
	fs.StringVar(&cfg.PluginPaths, "plugins", "", "comma-separated declarative FlatScan plugin pack files or directories")
	fs.StringVar(&cfg.IOCAllowlistPath, "ioc-allowlist", "", "optional IOC allowlist file for suppressing environment, PKI, or format infrastructure")
	fs.StringVar(&cfg.CaseID, "case", "", "case identifier for local case database recording")
	fs.StringVar(&cfg.CaseDBPath, "case-db", "", "local JSONL case database path; defaults to reports/flatscan_cases.jsonl when --case is used")
	fs.BoolVar(&cfg.Debug, "debug", false, "enable scanner debug logs")
	fs.BoolVar(&cfg.Interactive, "interactive", false, "launch guided interactive mode")
	fs.BoolVar(&cfg.Interactive, "i", false, "launch guided interactive mode")
	fs.BoolVar(&cfg.CommandShell, "shell", false, "launch manual FlatScan command shell")
	fs.BoolVar(&cfg.EnableCarving, "carve", false, "enable recursive safe file carving from raw bytes")
	fs.BoolVar(&cfg.ExternalTools, "external-tools", false, "run optional safe external metadata tools when installed")
	fs.BoolVar(&cfg.NoProgress, "no-progress", false, "disable progress percentage output")
	fs.BoolVar(&cfg.NoSplash, "no-splash", false, "disable startup splash loading bar")
	fs.BoolVar(&cfg.NoColor, "no-color", false, "disable colorized terminal output")
	fs.StringVar(&cfg.DirPath, "dir", "", "scan all files in a directory (batch mode)")
	fs.BoolVar(&cfg.WatchMode, "watch", false, "monitor directory for new files and auto-scan (requires --dir)")
	fs.IntVar(&cfg.WatchIntervalSec, "watch-interval", 3, "polling interval in seconds for watch mode")
	fs.IntVar(&cfg.SplashSeconds, "splash-seconds", cfg.SplashSeconds, "startup splash loading duration in seconds")
	fs.IntVar(&cfg.MinStringLen, "min-string", cfg.MinStringLen, "minimum string length to extract")
	fs.IntVar(&cfg.MaxDecodeDepth, "decode-depth", cfg.MaxDecodeDepth, "maximum nested decode depth")
	fs.Int64Var(&cfg.MaxAnalyzeBytes, "max-analyze-bytes", cfg.MaxAnalyzeBytes, "maximum bytes retained for in-memory analysis")
	fs.IntVar(&cfg.MaxArchiveFiles, "max-archive-files", cfg.MaxArchiveFiles, "maximum archive entries inspected")
	fs.IntVar(&cfg.MaxCarves, "max-carves", cfg.MaxCarves, "maximum embedded artifacts reported by safe carving")
	showVersion := fs.Bool("version", false, "print FlatScan version")

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "FlatScan %s - static malicious file scanner\n\n", version)
		fmt.Fprintln(fs.Output(), "Usage:")
		fmt.Fprintln(fs.Output(), `  ./flatscan -m "quick" -f "sample.bin" --extract-ioc "iocs.txt" --report-mode Full`)
		fmt.Fprintln(fs.Output(), `  ./flatscan --dir ./samples -m deep        # batch scan directory`)
		fmt.Fprintln(fs.Output(), `  ./flatscan --dir ./inbox --watch -m deep   # monitor directory for new files`)
		fmt.Fprintln(fs.Output(), `  ./flatscan -f sample.bin --json -          # JSON to stdout`)
		fmt.Fprintln(fs.Output(), `  ./flatscan -f sample.bin --stix out.json   # STIX 2.1 threat intel export`)
		fmt.Fprintln(fs.Output(), `  ./flatscan --interactive`)
		fmt.Fprintln(fs.Output(), `  ./flatscan --shell`)
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
	if cfg.Interactive && cfg.CommandShell {
		return cfg, errors.New("use either --interactive or --shell, not both")
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

	if cfg.FilePath == "" && cfg.DirPath == "" {
		if cfg.Interactive || cfg.CommandShell {
			return cfg, nil
		}
		return cfg, errors.New("missing required -f/--file path or --dir path")
	}
	if cfg.WatchMode && cfg.DirPath == "" {
		return cfg, errors.New("--watch requires --dir")
	}

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
	if cfg.MaxCarves < 1 || cfg.MaxCarves > 1000 {
		return cfg, errors.New("--max-carves must be between 1 and 1000")
	}
	if cfg.SplashSeconds < 0 || cfg.SplashSeconds > 120 {
		return cfg, errors.New("--splash-seconds must be between 0 and 120")
	}

	if cfg.FilePath != "" {
		clean, err := filepath.Abs(cfg.FilePath)
		if err != nil {
			return cfg, err
		}
		cfg.FilePath = clean
	}
	if cfg.DirPath != "" {
		clean, err := filepath.Abs(cfg.DirPath)
		if err != nil {
			return cfg, err
		}
		cfg.DirPath = clean
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

// renderReportForTerminal returns a colorized report when outputting to a
// terminal, and a plain-text report otherwise.
func renderReportForTerminal(result ScanResult, cfg Config) string {
	if !cfg.NoColor && colorEnabled() {
		return RenderColorReport(result, cfg.ReportMode)
	}
	return RenderReport(result, cfg.ReportMode)
}
