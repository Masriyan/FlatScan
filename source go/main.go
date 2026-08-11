package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"
)

// stderrColorEnabled returns true when stderr is a terminal and NO_COLOR is unset.
func stderrColorEnabled() bool {
	return fileColorEnabled(os.Stderr)
}

// stdoutColorEnabled returns true when stdout is a terminal and NO_COLOR is unset.
func stdoutColorEnabled() bool {
	return fileColorEnabled(os.Stdout)
}

// fileColorEnabled reports whether the given file is a character device (a
// terminal) with NO_COLOR unset — the shared basis for color decisions.
func fileColorEnabled(f *os.File) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return stat.Mode()&os.ModeCharDevice != 0
}

const defaultVersion = "0.10.2"

// version can be overridden at build time via:
//
//	go build -ldflags "-X main.version=1.0.0" .
var version = defaultVersion

// errVersionRequested and errCompletionRequested are sentinels returned by
// parseFlags instead of calling os.Exit directly. main() turns them into a
// clean exit(0); the interactive command shell catches them and keeps running
// (typing "--version" inside the shell used to kill the whole process).
var (
	errVersionRequested    = errors.New("version requested")
	errCompletionRequested = errors.New("completion requested")
)

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
	SimilarityDBPath string
	IntelDBPath      string
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
	WatchAlertOnly   bool
	CI               bool
	CIThreshold      int
	OutputFormat     string
	BatchJSONPath    string
	WatchIntervalSec int
	WebMode          bool
	WebPort          int
	SplashSeconds    int
	MinStringLen     int
	MaxDecodeDepth   int
	MaxAnalyzeBytes  int64
	MaxArchiveFiles  int
	MaxCarves        int
	MaxPayloadDepth  int
	Quiet            bool
}

func main() {
	// Ctrl-C and SIGTERM cancel this context. The long-running modes (web,
	// watch) select on it so they can shut down cleanly and remove the temp
	// directories holding uploaded samples. A single scan is not itself
	// cancellable mid-pipeline — that would mean threading a context through
	// every analysis stage — so interrupting one still abandons it.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) || errors.Is(err, errVersionRequested) || errors.Is(err, errCompletionRequested) {
			os.Exit(0)
		}
		// Turn the flag package's terse "flag provided but not defined: -foo"
		// into a clean, actionable message with a did-you-mean suggestion.
		msg := err.Error()
		if strings.Contains(msg, "flag provided but not defined") {
			bad := strings.TrimSpace(msg[strings.LastIndex(msg, ":")+1:])
			fmt.Fprintf(os.Stderr, "error: unknown flag %s\n", bad)
			if sug := suggestFlag(strings.TrimLeft(bad, "-")); sug != "" {
				fmt.Fprintf(os.Stderr, "  did you mean --%s ?\n", sug)
			}
			fmt.Fprintln(os.Stderr, "  run 'flatscan --help' to see all flags")
			os.Exit(2)
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

	if cfg.WebMode {
		if err := RunWebServer(ctx, cfg); err != nil {
			fmt.Fprintln(os.Stderr, "web server failed:", err)
			os.Exit(1)
		}
		return
	}

	if cfg.DirPath != "" && cfg.WatchMode {
		if err := RunWatchMode(ctx, cfg); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}

	if cfg.DirPath != "" {
		if err := RunBatchScan(cfg); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		os.Exit(batchExitCode)
	}

	result, err := RunConfiguredScan(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if cfg.CI {
		label := "CLEAN"
		if result.RiskScore >= 80 {
			label = "MALICIOUS"
		} else if result.RiskScore >= 30 {
			label = "SUSPICIOUS"
		}
		fmt.Fprintf(os.Stderr, "FLATSCAN: %s score=%d file=%s findings=%d sha256=%s\n",
			label, result.RiskScore, result.FileName, len(result.Findings), result.Hashes.SHA256)
		// Exit codes mirror the single-file matrix so CI pipelines can tell
		// malicious (20) from merely suspicious/over-threshold (10).
		switch {
		case result.RiskScore >= 80:
			os.Exit(20)
		case result.RiskScore >= cfg.CIThreshold:
			os.Exit(10)
		}
		os.Exit(0)
	}

	if !cfg.Quiet {
		PrintPostScanHints(result, cfg, os.Stdout)
	}

	switch {
	case result.RiskScore >= 80:
		os.Exit(20)
	case result.RiskScore >= 30:
		os.Exit(10)
	}
}

func RunConfiguredScan(cfg Config) (result ScanResult, err error) {
	progress := NewProgress(!cfg.NoProgress, os.Stderr)
	defer func() {
		if recovered := recover(); recovered != nil {
			progress.Done()
			// Recovering keeps one malformed sample from taking down a batch of
			// 500, which is the right trade for a tool that parses hostile
			// input. But a panic here is always a parser bug, and returning it
			// only as an error string on one file means it never gets
			// investigated. Print the stack to stderr unconditionally so it is
			// visible without needing --debug to reproduce.
			fmt.Fprintf(os.Stderr, "\n[flatscan] BUG: recovered panic while scanning %q: %v\n%s\n"+
				"[flatscan] this is a parser defect — please report it with the sample if possible\n",
				cfg.FilePath, recovered, debug.Stack())
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
	} else if cfg.JSONPath != "-" && cfg.OutputFormat == "text" && !cfg.CI && !cfg.Quiet {
		// Print text report to stdout, but not when JSON stdout is active,
		// output-format is non-text, CI mode is active, or quiet is set
		// (batch/watch suppress per-file reports so only the summary shows).
		fmt.Print(report)
	}

	// --output-format handling (json/csv/jsonl write to stdout)
	switch cfg.OutputFormat {
	case "json":
		if cfg.JSONPath != "-" { // avoid double-printing if --json - is also set
			data, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return result, fmt.Errorf("json render failed: %w", err)
			}
			fmt.Println(string(data))
		}
	case "csv":
		if cfg.JSONPath != "-" { // avoid mixing CSV with JSON on stdout
			fmt.Printf("%s,%d,%s,%d,%d,%s\n",
				result.FileName, result.RiskScore, result.Verdict,
				len(result.Findings), IOCCount(result.IOCs), result.Hashes.SHA256)
		}
	case "jsonl":
		if cfg.JSONPath != "-" { // avoid mixing JSONL with pretty JSON on stdout
			data, err := json.Marshal(result)
			if err != nil {
				return result, fmt.Errorf("jsonl render failed: %w", err)
			}
			fmt.Println(string(data))
		}
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
		OutputFormat:    "text",
		SplashSeconds:   20,
		MinStringLen:    5,
		MaxDecodeDepth:  2,
		MaxAnalyzeBytes: 256 * 1024 * 1024,
		MaxArchiveFiles: 500,
		MaxCarves:       80,
		MaxPayloadDepth: 3,
		CIThreshold:     55,
	}

	fs := flag.NewFlagSet("flatscan", flag.ContinueOnError)
	// Silence the flag package's own error line and usage dump; main() renders a
	// single actionable message (with a did-you-mean) on parse failure instead.
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.Mode, "m", cfg.Mode, "")
	fs.StringVar(&cfg.Mode, "mode", cfg.Mode, "")
	fs.StringVar(&cfg.FilePath, "f", "", "")
	fs.StringVar(&cfg.FilePath, "file", "", "")
	fs.StringVar(&cfg.IOCPath, "extract-ioc", "", "")
	fs.StringVar(&cfg.ReportMode, "report-mode", cfg.ReportMode, "")
	fs.StringVar(&cfg.ReportPath, "report", "", "")
	fs.StringVar(&cfg.PDFPath, "pdf", "", "")
	fs.StringVar(&cfg.JSONPath, "json", "", "")
	fs.StringVar(&cfg.HTMLPath, "html", "", "")
	fs.StringVar(&cfg.YARAPath, "yara", "", "")
	fs.StringVar(&cfg.SigmaPath, "sigma", "", "")
	fs.StringVar(&cfg.STIXPath, "stix", "", "")
	fs.StringVar(&cfg.ReportPackPath, "report-pack", "", "")
	fs.StringVar(&cfg.RulePaths, "rules", "", "")
	fs.StringVar(&cfg.PluginPaths, "plugins", "", "")
	fs.StringVar(&cfg.IOCAllowlistPath, "ioc-allowlist", "", "")
	fs.StringVar(&cfg.SimilarityDBPath, "similarity-db", "", "")
	fs.StringVar(&cfg.IntelDBPath, "intel-db", "", "")
	fs.StringVar(&cfg.CaseID, "case", "", "")
	fs.StringVar(&cfg.CaseDBPath, "case-db", "", "")
	fs.BoolVar(&cfg.Debug, "debug", false, "")
	fs.BoolVar(&cfg.Interactive, "interactive", false, "")
	fs.BoolVar(&cfg.Interactive, "i", false, "")
	fs.BoolVar(&cfg.CommandShell, "shell", false, "")
	fs.BoolVar(&cfg.EnableCarving, "carve", false, "")
	fs.BoolVar(&cfg.ExternalTools, "external-tools", false, "")
	fs.BoolVar(&cfg.NoProgress, "no-progress", false, "")
	fs.BoolVar(&cfg.NoSplash, "no-splash", false, "")
	fs.BoolVar(&cfg.NoColor, "no-color", false, "")
	fs.BoolVar(&cfg.Quiet, "quiet", false, "")
	fs.BoolVar(&cfg.Quiet, "q", false, "")
	fs.StringVar(&cfg.DirPath, "dir", "", "")
	fs.BoolVar(&cfg.WatchMode, "watch", false, "")
	fs.BoolVar(&cfg.WatchAlertOnly, "watch-alert-only", false, "")
	fs.BoolVar(&cfg.CI, "ci", false, "")
	fs.IntVar(&cfg.CIThreshold, "ci-threshold", cfg.CIThreshold, "")
	fs.StringVar(&cfg.OutputFormat, "output-format", cfg.OutputFormat, "")
	fs.StringVar(&cfg.BatchJSONPath, "batch-json", "", "")
	fs.IntVar(&cfg.WatchIntervalSec, "watch-interval", 3, "")
	fs.BoolVar(&cfg.WebMode, "web", false, "")
	fs.IntVar(&cfg.WebPort, "web-port", 5000, "")
	fs.IntVar(&cfg.SplashSeconds, "splash-seconds", cfg.SplashSeconds, "")
	fs.IntVar(&cfg.MinStringLen, "min-string", cfg.MinStringLen, "")
	fs.IntVar(&cfg.MaxDecodeDepth, "decode-depth", cfg.MaxDecodeDepth, "")
	fs.Int64Var(&cfg.MaxAnalyzeBytes, "max-analyze-bytes", cfg.MaxAnalyzeBytes, "")
	fs.IntVar(&cfg.MaxArchiveFiles, "max-archive-files", cfg.MaxArchiveFiles, "")
	fs.IntVar(&cfg.MaxCarves, "max-carves", cfg.MaxCarves, "")
	fs.IntVar(&cfg.MaxPayloadDepth, "resolve-depth", cfg.MaxPayloadDepth, "")
	showVersion := fs.Bool("version", false, "")
	completionShell := fs.String("completion", "", "")
	helpLong := fs.Bool("help", false, "")
	helpShort := fs.Bool("h", false, "")

	// The flag package calls fs.Usage on a parse error; suppress it so main()
	// can render a single actionable did-you-mean message instead of the full
	// help dump. Explicit --help/-h below still prints the grouped help.
	fs.Usage = func() {}

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}

	if *helpLong || *helpShort {
		// Explicit --help/-h: help is the requested output, so it goes to
		// stdout (pipeable to less/grep) and exits 0.
		printGroupedHelp(os.Stdout)
		return cfg, flag.ErrHelp
	}

	if *completionShell != "" {
		switch strings.ToLower(*completionShell) {
		case "bash":
			PrintBashCompletion(os.Stdout)
		case "zsh":
			PrintZshCompletion(os.Stdout)
		case "fish":
			PrintFishCompletion(os.Stdout)
		default:
			return cfg, fmt.Errorf("unknown shell %q — valid values: bash, zsh, fish", *completionShell)
		}
		return cfg, errCompletionRequested
	}

	if *showVersion {
		fmt.Println("FlatScan", version)
		return cfg, errVersionRequested
	}
	if cfg.Interactive && cfg.CommandShell {
		return cfg, errors.New("use either --interactive or --shell, not both")
	}
	// Reject mode combinations where one flag would be silently discarded.
	if cfg.WebMode {
		switch {
		case cfg.FilePath != "":
			return cfg, errors.New("--web cannot be combined with -f (the web UI takes uploads); run one or the other")
		case cfg.DirPath != "":
			return cfg, errors.New("--web cannot be combined with --dir; run one or the other")
		case cfg.Interactive || cfg.CommandShell:
			return cfg, errors.New("--web cannot be combined with --interactive or --shell")
		}
	}
	if cfg.CI && (cfg.Interactive || cfg.CommandShell) {
		return cfg, errors.New("--ci cannot be combined with --interactive or --shell")
	}
	if cfg.WatchMode && cfg.FilePath != "" {
		return cfg, errors.New("--watch monitors a directory: use --dir <path>, not -f")
	}
	if cfg.CI {
		cfg.NoSplash = true
		cfg.NoProgress = true
	}
	// --quiet implies no splash and no progress: it promises to suppress
	// everything except the verdict, and progress/splash write to stderr.
	if cfg.Quiet {
		cfg.NoSplash = true
		cfg.NoProgress = true
	}

	cfg.Mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
	switch cfg.Mode {
	case "quick", "standard", "deep":
	default:
		return cfg, fmt.Errorf("unknown mode %q — valid values: quick, standard, deep", cfg.Mode)
	}

	cfg.ReportMode = normalizeReportMode(cfg.ReportMode)
	if cfg.ReportMode == "" {
		return cfg, errors.New("invalid --report-mode — valid values: Full, Summary, minimal")
	}

	if cfg.WatchIntervalSec < 1 {
		return cfg, errors.New("--watch-interval must be at least 1 (seconds)")
	}
	if cfg.WebPort < 1 || cfg.WebPort > 65535 {
		return cfg, errors.New("--web-port must be between 1 and 65535")
	}

	if cfg.FilePath == "" && cfg.DirPath == "" {
		if cfg.Interactive || cfg.CommandShell || cfg.WebMode {
			return cfg, nil
		}
		return cfg, errors.New("no target specified — use -f <file> or --dir <directory>")
	}
	if cfg.WatchMode && cfg.DirPath == "" {
		return cfg, errors.New("--watch requires --dir")
	}

	cfg.OutputFormat = strings.ToLower(strings.TrimSpace(cfg.OutputFormat))
	switch cfg.OutputFormat {
	case "text", "json", "csv", "jsonl":
	case "":
		cfg.OutputFormat = "text"
	default:
		return cfg, fmt.Errorf("unknown --output-format %q — valid values: text, json, csv, jsonl", cfg.OutputFormat)
	}
	if cfg.CIThreshold < 1 || cfg.CIThreshold > 100 {
		return cfg, errors.New("--ci-threshold must be between 1 and 100")
	}

	if cfg.MinStringLen < 3 {
		return cfg, errors.New("--min-string must be at least 3")
	}
	if cfg.MaxDecodeDepth < 0 || cfg.MaxDecodeDepth > 5 {
		return cfg, errors.New("--decode-depth must be between 0 and 5")
	}
	if cfg.MaxPayloadDepth < 0 || cfg.MaxPayloadDepth > 6 {
		return cfg, errors.New("--resolve-depth must be between 0 and 6")
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

func printGroupedHelp(w io.Writer) {
	// Colorize only when writing to a terminal (stdout for explicit --help,
	// stderr when help accompanies an error). NO_COLOR is respected via the
	// stderr/std color helpers below.
	useColor := false
	if f, ok := w.(*os.File); ok {
		if f == os.Stdout {
			useColor = stdoutColorEnabled()
		} else {
			useColor = stderrColorEnabled()
		}
	}

	head := func(s string) string {
		if useColor {
			return colorize(colorCyan, colorize(colorBold, s))
		}
		return s
	}
	flag_ := func(s string) string {
		if useColor {
			return colorize(colorGreen, s)
		}
		return s
	}
	val := func(s string) string {
		if useColor {
			return dim(s)
		}
		return s
	}
	note := func(s string) string {
		if useColor {
			return dim(s)
		}
		return s
	}

	line := func(s string) { fmt.Fprintln(w, s) }
	line(fmt.Sprintf("FlatScan %s — static malicious file scanner", version))
	line("")
	line(head("USAGE"))
	line(fmt.Sprintf("  flatscan %s                     %s", flag_("-f <file> [options]"), note("scan a single file")))
	line(fmt.Sprintf("  flatscan %s              %s", flag_("--dir <dir> [-m deep]"), note("batch scan directory")))
	line(fmt.Sprintf("  flatscan %s  %s", flag_("--dir <dir> --watch [-m deep]"), note("watch & auto-scan new files")))
	line(fmt.Sprintf("  flatscan %s                        %s", flag_("--interactive"), note("guided wizard mode")))
	line(fmt.Sprintf("  flatscan %s                             %s", flag_("--shell"), note("manual command shell")))
	line("")
	line(head("SCAN TARGET"))
	line(fmt.Sprintf("  %s  %s  file to scan", flag_("-f, --file <path>"), val("           ")))
	line(fmt.Sprintf("  %s  %s  scan all files in a directory", flag_("--dir <path>"), val("              ")))
	line(fmt.Sprintf("  %s  %s  %s", flag_("-m, --mode <mode>"), val("          "), "quick | standard | deep  "+note("(default: quick)")))
	line("")
	line(head("OUTPUT"))
	line(fmt.Sprintf("  %s  plain-text report", flag_("--report <path>")))
	line(fmt.Sprintf("  %s  machine-readable JSON  %s", flag_("--json <path>"), note("(use - for stdout)")))
	line(fmt.Sprintf("  %s  professional PDF report", flag_("--pdf <path>")))
	line(fmt.Sprintf("  %s  interactive HTML analyst report", flag_("--html <path>")))
	line(fmt.Sprintf("  %s  write all report formats at once", flag_("--report-pack <dir>")))
	line(fmt.Sprintf("  %s  IOC text export", flag_("--extract-ioc <path>")))
	line(fmt.Sprintf("  %s  generated YARA hunting rule", flag_("--yara <path>")))
	line(fmt.Sprintf("  %s  generated Sigma hunting rule", flag_("--sigma <path>")))
	line(fmt.Sprintf("  %s  STIX 2.1 threat intel bundle", flag_("--stix <path>")))
	line(fmt.Sprintf("  %s  Full | Summary | minimal  %s", flag_("--report-mode"), note("(default: summary)")))
	line(fmt.Sprintf("  %s  text | json | csv | jsonl  %s", flag_("--output-format"), note("(default: text)")))
	line("")
	line(head("ADVANCED"))
	line(fmt.Sprintf("  %s  recursive safe file carving", flag_("--carve")))
	line(fmt.Sprintf("  %s  max nested decode depth 0–5  %s", flag_("--decode-depth <n>"), note("(default: 2)")))
	line(fmt.Sprintf("  %s  recursive payload-resolution depth 0–6 (0=off)  %s", flag_("--resolve-depth <n>"), note("(default: 3)")))
	line(fmt.Sprintf("  %s  comma-separated rule pack files/dirs", flag_("--rules <paths>")))
	line(fmt.Sprintf("  %s  comma-separated plugin pack files/dirs", flag_("--plugins <paths>")))
	line(fmt.Sprintf("  %s  run optional external metadata tools", flag_("--external-tools")))
	line(fmt.Sprintf("  %s  suppress infrastructure IOCs", flag_("--ioc-allowlist <path>")))
	line(fmt.Sprintf("  %s  JSONL reference store for similarity matching", flag_("--similarity-db <path>")))
	line(fmt.Sprintf("  %s  JSONL offline threat-intel enrichment database", flag_("--intel-db <path>")))
	line("")
	line(head("LIMITS"))
	line(fmt.Sprintf("  %s  minimum extracted string length  %s", flag_("--min-string <n>"), note("(default: 5, min 3)")))
	line(fmt.Sprintf("  %s  max bytes read into memory for analysis  %s", flag_("--max-analyze-bytes <n>"), note("(default: 256MiB)")))
	line(fmt.Sprintf("  %s  max archive entries inspected  %s", flag_("--max-archive-files <n>"), note("(default: 500)")))
	line(fmt.Sprintf("  %s  max carved artifacts reported  %s", flag_("--max-carves <n>"), note("(default: 80, 1–1000)")))
	line(fmt.Sprintf("  %s  splash screen duration cap  %s", flag_("--splash-seconds <n>"), note("(default: 20, 0–120)")))
	line("")
	line(head("CI/CD"))
	line(fmt.Sprintf("  %s  CI mode: suppress UI, exit 10 if score >= threshold", flag_("--ci")))
	line(fmt.Sprintf("  %s  score threshold for --ci  %s", flag_("--ci-threshold <n>"), note("(default: 55)")))
	line(fmt.Sprintf("  %s  exit codes: 0=clean 10=suspicious 20=malicious 1=error", note("")))
	line("")
	line(head("WEB"))
	line(fmt.Sprintf("  %s  launch local web GUI on http://localhost:<port>", flag_("--web")))
	line(fmt.Sprintf("  %s  port for --web mode  %s", flag_("--web-port <n>"), note("(default: 5000)")))
	line("")
	line(head("WATCH / CASE"))
	line(fmt.Sprintf("  %s  save batch results as JSON summary", flag_("--batch-json <path>")))
	line(fmt.Sprintf("  %s  monitor --dir for new files", flag_("--watch")))
	line(fmt.Sprintf("  %s  only alert on high-score files in watch mode", flag_("--watch-alert-only")))
	line(fmt.Sprintf("  %s  poll interval in seconds  %s", flag_("--watch-interval <n>"), note("(default: 3)")))
	line(fmt.Sprintf("  %s  case database record identifier", flag_("--case <id>")))
	line(fmt.Sprintf("  %s  case JSONL database path", flag_("--case-db <path>")))
	line("")
	line(head("FLAGS"))
	line(fmt.Sprintf("  %s  suppress report, tips & progress; keep the verdict line", flag_("-q, --quiet")))
	line(fmt.Sprintf("  %s", flag_("--no-color  --no-progress  --no-splash  --debug")))
	line(fmt.Sprintf("  %s  print completion script %s", flag_("--completion <shell>"), note("(bash | zsh | fish)")))
	line(fmt.Sprintf("  %s  %s", flag_("-h, --help"), note("show this help")))
	line(fmt.Sprintf("  %s", flag_("--version")))
	line("")
	line(note("Examples:"))
	line(fmt.Sprintf(`  flatscan -f sample.bin -m deep --pdf report.pdf --html report.html`))
	line(fmt.Sprintf(`  flatscan --dir ./inbox -m deep --report-pack ./out`))
	line(fmt.Sprintf(`  flatscan --completion bash >> ~/.bashrc`))
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

// knownFlags is the canonical list of long flag names, used for did-you-mean
// suggestions on an unknown flag. Keep in sync with the flags registered in
// parseFlags.
var knownFlags = []string{
	"mode", "file", "dir", "report-mode", "report", "pdf", "json", "html",
	"yara", "sigma", "stix", "report-pack", "rules", "plugins", "extract-ioc",
	"ioc-allowlist", "similarity-db", "intel-db", "case", "case-db", "debug",
	"interactive", "shell", "carve", "external-tools", "no-progress",
	"no-splash", "no-color", "quiet", "watch", "watch-alert-only", "ci",
	"ci-threshold", "output-format", "batch-json", "watch-interval", "web",
	"web-port", "splash-seconds", "min-string", "decode-depth",
	"max-analyze-bytes", "max-archive-files", "max-carves", "resolve-depth",
	"version", "completion", "help",
}

// suggestFlag returns the closest known flag name to bad (Levenshtein distance),
// or "" when nothing is close enough to be a helpful suggestion.
func suggestFlag(bad string) string {
	bad = strings.ToLower(strings.TrimSpace(bad))
	if bad == "" {
		return ""
	}
	best, bestDist := "", 1<<30
	for _, f := range knownFlags {
		if d := levenshtein(bad, f); d < bestDist {
			best, bestDist = f, d
		}
	}
	// Only suggest when the edit distance is small relative to the input; a
	// wild typo shouldn't map to an unrelated flag.
	limit := len(bad)/2 + 1
	if bestDist <= limit {
		return best
	}
	return ""
}

func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			del, ins, sub := prev[j]+1, cur[j-1]+1, prev[j-1]+cost
			m := del
			if ins < m {
				m = ins
			}
			if sub < m {
				m = sub
			}
			cur[j] = m
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}
