package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func RunInteractive(in io.Reader, out, errOut io.Writer, base Config) error {
	reader := bufio.NewReader(in)
	fmt.Fprintln(out)
	PrintASCIIBanner(out)
	fmt.Fprintln(out, "Interactive mode")
	fmt.Fprintln(out, "Choose guided wizard mode or manual command mode. Existing CLI flags still work outside this menu.")

	for {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "1) Guided scan wizard")
		fmt.Fprintln(out, "2) Manual command shell")
		fmt.Fprintln(out, "3) Show examples")
		fmt.Fprintln(out, "4) Quit")
		choice, err := promptLine(reader, out, "Select option [1]: ")
		if err != nil {
			return err
		}
		switch strings.TrimSpace(choice) {
		case "", "1":
			if err := runGuidedScan(reader, out, errOut, base); err != nil {
				fmt.Fprintf(errOut, "guided scan failed: %v\n", err)
			}
		case "2":
			if err := runCommandShell(reader, out, errOut, true); err != nil {
				return err
			}
		case "3", "help", "?":
			printInteractiveExamples(out)
		case "4", "q", "quit", "exit":
			fmt.Fprintln(out, "Bye.")
			return nil
		default:
			fmt.Fprintln(out, "Unknown option. Enter 1, 2, 3, or 4.")
		}
	}
}

func RunCommandShell(in io.Reader, out, errOut io.Writer, base Config) error {
	_ = base
	return runCommandShell(bufio.NewReader(in), out, errOut, false)
}

func runCommandShell(reader *bufio.Reader, out, errOut io.Writer, returnToMenu bool) error {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "FlatScan manual command shell")
	fmt.Fprintln(out, "Type flags exactly as you would after ./flatscan, or type help, examples, back, or exit.")
	fmt.Fprintln(out, `Example: -m deep -f sample.exe --report-mode Full --json reports/sample.json --carve --no-splash`)
	for {
		line, err := promptLine(reader, out, "flatscan> ")
		if err != nil {
			if errors.Is(err, io.EOF) {
				fmt.Fprintln(out)
				return nil
			}
			return err
		}
		line = strings.TrimSpace(line)
		switch strings.ToLower(line) {
		case "":
			continue
		case "exit", "quit":
			return nil
		case "back":
			if returnToMenu {
				return nil
			}
			fmt.Fprintln(out, "Use exit or quit to leave the shell.")
			continue
		case "help", "?":
			printInteractiveHelp(out)
			continue
		case "examples":
			printInteractiveExamples(out)
			continue
		case "version", "--version", "-version":
			fmt.Fprintf(out, "FlatScan %s\n", version)
			continue
		}

		args, err := splitInteractiveArgs(line)
		if err != nil {
			fmt.Fprintf(errOut, "parse error: %v\n", err)
			continue
		}
		args = stripFlatScanCommand(args)
		cfg, err := parseFlags(args)
		if err != nil {
			if errors.Is(err, flag.ErrHelp) {
				continue
			}
			fmt.Fprintf(errOut, "command error: %v\n", err)
			continue
		}
		if cfg.Interactive || cfg.CommandShell {
			fmt.Fprintln(errOut, "interactive launch flags are not valid inside the command shell")
			continue
		}
		cfg.NoSplash = true
		result, err := RunInteractiveScan(cfg, out)
		if err != nil {
			fmt.Fprintf(errOut, "%v\n", err)
			continue
		}
		fmt.Fprintf(out, "\nCompleted: %s | %s | score=%d | sha256=%s\n", result.FileName, result.Verdict, result.RiskScore, result.Hashes.SHA256)
	}
}

func runGuidedScan(reader *bufio.Reader, out, errOut io.Writer, base Config) error {
	defaultMode := "deep"
	if base.Mode != "" && base.Mode != "quick" {
		defaultMode = base.Mode
	}
	defaultReportMode := "Full"
	if base.ReportMode != "" && base.ReportMode != "summary" {
		defaultReportMode = base.ReportMode
	}
	cfg := Config{
		Mode:             defaultMode,
		ReportMode:       normalizeReportMode(defaultReportMode),
		Debug:            base.Debug,
		IOCAllowlistPath: base.IOCAllowlistPath,
		RulePaths:        base.RulePaths,
		PluginPaths:      base.PluginPaths,
		SplashSeconds:    base.SplashSeconds,
		MinStringLen:     base.MinStringLen,
		MaxDecodeDepth:   base.MaxDecodeDepth,
		MaxAnalyzeBytes:  base.MaxAnalyzeBytes,
		MaxArchiveFiles:  base.MaxArchiveFiles,
		MaxCarves:        base.MaxCarves,
		NoSplash:         true,
	}
	if cfg.Mode == "" {
		cfg.Mode = "deep"
	}
	if cfg.ReportMode == "" {
		cfg.ReportMode = "full"
	}
	if cfg.MinStringLen == 0 {
		cfg.MinStringLen = 5
	}
	if cfg.MaxDecodeDepth == 0 {
		cfg.MaxDecodeDepth = 2
	}
	if cfg.MaxAnalyzeBytes == 0 {
		cfg.MaxAnalyzeBytes = 256 * 1024 * 1024
	}
	if cfg.MaxArchiveFiles == 0 {
		cfg.MaxArchiveFiles = 500
	}
	if cfg.MaxCarves == 0 {
		cfg.MaxCarves = 80
	}

	target, err := promptRequiredFile(reader, out)
	if err != nil {
		return err
	}
	cfg.FilePath = target

	mode, err := promptChoice(reader, out, "Scan mode", []string{"deep", "standard", "quick"}, cfg.Mode)
	if err != nil {
		return err
	}
	cfg.Mode = mode

	reportMode, err := promptChoice(reader, out, "Report mode", []string{"Full", "Summary", "minimal"}, defaultReportMode)
	if err != nil {
		return err
	}
	cfg.ReportMode = normalizeReportMode(reportMode)

	baseName := outputBaseName(cfg.FilePath)
	outputDir, err := promptDefault(reader, out, "Output directory", "reports")
	if err != nil {
		return err
	}
	outputDir = strings.TrimSpace(outputDir)
	if outputDir == "" {
		outputDir = "reports"
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "Output profile")
	fmt.Fprintln(out, "1) Terminal only")
	fmt.Fprintln(out, "2) Standard files: text, JSON, IOC")
	fmt.Fprintln(out, "3) Full analyst/CISO pack: text, JSON, IOC, PDF, HTML, YARA, Sigma, STIX, report pack")
	fmt.Fprintln(out, "4) Custom paths")
	profile, err := promptLine(reader, out, "Select output profile [3]: ")
	if err != nil {
		return err
	}
	switch strings.TrimSpace(profile) {
	case "", "3":
		cfg.ReportPath = filepath.Join(outputDir, baseName+".full.txt")
		cfg.JSONPath = filepath.Join(outputDir, baseName+".report.json")
		cfg.IOCPath = filepath.Join(outputDir, baseName+".iocs.txt")
		cfg.PDFPath = filepath.Join(outputDir, baseName+".ciso.pdf")
		cfg.HTMLPath = filepath.Join(outputDir, baseName+".analyst.html")
		cfg.YARAPath = filepath.Join(outputDir, baseName+".yar")
		cfg.SigmaPath = filepath.Join(outputDir, baseName+".sigma.yml")
		cfg.STIXPath = filepath.Join(outputDir, baseName+".stix.json")
		cfg.ReportPackPath = filepath.Join(outputDir, baseName+"-pack")
	case "1":
	case "2":
		cfg.ReportPath = filepath.Join(outputDir, baseName+".full.txt")
		cfg.JSONPath = filepath.Join(outputDir, baseName+".report.json")
		cfg.IOCPath = filepath.Join(outputDir, baseName+".iocs.txt")
	case "4":
		if err := promptCustomOutputPaths(reader, out, &cfg); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown output profile %q", profile)
	}

	cfg.EnableCarving, err = promptYesNo(reader, out, "Enable safe carving", true)
	if err != nil {
		return err
	}
	cfg.ExternalTools, err = promptYesNo(reader, out, "Run optional external metadata tools", false)
	if err != nil {
		return err
	}
	cfg.Debug, err = promptYesNo(reader, out, "Enable debug log", cfg.Debug)
	if err != nil {
		return err
	}
	cfg.NoProgress, err = promptYesNo(reader, out, "Disable progress output", false)
	if err != nil {
		return err
	}

	if cfg.IOCAllowlistPath == "" {
		cfg.IOCAllowlistPath, err = promptDefault(reader, out, "Optional IOC allowlist path", "")
		if err != nil {
			return err
		}
	}
	if cfg.RulePaths == "" {
		cfg.RulePaths, err = promptDefault(reader, out, "Optional rule pack path(s)", "")
		if err != nil {
			return err
		}
	}
	if cfg.PluginPaths == "" {
		cfg.PluginPaths, err = promptDefault(reader, out, "Optional plugin pack path(s)", "")
		if err != nil {
			return err
		}
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "Starting scan with equivalent command:")
	fmt.Fprintln(out, renderEquivalentCommand(cfg))

	result, err := RunInteractiveScan(cfg, out)
	if err != nil {
		fmt.Fprintf(errOut, "%v\n", err)
		return err
	}
	fmt.Fprintf(out, "\nCompleted: %s | %s | score=%d | sha256=%s\n", result.FileName, result.Verdict, result.RiskScore, result.Hashes.SHA256)
	return nil
}

// RunInteractiveScan executes a configured scan with a rich animated progress
// bar designed for interactive terminal sessions. It intercepts the standard
// Progress output and renders animated block characters with phase info.
func RunInteractiveScan(cfg Config, out io.Writer) (result ScanResult, err error) {
	target := filepath.Base(cfg.FilePath)
	progress, ip := NewProgressWithInteractiveBar(out, target, cfg.Mode)
	_ = ip

	defer func() {
		if recovered := recover(); recovered != nil {
			ip.Done()
			err = fmt.Errorf("fatal scanner error: %v", recovered)
			if cfg.Debug {
				err = fmt.Errorf("%w; debug: recovered panic while scanning %q", err, cfg.FilePath)
			}
		}
	}()

	start := time.Now()
	result, err = ScanFile(cfg, progress)
	ip.Done()
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
		plainReport := RenderReport(result, cfg.ReportMode)
		if err := os.WriteFile(cfg.ReportPath, []byte(plainReport), 0o644); err != nil {
			return result, fmt.Errorf("report write failed: %w", err)
		}
	} else {
		fmt.Fprint(out, report)
	}

	if cfg.JSONPath != "" {
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

func promptRequiredFile(reader *bufio.Reader, out io.Writer) (string, error) {
	for {
		value, err := promptLine(reader, out, "Target file path: ")
		if err != nil {
			return "", err
		}
		value = strings.TrimSpace(strings.Trim(value, `"`))
		if value == "" {
			fmt.Fprintln(out, "Target file path is required.")
			continue
		}
		abs, err := filepath.Abs(value)
		if err != nil {
			return "", err
		}
		stat, err := os.Stat(abs)
		if err != nil {
			fmt.Fprintf(out, "Cannot access file: %v\n", err)
			continue
		}
		if stat.IsDir() {
			fmt.Fprintln(out, "Path is a directory; provide a file.")
			continue
		}
		return abs, nil
	}
}

func promptChoice(reader *bufio.Reader, out io.Writer, label string, values []string, fallback string) (string, error) {
	fmt.Fprintf(out, "%s options: %s\n", label, strings.Join(values, ", "))
	value, err := promptDefault(reader, out, label, fallback)
	if err != nil {
		return "", err
	}
	if value == "" {
		return fallback, nil
	}
	for _, option := range values {
		if strings.EqualFold(value, option) {
			return option, nil
		}
	}
	return "", fmt.Errorf("invalid %s %q", strings.ToLower(label), value)
}

func promptCustomOutputPaths(reader *bufio.Reader, out io.Writer, cfg *Config) error {
	var err error
	cfg.ReportPath, err = promptDefault(reader, out, "Text report path", "")
	if err != nil {
		return err
	}
	cfg.JSONPath, err = promptDefault(reader, out, "JSON report path", "")
	if err != nil {
		return err
	}
	cfg.IOCPath, err = promptDefault(reader, out, "IOC export path", "")
	if err != nil {
		return err
	}
	cfg.PDFPath, err = promptDefault(reader, out, "PDF report path", "")
	if err != nil {
		return err
	}
	cfg.HTMLPath, err = promptDefault(reader, out, "HTML report path", "")
	if err != nil {
		return err
	}
	cfg.YARAPath, err = promptDefault(reader, out, "YARA rule path", "")
	if err != nil {
		return err
	}
	cfg.SigmaPath, err = promptDefault(reader, out, "Sigma rule path", "")
	if err != nil {
		return err
	}
	cfg.ReportPackPath, err = promptDefault(reader, out, "Report pack directory", "")
	return err
}

func promptYesNo(reader *bufio.Reader, out io.Writer, label string, fallback bool) (bool, error) {
	defaultText := "n"
	if fallback {
		defaultText = "y"
	}
	value, err := promptDefault(reader, out, label+" (y/n)", defaultText)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return fallback, nil
	case "y", "yes", "true", "1":
		return true, nil
	case "n", "no", "false", "0":
		return false, nil
	default:
		return false, fmt.Errorf("invalid yes/no value %q", value)
	}
}

func promptDefault(reader *bufio.Reader, out io.Writer, label, fallback string) (string, error) {
	prompt := label
	if fallback != "" {
		prompt += " [" + fallback + "]"
	}
	prompt += ": "
	value, err := promptLine(reader, out, prompt)
	if err != nil {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, nil
	}
	return value, nil
}

func promptLine(reader *bufio.Reader, out io.Writer, prompt string) (string, error) {
	fmt.Fprint(out, prompt)
	value, err := reader.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && strings.TrimSpace(value) != "" {
			return strings.TrimRight(value, "\r\n"), nil
		}
		return "", err
	}
	return strings.TrimRight(value, "\r\n"), nil
}

func printInteractiveHelp(out io.Writer) {
	fmt.Fprintln(out, "Manual command mode accepts the same flags as the normal CLI.")
	fmt.Fprintln(out, "Do not include shell redirection or pipes inside the prompt.")
	fmt.Fprintln(out, "Commands: help, examples, version, back, exit.")
	fmt.Fprintln(out, "Use quotes around file paths containing spaces.")
}

func printInteractiveExamples(out io.Writer) {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Examples:")
	fmt.Fprintln(out, `  ./flatscan --interactive`)
	fmt.Fprintln(out, `  ./flatscan --shell`)
	fmt.Fprintln(out, `  -m quick -f sample.bin --report-mode Summary`)
	fmt.Fprintln(out, `  -m deep -f "sample with spaces.bin" --report-mode Full --json reports/sample.json --extract-ioc reports/sample.iocs.txt --carve`)
	fmt.Fprintln(out, `  -m deep -f sample.msix --report-pack reports/sample-pack --rules rules --plugins plugins --ioc-allowlist allowlist.txt --debug`)
}

func splitInteractiveArgs(line string) ([]string, error) {
	var args []string
	var current strings.Builder
	var quote rune
	escaped := false
	for _, r := range line {
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
			continue
		}
		switch r {
		case '\'', '"':
			quote = r
		case ' ', '\t', '\n', '\r':
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if escaped {
		current.WriteRune('\\')
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote")
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args, nil
}

func stripFlatScanCommand(args []string) []string {
	if len(args) == 0 {
		return args
	}
	first := filepath.Base(args[0])
	first = strings.TrimPrefix(first, "./")
	if first == "flatscan" || first == "flatscan.exe" {
		return args[1:]
	}
	return args
}

func outputBaseName(path string) string {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	if ext != "" {
		base = strings.TrimSuffix(base, ext)
	}
	base = strings.TrimSpace(base)
	if base == "" || base == "." {
		base = "sample"
	}
	var b strings.Builder
	for _, r := range strings.ToLower(base) {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	value := strings.Trim(b.String(), "_")
	if value == "" {
		return "sample"
	}
	return value
}

func renderEquivalentCommand(cfg Config) string {
	args := []string{"./flatscan", "-m", cfg.Mode, "-f", cfg.FilePath, "--report-mode", cfg.ReportMode}
	addPath := func(flag, value string) {
		if strings.TrimSpace(value) != "" {
			args = append(args, flag, value)
		}
	}
	addPath("--report", cfg.ReportPath)
	addPath("--extract-ioc", cfg.IOCPath)
	addPath("--json", cfg.JSONPath)
	addPath("--pdf", cfg.PDFPath)
	addPath("--html", cfg.HTMLPath)
	addPath("--yara", cfg.YARAPath)
	addPath("--sigma", cfg.SigmaPath)
	addPath("--report-pack", cfg.ReportPackPath)
	addPath("--rules", cfg.RulePaths)
	addPath("--plugins", cfg.PluginPaths)
	addPath("--ioc-allowlist", cfg.IOCAllowlistPath)
	if cfg.EnableCarving {
		args = append(args, "--carve")
	}
	if cfg.ExternalTools {
		args = append(args, "--external-tools")
	}
	if cfg.Debug {
		args = append(args, "--debug")
	}
	if cfg.NoProgress {
		args = append(args, "--no-progress")
	}
	if cfg.NoSplash {
		args = append(args, "--no-splash")
	}
	for i, arg := range args {
		args[i] = shellQuote(arg)
	}
	return strings.Join(args, " ")
}

func shellQuote(value string) string {
	if value == "" {
		return `""`
	}
	if strings.IndexFunc(value, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '"' || r == '\'' || r == '\\' || r == '$' || r == '`'
	}) == -1 {
		return value
	}
	return `"` + strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `"`, `\"`) + `"`
}
