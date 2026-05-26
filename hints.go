package main

import (
	"fmt"
	"io"
)

// PrintPostScanHints prints actionable follow-up tips after a scan based on
// what was found vs. what output flags were used.
func PrintPostScanHints(result ScanResult, cfg Config, out io.Writer) {
	if cfg.JSONPath == "-" || cfg.CI || cfg.OutputFormat != "text" {
		return // don't pollute machine-readable output streams
	}

	useColor := !cfg.NoColor && colorEnabled()
	var hints []string

	if len(result.HighEntropyRegions) > 0 && !cfg.EnableCarving {
		hints = append(hints, "re-run with --carve to extract embedded payloads from high-entropy regions")
	}

	if cfg.Mode == "quick" && len(result.Findings) >= 3 {
		hints = append(hints, "re-run with -m deep for thorough string, decode, and entropy analysis")
	}

	if result.RiskScore >= 55 {
		if cfg.PDFPath == "" && cfg.ReportPackPath == "" {
			hints = append(hints, "add --pdf report.pdf for a CISO-ready executive report")
		}
		if cfg.YARAPath == "" && cfg.ReportPackPath == "" {
			hints = append(hints, "add --yara rule.yar to generate a YARA hunting rule")
		}
	}

	iocTotal := IOCCount(result.IOCs)
	if iocTotal > 0 && cfg.STIXPath == "" && cfg.ReportPackPath == "" {
		hints = append(hints, "add --stix out.json to export indicators as STIX 2.1 threat intel")
	}

	if cfg.Mode == "deep" && !cfg.ExternalTools {
		hints = append(hints, "add --external-tools to run optional metadata tools (exiftool, file, strings)")
	}

	if len(hints) == 0 {
		return
	}

	if useColor {
		fmt.Fprintf(out, "\n%s\n", colorize(colorCyan, "Tips:"))
		for _, hint := range hints {
			fmt.Fprintf(out, "  %s %s\n", dim("→"), dim(hint))
		}
	} else {
		fmt.Fprintln(out, "\nTips:")
		for _, hint := range hints {
			fmt.Fprintf(out, "  → %s\n", hint)
		}
	}
}
