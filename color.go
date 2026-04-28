package main

import (
	"fmt"
	"os"
	"strings"
)

// ANSI color codes for terminal output.
const (
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
	colorRed     = "\033[91m"
	colorGreen   = "\033[92m"
	colorYellow  = "\033[93m"
	colorBlue    = "\033[94m"
	colorMagenta = "\033[95m"
	colorCyan    = "\033[96m"
	colorWhite   = "\033[97m"
	colorOrange  = "\033[38;5;208m"
	colorGray    = "\033[90m"

	// Background colors for badges
	bgRed    = "\033[41m"
	bgOrange = "\033[48;5;208m"
	bgYellow = "\033[43m"
	bgGreen  = "\033[42m"
	bgBlue   = "\033[44m"
	bgGray   = "\033[100m"
)

// colorEnabled returns true when stdout is a terminal and NO_COLOR is not set.
func colorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	stat, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return stat.Mode()&os.ModeCharDevice != 0
}

// ansiSeverityColor returns the ANSI color for a severity level.
func ansiSeverityColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return colorRed + colorBold
	case "high":
		return colorRed
	case "medium":
		return colorOrange
	case "low":
		return colorYellow
	case "info":
		return colorCyan
	default:
		return colorGray
	}
}

// severityBadge returns a colored severity badge like "[Critical]".
func severityBadge(severity string) string {
	return ansiSeverityColor(severity) + "[" + severity + "]" + colorReset
}

// verdictColor returns the ANSI color for a verdict string.
func verdictColor(verdict string) string {
	switch verdict {
	case "Likely malicious":
		return colorRed + colorBold
	case "High suspicion":
		return colorRed
	case "Suspicious":
		return colorOrange
	case "Low suspicion":
		return colorYellow
	default:
		return colorGreen
	}
}

// Colored text helpers.
func colorize(color, text string) string { return color + text + colorReset }
func bold(text string) string             { return colorBold + text + colorReset }
func dim(text string) string              { return colorDim + text + colorReset }

// RenderColorReport produces a colorized terminal report.
func RenderColorReport(result ScanResult, mode string) string {
	switch mode {
	case "minimal":
		return renderColorMinimalReport(result)
	case "full":
		return renderColorFullReport(result)
	default:
		return renderColorSummaryReport(result)
	}
}

func renderColorMinimalReport(result ScanResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n", bold("FlatScan"), dim(result.Version))
	fmt.Fprintf(&b, "%s %s\n", dim("Target:"), result.Target)
	fmt.Fprintf(&b, "%s %s %s\n", dim("Verdict:"),
		colorize(verdictColor(result.Verdict), result.Verdict),
		dim(fmt.Sprintf("(%d/100)", result.RiskScore)))
	fmt.Fprintf(&b, "%s %s\n", dim("Type:"), result.FileType)
	fmt.Fprintf(&b, "%s %s\n", dim("SHA256:"), colorize(colorCyan, result.Hashes.SHA256))
	fmt.Fprintf(&b, "%s %d | %s %d\n",
		dim("Findings:"), len(result.Findings),
		dim("IOCs:"), IOCCount(result.IOCs))
	return b.String()
}

func renderColorSummaryReport(result ScanResult) string {
	var b strings.Builder
	writeColorHeader(&b, result)
	writeColorProfile(&b, result)
	writeColorFindings(&b, result.Findings, 12)
	writeColorIOCSummary(&b, result.IOCs)
	if len(result.SuspiciousStrings) > 0 {
		fmt.Fprintln(&b, dim("\nSuspicious strings:"))
		writeList(&b, result.SuspiciousStrings, 10)
	}
	if len(result.DecodedArtifacts) > 0 {
		fmt.Fprintln(&b, dim("\nDecoded artifacts:"))
		for _, artifact := range limitArtifacts(result.DecodedArtifacts, 8) {
			fmt.Fprintf(&b, "  %s %s from %s: %s\n",
				dim("•"),
				colorize(colorCyan, artifact.Encoding),
				dim(artifact.Source),
				artifact.Preview)
		}
	}
	return b.String()
}

func renderColorFullReport(result ScanResult) string {
	var b strings.Builder
	writeColorHeader(&b, result)
	writeColorProfile(&b, result)
	writeColorHashes(&b, result)
	writeColorFindings(&b, result.Findings, 0)
	writeColorFunctions(&b, result.Functions)
	writeColorIOCsFull(&b, result.IOCs)
	writeDecodedFull(&b, result.DecodedArtifacts)
	writeAdvancedDetails(&b, result)
	writeFormatDetails(&b, result)
	writeArchiveEntries(&b, result.ArchiveEntries)
	if len(result.SuspiciousStrings) > 0 {
		fmt.Fprintln(&b, dim("\nSuspicious strings:"))
		writeList(&b, result.SuspiciousStrings, 0)
	}
	if len(result.DebugLog) > 0 {
		fmt.Fprintln(&b, dim("\nDebug log:"))
		writeList(&b, result.DebugLog, 0)
	}
	return b.String()
}

func writeColorHeader(b *strings.Builder, result ScanResult) {
	// Decorative header line
	fmt.Fprintln(b, dim("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
	fmt.Fprintf(b, "%s %s\n", bold("FlatScan"), dim(result.Version+" report"))
	fmt.Fprintln(b, dim("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
	fmt.Fprintf(b, "%s %s\n", dim("Target:"), bold(result.Target))
	fmt.Fprintf(b, "%s %s\n", dim("Mode:"), colorize(colorCyan, result.Mode))

	// Colorized verdict with risk score bar
	vColor := verdictColor(result.Verdict)
	fmt.Fprintf(b, "%s %s %s\n", dim("Verdict:"),
		colorize(vColor, result.Verdict),
		renderScoreBar(result.RiskScore))

	fmt.Fprintf(b, "%s %s\n", dim("File type:"), result.FileType)
	if result.MIMEHint != "" {
		fmt.Fprintf(b, "%s %s\n", dim("MIME hint:"), result.MIMEHint)
	}
	fmt.Fprintf(b, "%s %s (%d bytes)\n", dim("Size:"), formatBytes(result.Size), result.Size)
	fmt.Fprintf(b, "%s %s", dim("Analyzed:"), formatBytes(result.AnalyzedBytes))
	if result.TruncatedAnalysis {
		fmt.Fprintf(b, " %s", colorize(colorYellow, "(truncated)"))
	}
	fmt.Fprintln(b)

	// Color-coded entropy
	eColor := colorGreen
	if result.Entropy >= 7.70 {
		eColor = colorRed
	} else if result.Entropy >= 7.20 {
		eColor = colorOrange
	} else if result.Entropy >= 6.50 {
		eColor = colorYellow
	}
	fmt.Fprintf(b, "%s %s %s\n", dim("Entropy:"),
		colorize(eColor, fmt.Sprintf("%.2f/8.00", result.Entropy)),
		dim("- "+result.EntropyAssessment))

	fmt.Fprintf(b, "%s %d", dim("Strings:"), result.StringsTotal)
	if result.StringsTruncated {
		fmt.Fprintf(b, " %s", colorize(colorYellow, "(truncated)"))
	}
	fmt.Fprintln(b)
	if result.Duration != "" {
		fmt.Fprintf(b, "%s %s\n", dim("Duration:"), result.Duration)
	}
}

// renderScoreBar creates a small inline risk score visualization.
func renderScoreBar(score int) string {
	barLen := 20
	filled := score * barLen / 100
	if filled > barLen {
		filled = barLen
	}
	empty := barLen - filled

	barColor := colorGreen
	if score >= 80 {
		barColor = colorRed
	} else if score >= 55 {
		barColor = colorOrange
	} else if score >= 30 {
		barColor = colorYellow
	}

	return fmt.Sprintf("%s%s%s%s %s",
		barColor,
		strings.Repeat("▓", filled),
		colorReset+colorGray,
		strings.Repeat("░", empty),
		colorize(barColor+colorBold, fmt.Sprintf("%d/100", score)))
}

func writeColorProfile(b *strings.Builder, result ScanResult) {
	if result.Profile.Classification == "" && len(result.Profile.TTPs) == 0 && len(result.Profile.CryptoIndicators) == 0 {
		return
	}
	fmt.Fprintln(b, bold("\n🔍 Malware Profile"))
	if result.Profile.Classification != "" {
		fmt.Fprintf(b, "  %s %s\n", dim("Classification:"), colorize(colorMagenta, result.Profile.Classification))
	}
	if result.Profile.Confidence != "" {
		fmt.Fprintf(b, "  %s %s (%d/100)\n", dim("Confidence:"), result.Profile.Confidence, result.Profile.ConfidenceScore)
	}
	if len(result.Profile.MalwareType) > 0 {
		fmt.Fprintf(b, "  %s %s\n", dim("Likely type:"), colorize(colorRed, strings.Join(result.Profile.MalwareType, ", ")))
	}
	if len(result.Profile.KeyCapabilities) > 0 {
		fmt.Fprintf(b, "  %s %s\n", dim("Capabilities:"), strings.Join(result.Profile.KeyCapabilities, ", "))
	}
	if len(result.Profile.TTPs) > 0 {
		fmt.Fprintf(b, "  %s %d\n", dim("MITRE TTPs:"), len(result.Profile.TTPs))
	}
	if len(result.Profile.CryptoIndicators) > 0 {
		fmt.Fprintf(b, "  %s %d\n", dim("Crypto indicators:"), len(result.Profile.CryptoIndicators))
	}
	if result.Profile.ExecutiveAssessment != "" {
		fmt.Fprintf(b, "  %s %s\n", dim("Assessment:"), result.Profile.ExecutiveAssessment)
	}
}

func writeColorFindings(b *strings.Builder, findings []Finding, limit int) {
	fmt.Fprintf(b, "\n%s %s\n", bold("⚠ Findings:"), dim(fmt.Sprintf("%d", len(findings))))
	if len(findings) == 0 {
		fmt.Fprintf(b, "  %s No strong static indicators found.\n", colorize(colorGreen, "✓"))
		return
	}
	for index, finding := range findings {
		if limit > 0 && index >= limit {
			fmt.Fprintf(b, "  %s %d more findings omitted in summary mode\n",
				dim("..."), len(findings)-limit)
			break
		}
		fmt.Fprintf(b, "  %s %s: %s",
			severityBadge(finding.Severity),
			colorize(colorBlue, finding.Category),
			finding.Title)
		if finding.Evidence != "" {
			fmt.Fprintf(b, " %s", dim("("+finding.Evidence+")"))
		}
		if finding.Score > 0 {
			fmt.Fprintf(b, " %s", dim(fmt.Sprintf("score=%d", finding.Score)))
		}
		fmt.Fprintln(b)
		if finding.Tactic != "" || finding.Technique != "" {
			fmt.Fprintf(b, "    %s %s", dim("ATT&CK:"), colorize(colorMagenta, finding.Tactic))
			if finding.Technique != "" {
				fmt.Fprintf(b, " / %s", colorize(colorMagenta, finding.Technique))
			}
			fmt.Fprintln(b)
		}
		if finding.Recommendation != "" {
			fmt.Fprintf(b, "    %s %s\n", dim("→"), finding.Recommendation)
		}
	}
}

func writeColorHashes(b *strings.Builder, result ScanResult) {
	fmt.Fprintln(b, bold("\n🔑 Hashes"))
	fmt.Fprintf(b, "  %s %s\n", dim("MD5:"), colorize(colorCyan, result.Hashes.MD5))
	fmt.Fprintf(b, "  %s %s\n", dim("SHA1:"), colorize(colorCyan, result.Hashes.SHA1))
	fmt.Fprintf(b, "  %s %s\n", dim("SHA256:"), colorize(colorCyan, result.Hashes.SHA256))
	fmt.Fprintf(b, "  %s %s\n", dim("SHA512:"), colorize(colorCyan, result.Hashes.SHA512))
	if result.PE != nil && result.PE.ImportHash != "" {
		fmt.Fprintf(b, "  %s %s\n", dim("Import:"), colorize(colorCyan, result.PE.ImportHash))
	}
}

func writeColorFunctions(b *strings.Builder, functions []FunctionHit) {
	if len(functions) == 0 {
		return
	}
	fmt.Fprintf(b, "\n%s %s\n", bold("🔧 Suspicious APIs:"), dim(fmt.Sprintf("%d", len(functions))))
	seen := make(map[string]struct{})
	written := 0
	for _, fn := range functions {
		key := fn.Name + fn.Family + fn.Source
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		fmt.Fprintf(b, "  %s %s %s\n",
			severityBadge(fn.Severity),
			fn.Name,
			dim("("+fn.Family+", "+fn.Source+")"))
		written++
		if written >= 200 {
			fmt.Fprintln(b, dim("  ... capped at 200"))
			break
		}
	}
}

func writeColorIOCSummary(b *strings.Builder, iocs IOCSet) {
	total := IOCCount(iocs)
	fmt.Fprintf(b, "\n%s %s\n", bold("🌐 IOCs:"), dim(fmt.Sprintf("%d total", total)))
	if total == 0 {
		return
	}
	writeColorIOCSection(b, "URLs", iocs.URLs, 5)
	writeColorIOCSection(b, "Domains", iocs.Domains, 5)
	writeColorIOCSection(b, "IPv4", iocs.IPv4, 5)
	if len(iocs.PEHashes) > 0 {
		fmt.Fprintf(b, "  %s %s (%d)\n", dim("PE Hashes:"),
			strings.Join(firstPEHashSummaries(iocs.PEHashes, 3), ", "),
			len(iocs.PEHashes))
	}
	if iocs.SuppressedCount > 0 {
		fmt.Fprintf(b, "  %s %d IOC(s) suppressed by allowlist\n", dim("Filtered:"), iocs.SuppressedCount)
	}
}

func writeColorIOCsFull(b *strings.Builder, iocs IOCSet) {
	total := IOCCount(iocs)
	fmt.Fprintf(b, "\n%s %s\n", bold("🌐 IOCs:"), dim(fmt.Sprintf("%d total", total)))
	if total == 0 {
		return
	}
	writeColorIOCSection(b, "URLs", iocs.URLs, 0)
	writeColorIOCSection(b, "Domains", iocs.Domains, 0)
	writeColorIOCSection(b, "IPv4", iocs.IPv4, 0)
	writeColorIOCSection(b, "IPv6", iocs.IPv6, 0)
	writeColorIOCSection(b, "Emails", iocs.Emails, 0)
	writeColorIOCSection(b, "CVEs", iocs.CVEs, 0)
	writeColorIOCSection(b, "MD5", iocs.MD5, 0)
	writeColorIOCSection(b, "SHA1", iocs.SHA1, 0)
	writeColorIOCSection(b, "SHA256", iocs.SHA256, 0)
	writeColorIOCSection(b, "Registry", iocs.RegistryKeys, 0)
	writeColorIOCSection(b, "Win paths", iocs.WindowsPaths, 0)
	writeColorIOCSection(b, "Unix paths", iocs.UnixPaths, 0)
	if len(iocs.PEHashes) > 0 {
		fmt.Fprintf(b, "  %s\n", dim("PE Hashes:"))
		for _, pe := range iocs.PEHashes {
			fmt.Fprintf(b, "    %s %s %s\n",
				colorize(colorCyan, pe.SHA256[:16]+"..."),
				dim(pe.Path),
				dim("["+pe.Tier+"]"))
		}
	}
	if iocs.SuppressedCount > 0 {
		fmt.Fprintf(b, "  %s %d IOC(s) suppressed by allowlist\n", dim("Filtered:"), iocs.SuppressedCount)
	}
}

func writeColorIOCSection(b *strings.Builder, label string, values []string, limit int) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(b, "  %s (%d):\n", dim(label), len(values))
	for i, v := range values {
		if limit > 0 && i >= limit {
			fmt.Fprintf(b, "    %s %d more\n", dim("..."), len(values)-limit)
			break
		}
		fmt.Fprintf(b, "    %s %s\n", dim("•"), colorize(colorCyan, v))
	}
}
