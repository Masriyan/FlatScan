package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func RenderReport(result ScanResult, mode string) string {
	switch mode {
	case "minimal":
		return renderMinimalReport(result)
	case "full":
		return renderFullReport(result)
	default:
		return renderSummaryReport(result)
	}
}

func renderMinimalReport(result ScanResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "FlatScan %s\n", result.Version)
	fmt.Fprintf(&b, "Target: %s\n", result.Target)
	fmt.Fprintf(&b, "Verdict: %s (%d/100)\n", result.Verdict, result.RiskScore)
	fmt.Fprintf(&b, "Type: %s\n", result.FileType)
	fmt.Fprintf(&b, "SHA256: %s\n", result.Hashes.SHA256)
	fmt.Fprintf(&b, "Findings: %d | IOCs: %d\n", len(result.Findings), IOCCount(result.IOCs))
	return b.String()
}

func renderSummaryReport(result ScanResult) string {
	var b strings.Builder
	writeHeader(&b, result)
	writeProfile(&b, result)
	writeFindings(&b, result.Findings, 12)
	writeIOCSummary(&b, result.IOCs)
	if len(result.SuspiciousStrings) > 0 {
		fmt.Fprintln(&b, "\nSuspicious strings:")
		writeList(&b, result.SuspiciousStrings, 10)
	}
	if len(result.DecodedArtifacts) > 0 {
		fmt.Fprintln(&b, "\nDecoded artifacts:")
		for _, artifact := range limitArtifacts(result.DecodedArtifacts, 8) {
			fmt.Fprintf(&b, "- %s from %s: %s\n", artifact.Encoding, artifact.Source, artifact.Preview)
		}
	}
	return b.String()
}

func renderFullReport(result ScanResult) string {
	var b strings.Builder
	writeHeader(&b, result)
	writeProfile(&b, result)
	writeHashes(&b, result)
	writeFindings(&b, result.Findings, 0)
	writeFunctions(&b, result.Functions)
	writeIOCsFull(&b, result.IOCs)
	writeDecodedFull(&b, result.DecodedArtifacts)
	writeFormatDetails(&b, result)
	writeArchiveEntries(&b, result.ArchiveEntries)
	if len(result.SuspiciousStrings) > 0 {
		fmt.Fprintln(&b, "\nSuspicious strings:")
		writeList(&b, result.SuspiciousStrings, 0)
	}
	if len(result.DebugLog) > 0 {
		fmt.Fprintln(&b, "\nDebug log:")
		writeList(&b, result.DebugLog, 0)
	}
	return b.String()
}

func writeProfile(b *strings.Builder, result ScanResult) {
	if result.Profile.Classification == "" && len(result.Profile.TTPs) == 0 && len(result.Profile.CryptoIndicators) == 0 {
		return
	}
	fmt.Fprintln(b, "\nMalware profile:")
	if result.Profile.Classification != "" {
		fmt.Fprintf(b, "- Classification: %s\n", result.Profile.Classification)
	}
	if result.Profile.Confidence != "" {
		fmt.Fprintf(b, "- Confidence: %s (%d/100)\n", result.Profile.Confidence, result.Profile.ConfidenceScore)
	}
	if len(result.Profile.MalwareType) > 0 {
		fmt.Fprintf(b, "- Likely type: %s\n", strings.Join(result.Profile.MalwareType, ", "))
	}
	if len(result.Profile.KeyCapabilities) > 0 {
		fmt.Fprintf(b, "- Capabilities: %s\n", strings.Join(result.Profile.KeyCapabilities, ", "))
	}
	if len(result.Profile.TTPs) > 0 {
		fmt.Fprintf(b, "- MITRE TTPs mapped: %d\n", len(result.Profile.TTPs))
	}
	if len(result.Profile.CryptoIndicators) > 0 {
		fmt.Fprintf(b, "- Crypto indicators: %d\n", len(result.Profile.CryptoIndicators))
	}
	if result.Profile.ExecutiveAssessment != "" {
		fmt.Fprintf(b, "- Assessment: %s\n", result.Profile.ExecutiveAssessment)
	}
}

func writeHeader(b *strings.Builder, result ScanResult) {
	fmt.Fprintf(b, "FlatScan %s report\n", result.Version)
	fmt.Fprintf(b, "Target: %s\n", result.Target)
	fmt.Fprintf(b, "Mode: %s\n", result.Mode)
	fmt.Fprintf(b, "Verdict: %s (%d/100)\n", result.Verdict, result.RiskScore)
	fmt.Fprintf(b, "File type: %s\n", result.FileType)
	if result.MIMEHint != "" {
		fmt.Fprintf(b, "MIME hint: %s\n", result.MIMEHint)
	}
	fmt.Fprintf(b, "Size: %s (%d bytes)\n", formatBytes(result.Size), result.Size)
	fmt.Fprintf(b, "Analyzed bytes: %s", formatBytes(result.AnalyzedBytes))
	if result.TruncatedAnalysis {
		fmt.Fprint(b, " (truncated)")
	}
	fmt.Fprintln(b)
	fmt.Fprintf(b, "Entropy: %.2f/8.00 - %s\n", result.Entropy, result.EntropyAssessment)
	fmt.Fprintf(b, "Strings: %d", result.StringsTotal)
	if result.StringsTruncated {
		fmt.Fprint(b, " (stored output truncated)")
	}
	fmt.Fprintln(b)
	if result.Duration != "" {
		fmt.Fprintf(b, "Duration: %s\n", result.Duration)
	}
}

func writeHashes(b *strings.Builder, result ScanResult) {
	fmt.Fprintln(b, "\nHashes:")
	fmt.Fprintf(b, "- MD5: %s\n", result.Hashes.MD5)
	fmt.Fprintf(b, "- SHA1: %s\n", result.Hashes.SHA1)
	fmt.Fprintf(b, "- SHA256: %s\n", result.Hashes.SHA256)
	fmt.Fprintf(b, "- SHA512: %s\n", result.Hashes.SHA512)
	if result.PE != nil && result.PE.ImportHash != "" {
		fmt.Fprintf(b, "- PE import hash: %s\n", result.PE.ImportHash)
	}
}

func writeFindings(b *strings.Builder, findings []Finding, limit int) {
	fmt.Fprintf(b, "\nFindings: %d\n", len(findings))
	if len(findings) == 0 {
		fmt.Fprintln(b, "- No strong static indicators were found.")
		return
	}
	for index, finding := range findings {
		if limit > 0 && index >= limit {
			fmt.Fprintf(b, "- ... %d more findings omitted in summary mode\n", len(findings)-limit)
			break
		}
		fmt.Fprintf(b, "- [%s] %s: %s", finding.Severity, finding.Category, finding.Title)
		if finding.Evidence != "" {
			fmt.Fprintf(b, " (%s)", finding.Evidence)
		}
		if finding.Score > 0 {
			fmt.Fprintf(b, " score=%d", finding.Score)
		}
		if finding.Offset > 0 {
			fmt.Fprintf(b, " offset=0x%x", finding.Offset)
		}
		fmt.Fprintln(b)
		if finding.Tactic != "" || finding.Technique != "" {
			fmt.Fprintf(b, "  ATT&CK: %s", finding.Tactic)
			if finding.Technique != "" {
				fmt.Fprintf(b, " / %s", finding.Technique)
			}
			fmt.Fprintln(b)
		}
		if finding.Recommendation != "" {
			fmt.Fprintf(b, "  Recommendation: %s\n", finding.Recommendation)
		}
	}
}

func writeFunctions(b *strings.Builder, functions []FunctionHit) {
	if len(functions) == 0 {
		return
	}
	fmt.Fprintf(b, "\nSuspicious functions/APIs: %d\n", len(functions))
	seen := make(map[string]struct{})
	written := 0
	for _, fn := range functions {
		key := fn.Name + fn.Family + fn.Source
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		fmt.Fprintf(b, "- [%s] %s (%s, %s)\n", fn.Severity, fn.Name, fn.Family, fn.Source)
		written++
		if written >= 200 {
			fmt.Fprintln(b, "- ... function list capped at 200 unique entries")
			break
		}
	}
}

func writeIOCSummary(b *strings.Builder, iocs IOCSet) {
	fmt.Fprintf(b, "\nIOCs: %d total\n", IOCCount(iocs))
	writeCategorySummary(b, "URLs", iocs.URLs)
	writeCategorySummary(b, "Domains", iocs.Domains)
	writeCategorySummary(b, "IPv4", iocs.IPv4)
	writeCategorySummary(b, "IPv6", iocs.IPv6)
	writeCategorySummary(b, "Emails", iocs.Emails)
	writeCategorySummary(b, "Hashes", append(append(append(append([]string{}, iocs.MD5...), iocs.SHA1...), iocs.SHA256...), iocs.SHA512...))
	writeCategorySummary(b, "Registry keys", iocs.RegistryKeys)
	writeCategorySummary(b, "Windows paths", iocs.WindowsPaths)
	writeCategorySummary(b, "Unix paths", iocs.UnixPaths)
}

func writeCategorySummary(b *strings.Builder, name string, values []string) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(b, "- %s (%d): ", name, len(values))
	sample := values
	if len(sample) > 3 {
		sample = sample[:3]
	}
	fmt.Fprintln(b, strings.Join(sample, ", "))
}

func writeIOCsFull(b *strings.Builder, iocs IOCSet) {
	fmt.Fprintf(b, "\nIOCs: %d total\n", IOCCount(iocs))
	writeIOCSection(b, "URLs", iocs.URLs)
	writeIOCSection(b, "Domains", iocs.Domains)
	writeIOCSection(b, "IPv4", iocs.IPv4)
	writeIOCSection(b, "IPv6", iocs.IPv6)
	writeIOCSection(b, "Emails", iocs.Emails)
	writeIOCSection(b, "MD5", iocs.MD5)
	writeIOCSection(b, "SHA1", iocs.SHA1)
	writeIOCSection(b, "SHA256", iocs.SHA256)
	writeIOCSection(b, "SHA512", iocs.SHA512)
	writeIOCSection(b, "CVEs", iocs.CVEs)
	writeIOCSection(b, "Registry keys", iocs.RegistryKeys)
	writeIOCSection(b, "Windows paths", iocs.WindowsPaths)
	writeIOCSection(b, "Unix paths", iocs.UnixPaths)
}

func writeIOCSection(b *strings.Builder, name string, values []string) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(b, "\n%s:\n", name)
	writeList(b, values, 0)
}

func writeDecodedFull(b *strings.Builder, artifacts []DecodedArtifact) {
	if len(artifacts) == 0 {
		return
	}
	fmt.Fprintf(b, "\nDecoded artifacts: %d\n", len(artifacts))
	for _, artifact := range artifacts {
		fmt.Fprintf(b, "- %s from %s: %s\n", artifact.Encoding, artifact.Source, artifact.Preview)
		if IOCCount(artifact.IOCs) > 0 {
			fmt.Fprintf(b, "  IOCs in decoded data: %d\n", IOCCount(artifact.IOCs))
		}
	}
}

func writeFormatDetails(b *strings.Builder, result ScanResult) {
	if len(result.HighEntropyRegions) > 0 {
		fmt.Fprintln(b, "\nHigh entropy regions:")
		for _, region := range result.HighEntropyRegions {
			fmt.Fprintf(b, "- offset=0x%x length=%d entropy=%.2f\n", region.Offset, region.Length, region.Entropy)
		}
	}

	if result.PE != nil {
		fmt.Fprintln(b, "\nPE details:")
		fmt.Fprintf(b, "- Machine: %s\n", result.PE.Machine)
		fmt.Fprintf(b, "- Timestamp: %s\n", result.PE.Timestamp)
		fmt.Fprintf(b, "- Subsystem: %s\n", result.PE.Subsystem)
		fmt.Fprintf(b, "- Image base: %s\n", result.PE.ImageBase)
		fmt.Fprintf(b, "- Entry point: %s\n", result.PE.EntryPoint)
		fmt.Fprintf(b, "- Managed .NET runtime: %v\n", result.PE.ManagedRuntime)
		fmt.Fprintf(b, "- Certificate table present: %v\n", result.PE.HasCertificate)
		if result.PE.OverlaySize > 0 {
			fmt.Fprintf(b, "- Overlay: offset=0x%x size=%s\n", result.PE.OverlayOffset, formatBytes(result.PE.OverlaySize))
		}
		writeSections(b, result.PE.Sections)
		if len(result.PE.Imports) > 0 {
			fmt.Fprintf(b, "\nPE imports: %d stored\n", len(result.PE.Imports))
			writeList(b, result.PE.Imports, 80)
		}
	}
	if result.ELF != nil {
		fmt.Fprintln(b, "\nELF details:")
		fmt.Fprintf(b, "- Class: %s\n", result.ELF.Class)
		fmt.Fprintf(b, "- Machine: %s\n", result.ELF.Machine)
		fmt.Fprintf(b, "- Type: %s\n", result.ELF.Type)
		writeSections(b, result.ELF.Sections)
		if len(result.ELF.Imports) > 0 {
			fmt.Fprintf(b, "\nELF imports: %d stored\n", len(result.ELF.Imports))
			writeList(b, result.ELF.Imports, 80)
		}
	}
	if result.MachO != nil {
		fmt.Fprintln(b, "\nMach-O details:")
		fmt.Fprintf(b, "- CPU: %s\n", result.MachO.CPU)
		fmt.Fprintf(b, "- Type: %s\n", result.MachO.Type)
		writeSections(b, result.MachO.Sections)
		if len(result.MachO.Imports) > 0 {
			fmt.Fprintf(b, "\nMach-O imports: %d stored\n", len(result.MachO.Imports))
			writeList(b, result.MachO.Imports, 80)
		}
	}
}

func writeSections(b *strings.Builder, sections []SectionInfo) {
	if len(sections) == 0 {
		return
	}
	fmt.Fprintln(b, "\nSections:")
	for _, section := range sections {
		flags := ""
		if section.Executable {
			flags += "X"
		}
		if section.Writable {
			flags += "W"
		}
		if flags == "" {
			flags = "-"
		}
		fmt.Fprintf(b, "- %s raw=0x%x size=%d entropy=%.2f flags=%s\n", section.Name, section.RawOffset, section.RawSize, section.Entropy, flags)
	}
}

func writeArchiveEntries(b *strings.Builder, entries []ArchiveEntry) {
	if len(entries) == 0 {
		return
	}
	fmt.Fprintf(b, "\nArchive entries: %d\n", len(entries))
	for _, entry := range entries {
		fmt.Fprintf(b, "- %s size=%d compressed=%d", entry.Name, entry.Size, entry.CompressedSize)
		if entry.SuspiciousReason != "" {
			fmt.Fprintf(b, " reason=%s", entry.SuspiciousReason)
		}
		fmt.Fprintln(b)
	}
}

func WriteIOCFile(path string, result ScanResult) error {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# FlatScan IOC Export\n")
	fmt.Fprintf(&b, "target=%s\n", result.Target)
	fmt.Fprintf(&b, "sha256=%s\n", result.Hashes.SHA256)
	fmt.Fprintf(&b, "verdict=%s\n", result.Verdict)
	fmt.Fprintf(&b, "risk_score=%d\n", result.RiskScore)
	if IOCCount(result.IOCs) == 0 {
		fmt.Fprintln(&b, "\n# No IOCs extracted")
		return os.WriteFile(path, []byte(b.String()), 0o644)
	}
	writeIOCExportSection(&b, "urls", result.IOCs.URLs)
	writeIOCExportSection(&b, "domains", result.IOCs.Domains)
	writeIOCExportSection(&b, "ipv4", result.IOCs.IPv4)
	writeIOCExportSection(&b, "ipv6", result.IOCs.IPv6)
	writeIOCExportSection(&b, "emails", result.IOCs.Emails)
	writeIOCExportSection(&b, "md5", result.IOCs.MD5)
	writeIOCExportSection(&b, "sha1", result.IOCs.SHA1)
	writeIOCExportSection(&b, "sha256", result.IOCs.SHA256)
	writeIOCExportSection(&b, "sha512", result.IOCs.SHA512)
	writeIOCExportSection(&b, "cves", result.IOCs.CVEs)
	writeIOCExportSection(&b, "registry_keys", result.IOCs.RegistryKeys)
	writeIOCExportSection(&b, "windows_paths", result.IOCs.WindowsPaths)
	writeIOCExportSection(&b, "unix_paths", result.IOCs.UnixPaths)
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func writeIOCExportSection(b *strings.Builder, name string, values []string) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(b, "\n[%s]\n", name)
	for _, value := range values {
		fmt.Fprintln(b, value)
	}
}

func writeList(b *strings.Builder, values []string, limit int) {
	for index, value := range values {
		if limit > 0 && index >= limit {
			fmt.Fprintf(b, "- ... %d more omitted\n", len(values)-limit)
			return
		}
		fmt.Fprintf(b, "- %s\n", value)
	}
}

func previewString(value string, limit int) string {
	value = strings.ReplaceAll(value, "\r", "\\r")
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, "\t", "\\t")
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	if limit <= 3 {
		return value[:limit]
	}
	return value[:limit-3] + "..."
}

func limitArtifacts(values []DecodedArtifact, limit int) []DecodedArtifact {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

func formatBytes(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(size)/float64(div), "KMGTPE"[exp])
}
