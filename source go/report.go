package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	writeAdvancedDetails(&b, result)
	writeConfigAndEnrichment(&b, result)
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

func writeConfigAndEnrichment(b *strings.Builder, result ScanResult) {
	if cfg := result.MalwareConfig; cfg != nil {
		fmt.Fprintln(b, "\nMalware configuration:")
		if cfg.Family != "" {
			fmt.Fprintf(b, "- Family: %s\n", cfg.Family)
		}
		writeCategorySummary(b, "C2", cfg.C2)
		writeCategorySummary(b, "Webhooks", cfg.Webhooks)
		writeCategorySummary(b, "Bot tokens", cfg.BotTokens)
		writeCategorySummary(b, "Mutexes", cfg.Mutexes)
		writeCategorySummary(b, "Wallets", cfg.Wallets)
		writeCategorySummary(b, "Campaign IDs", cfg.CampaignID)
		writeCategorySummary(b, "Build IDs", cfg.BuildID)
		writeCategorySummary(b, "Versions", cfg.Version)
	}
	if len(result.Enrichment) > 0 {
		fmt.Fprintln(b, "\nThreat-intel enrichment:")
		for _, e := range result.Enrichment {
			line := fmt.Sprintf("- [%s] %s", e.Type, e.Indicator)
			if e.Family != "" {
				line += " → " + e.Family
			}
			if e.Campaign != "" {
				line += " / " + e.Campaign
			}
			if e.FirstSeen != "" {
				line += " (first seen " + e.FirstSeen + ")"
			}
			fmt.Fprintln(b, line)
			if e.Note != "" {
				fmt.Fprintf(b, "    note: %s\n", e.Note)
			}
		}
	}
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
	if len(result.Profile.ExpectedBehavior) > 0 {
		fmt.Fprintln(b, "- Expected behavior (validate in sandbox/EDR):")
		for _, behavior := range result.Profile.ExpectedBehavior {
			fmt.Fprintf(b, "    • %s\n", behavior)
		}
	}
}

func writeHeader(b *strings.Builder, result ScanResult) {
	fmt.Fprintf(b, "FlatScan %s report\n", result.Version)
	fmt.Fprintf(b, "Target: %s\n", result.Target)
	fmt.Fprintf(b, "Mode: %s\n", result.Mode)
	fmt.Fprintf(b, "Verdict: %s (%d/100)\n", result.Verdict, result.RiskScore)
	if len(result.ScoreBreakdown) > 0 {
		fmt.Fprintf(b, "Score breakdown: %s\n", formatScoreBreakdown(result.ScoreBreakdown))
	}
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
		if finding.Confidence > 0 {
			fmt.Fprintf(b, " confidence=%d", finding.Confidence)
		}
		if finding.EvidenceCount > 1 {
			fmt.Fprintf(b, " evidence=%d", finding.EvidenceCount)
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
	if len(iocs.PEHashes) > 0 {
		fmt.Fprintf(b, "- Embedded PE hashes (%d): %s\n", len(iocs.PEHashes), strings.Join(firstPEHashSummaries(iocs.PEHashes, 3), ", "))
	}
	writeCategorySummary(b, "URLs", iocs.URLs)
	writeCategorySummary(b, "Domains", iocs.Domains)
	writeCategorySummary(b, "IPv4", iocs.IPv4)
	writeCategorySummary(b, "IPv6", iocs.IPv6)
	writeCategorySummary(b, "Emails", iocs.Emails)
	writeCategorySummary(b, "Hashes", append(append(append(append([]string{}, iocs.MD5...), iocs.SHA1...), iocs.SHA256...), iocs.SHA512...))
	writeCategorySummary(b, "Registry keys", iocs.RegistryKeys)
	writeCategorySummary(b, "Windows paths", iocs.WindowsPaths)
	writeCategorySummary(b, "Unix paths", iocs.UnixPaths)
	writeCategorySummary(b, "Mutexes", iocs.Mutexes)
	writeCategorySummary(b, "Named pipes", iocs.NamedPipes)
	writeCategorySummary(b, "Crypto wallets", iocs.CryptoWallets)
	if iocs.SuppressedCount > 0 {
		fmt.Fprintf(b, "- Suppressed as known-benign/contextual: %d\n", iocs.SuppressedCount)
	}
	if counts := nonActionableCategoryCounts(iocs.Classified); len(counts) > 0 {
		fmt.Fprintf(b, "- Categorized as non-actionable (excluded from IOC/STIX export): %s\n", counts)
	}
}

// nonActionableCategoryCounts summarizes how many classified indicators fell
// into each non-actionable category (build artifact / source path / namespace /
// compiler metadata), for analyst transparency in the report.
func nonActionableCategoryCounts(classified []ClassifiedIOC) string {
	counts := map[string]int{}
	for _, c := range classified {
		if !actionableIOCCategory(c.Category) {
			counts[c.Category]++
		}
	}
	if len(counts) == 0 {
		return ""
	}
	order := []string{iocCatBuildArtifact, iocCatCompilerMeta, iocCatSourcePath, iocCatNamespace}
	var parts []string
	for _, cat := range order {
		if n := counts[cat]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", cat, n))
		}
	}
	return strings.Join(parts, " ")
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
	writePEHashIOCSection(b, iocs.PEHashes)
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
	writeIOCSection(b, "Mutexes", iocs.Mutexes)
	writeIOCSection(b, "Named pipes", iocs.NamedPipes)
	writeIOCSection(b, "Crypto wallets", iocs.CryptoWallets)
	if iocs.SuppressedCount > 0 {
		fmt.Fprintf(b, "\nSuppressed IOCs: %d\n", iocs.SuppressedCount)
		if iocs.SuppressionReason != "" {
			fmt.Fprintf(b, "- Reason: %s\n", iocs.SuppressionReason)
		}
		for i, item := range iocs.SuppressionLog {
			if i >= 80 {
				fmt.Fprintf(b, "- ... %d more suppressed values omitted\n", len(iocs.SuppressionLog)-i)
				break
			}
			fmt.Fprintf(b, "- [%s] %s (%s)\n", item.Type, item.Value, item.Reason)
		}
	}
}

func writePEHashIOCSection(b *strings.Builder, values []PEHashIOC) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(b, "\nEmbedded PE payload hashes:\n")
	for _, value := range values {
		fmt.Fprintf(b, "- [%s] %s sha256=%s", value.Tier, value.Path, value.SHA256)
		if value.Size > 0 {
			fmt.Fprintf(b, " size=%d", value.Size)
		}
		if value.CompressedSize > 0 {
			fmt.Fprintf(b, " compressed=%d ratio=%.3f", value.CompressedSize, value.CompressionRatio)
		}
		if value.Entropy > 0 {
			fmt.Fprintf(b, " entropy=%.2f", value.Entropy)
		}
		if value.CarvedOffset != "" {
			fmt.Fprintf(b, " offset=%s", value.CarvedOffset)
		}
		if value.Note != "" {
			fmt.Fprintf(b, " note=%s", value.Note)
		}
		fmt.Fprintln(b)
	}
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

func writeAdvancedDetails(b *strings.Builder, result ScanResult) {
	if len(result.FamilyMatches) > 0 {
		fmt.Fprintf(b, "\nFamily classifier: %d hypotheses\n", len(result.FamilyMatches))
		for _, match := range result.FamilyMatches {
			fmt.Fprintf(b, "- [%s] %s (%s) score=%d", match.Confidence, match.Family, match.Category, match.Score)
			if len(match.Evidence) > 0 {
				fmt.Fprintf(b, " evidence=%s", strings.Join(match.Evidence, "; "))
			}
			fmt.Fprintln(b)
		}
	}
	if len(result.RulePacks) > 0 {
		fmt.Fprintf(b, "\nRule packs: %d\n", len(result.RulePacks))
		for _, pack := range result.RulePacks {
			fmt.Fprintf(b, "- %s rules=%d fired=%d", nonEmpty(pack.Name, pack.Path), pack.RulesLoaded, pack.RulesFired)
			if len(pack.Warnings) > 0 {
				fmt.Fprintf(b, " warnings=%s", strings.Join(pack.Warnings, " | "))
			}
			fmt.Fprintln(b)
		}
	}
	if len(result.ConfigArtifacts) > 0 {
		fmt.Fprintf(b, "\nCrypto/config artifacts: %d\n", len(result.ConfigArtifacts))
		for _, artifact := range result.ConfigArtifacts {
			fmt.Fprintf(b, "- [%s] %s from %s: %s", artifact.Confidence, artifact.Type, artifact.Source, artifact.Preview)
			if artifact.Evidence != "" {
				fmt.Fprintf(b, " (%s)", artifact.Evidence)
			}
			if IOCCount(artifact.IOCs) > 0 {
				fmt.Fprintf(b, " iocs=%d", IOCCount(artifact.IOCs))
			}
			fmt.Fprintln(b)
		}
	}
	if len(result.CarvedArtifacts) > 0 {
		fmt.Fprintf(b, "\nCarved artifacts: %d\n", len(result.CarvedArtifacts))
		for _, artifact := range result.CarvedArtifacts {
			fmt.Fprintf(b, "- %s offset=0x%x length=%d sha256=%s entropy=%.2f", artifact.Type, artifact.Offset, artifact.Length, artifact.SHA256, artifact.Entropy)
			if artifact.Preview != "" {
				fmt.Fprintf(b, " preview=%s", artifact.Preview)
			}
			fmt.Fprintln(b)
		}
	}
	if len(result.PayloadTree) > 0 {
		fmt.Fprintf(b, "\nResolved payload tree: %d buried stage(s)\n", len(result.PayloadTree))
		for _, node := range result.PayloadTree {
			indent := strings.Repeat("  ", node.Depth)
			hash := node.SHA256
			if len(hash) > 16 {
				hash = hash[:16]
			}
			fmt.Fprintf(b, "%s- [%s] %s (%d bytes, entropy %.2f, sha256 %s)", indent, node.Method, node.FileType, node.Size, node.Entropy, hash)
			if node.Score > 0 {
				fmt.Fprintf(b, " score=%d", node.Score)
			}
			if node.Verdict != "" {
				fmt.Fprintf(b, " verdict=%q", node.Verdict)
			}
			if node.Family != "" {
				fmt.Fprintf(b, " family=%s", node.Family)
			}
			fmt.Fprintln(b)
			if node.Detail != "" {
				fmt.Fprintf(b, "%s    via %s\n", indent, node.Detail)
			}
			for _, f := range node.Findings {
				fmt.Fprintf(b, "%s    finding: %s\n", indent, f)
			}
			for _, ioc := range node.IOCs {
				fmt.Fprintf(b, "%s    ioc: %s\n", indent, ioc)
			}
		}
	}
	if result.Similarity.FlatHash != "" {
		fmt.Fprintln(b, "\nSimilarity hashes:")
		if formatted := strings.TrimSpace(formatSimilarity(result.Similarity)); formatted != "" {
			for _, line := range strings.Split(formatted, "\n") {
				fmt.Fprintf(b, "- %s\n", line)
			}
		}
	}
	if len(result.DGADomains) > 0 {
		fmt.Fprintf(b, "\nAlgorithmically-generated (DGA) domains: %d\n", len(result.DGADomains))
		for _, d := range result.DGADomains {
			fmt.Fprintf(b, "- %s (score %.2f) %s\n", d.Domain, d.Score, strings.Join(d.Reasons, ", "))
		}
	}
	if len(result.ExternalTools) > 0 {
		fmt.Fprintf(b, "\nExternal tool integration: %d tools\n", len(result.ExternalTools))
		for _, tool := range result.ExternalTools {
			fmt.Fprintf(b, "- %s status=%s found=%v", tool.Name, tool.Status, tool.Found)
			if tool.Output != "" {
				fmt.Fprintf(b, " output=%s", previewString(tool.Output, 160))
			}
			if tool.Error != "" {
				fmt.Fprintf(b, " error=%s", tool.Error)
			}
			fmt.Fprintln(b)
		}
	}
	if len(result.Plugins) > 0 {
		fmt.Fprintf(b, "\nAnalysis plugins: %d\n", len(result.Plugins))
		for _, plugin := range result.Plugins {
			fmt.Fprintf(b, "- %s status=%s", plugin.Name, plugin.Status)
			if plugin.Summary != "" {
				fmt.Fprintf(b, " summary=%s", plugin.Summary)
			}
			if len(plugin.Warnings) > 0 {
				fmt.Fprintf(b, " warnings=%s", strings.Join(plugin.Warnings, " | "))
			}
			fmt.Fprintln(b)
		}
	}
	if result.Case != nil {
		fmt.Fprintf(b, "\nCase database:\n- Case ID: %s\n- Stored: %v\n- Path: %s\n", result.Case.CaseID, result.Case.Stored, result.Case.DatabasePath)
		if len(result.Case.RelatedHashes) > 0 {
			fmt.Fprintf(b, "- Related hashes: %s\n", strings.Join(result.Case.RelatedHashes, ", "))
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

	if result.APK != nil {
		fmt.Fprintln(b, "\nAPK details:")
		if result.APK.PackageName != "" {
			fmt.Fprintf(b, "- Package: %s\n", result.APK.PackageName)
		}
		if result.APK.VersionName != "" || result.APK.VersionCode != "" {
			fmt.Fprintf(b, "- Version: name=%s code=%s\n", result.APK.VersionName, result.APK.VersionCode)
		}
		if result.APK.MinSDK != "" || result.APK.TargetSDK != "" {
			fmt.Fprintf(b, "- SDK: min=%s target=%s\n", result.APK.MinSDK, result.APK.TargetSDK)
		}
		fmt.Fprintf(b, "- Manifest format: %s\n", result.APK.ManifestFormat)
		fmt.Fprintf(b, "- APK entries: %d\n", result.APK.FileCount)
		if len(result.APK.Permissions) > 0 {
			fmt.Fprintf(b, "\nAndroid permissions: %d\n", len(result.APK.Permissions))
			for _, permission := range result.APK.Permissions {
				detail := permission.Name
				if permission.Risk != "" {
					detail += " risk=" + permission.Risk
				}
				if permission.Category != "" {
					detail += " category=" + permission.Category
				}
				if permission.Protection != "" {
					detail += " protection=" + permission.Protection
				}
				fmt.Fprintf(b, "- %s\n", detail)
			}
		}
		if len(result.APK.ExportedComponents) > 0 {
			fmt.Fprintf(b, "\nExported Android components: %d\n", len(result.APK.ExportedComponents))
			for _, component := range result.APK.ExportedComponents {
				fmt.Fprintf(b, "- %s %s", component.Type, component.Name)
				if component.Permission != "" {
					fmt.Fprintf(b, " permission=%s", component.Permission)
				}
				if !component.ExportedDeclared {
					fmt.Fprint(b, " exported=inferred-from-intent-filter")
				}
				fmt.Fprintln(b)
				if len(component.IntentActions) > 0 {
					fmt.Fprintf(b, "  Actions: %s\n", strings.Join(component.IntentActions, ", "))
				}
			}
		}
		if len(result.APK.NativeLibraries) > 0 {
			fmt.Fprintf(b, "\nNative libraries: %d\n", len(result.APK.NativeLibraries))
			writeList(b, result.APK.NativeLibraries, 120)
		}
		if len(result.APK.EmbeddedPayloads) > 0 {
			fmt.Fprintf(b, "\nEmbedded APK payloads: %d\n", len(result.APK.EmbeddedPayloads))
			writeList(b, result.APK.EmbeddedPayloads, 120)
		}
		if len(result.APK.NetworkSecurityConfig) > 0 {
			fmt.Fprintf(b, "\nNetwork security config references: %d\n", len(result.APK.NetworkSecurityConfig))
			writeList(b, result.APK.NetworkSecurityConfig, 80)
		}
		if len(result.APK.SignatureFiles) > 0 {
			fmt.Fprintf(b, "\nAPK signature files: %d\n", len(result.APK.SignatureFiles))
			writeList(b, result.APK.SignatureFiles, 40)
		}
	}
	if len(result.DEXFiles) > 0 {
		fmt.Fprintf(b, "\nDEX analysis: %d file(s)\n", len(result.DEXFiles))
		for _, dex := range result.DEXFiles {
			fmt.Fprintf(b, "- %s version=%s strings=%d parsed=%d", dex.Name, dex.Version, dex.StringsTotal, dex.StringsParsed)
			if dex.StringsTruncated {
				fmt.Fprint(b, " truncated=true")
			}
			fmt.Fprintln(b)
			if len(dex.APIHits) > 0 {
				for _, hit := range dex.APIHits {
					fmt.Fprintf(b, "  [%s] %s: %s\n", hit.Severity, hit.Category, hit.Indicator)
				}
			}
			if IOCCount(dex.IOCs) > 0 {
				fmt.Fprintf(b, "  IOCs in DEX strings: %d\n", IOCCount(dex.IOCs))
			}
		}
	}

	if result.MSIX != nil {
		fmt.Fprintln(b, "\nMSIX/AppX metadata:")
		if result.MSIX.IdentityName != "" {
			fmt.Fprintf(b, "- Identity name: %s\n", result.MSIX.IdentityName)
		}
		if result.MSIX.IdentityPublisher != "" {
			fmt.Fprintf(b, "- Publisher: %s trusted=%v\n", result.MSIX.IdentityPublisher, result.MSIX.PublisherTrusted)
		}
		if result.MSIX.IdentityVersion != "" {
			fmt.Fprintf(b, "- Version: %s\n", result.MSIX.IdentityVersion)
		}
		if len(result.MSIX.DeclaredExecutables) > 0 {
			fmt.Fprintf(b, "- Declared executables: %s\n", strings.Join(result.MSIX.DeclaredExecutables, ", "))
		}
		if len(result.MSIX.Capabilities) > 0 {
			fmt.Fprintf(b, "- Capabilities: %s\n", strings.Join(result.MSIX.Capabilities, ", "))
		}
		if len(result.MSIX.UndeclaredExecutables) > 0 {
			fmt.Fprintf(b, "- Undeclared executables: %s\n", strings.Join(result.MSIX.UndeclaredExecutables, ", "))
		}
		if result.MSIX.SignatureSHA256 != "" {
			fmt.Fprintf(b, "- AppxSignature.p7x: sha256=%s size=%d status=%s\n", result.MSIX.SignatureSHA256, result.MSIX.SignatureSize, result.MSIX.SignatureParseStatus)
		}
		if len(result.MSIX.CertificateSubjects) > 0 {
			fmt.Fprintf(b, "- Certificate subjects: %s\n", strings.Join(result.MSIX.CertificateSubjects, " | "))
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
		if result.PE.SignatureStatus != "" {
			fmt.Fprintf(b, "- Signature: %s\n", result.PE.SignatureStatus)
		}
		if len(result.PE.CertificateSubjects) > 0 {
			fmt.Fprintf(b, "- Signer subject(s): %s\n", strings.Join(result.PE.CertificateSubjects, "; "))
		}
		if result.PE.SelfSigned {
			fmt.Fprintln(b, "- Self-signed: true")
		}
		if len(result.PE.SecurityFeatures) > 0 {
			fmt.Fprintf(b, "- Security mitigations: %s\n", strings.Join(result.PE.SecurityFeatures, ", "))
		}
		if len(result.PE.MissingMitigations) > 0 {
			fmt.Fprintf(b, "- Missing mitigations: %s\n", strings.Join(result.PE.MissingMitigations, ", "))
		}
		if len(result.PE.ImageCharacteristics) > 0 {
			fmt.Fprintf(b, "- Image characteristics: %s\n", strings.Join(result.PE.ImageCharacteristics, ", "))
		}
		if result.PE.HasTLSCallbacks {
			fmt.Fprintf(b, "- TLS callbacks: %d\n", result.PE.TLSCallbackCount)
		}
		if result.PE.EntryPointAnomaly != "" {
			fmt.Fprintf(b, "- Entry point: %s (%s)\n", result.PE.EntryPointSection, result.PE.EntryPointAnomaly)
		}
		if result.PE.RichHeaderHash != "" {
			fmt.Fprintf(b, "- Rich header hash: %s\n", result.PE.RichHeaderHash)
		}
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
	if result.PDF != nil {
		p := result.PDF
		fmt.Fprintln(b, "\nPDF details:")
		fmt.Fprintf(b, "- Version: %s\n", nonEmpty(p.Version, "unknown"))
		fmt.Fprintf(b, "- Objects: %d | streams: %d (%d decompressed)\n", p.ObjectCount, p.StreamCount, p.StreamsDecompressed)
		if p.IncrementalUpdates > 1 {
			fmt.Fprintf(b, "- Incremental updates: %d\n", p.IncrementalUpdates)
		}
		if p.Encrypted {
			fmt.Fprintln(b, "- Encrypted: yes")
		}
		if p.Linearized {
			fmt.Fprintln(b, "- Linearized: yes")
		}
		if len(p.Keywords) > 0 {
			var parts []string
			for _, hit := range p.Keywords {
				part := fmt.Sprintf("%s x%d", hit.Keyword, hit.Count)
				if hit.Obfuscated {
					part += " (hex-escaped)"
				}
				parts = append(parts, part)
			}
			fmt.Fprintf(b, "- Structure: %s\n", strings.Join(parts, ", "))
		}
		if len(p.ObfuscatedNames) > 0 {
			fmt.Fprintln(b, "- Obfuscated names:")
			writeList(b, p.ObfuscatedNames, 40)
		}
		if len(p.EmbeddedFiles) > 0 {
			fmt.Fprintf(b, "- Embedded files: %s\n", strings.Join(p.EmbeddedFiles, ", "))
		}
		if len(p.LaunchTargets) > 0 {
			fmt.Fprintf(b, "- Launch targets: %s\n", strings.Join(p.LaunchTargets, ", "))
		}
		if len(p.EmbeddedPayloads) > 0 {
			fmt.Fprintf(b, "- Embedded payload types: %s\n", strings.Join(p.EmbeddedPayloads, ", "))
		}
		if len(p.ExecutableLinks) > 0 {
			fmt.Fprintln(b, "- Executable link targets:")
			writeList(b, p.ExecutableLinks, 40)
		}
		if len(p.ArchiveLinks) > 0 {
			fmt.Fprintln(b, "- Archive link targets:")
			writeList(b, p.ArchiveLinks, 40)
		}
		if len(p.Masquerades) > 0 {
			fmt.Fprintln(b, "- Disguised names:")
			var parts []string
			for _, hit := range p.Masquerades {
				part := fmt.Sprintf("%s — %s", hit.Value, hit.Technique)
				if hit.LooksLike != "" {
					part += fmt.Sprintf(" (reads as %q)", hit.LooksLike)
				}
				parts = append(parts, part)
			}
			writeList(b, parts, 40)
		}
		if len(p.JavaScript) > 0 {
			fmt.Fprintf(b, "- JavaScript recovered (%d):\n", len(p.JavaScript))
			writeList(b, p.JavaScript, 20)
		}
	}
	if result.Code != nil {
		c := result.Code
		fmt.Fprintln(b, "\nCode analysis (disassembly):")
		fmt.Fprintf(b, "- Arch: %s\n", c.Arch)
		fmt.Fprintf(b, "- Entry offset: 0x%x\n", c.EntryOffset)
		fmt.Fprintf(b, "- Instructions decoded: %d (decode errors: %d)\n", c.InstructionsDecoded, c.DecodeErrors)
		fmt.Fprintf(b, "- Indirect calls/jumps: %d / %d\n", c.IndirectCalls, c.IndirectJumps)
		if len(c.Techniques) > 0 {
			fmt.Fprintf(b, "- Techniques: %s\n", strings.Join(c.Techniques, ", "))
		}
		if len(c.ResolvedHashedAPIs) > 0 {
			fmt.Fprintf(b, "- Resolved hashed APIs: %s\n", strings.Join(c.ResolvedHashedAPIs, ", "))
		}
		if len(c.EntryDisasm) > 0 {
			fmt.Fprintln(b, "- Entry-point disassembly:")
			for _, line := range c.EntryDisasm {
				fmt.Fprintf(b, "    %s\n", line)
			}
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
		if entry.CompressionRatio > 0 {
			fmt.Fprintf(b, " ratio=%.3f", entry.CompressionRatio)
		}
		if entry.Offset > 0 {
			fmt.Fprintf(b, " offset=0x%x", entry.Offset)
		}
		if entry.Type != "" {
			fmt.Fprintf(b, " type=%s", entry.Type)
		}
		if entry.Entropy > 0 {
			fmt.Fprintf(b, " entropy=%.2f", entry.Entropy)
		}
		if entry.SHA256 != "" {
			fmt.Fprintf(b, " sha256=%s", entry.SHA256)
		}
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
	if result.IOCs.SuppressedCount > 0 {
		fmt.Fprintf(&b, "suppressed_iocs=%d\n", result.IOCs.SuppressedCount)
	}
	if IOCCount(result.IOCs) == 0 {
		fmt.Fprintln(&b, "\n# No IOCs extracted")
		return os.WriteFile(path, []byte(b.String()), 0o644)
	}
	// Export only actionable indicators: drop build-artifact / source-path /
	// compiler-metadata / package-namespace noise so the IOC list stays
	// trustworthy. The full, categorized set remains in the JSON report.
	export := actionableIOCs(result.IOCs)
	if dropped := IOCCount(result.IOCs) - IOCCount(export); dropped > 0 {
		fmt.Fprintf(&b, "non_actionable_excluded=%d\n", dropped)
	}
	writePEHashExportSection(&b, export.PEHashes)
	writeIOCExportSection(&b, "urls", export.URLs)
	writeIOCExportSection(&b, "domains", export.Domains)
	writeIOCExportSection(&b, "ipv4", export.IPv4)
	writeIOCExportSection(&b, "ipv6", export.IPv6)
	writeIOCExportSection(&b, "emails", export.Emails)
	writeIOCExportSection(&b, "md5", export.MD5)
	writeIOCExportSection(&b, "sha1", export.SHA1)
	writeIOCExportSection(&b, "sha256", export.SHA256)
	writeIOCExportSection(&b, "sha512", export.SHA512)
	writeIOCExportSection(&b, "cves", export.CVEs)
	writeIOCExportSection(&b, "registry_keys", export.RegistryKeys)
	writeIOCExportSection(&b, "windows_paths", export.WindowsPaths)
	writeIOCExportSection(&b, "unix_paths", export.UnixPaths)
	writeIOCExportSection(&b, "mutexes", export.Mutexes)
	writeIOCExportSection(&b, "named_pipes", export.NamedPipes)
	writeIOCExportSection(&b, "crypto_wallets", export.CryptoWallets)
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func writePEHashExportSection(b *strings.Builder, values []PEHashIOC) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintln(b, "\n[pe_hashes]")
	for _, value := range values {
		fmt.Fprintf(b, "%s path=%s tier=%s", value.SHA256, value.Path, value.Tier)
		if value.Note != "" {
			fmt.Fprintf(b, " note=%q", value.Note)
		}
		fmt.Fprintln(b)
	}
}

func firstPEHashSummaries(values []PEHashIOC, limit int) []string {
	var out []string
	for i, value := range values {
		if limit > 0 && i >= limit {
			out = append(out, fmt.Sprintf("%d more", len(values)-i))
			break
		}
		sha := value.SHA256
		if len(sha) > 12 {
			sha = sha[:12]
		}
		out = append(out, fmt.Sprintf("%s=%s", value.Path, sha))
	}
	return out
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

func formatScoreBreakdown(breakdown map[string]int) string {
	type kv struct {
		k string
		v int
	}
	var pairs []kv
	for k, v := range breakdown {
		if v > 0 {
			pairs = append(pairs, kv{k, v})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].v == pairs[j].v {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v > pairs[j].v
	})
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, fmt.Sprintf("%s:%d", p.k, p.v))
	}
	return "[" + strings.Join(parts, " ") + "]"
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
