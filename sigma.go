package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var sigmaFieldRe = regexp.MustCompile(`[^A-Za-z0-9_.|]+`)

func WriteSigmaRule(path string, result ScanResult) error {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(RenderSigmaRule(result)), 0o644)
}

func RenderSigmaRule(result ScanResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "title: %s\n", sigmaQuote("FlatScan Hunt - "+nonEmpty(result.FileName, "sample")))
	fmt.Fprintf(&b, "id: %s\n", sigmaQuote(sigmaDeterministicID(result)))
	fmt.Fprintln(&b, "status: experimental")
	fmt.Fprintf(&b, "description: %s\n", sigmaQuote("Auto-generated hunt rule from FlatScan static analysis. Validate before production deployment."))
	fmt.Fprintln(&b, "references:")
	fmt.Fprintln(&b, "  - https://github.com/Masriyan/FlatScan")
	fmt.Fprintln(&b, "author: FlatScan by sudo3rs")
	fmt.Fprintf(&b, "date: %s\n", time.Now().UTC().Format("2006-01-02"))
	tags := sigmaTags(result)
	if len(tags) > 0 {
		fmt.Fprintln(&b, "tags:")
		for _, tag := range tags {
			fmt.Fprintf(&b, "  - %s\n", tag)
		}
	}
	fmt.Fprintln(&b, "logsource:")
	if isAndroidPackage(result) || result.APK != nil {
		fmt.Fprintln(&b, "  product: android")
		fmt.Fprintln(&b, "  category: application")
	} else {
		fmt.Fprintln(&b, "  product: generic")
		fmt.Fprintln(&b, "  category: process_creation")
	}
	fmt.Fprintln(&b, "detection:")
	selectionCount := writeSigmaSelections(&b, result)
	if selectionCount == 0 {
		fmt.Fprintln(&b, "  selection_fallback:")
		fmt.Fprintf(&b, "    Image|endswith: %s\n", sigmaQuote(result.FileName))
		selectionCount = 1
	}
	filterCount := writeSigmaFilters(&b, result)
	condition := "1 of selection_*"
	if filterCount > 0 {
		condition += " and not 1 of filter_*"
	}
	fmt.Fprintf(&b, "  condition: %s\n", condition)
	fmt.Fprintln(&b, "fields:")
	for _, field := range sigmaFields(result) {
		fmt.Fprintf(&b, "  - %s\n", field)
	}
	fmt.Fprintln(&b, "falsepositives:")
	for _, fp := range sigmaFalsePositives(result) {
		fmt.Fprintf(&b, "  - %s\n", sigmaQuote(fp))
	}
	fmt.Fprintf(&b, "level: %s\n", sigmaLevel(result.RiskScore))
	return b.String()
}

func writeSigmaSelections(b *strings.Builder, result ScanResult) int {
	count := 0
	archiveRule := (isArchiveLike(result) || result.MSIX != nil) && result.APK == nil
	if result.Hashes.SHA256 != "" {
		fmt.Fprintln(b, "  selection_hash:")
		fmt.Fprintf(b, "    Hashes|contains: %s\n", sigmaQuote(result.Hashes.SHA256))
		count++
	}
	if len(result.IOCs.PEHashes) > 0 {
		fmt.Fprintln(b, "  selection_payload_hashes:")
		fmt.Fprintln(b, "    Hashes|contains:")
		for _, peHash := range firstPEHashes(result.IOCs.PEHashes, 20) {
			fmt.Fprintf(b, "      - %s\n", sigmaQuote(peHash.SHA256))
		}
		fmt.Fprintln(b, "  # Analyst note: payload hash matches are high-confidence pivots for extracted embedded executables.")
		count++
	}
	if result.FileName != "" && !archiveRule {
		fmt.Fprintln(b, "  selection_filename:")
		fmt.Fprintf(b, "    Image|endswith: %s\n", sigmaQuote(result.FileName))
		count++
	}
	if archiveRule {
		patterns := payloadImagePatterns(result)
		if len(patterns) > 0 {
			fmt.Fprintln(b, "  selection_payload_image:")
			fmt.Fprintln(b, "    Image|endswith:")
			for _, pattern := range firstStrings(patterns, 30) {
				fmt.Fprintf(b, "      - %s\n", sigmaQuote(pattern))
			}
			fmt.Fprintln(b, "  # Analyst note: payload image selections are medium-confidence and should be paired with hash or package-delivery context.")
			count++
		}
		return count
	}
	networkValues := firstStrings(append(append([]string{}, result.IOCs.URLs...), result.IOCs.Domains...), 20)
	if len(networkValues) > 0 {
		fmt.Fprintln(b, "  selection_network_iocs:")
		fmt.Fprintln(b, "    CommandLine|contains:")
		for _, value := range networkValues {
			fmt.Fprintf(b, "      - %s\n", sigmaQuote(value))
		}
		count++
	}
	stringValues := firstStrings(result.SuspiciousStrings, 20)
	if len(stringValues) > 0 {
		fmt.Fprintln(b, "  selection_static_strings:")
		fmt.Fprintln(b, "    CommandLine|contains:")
		for _, value := range stringValues {
			fmt.Fprintf(b, "      - %s\n", sigmaQuote(value))
		}
		count++
	}
	if result.APK != nil {
		if result.APK.PackageName != "" {
			fmt.Fprintln(b, "  selection_android_package:")
			fmt.Fprintf(b, "    PackageName: %s\n", sigmaQuote(result.APK.PackageName))
			count++
		}
		permissions := firstStrings(androidPermissionNames(result.APK.Permissions), 20)
		if len(permissions) > 0 {
			fmt.Fprintln(b, "  selection_android_permissions:")
			fmt.Fprintln(b, "    Permissions|contains:")
			for _, permission := range permissions {
				fmt.Fprintf(b, "      - %s\n", sigmaQuote(permission))
			}
			count++
		}
		components := firstStrings(androidComponentNames(result.APK.ExportedComponents), 20)
		if len(components) > 0 {
			fmt.Fprintln(b, "  selection_android_exported_components:")
			fmt.Fprintln(b, "    ComponentName|contains:")
			for _, component := range components {
				fmt.Fprintf(b, "      - %s\n", sigmaQuote(component))
			}
			count++
		}
	}
	apiValues := firstStrings(androidAPIIndicators(result.DEXFiles), 20)
	if len(apiValues) > 0 {
		fmt.Fprintln(b, "  selection_android_api_indicators:")
		fmt.Fprintln(b, "    CommandLine|contains:")
		for _, value := range apiValues {
			fmt.Fprintf(b, "      - %s\n", sigmaQuote(value))
		}
		count++
	}
	_ = count
	return count
}

func writeSigmaFilters(b *strings.Builder, result ScanResult) int {
	if result.APK != nil || !(isArchiveLike(result) || result.MSIX != nil) {
		return 0
	}
	count := 0
	fmt.Fprintln(b, "  filter_benign_windowsapps:")
	fmt.Fprintln(b, "    Image|contains:")
	fmt.Fprintln(b, `      - "\\WindowsApps\\"`)
	fmt.Fprintln(b, `      - "\\Program Files\\WindowsApps\\"`)
	count++
	if result.MSIX != nil && result.MSIX.PublisherTrusted {
		fmt.Fprintln(b, "  filter_trusted_publisher_context:")
		fmt.Fprintln(b, "    Company|contains:")
		fmt.Fprintln(b, `      - "Microsoft Corporation"`)
		count++
	}
	return count
}

func sigmaTags(result ScanResult) []string {
	seen := map[string]struct{}{}
	var tags []string
	add := func(value string) {
		value = strings.ToLower(strings.TrimSpace(value))
		value = strings.ReplaceAll(value, " ", "_")
		value = sigmaFieldRe.ReplaceAllString(value, "_")
		value = strings.Trim(value, "_")
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		tags = append(tags, value)
	}
	add("flatscan")
	add("flatscan.risk." + sigmaLevel(result.RiskScore))
	for _, entry := range result.Profile.TTPs {
		if entry.ID != "" {
			add("attack." + strings.ToLower(entry.ID))
		} else if entry.Tactic != "" {
			add("attack." + entry.Tactic)
		}
	}
	if result.APK != nil {
		add("attack.mobile")
	}
	return tags
}

func sigmaFields(result ScanResult) []string {
	fields := []string{"Image", "CommandLine", "Hashes"}
	if result.APK == nil && (isArchiveLike(result) || result.MSIX != nil) {
		fields = append(fields, "ParentImage", "Company")
	}
	if result.APK != nil {
		fields = append(fields, "PackageName", "Permissions", "ComponentName")
	}
	return uniqueSorted(fields)
}

func sigmaFalsePositives(result ScanResult) []string {
	values := []string{"Legitimate software containing the same static strings or IOCs", "Benign test samples from malware labs or training environments"}
	if result.APK == nil && (isArchiveLike(result) || result.MSIX != nil) {
		values = append(values, "Legitimate packaged applications with the same payload name; prioritize hash selections over filename-only matches")
	}
	if result.APK != nil {
		values = append(values, "Legitimate Android applications using sensitive permissions for documented business functionality")
	}
	return values
}

func firstPEHashes(values []PEHashIOC, limit int) []PEHashIOC {
	if limit <= 0 || len(values) <= limit {
		return values
	}
	return values[:limit]
}

func payloadImagePatterns(result ScanResult) []string {
	var patterns []string
	for _, peHash := range result.IOCs.PEHashes {
		name := filepath.Base(strings.ReplaceAll(peHash.Path, "\\", "/"))
		if name == "." || name == "/" || name == "" {
			continue
		}
		patterns = appendUnique(patterns, `\`+name, `/`+name)
		if strings.Contains(peHash.Path, "/") {
			patterns = appendUnique(patterns, `\`+strings.ReplaceAll(peHash.Path, "/", `\`), `/`+peHash.Path)
		}
	}
	return uniqueSorted(patterns)
}

func sigmaLevel(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 55:
		return "high"
	case score >= 30:
		return "medium"
	case score >= 10:
		return "low"
	default:
		return "informational"
	}
}

func sigmaDeterministicID(result ScanResult) string {
	seed := result.Hashes.SHA256
	if seed == "" {
		sum := sha256.Sum256([]byte(result.FileName + "|" + result.Target))
		seed = hex.EncodeToString(sum[:])
	}
	if len(seed) < 32 {
		sum := sha256.Sum256([]byte(seed))
		seed = hex.EncodeToString(sum[:])
	}
	return fmt.Sprintf("%s-%s-%s-%s-%s", seed[0:8], seed[8:12], seed[12:16], seed[16:20], seed[20:32])
}

func sigmaQuote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.Join(strings.Fields(value), " ")
	return `"` + value + `"`
}

func androidPermissionNames(values []AndroidPermission) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value.Name)
	}
	return uniqueSorted(out)
}

func androidComponentNames(values []AndroidComponent) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value.Name != "" {
			out = append(out, value.Name)
		}
	}
	return uniqueSorted(out)
}

func androidAPIIndicators(values []DEXInfo) []string {
	var out []string
	for _, dex := range values {
		for _, hit := range dex.APIHits {
			out = append(out, hit.Indicator)
		}
	}
	return uniqueSorted(out)
}
