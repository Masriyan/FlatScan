package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var yaraIdentifierRe = regexp.MustCompile(`[^A-Za-z0-9_]`)

func WriteYARARule(path string, result ScanResult) error {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(RenderYARARule(result)), 0o644)
}

func RenderYARARule(result ScanResult) string {
	ruleName := yaraRuleName(result)
	var b strings.Builder
	useEntropy := result.Entropy >= 7.0
	if useEntropy {
		fmt.Fprintln(&b, `import "math"`)
		fmt.Fprintln(&b)
	}
	fmt.Fprintf(&b, "rule %s {\n", ruleName)
	fmt.Fprintln(&b, "  meta:")
	fmt.Fprintln(&b, `    author = "FlatScan by sudo3rs"`)
	fmt.Fprintln(&b, `    description = "Auto-generated static hunting rule from FlatScan analysis"`)
	fmt.Fprintf(&b, "    generated_utc = %s\n", yaraQuote(time.Now().UTC().Format(time.RFC3339)))
	fmt.Fprintf(&b, "    sample_name = %s\n", yaraQuote(result.FileName))
	fmt.Fprintf(&b, "    sha256 = %q\n", result.Hashes.SHA256)
	fmt.Fprintf(&b, "    verdict = %s\n", yaraQuote(result.Verdict))
	fmt.Fprintf(&b, "    risk_score = %d\n", result.RiskScore)
	if len(result.Profile.MalwareType) > 0 {
		fmt.Fprintf(&b, "    malware_type = %s\n", yaraQuote(strings.Join(result.Profile.MalwareType, ", ")))
	}
	if result.PE != nil && result.PE.ImportHash != "" {
		fmt.Fprintf(&b, "    pe_import_hash = %q\n", result.PE.ImportHash)
	}

	stringEntries := yaraStringEntries(result)
	quality, fpRisk := yaraRuleQuality(result, stringEntries)
	fmt.Fprintf(&b, "    rule_quality_score = %d\n", quality)
	fmt.Fprintf(&b, "    expected_fp_risk = %s\n", yaraQuote(fpRisk))
	if len(stringEntries) > 0 {
		fmt.Fprintln(&b, "  strings:")
		for _, entry := range stringEntries {
			fmt.Fprintf(&b, "    %s = %s %s\n", entry.Identifier, yaraQuote(entry.Value), entry.Modifier)
		}
	}

	fmt.Fprintln(&b, "  condition:")
	conditions := yaraConditions(result, stringEntries)
	if len(conditions) == 0 {
		fmt.Fprintln(&b, "    false")
	} else {
		fileGuard := yaraFileGuard(result, stringEntries)
		fmt.Fprintf(&b, "    %s and (\n", fileGuard)
		for i, condition := range conditions {
			suffix := " or"
			if i == len(conditions)-1 {
				suffix = ""
			}
			fmt.Fprintf(&b, "      %s%s\n", condition, suffix)
		}
		fmt.Fprint(&b, "    )")
		if useEntropy {
			fmt.Fprintf(&b, " and math.entropy(0, filesize) >= %.2f\n", minFloat(result.Entropy, 7.95)-0.20)
		} else {
			fmt.Fprintln(&b)
		}
	}
	fmt.Fprintln(&b, "}")
	return b.String()
}

type yaraStringEntry struct {
	Identifier string
	Value      string
	Modifier   string
	Group      string
}

func yaraStringEntries(result ScanResult) []yaraStringEntry {
	var entries []yaraStringEntry
	addGroup := func(group string, values []string, modifier string, limit int) {
		seen := map[string]struct{}{}
		for _, value := range values {
			value = normalizeYARAString(value)
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			entries = append(entries, yaraStringEntry{
				Identifier: fmt.Sprintf("$%s%03d", group, len(seen)),
				Value:      value,
				Modifier:   modifier,
				Group:      group,
			})
			if len(seen) >= limit {
				break
			}
		}
	}

	addGroup("url", filterYARAValues(yaraActionable("url", result.IOCs.URLs), result), "ascii wide", 12)
	addGroup("dom", filterYARAValues(yaraActionable("domain", result.IOCs.Domains), result), "ascii wide nocase", 12)
	addGroup("reg", result.IOCs.RegistryKeys, "ascii wide nocase", 8)
	addGroup("path", append(yaraActionable("windows_path", result.IOCs.WindowsPaths), yaraActionable("unix_path", result.IOCs.UnixPaths)...), "ascii wide nocase", 8)
	addGroup("str", filterYARAValues(result.SuspiciousStrings, result), "ascii wide nocase", 24)
	addGroup("entry", suspiciousArchiveEntryNames(result), "ascii", 16)
	if result.MSIX != nil {
		addGroup("msix", []string{"AppxManifest.xml", "AppxSignature.p7x", "AppxBlockMap.xml", "[Content_Types].xml"}, "ascii", 4)
	}
	return entries
}

func yaraConditions(result ScanResult, entries []yaraStringEntry) []string {
	counts := map[string]int{}
	for _, entry := range entries {
		counts[entry.Group]++
	}
	var conditions []string
	for _, group := range []string{"url", "dom", "reg", "path", "str", "entry"} {
		count := counts[group]
		if count == 0 {
			continue
		}
		if group == "str" && count >= 2 {
			conditions = append(conditions, "2 of ($str*)")
		} else {
			conditions = append(conditions, fmt.Sprintf("any of ($%s*)", group))
		}
	}
	if result.MSIX != nil && counts["msix"] >= 4 {
		filtered := conditions[:0]
		for _, condition := range conditions {
			if condition != "any of ($msix*)" {
				filtered = append(filtered, condition)
			}
		}
		conditions = filtered
		if len(conditions) == 0 && counts["entry"] > 0 {
			conditions = append(conditions, "any of ($entry*)")
		}
	}
	return conditions
}

func yaraFileGuard(result ScanResult, entries []yaraStringEntry) string {
	switch result.FileType {
	case "PE executable":
		return "uint16(0) == 0x5a4d"
	case "MSIX/AppX package":
		if countYARAGroup(entries, "msix") >= 4 {
			return "uint32(0) == 0x04034b50 and all of ($msix*)"
		}
		return "uint32(0) == 0x04034b50"
	case "ZIP container", "APK package", "JAR package", "Office Open XML document":
		return "uint32(0) == 0x04034b50"
	default:
		return "filesize > 0"
	}
}

func countYARAGroup(entries []yaraStringEntry, group string) int {
	count := 0
	for _, entry := range entries {
		if entry.Group == group {
			count++
		}
	}
	return count
}

func suspiciousArchiveEntryNames(result ScanResult) []string {
	var values []string
	for _, entry := range result.ArchiveEntries {
		if entry.SuspiciousReason != "" || archivePEPayloadName(entry.Name) || obfuscatedArchiveNameReason(entry.Name) != "" {
			values = appendUnique(values, normalizeArchivePath(entry.Name))
		}
	}
	for _, peHash := range result.IOCs.PEHashes {
		if peHash.Path != "" {
			values = appendUnique(values, normalizeArchivePath(peHash.Path))
		}
	}
	return uniqueSorted(values)
}

func filterYARAValues(values []string, result ScanResult) []string {
	var out []string
	for _, value := range values {
		value = stripScannerStringPrefix(value)
		if isYARASelfGeneratedString(value, result) {
			continue
		}
		if isGenericFormatString(value) {
			continue
		}
		if isCompilerOrLibraryString(value) {
			continue // toolchain/runtime noise → high-FP YARA atoms
		}
		out = appendUnique(out, value)
	}
	return out
}

// isCompilerOrLibraryString flags toolchain/runtime/library strings that make
// poor (high false-positive) YARA atoms — they appear in countless benign
// binaries built with the same compiler/runtime.
func isCompilerOrLibraryString(value string) bool {
	lower := strings.ToLower(value)
	markers := []string{
		"gcc: (", "go build id", "go1.", "rustc", "clang version", "mingw",
		"__cxa_", "_zn", "std::", "msvcrt", "vcruntime", "libstdc++", "libgcc",
		"glibc_", "libc.so", "ld-linux", "operator new", "bad_alloc",
		".cpp", ".rs\x00", "/rustc/", "cargo/registry", "go/pkg/mod",
		"visual c++ runtime", "this program cannot be run", "ucrtbase",
		"api-ms-win-", "kernelbase.dll", "mscoree.dll", ".pdb",
	}
	for _, m := range markers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	// Drop build-artifact / source-path / namespace values via the IOC classifier.
	if !actionableIOCCategory(classifyIOCValue("unix_path", value).Category) {
		return true
	}
	return false
}

// yaraActionable drops values the IOC classifier marks non-actionable (build
// artifact / source path / namespace), so generated rules key on real IOCs.
func yaraActionable(iocType string, values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if actionableIOCCategory(classifyIOCValue(iocType, v).Category) {
			out = append(out, v)
		}
	}
	return out
}

func stripScannerStringPrefix(value string) string {
	if !strings.HasPrefix(value, "archive:") {
		return value
	}
	if idx := strings.LastIndex(value, ": "); idx >= 0 && idx+2 < len(value) {
		return value[idx+2:]
	}
	return value
}

func isYARASelfGeneratedString(value string, result ScanResult) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return true
	}
	self := []string{
		"flatscan",
		"suspicious archive/dropper",
		"likely malicious",
		strings.ToLower(result.Verdict),
		strings.ToLower(result.Profile.Classification),
	}
	for _, marker := range self {
		if marker != "" && strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func isGenericFormatString(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "schemas.microsoft.com") ||
		strings.Contains(lower, "schemas.openxmlformats.org") ||
		strings.Contains(lower, "www.w3.org/2001") ||
		strings.Contains(lower, "appxmanifest.xml") && !strings.Contains(lower, "/")
}

func normalizeYARAString(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\t", " ")
	value = strings.Join(strings.Fields(value), " ")
	if len(value) < 5 {
		return ""
	}
	if len(value) > 180 {
		value = value[:180]
	}
	return value
}

func yaraRuleName(result ScanResult) string {
	base := result.FileName
	if base == "" {
		base = "sample"
	}
	base = strings.TrimSuffix(base, filepath.Ext(base))
	base = yaraIdentifierRe.ReplaceAllString(base, "_")
	base = strings.Trim(base, "_")
	if base == "" {
		base = "sample"
	}
	sha := result.Hashes.SHA256
	if len(sha) > 8 {
		sha = sha[:8]
	}
	name := "FlatScan_" + base
	if sha != "" {
		name += "_" + sha
	}
	if name[0] >= '0' && name[0] <= '9' {
		name = "FlatScan_" + name
	}
	return name
}

func yaraEscape(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return value
}

func yaraQuote(value string) string {
	return `"` + yaraEscape(value) + `"`
}

// yaraRuleQuality scores the generated rule (0–100) and assigns an expected
// false-positive risk. Quality rises with the number of unique, high-specificity
// atoms (URLs, registry keys, mutex/path strings) and a strong file guard; it
// falls when the rule rests on few or generic atoms.
func yaraRuleQuality(result ScanResult, entries []yaraStringEntry) (int, string) {
	groups := map[string]int{}
	for _, e := range entries {
		groups[e.Group]++
	}
	score := 0
	score += minInt(groups["url"], 4) * 12 // URLs are high-specificity
	score += minInt(groups["reg"], 3) * 8
	score += minInt(groups["entry"], 4) * 8 // embedded payload names
	score += minInt(groups["path"], 3) * 6
	score += minInt(groups["dom"], 4) * 5
	score += minInt(groups["str"], 6) * 3
	if result.PE != nil && result.PE.ImportHash != "" {
		score += 10 // imphash pin in meta
	}
	if result.FileType == "PE executable" || strings.Contains(result.FileType, "package") {
		score += 8 // a real magic-byte file guard
	}
	if score > 100 {
		score = 100
	}
	risk := "high"
	switch {
	case score >= 70:
		risk = "low"
	case score >= 40:
		risk = "medium"
	}
	// A rule with only a couple of generic string atoms and no anchor is risky.
	if len(entries) <= 2 && groups["url"] == 0 && groups["reg"] == 0 {
		risk = "high"
	}
	return score, risk
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
