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
	fmt.Fprintln(&b, "  strings:")
	if len(stringEntries) == 0 {
		fmt.Fprintln(&b, `    $fallback = "FlatScanNoHighSignalString" ascii`)
	} else {
		for _, entry := range stringEntries {
			fmt.Fprintf(&b, "    %s = %s %s\n", entry.Identifier, yaraQuote(entry.Value), entry.Modifier)
		}
	}

	fmt.Fprintln(&b, "  condition:")
	conditions := yaraConditions(stringEntries)
	if len(conditions) == 0 {
		fmt.Fprintln(&b, "    false")
	} else {
		fileGuard := "filesize > 0"
		if strings.Contains(strings.ToLower(result.FileType), "pe executable") {
			fileGuard = "uint16(0) == 0x5a4d"
		}
		fmt.Fprintf(&b, "    %s and (\n", fileGuard)
		for i, condition := range conditions {
			suffix := " or"
			if i == len(conditions)-1 {
				suffix = ""
			}
			fmt.Fprintf(&b, "      %s%s\n", condition, suffix)
		}
		fmt.Fprintln(&b, "    )")
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

	addGroup("url", result.IOCs.URLs, "ascii wide", 12)
	addGroup("dom", result.IOCs.Domains, "ascii wide nocase", 12)
	addGroup("reg", result.IOCs.RegistryKeys, "ascii wide nocase", 8)
	addGroup("path", append(append([]string{}, result.IOCs.WindowsPaths...), result.IOCs.UnixPaths...), "ascii wide nocase", 8)
	addGroup("str", result.SuspiciousStrings, "ascii wide nocase", 24)

	if len(result.Profile.MalwareType) > 0 {
		addGroup("type", result.Profile.MalwareType, "ascii wide nocase", 6)
	}
	return entries
}

func yaraConditions(entries []yaraStringEntry) []string {
	counts := map[string]int{}
	for _, entry := range entries {
		counts[entry.Group]++
	}
	var conditions []string
	for _, group := range []string{"url", "dom", "reg", "path", "str", "type"} {
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
	return conditions
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
