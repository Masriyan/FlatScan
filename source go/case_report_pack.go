package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func WriteReportPack(dir string, result ScanResult, cfg Config) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	base := reportBaseName(result)
	outputs := []struct {
		name string
		fn   func(string) error
	}{
		{base + ".full.txt", func(path string) error { return os.WriteFile(path, []byte(RenderReport(result, "full")), 0o644) }},
		{base + ".summary.txt", func(path string) error { return os.WriteFile(path, []byte(RenderReport(result, "summary")), 0o644) }},
		{base + ".report.json", func(path string) error {
			data, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return err
			}
			return os.WriteFile(path, append(data, '\n'), 0o644)
		}},
		{base + ".ciso.pdf", func(path string) error { return WritePDFReport(path, result) }},
		{base + ".analyst.html", func(path string) error { return WriteHTMLReport(path, result) }},
		{base + ".iocs.txt", func(path string) error { return WriteIOCFile(path, result) }},
		{base + ".yar", func(path string) error { return WriteYARARule(path, result) }},
		{base + ".sigma.yml", func(path string) error { return WriteSigmaRule(path, result) }},
		{base + ".stix.json", func(path string) error { return WriteSTIXBundle(path, result) }},
		{base + ".executive.md", func(path string) error { return os.WriteFile(path, []byte(RenderExecutiveMarkdown(result)), 0o644) }},
	}
	for _, output := range outputs {
		if err := output.fn(filepath.Join(dir, output.name)); err != nil {
			return fmt.Errorf("%s: %w", output.name, err)
		}
	}
	return nil
}

func RenderExecutiveMarkdown(result ScanResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# FlatScan Executive Summary\n\n")
	fmt.Fprintf(&b, "- Sample: `%s`\n", result.FileName)
	fmt.Fprintf(&b, "- Verdict: **%s** (%d/100)\n", result.Verdict, result.RiskScore)
	fmt.Fprintf(&b, "- Classification: %s\n", reportClassification(result))
	fmt.Fprintf(&b, "- SHA256: `%s`\n", result.Hashes.SHA256)
	fmt.Fprintf(&b, "- Findings: %d\n", len(result.Findings))
	fmt.Fprintf(&b, "- IOCs: %d\n", IOCCount(result.IOCs))
	if result.Profile.ExecutiveAssessment != "" {
		fmt.Fprintf(&b, "\n## Assessment\n\n%s\n", result.Profile.ExecutiveAssessment)
	}
	if len(result.FamilyMatches) > 0 {
		fmt.Fprintf(&b, "\n## Family Hypotheses\n\n")
		for _, family := range result.FamilyMatches {
			fmt.Fprintf(&b, "- %s (%s): %s\n", family.Family, family.Confidence, strings.Join(family.Evidence, ", "))
		}
	}
	if len(result.Profile.RecommendedActions) > 0 {
		fmt.Fprintf(&b, "\n## Recommended Actions\n\n")
		for _, action := range result.Profile.RecommendedActions {
			fmt.Fprintf(&b, "- %s\n", action)
		}
	}
	return b.String()
}

func StoreCaseRecord(cfg Config, result *ScanResult) error {
	if result == nil {
		return nil
	}
	caseID := cfg.CaseID
	if caseID == "" {
		caseID = "default"
	}
	dbPath := cfg.CaseDBPath
	if dbPath == "" {
		dbPath = filepath.Join("reports", "flatscan_cases.jsonl")
	}
	if dir := filepath.Dir(dbPath); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			result.Case = &CaseRecord{CaseID: caseID, DatabasePath: dbPath, Stored: false, Error: err.Error()}
			return err
		}
	}
	related := findRelatedCaseHashes(dbPath, result.Hashes.SHA256)
	record := map[string]any{
		"case_id":      caseID,
		"stored_at":    time.Now().UTC().Format(time.RFC3339),
		"target":       result.Target,
		"file_name":    result.FileName,
		"sha256":       result.Hashes.SHA256,
		"md5":          result.Hashes.MD5,
		"verdict":      result.Verdict,
		"risk_score":   result.RiskScore,
		"file_type":    result.FileType,
		"ioc_count":    IOCCount(result.IOCs),
		"families":     result.FamilyMatches,
		"flat_hash":    result.Similarity.FlatHash,
		"related_hash": related,
	}
	data, err := json.Marshal(record)
	if err != nil {
		result.Case = &CaseRecord{CaseID: caseID, DatabasePath: dbPath, Stored: false, Error: err.Error()}
		return err
	}
	handle, err := os.OpenFile(dbPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		result.Case = &CaseRecord{CaseID: caseID, DatabasePath: dbPath, Stored: false, Error: err.Error()}
		return err
	}
	defer handle.Close()
	if _, err := handle.Write(append(data, '\n')); err != nil {
		result.Case = &CaseRecord{CaseID: caseID, DatabasePath: dbPath, Stored: false, Error: err.Error()}
		return err
	}
	result.Case = &CaseRecord{
		CaseID:        caseID,
		DatabasePath:  dbPath,
		Stored:        true,
		StoredAt:      time.Now().UTC().Format(time.RFC3339),
		RelatedHashes: related,
	}
	return nil
}

func findRelatedCaseHashes(path, sha256Value string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var record map[string]any
		if json.Unmarshal([]byte(line), &record) != nil {
			continue
		}
		sha, _ := record["sha256"].(string)
		if sha == "" || sha == sha256Value {
			continue
		}
		out = appendUnique(out, sha)
		if len(out) >= 20 {
			break
		}
	}
	return out
}

func reportBaseName(result ScanResult) string {
	base := strings.TrimSuffix(result.FileName, filepath.Ext(result.FileName))
	if base == "" {
		base = "sample"
	}
	var out strings.Builder
	for _, r := range strings.ToLower(base) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out.WriteRune(r)
		default:
			out.WriteByte('_')
		}
	}
	clean := strings.Trim(out.String(), "_")
	if clean == "" {
		clean = "sample"
	}
	if len(result.Hashes.SHA256) >= 8 {
		clean += "_" + result.Hashes.SHA256[:8]
	}
	return clean
}
