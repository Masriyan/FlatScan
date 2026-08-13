package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Offline threat-intel enrichment (improvementprompt-v3 Task 6).
//
// An optional local JSONL database (--intel-db) maps known indicators
// (hash / imphash / flat-hash / url / domain / ipv4) to family, campaign,
// first-seen, related samples, and a note. On scan, the sample's own hashes and
// extracted IOCs are looked up and any hits attached. Fully offline, no network
// — mirrors the case DB and similarity store.

// IntelRecord is one line of the intel database.
type IntelRecord struct {
	Indicator string   `json:"indicator"`
	Type      string   `json:"type"` // sha256 | imphash | flat_hash | url | domain | ipv4
	Family    string   `json:"family,omitempty"`
	Campaign  string   `json:"campaign,omitempty"`
	FirstSeen string   `json:"first_seen,omitempty"`
	Related   []string `json:"related,omitempty"`
	Note      string   `json:"note,omitempty"`
}

// EnrichFromIntel looks up the sample's indicators in the intel records and
// records any matches (plus a finding for a family/campaign attribution).
func EnrichFromIntel(result *ScanResult, records []IntelRecord, debugf debugLogger) {
	if result == nil || len(records) == 0 {
		return
	}
	// Index the sample's own indicators for O(1) lookup.
	own := map[string]string{} // value(lower) -> type
	addOwn := func(t string, vals ...string) {
		for _, v := range vals {
			if v != "" {
				own[strings.ToLower(v)] = t
			}
		}
	}
	addOwn("sha256", result.Hashes.SHA256)
	addOwn("imphash", importHashOf(result))
	addOwn("flat_hash", result.Similarity.FlatHash)
	addOwn("url", result.IOCs.URLs...)
	addOwn("domain", result.IOCs.Domains...)
	addOwn("ipv4", result.IOCs.IPv4...)

	var matches []EnrichmentMatch
	for _, rec := range records {
		if rec.Indicator == "" {
			continue
		}
		if t, ok := own[strings.ToLower(rec.Indicator)]; ok && (rec.Type == "" || strings.EqualFold(rec.Type, t)) {
			matches = append(matches, EnrichmentMatch{
				Indicator: rec.Indicator,
				Type:      t,
				Family:    rec.Family,
				Campaign:  rec.Campaign,
				FirstSeen: rec.FirstSeen,
				Related:   rec.Related,
				Note:      rec.Note,
			})
		}
	}
	if len(matches) == 0 {
		return
	}
	result.Enrichment = matches

	top := matches[0]
	desc := "indicator matched local threat-intel"
	if top.Family != "" {
		desc = "matches known " + top.Family
		if top.Campaign != "" {
			desc += " / " + top.Campaign
		}
	}
	AddCorrelatedFinding(result, "High", "Threat Intel",
		"Known threat-intel match",
		fmt.Sprintf("%s (indicator %q, first seen %s)", desc, top.Indicator, orNA(top.FirstSeen)),
		24, 0, "", "",
		"Treat as a confirmed known threat; pull related samples and infrastructure from your intel platform.",
		len(matches), 95)
	debugf("intel: %d enrichment match(es), top=%s", len(matches), top.Family)
}

func orNA(s string) string {
	if s == "" {
		return "n/a"
	}
	return s
}

// importHashOf returns the PE import hash if available (the imphash dimension).
func importHashOf(result *ScanResult) string {
	if result != nil && result.PE != nil {
		return result.PE.ImportHash
	}
	return ""
}

// LoadIntelDB reads a JSONL intel database. Missing path/file is not an error.
func LoadIntelDB(path string) ([]IntelRecord, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only handle: Close discards nothing

	var records []IntelRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var rec IntelRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.Indicator != "" {
			records = append(records, rec)
		}
	}
	return records, scanner.Err()
}
