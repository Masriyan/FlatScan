package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// STIX 2.1 Bundle types for threat intelligence sharing.
// Spec: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html

type stixBundle struct {
	Type    string        `json:"type"`
	ID      string        `json:"id"`
	Objects []interface{} `json:"objects"`
}

type stixMalwareAnalysis struct {
	Type               string   `json:"type"`
	SpecVersion        string   `json:"spec_version"`
	ID                 string   `json:"id"`
	Created            string   `json:"created"`
	Modified           string   `json:"modified"`
	Product            string   `json:"product"`
	Version            string   `json:"version,omitempty"`
	AnalysisStarted    string   `json:"analysis_started,omitempty"`
	AnalysisEnded      string   `json:"analysis_ended,omitempty"`
	ResultName         string   `json:"result_name,omitempty"`
	Result             string   `json:"result,omitempty"`
	AnalysisSCORefs    []string `json:"analysis_sco_refs,omitempty"`
	SampleRef          string   `json:"sample_ref,omitempty"`
	ConfigurationScore int      `json:"x_risk_score,omitempty"`
}

type stixFile struct {
	Type        string       `json:"type"`
	SpecVersion string       `json:"spec_version"`
	ID          string       `json:"id"`
	Name        string       `json:"name,omitempty"`
	Size        int64        `json:"size,omitempty"`
	Hashes      stixHashes   `json:"hashes,omitempty"`
	MIMEType    string       `json:"mime_type,omitempty"`
	Extensions  stixFileExts `json:"extensions,omitempty"`
}

type stixHashes struct {
	MD5    string `json:"MD5,omitempty"`
	SHA1   string `json:"SHA-1,omitempty"`
	SHA256 string `json:"SHA-256,omitempty"`
	SHA512 string `json:"SHA-512,omitempty"`
}

type stixFileExts struct {
	PEExt *stixPEExt `json:"windows-pebinary-ext,omitempty"`
}

type stixPEExt struct {
	PEType     string `json:"pe_type,omitempty"`
	Machine    string `json:"machine_hex,omitempty"`
	ImportHash string `json:"imphash,omitempty"`
}

type stixIndicator struct {
	Type            string   `json:"type"`
	SpecVersion     string   `json:"spec_version"`
	ID              string   `json:"id"`
	Created         string   `json:"created"`
	Modified        string   `json:"modified"`
	Name            string   `json:"name"`
	Description     string   `json:"description,omitempty"`
	Pattern         string   `json:"pattern"`
	PatternType     string   `json:"pattern_type"`
	ValidFrom       string   `json:"valid_from"`
	KillChainPhases []stixKC `json:"kill_chain_phases,omitempty"`
	Labels          []string `json:"labels,omitempty"`
}

type stixKC struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

type stixRelationship struct {
	Type            string `json:"type"`
	SpecVersion     string `json:"spec_version"`
	ID              string `json:"id"`
	Created         string `json:"created"`
	Modified        string `json:"modified"`
	RelationshipType string `json:"relationship_type"`
	SourceRef       string `json:"source_ref"`
	TargetRef       string `json:"target_ref"`
}

type stixMalware struct {
	Type        string   `json:"type"`
	SpecVersion string   `json:"spec_version"`
	ID          string   `json:"id"`
	Created     string   `json:"created"`
	Modified    string   `json:"modified"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	MalwareTypes []string `json:"malware_types,omitempty"`
	IsFamily    bool     `json:"is_family"`
	Labels      []string `json:"labels,omitempty"`
}

// WriteSTIXBundle exports a ScanResult as a STIX 2.1 JSON bundle.
func WriteSTIXBundle(path string, result ScanResult) error {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	bundle := buildSTIXBundle(result)
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("stix marshal: %w", err)
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func buildSTIXBundle(result ScanResult) stixBundle {
	now := time.Now().UTC().Format(time.RFC3339)
	bundleID := stixID("bundle", result.Hashes.SHA256)

	var objects []interface{}

	// 1. File SCO (observable)
	fileID := stixID("file", result.Hashes.SHA256)
	fileSCO := stixFile{
		Type:        "file",
		SpecVersion: "2.1",
		ID:          fileID,
		Name:        result.FileName,
		Size:        result.Size,
		MIMEType:    result.MIMEHint,
		Hashes: stixHashes{
			MD5:    strings.ToUpper(result.Hashes.MD5),
			SHA1:   strings.ToUpper(result.Hashes.SHA1),
			SHA256: strings.ToUpper(result.Hashes.SHA256),
			SHA512: strings.ToUpper(result.Hashes.SHA512),
		},
	}
	if result.PE != nil {
		fileSCO.Extensions.PEExt = &stixPEExt{
			PEType:     result.PE.Subsystem,
			Machine:    result.PE.Machine,
			ImportHash: result.PE.ImportHash,
		}
	}
	objects = append(objects, fileSCO)

	// 2. Malware Analysis SDO
	analysisID := stixID("malware-analysis", result.Hashes.SHA256+"--flatscan")
	verdictResult := "unknown"
	if result.RiskScore >= 80 {
		verdictResult = "malicious"
	} else if result.RiskScore >= 30 {
		// 30-79: FlatScan calls this "Suspicious" or "High suspicion"
		verdictResult = "suspicious"
	} else if result.RiskScore >= 10 {
		// 10-29: "Low suspicion" — mapped to benign in STIX
		verdictResult = "benign"
	}
	analysis := stixMalwareAnalysis{
		Type:               "malware-analysis",
		SpecVersion:        "2.1",
		ID:                 analysisID,
		Created:            now,
		Modified:           now,
		Product:            "FlatScan",
		Version:            result.Version,
		ResultName:         result.Verdict,
		Result:             verdictResult,
		SampleRef:          fileID,
		ConfigurationScore: result.RiskScore,
	}
	objects = append(objects, analysis)

	// 3. IOC Indicators
	indicatorIDs := []string{}

	for i, url := range result.IOCs.URLs {
		if i >= 50 {
			break
		}
		id := stixID("indicator", result.Hashes.SHA256+"--url--"+url)
		ind := stixIndicator{
			Type:        "indicator",
			SpecVersion: "2.1",
			ID:          id,
			Created:     now,
			Modified:    now,
			Name:        "URL: " + truncStr(url, 120),
			Pattern:     fmt.Sprintf("[url:value = '%s']", escapeSTIXPattern(url)),
			PatternType: "stix",
			ValidFrom:   now,
			Labels:      []string{"malicious-activity"},
		}
		objects = append(objects, ind)
		indicatorIDs = append(indicatorIDs, id)
	}

	for i, domain := range result.IOCs.Domains {
		if i >= 50 {
			break
		}
		id := stixID("indicator", result.Hashes.SHA256+"--domain--"+domain)
		ind := stixIndicator{
			Type:        "indicator",
			SpecVersion: "2.1",
			ID:          id,
			Created:     now,
			Modified:    now,
			Name:        "Domain: " + domain,
			Pattern:     fmt.Sprintf("[domain-name:value = '%s']", escapeSTIXPattern(domain)),
			PatternType: "stix",
			ValidFrom:   now,
			Labels:      []string{"malicious-activity"},
		}
		objects = append(objects, ind)
		indicatorIDs = append(indicatorIDs, id)
	}

	for i, ip := range result.IOCs.IPv4 {
		if i >= 50 {
			break
		}
		id := stixID("indicator", result.Hashes.SHA256+"--ipv4--"+ip)
		ind := stixIndicator{
			Type:        "indicator",
			SpecVersion: "2.1",
			ID:          id,
			Created:     now,
			Modified:    now,
			Name:        "IPv4: " + ip,
			Pattern:     fmt.Sprintf("[ipv4-addr:value = '%s']", ip),
			PatternType: "stix",
			ValidFrom:   now,
			Labels:      []string{"malicious-activity"},
		}
		objects = append(objects, ind)
		indicatorIDs = append(indicatorIDs, id)
	}

	// 4. Malware SDO (if malicious)
	if result.RiskScore >= 55 {
		malwareID := stixID("malware", result.Hashes.SHA256+"--classification")
		malTypes := []string{"unknown"}
		if len(result.Profile.MalwareType) > 0 {
			malTypes = mapSTIXMalwareTypes(result.Profile.MalwareType)
		}
		mal := stixMalware{
			Type:         "malware",
			SpecVersion:  "2.1",
			ID:           malwareID,
			Created:      now,
			Modified:     now,
			Name:         nonEmpty(result.Profile.Classification, result.Verdict),
			Description:  result.Profile.ExecutiveAssessment,
			MalwareTypes: malTypes,
			IsFamily:     false,
		}
		objects = append(objects, mal)

		// Relationship: analysis → malware
		relID := stixID("relationship", result.Hashes.SHA256+"--analysis-to-malware")
		objects = append(objects, stixRelationship{
			Type:             "relationship",
			SpecVersion:      "2.1",
			ID:               relID,
			Created:          now,
			Modified:         now,
			RelationshipType: "characterizes",
			SourceRef:        analysisID,
			TargetRef:        malwareID,
		})

		// Relationships: indicators → malware
		for _, indID := range indicatorIDs {
			relID = stixID("relationship", indID+"--indicates--"+malwareID)
			objects = append(objects, stixRelationship{
				Type:             "relationship",
				SpecVersion:      "2.1",
				ID:               relID,
				Created:          now,
				Modified:         now,
				RelationshipType: "indicates",
				SourceRef:        indID,
				TargetRef:        malwareID,
			})
		}
	}

	return stixBundle{
		Type:    "bundle",
		ID:      bundleID,
		Objects: objects,
	}
}

// stixID creates a deterministic STIX identifier from a type and seed string.
func stixID(objectType, seed string) string {
	h := sha256.Sum256([]byte(seed))
	hex := fmt.Sprintf("%x", h)
	// Format as UUID-like: 8-4-4-4-12
	return fmt.Sprintf("%s--%s-%s-%s-%s-%s", objectType,
		hex[:8], hex[8:12], hex[12:16], hex[16:20], hex[20:32])
}

func escapeSTIXPattern(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "'", "\\'")
	return s
}

func mapSTIXMalwareTypes(types []string) []string {
	mapping := map[string]string{
		"stealer":     "spyware",
		"rat":         "remote-access-trojan",
		"ransomware":  "ransomware",
		"backdoor":    "backdoor",
		"dropper":     "dropper",
		"downloader":  "downloader",
		"worm":        "worm",
		"rootkit":     "rootkit",
		"keylogger":   "keylogger",
		"bot":         "bot",
		"cryptominer": "resource-exploitation",
		"adware":      "adware",
	}
	var out []string
	for _, t := range types {
		lower := strings.ToLower(t)
		for keyword, stixType := range mapping {
			if strings.Contains(lower, keyword) {
				out = appendUnique(out, stixType)
			}
		}
	}
	if len(out) == 0 {
		return []string{"unknown"}
	}
	return out
}
