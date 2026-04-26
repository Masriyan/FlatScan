package main

type Hashes struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
	SHA512 string `json:"sha512"`
}

type Finding struct {
	Severity       string `json:"severity"`
	Category       string `json:"category"`
	Title          string `json:"title"`
	Evidence       string `json:"evidence,omitempty"`
	Score          int    `json:"score"`
	Offset         int64  `json:"offset,omitempty"`
	Tactic         string `json:"tactic,omitempty"`
	Technique      string `json:"technique,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

type IOCSet struct {
	URLs         []string `json:"urls,omitempty"`
	Domains      []string `json:"domains,omitempty"`
	IPv4         []string `json:"ipv4,omitempty"`
	IPv6         []string `json:"ipv6,omitempty"`
	Emails       []string `json:"emails,omitempty"`
	MD5          []string `json:"md5,omitempty"`
	SHA1         []string `json:"sha1,omitempty"`
	SHA256       []string `json:"sha256,omitempty"`
	SHA512       []string `json:"sha512,omitempty"`
	CVEs         []string `json:"cves,omitempty"`
	RegistryKeys []string `json:"registry_keys,omitempty"`
	WindowsPaths []string `json:"windows_paths,omitempty"`
	UnixPaths    []string `json:"unix_paths,omitempty"`
}

type DecodedArtifact struct {
	Encoding string `json:"encoding"`
	Source   string `json:"source"`
	Preview  string `json:"preview"`
	IOCs     IOCSet `json:"iocs,omitempty"`
}

type FunctionHit struct {
	Name     string `json:"name"`
	Family   string `json:"family"`
	Severity string `json:"severity"`
	Source   string `json:"source"`
}

type TTPEntry struct {
	Tactic     string `json:"tactic"`
	Technique  string `json:"technique"`
	ID         string `json:"id,omitempty"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Evidence   string `json:"evidence,omitempty"`
	Finding    string `json:"finding"`
}

type CryptoIndicator struct {
	Primitive  string `json:"primitive"`
	Source     string `json:"source"`
	Purpose    string `json:"purpose,omitempty"`
	Confidence string `json:"confidence"`
	Evidence   string `json:"evidence,omitempty"`
}

type AnalysisProfile struct {
	Classification      string            `json:"classification"`
	MalwareType         []string          `json:"malware_type,omitempty"`
	Confidence          string            `json:"confidence"`
	ConfidenceScore     int               `json:"confidence_score"`
	BusinessImpact      []string          `json:"business_impact,omitempty"`
	KeyCapabilities     []string          `json:"key_capabilities,omitempty"`
	RecommendedActions  []string          `json:"recommended_actions,omitempty"`
	TTPs                []TTPEntry        `json:"ttps,omitempty"`
	CryptoIndicators    []CryptoIndicator `json:"crypto_indicators,omitempty"`
	ExecutiveAssessment string            `json:"executive_assessment,omitempty"`
}

type EntropyRegion struct {
	Offset  int64   `json:"offset"`
	Length  int     `json:"length"`
	Entropy float64 `json:"entropy"`
}

type PEInfo struct {
	Machine            string        `json:"machine,omitempty"`
	Timestamp          string        `json:"timestamp,omitempty"`
	Subsystem          string        `json:"subsystem,omitempty"`
	ImageBase          string        `json:"image_base,omitempty"`
	EntryPoint         string        `json:"entry_point,omitempty"`
	ManagedRuntime     bool          `json:"managed_runtime"`
	Imports            []string      `json:"imports,omitempty"`
	ImportHash         string        `json:"import_hash,omitempty"`
	Sections           []SectionInfo `json:"sections,omitempty"`
	HasCertificate     bool          `json:"has_certificate"`
	OverlayOffset      int64         `json:"overlay_offset,omitempty"`
	OverlaySize        int64         `json:"overlay_size,omitempty"`
	SuspiciousSections []string      `json:"suspicious_sections,omitempty"`
}

type SectionInfo struct {
	Name       string  `json:"name"`
	Virtual    uint32  `json:"virtual_address,omitempty"`
	RawOffset  uint32  `json:"raw_offset,omitempty"`
	RawSize    uint32  `json:"raw_size,omitempty"`
	Entropy    float64 `json:"entropy"`
	Executable bool    `json:"executable"`
	Writable   bool    `json:"writable"`
}

type ELFInfo struct {
	Class    string        `json:"class,omitempty"`
	Machine  string        `json:"machine,omitempty"`
	Type     string        `json:"type,omitempty"`
	Imports  []string      `json:"imports,omitempty"`
	Sections []SectionInfo `json:"sections,omitempty"`
}

type MachOInfo struct {
	CPU      string        `json:"cpu,omitempty"`
	Type     string        `json:"type,omitempty"`
	Imports  []string      `json:"imports,omitempty"`
	Sections []SectionInfo `json:"sections,omitempty"`
}

type ArchiveEntry struct {
	Name             string `json:"name"`
	Size             uint64 `json:"size"`
	CompressedSize   uint64 `json:"compressed_size"`
	SuspiciousReason string `json:"suspicious_reason,omitempty"`
}

type ScanResult struct {
	Tool               string            `json:"tool"`
	Version            string            `json:"version"`
	Mode               string            `json:"mode"`
	Target             string            `json:"target"`
	FileName           string            `json:"file_name"`
	Size               int64             `json:"size"`
	AnalyzedBytes      int64             `json:"analyzed_bytes"`
	TruncatedAnalysis  bool              `json:"truncated_analysis"`
	Duration           string            `json:"duration"`
	FileType           string            `json:"file_type"`
	MIMEHint           string            `json:"mime_hint,omitempty"`
	Hashes             Hashes            `json:"hashes"`
	Entropy            float64           `json:"entropy"`
	EntropyAssessment  string            `json:"entropy_assessment"`
	HighEntropyRegions []EntropyRegion   `json:"high_entropy_regions,omitempty"`
	StringsTotal       int               `json:"strings_total"`
	StringsTruncated   bool              `json:"strings_truncated"`
	SuspiciousStrings  []string          `json:"suspicious_strings,omitempty"`
	Functions          []FunctionHit     `json:"functions,omitempty"`
	DecodedArtifacts   []DecodedArtifact `json:"decoded_artifacts,omitempty"`
	IOCs               IOCSet            `json:"iocs,omitempty"`
	ArchiveEntries     []ArchiveEntry    `json:"archive_entries,omitempty"`
	PE                 *PEInfo           `json:"pe,omitempty"`
	ELF                *ELFInfo          `json:"elf,omitempty"`
	MachO              *MachOInfo        `json:"macho,omitempty"`
	Findings           []Finding         `json:"findings,omitempty"`
	Profile            AnalysisProfile   `json:"profile"`
	RiskScore          int               `json:"risk_score"`
	Verdict            string            `json:"verdict"`
	DebugLog           []string          `json:"debug_log,omitempty"`
}
