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
	Priority          string           `json:"priority,omitempty"`
	PEHashes          []PEHashIOC      `json:"pe_hashes,omitempty"`
	URLs              []string         `json:"urls,omitempty"`
	Domains           []string         `json:"domains,omitempty"`
	IPv4              []string         `json:"ipv4,omitempty"`
	IPv6              []string         `json:"ipv6,omitempty"`
	Emails            []string         `json:"emails,omitempty"`
	MD5               []string         `json:"md5,omitempty"`
	SHA1              []string         `json:"sha1,omitempty"`
	SHA256            []string         `json:"sha256,omitempty"`
	SHA512            []string         `json:"sha512,omitempty"`
	CVEs              []string         `json:"cves,omitempty"`
	RegistryKeys      []string         `json:"registry_keys,omitempty"`
	WindowsPaths      []string         `json:"windows_paths,omitempty"`
	UnixPaths         []string         `json:"unix_paths,omitempty"`
	SuppressedCount   int              `json:"suppressed_count,omitempty"`
	SuppressionReason string           `json:"suppression_reason,omitempty"`
	SuppressionLog    []IOCSuppression `json:"suppression_log,omitempty"`
}

type PEHashIOC struct {
	Path             string  `json:"path"`
	SHA256           string  `json:"sha256"`
	Size             uint64  `json:"size,omitempty"`
	CompressedSize   uint64  `json:"compressed_size,omitempty"`
	CompressionRatio float64 `json:"compression_ratio,omitempty"`
	Entropy          float64 `json:"entropy,omitempty"`
	CarvedOffset     string  `json:"carved_offset,omitempty"`
	Tier             string  `json:"tier"`
	Note             string  `json:"note,omitempty"`
}

type IOCSuppression struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
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
	Name             string  `json:"name"`
	Size             uint64  `json:"size"`
	CompressedSize   uint64  `json:"compressed_size"`
	CompressionRatio float64 `json:"compression_ratio,omitempty"`
	Offset           int64   `json:"offset,omitempty"`
	Type             string  `json:"type,omitempty"`
	SHA256           string  `json:"sha256,omitempty"`
	Entropy          float64 `json:"entropy,omitempty"`
	SuspiciousReason string  `json:"suspicious_reason,omitempty"`
}

type MSIXInfo struct {
	IdentityName          string   `json:"identity_name,omitempty"`
	IdentityPublisher     string   `json:"identity_publisher,omitempty"`
	IdentityVersion       string   `json:"identity_version,omitempty"`
	DeclaredExecutables   []string `json:"declared_executables,omitempty"`
	Capabilities          []string `json:"capabilities,omitempty"`
	UndeclaredExecutables []string `json:"undeclared_executables,omitempty"`
	PublisherTrusted      bool     `json:"publisher_trusted"`
	Finding               string   `json:"finding,omitempty"`
	SignatureSHA256       string   `json:"signature_sha256,omitempty"`
	SignatureSize         uint64   `json:"signature_size,omitempty"`
	SignatureParseStatus  string   `json:"signature_parse_status,omitempty"`
	CertificateSubjects   []string `json:"certificate_subjects,omitempty"`
	CertificateIssuers    []string `json:"certificate_issuers,omitempty"`
	CertificateSerials    []string `json:"certificate_serials,omitempty"`
}

type AndroidPermission struct {
	Name       string `json:"name"`
	Risk       string `json:"risk,omitempty"`
	Category   string `json:"category,omitempty"`
	Protection string `json:"protection,omitempty"`
}

type AndroidComponent struct {
	Type             string   `json:"type"`
	Name             string   `json:"name"`
	Exported         bool     `json:"exported"`
	ExportedDeclared bool     `json:"exported_declared"`
	Permission       string   `json:"permission,omitempty"`
	IntentActions    []string `json:"intent_actions,omitempty"`
	IntentCategories []string `json:"intent_categories,omitempty"`
}

type AndroidAPIHit struct {
	Category  string `json:"category"`
	Indicator string `json:"indicator"`
	Severity  string `json:"severity"`
	Source    string `json:"source"`
}

type DEXInfo struct {
	Name              string          `json:"name"`
	Version           string          `json:"version,omitempty"`
	StringsTotal      int             `json:"strings_total"`
	StringsParsed     int             `json:"strings_parsed"`
	StringsTruncated  bool            `json:"strings_truncated"`
	SuspiciousStrings []string        `json:"suspicious_strings,omitempty"`
	APIHits           []AndroidAPIHit `json:"api_hits,omitempty"`
	IOCs              IOCSet          `json:"iocs,omitempty"`
}

type APKInfo struct {
	PackageName           string              `json:"package_name,omitempty"`
	VersionCode           string              `json:"version_code,omitempty"`
	VersionName           string              `json:"version_name,omitempty"`
	MinSDK                string              `json:"min_sdk,omitempty"`
	TargetSDK             string              `json:"target_sdk,omitempty"`
	ManifestFormat        string              `json:"manifest_format,omitempty"`
	FileCount             int                 `json:"file_count"`
	Permissions           []AndroidPermission `json:"permissions,omitempty"`
	Components            []AndroidComponent  `json:"components,omitempty"`
	ExportedComponents    []AndroidComponent  `json:"exported_components,omitempty"`
	NativeLibraries       []string            `json:"native_libraries,omitempty"`
	EmbeddedPayloads      []string            `json:"embedded_payloads,omitempty"`
	NetworkSecurityConfig []string            `json:"network_security_config,omitempty"`
	AssetFiles            []string            `json:"asset_files,omitempty"`
	SignatureFiles        []string            `json:"signature_files,omitempty"`
}

type PluginResult struct {
	Name     string   `json:"name"`
	Version  string   `json:"version,omitempty"`
	Status   string   `json:"status"`
	Summary  string   `json:"summary,omitempty"`
	Findings int      `json:"findings,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

type RulePackSummary struct {
	Path        string   `json:"path"`
	Name        string   `json:"name,omitempty"`
	RulesLoaded int      `json:"rules_loaded"`
	RulesFired  int      `json:"rules_fired"`
	Warnings    []string `json:"warnings,omitempty"`
}

type RuleMatch struct {
	RuleID     string   `json:"rule_id"`
	Name       string   `json:"name"`
	Severity   string   `json:"severity"`
	Category   string   `json:"category"`
	Evidence   []string `json:"evidence,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
}

type CarvedArtifact struct {
	Type      string  `json:"type"`
	Offset    int64   `json:"offset"`
	Length    int     `json:"length"`
	SHA256    string  `json:"sha256"`
	Entropy   float64 `json:"entropy"`
	Reason    string  `json:"reason,omitempty"`
	Preview   string  `json:"preview,omitempty"`
	Contained bool    `json:"contained,omitempty"`
}

type FamilyMatch struct {
	Family     string   `json:"family"`
	Category   string   `json:"category"`
	Confidence string   `json:"confidence"`
	Score      int      `json:"score"`
	Evidence   []string `json:"evidence,omitempty"`
}

type ConfigArtifact struct {
	Type       string `json:"type"`
	Source     string `json:"source"`
	Confidence string `json:"confidence"`
	Evidence   string `json:"evidence,omitempty"`
	Preview    string `json:"preview,omitempty"`
	IOCs       IOCSet `json:"iocs,omitempty"`
}

type CryptoConfigSummary struct {
	Encodings          []string `json:"encodings,omitempty"`
	CryptoMarkers      []string `json:"crypto_markers,omitempty"`
	CandidateXORKeys   []string `json:"candidate_xor_keys,omitempty"`
	EmbeddedCompressed []string `json:"embedded_compressed,omitempty"`
	ConfigArtifacts    int      `json:"config_artifacts"`
}

type SimilarityInfo struct {
	FlatHash           string `json:"flat_hash,omitempty"`
	ByteHistogramHash  string `json:"byte_histogram_hash,omitempty"`
	StringSetHash      string `json:"string_set_hash,omitempty"`
	ImportHash         string `json:"import_hash,omitempty"`
	SectionHash        string `json:"section_hash,omitempty"`
	DEXStringHash      string `json:"dex_string_hash,omitempty"`
	ArchiveContentHash string `json:"archive_content_hash,omitempty"`
}

type ExternalToolResult struct {
	Name      string `json:"name"`
	Found     bool   `json:"found"`
	Path      string `json:"path,omitempty"`
	Status    string `json:"status"`
	Command   string `json:"command,omitempty"`
	Output    string `json:"output,omitempty"`
	Error     string `json:"error,omitempty"`
	TimedOut  bool   `json:"timed_out,omitempty"`
	Available bool   `json:"available"`
}

type CaseRecord struct {
	CaseID        string   `json:"case_id"`
	DatabasePath  string   `json:"database_path,omitempty"`
	Stored        bool     `json:"stored"`
	StoredAt      string   `json:"stored_at,omitempty"`
	RelatedHashes []string `json:"related_hashes,omitempty"`
	Error         string   `json:"error,omitempty"`
}

type ScanResult struct {
	Tool               string               `json:"tool"`
	Version            string               `json:"version"`
	Mode               string               `json:"mode"`
	Target             string               `json:"target"`
	FileName           string               `json:"file_name"`
	Size               int64                `json:"size"`
	AnalyzedBytes      int64                `json:"analyzed_bytes"`
	TruncatedAnalysis  bool                 `json:"truncated_analysis"`
	Duration           string               `json:"duration"`
	FileType           string               `json:"file_type"`
	MIMEHint           string               `json:"mime_hint,omitempty"`
	Hashes             Hashes               `json:"hashes"`
	Entropy            float64              `json:"entropy"`
	EntropyAssessment  string               `json:"entropy_assessment"`
	HighEntropyRegions []EntropyRegion      `json:"high_entropy_regions,omitempty"`
	StringsTotal       int                  `json:"strings_total"`
	StringsTruncated   bool                 `json:"strings_truncated"`
	SuspiciousStrings  []string             `json:"suspicious_strings,omitempty"`
	Functions          []FunctionHit        `json:"functions,omitempty"`
	DecodedArtifacts   []DecodedArtifact    `json:"decoded_artifacts,omitempty"`
	IOCs               IOCSet               `json:"iocs,omitempty"`
	ArchiveEntries     []ArchiveEntry       `json:"archive_entries,omitempty"`
	MSIX               *MSIXInfo            `json:"msix_metadata,omitempty"`
	APK                *APKInfo             `json:"apk,omitempty"`
	DEXFiles           []DEXInfo            `json:"dex_files,omitempty"`
	Plugins            []PluginResult       `json:"plugins,omitempty"`
	RulePacks          []RulePackSummary    `json:"rule_packs,omitempty"`
	RuleMatches        []RuleMatch          `json:"rule_matches,omitempty"`
	CarvedArtifacts    []CarvedArtifact     `json:"carved_artifacts,omitempty"`
	FamilyMatches      []FamilyMatch        `json:"family_matches,omitempty"`
	ConfigArtifacts    []ConfigArtifact     `json:"config_artifacts,omitempty"`
	CryptoConfig       CryptoConfigSummary  `json:"crypto_config,omitempty"`
	Similarity         SimilarityInfo       `json:"similarity,omitempty"`
	ExternalTools      []ExternalToolResult `json:"external_tools,omitempty"`
	Case               *CaseRecord          `json:"case,omitempty"`
	PE                 *PEInfo              `json:"pe,omitempty"`
	ELF                *ELFInfo             `json:"elf,omitempty"`
	MachO              *MachOInfo           `json:"macho,omitempty"`
	Findings           []Finding            `json:"findings,omitempty"`
	Profile            AnalysisProfile      `json:"profile"`
	RiskScore          int                  `json:"risk_score"`
	Verdict            string               `json:"verdict"`
	DebugLog           []string             `json:"debug_log,omitempty"`
}
