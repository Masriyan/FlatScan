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
	// Confidence (0–100) and EvidenceCount express how well-corroborated a
	// finding is. A finding backed by a single generic string carries low
	// confidence; one backed by a multi-signal evidence cluster (v3 Task 2)
	// carries high confidence. Defaults derive from severity; correlated
	// findings set them explicitly. See correlation.go.
	Confidence    int `json:"confidence,omitempty"`
	EvidenceCount int `json:"evidence_count,omitempty"`
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
	Mutexes           []string         `json:"mutexes,omitempty"`
	NamedPipes        []string         `json:"named_pipes,omitempty"`
	CryptoWallets     []string         `json:"crypto_wallets,omitempty"`
	SuppressedCount   int              `json:"suppressed_count,omitempty"`
	SuppressionReason string           `json:"suppression_reason,omitempty"`
	SuppressionLog    []IOCSuppression `json:"suppression_log,omitempty"`
	// Classified is an additive, per-value categorization of the extracted
	// indicators (actionable IOC vs. build artifact / source path / namespace /
	// benign infrastructure), with a confidence weight and context note. The
	// flat slices above are retained unchanged for backward compatibility;
	// Classified drives export hygiene and analyst context. See ioc_classify.go.
	Classified []ClassifiedIOC `json:"classified,omitempty"`
}

// ClassifiedIOC tags one extracted indicator with a category, a 0–100 confidence
// weight, and a short human context. Categories: ioc, suspicious-infra,
// benign-infra, build-artifact, compiler-runtime-metadata, source-path,
// package-namespace.
type ClassifiedIOC struct {
	Type       string `json:"type"`
	Value      string `json:"value"`
	Category   string `json:"category"`
	Confidence int    `json:"confidence"`
	Context    string `json:"context,omitempty"`
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
	ExpectedBehavior    []string          `json:"expected_behavior,omitempty"`
	ExecutiveAssessment string            `json:"executive_assessment,omitempty"`
}

// MalwareConfig holds structured configuration fields recovered from a sample
// (v3 Task 6) — the high-value primitives an analyst pivots on. Populated by the
// config-extractor framework (config_family.go), keyed to the detected family
// where one is identified.
type MalwareConfig struct {
	Family     string   `json:"family,omitempty"`
	C2         []string `json:"c2,omitempty"`
	Mutexes    []string `json:"mutexes,omitempty"`
	BotTokens  []string `json:"bot_tokens,omitempty"`
	Webhooks   []string `json:"webhooks,omitempty"`
	Wallets    []string `json:"wallets,omitempty"`
	CampaignID []string `json:"campaign_id,omitempty"`
	BuildID    []string `json:"build_id,omitempty"`
	Version    []string `json:"version,omitempty"`
}

// EnrichmentMatch records a hit of one of the sample's indicators against the
// optional offline threat-intel database (v3 Task 6, --intel-db).
type EnrichmentMatch struct {
	Indicator string   `json:"indicator"`
	Type      string   `json:"type"`
	Family    string   `json:"family,omitempty"`
	Campaign  string   `json:"campaign,omitempty"`
	FirstSeen string   `json:"first_seen,omitempty"`
	Related   []string `json:"related,omitempty"`
	Note      string   `json:"note,omitempty"`
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
	// PE Header Intelligence (security posture, toolchain, signer).
	DllCharacteristics   uint16   `json:"dll_characteristics,omitempty"`
	SecurityFeatures     []string `json:"security_features,omitempty"`
	MissingMitigations   []string `json:"missing_mitigations,omitempty"`
	ImageCharacteristics []string `json:"image_characteristics,omitempty"`
	HasTLSCallbacks      bool     `json:"has_tls_callbacks,omitempty"`
	TLSCallbackCount     int      `json:"tls_callback_count,omitempty"`
	RichHeaderHash       string   `json:"rich_header_hash,omitempty"`
	Signed               bool     `json:"signed,omitempty"`
	SignatureStatus      string   `json:"signature_status,omitempty"`
	SelfSigned           bool     `json:"self_signed,omitempty"`
	CertificateSubjects  []string `json:"certificate_subjects,omitempty"`
	CertificateIssuers   []string `json:"certificate_issuers,omitempty"`
	EntryPointSection    string   `json:"entry_point_section,omitempty"`
	EntryPointAnomaly    string   `json:"entry_point_anomaly,omitempty"`
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

// CodeInfo records the result of the instruction-level disassembly pass
// (disasm.go) — the analysis layer beneath the string corpus that sees
// techniques (API hashing, PEB walks, shellcode stubs, anti-VM) which leave no
// cleartext string behind.
type CodeInfo struct {
	Arch                string   `json:"arch,omitempty"`
	EntryOffset         int64    `json:"entry_offset,omitempty"`
	InstructionsDecoded int      `json:"instructions_decoded,omitempty"`
	DecodeErrors        int      `json:"decode_errors,omitempty"`
	IndirectCalls       int      `json:"indirect_calls,omitempty"`
	IndirectJumps       int      `json:"indirect_jumps,omitempty"`
	Techniques          []string `json:"techniques,omitempty"`
	EntryDisasm         []string `json:"entry_disasm,omitempty"`
	ResolvedHashedAPIs  []string `json:"resolved_hashed_apis,omitempty"`
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

// PayloadNode is one node in the recursive static payload-resolution tree
// (roadmap Flagship Epic, Tier 1). FlatScan peels every encoding/compression/
// single-byte-XOR/carve layer off the sample and re-scans whatever structured
// payload emerges, surfacing buried stages a flat string/IOC pass cannot see.
// The tree is built by pure data transformation — the sample is never executed
// (no detonation). Each node records its provenance (Method/Detail) plus a
// bounded re-scan (FileType/Score/Verdict/Family/top IOCs+findings) of the
// recovered bytes. See payload_resolve.go.
type PayloadNode struct {
	ID       int      `json:"id"`
	ParentID int      `json:"parent_id"`
	Depth    int      `json:"depth"`
	Method   string   `json:"method"`           // carve | base64 | hex | gzip | zlib | xor:0xNN
	Detail   string   `json:"detail,omitempty"` // source string / offset / key
	FileType string   `json:"file_type"`
	Size     int      `json:"size"`
	SHA256   string   `json:"sha256"`
	Entropy  float64  `json:"entropy"`
	Score    int      `json:"score,omitempty"`
	Verdict  string   `json:"verdict,omitempty"`
	Family   string   `json:"family,omitempty"`
	IOCs     []string `json:"iocs,omitempty"`     // top actionable indicators from the stage
	Findings []string `json:"findings,omitempty"` // top finding titles from the stage
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
	FlatHash           string            `json:"flat_hash,omitempty"`
	ByteHistogramHash  string            `json:"byte_histogram_hash,omitempty"`
	StringSetHash      string            `json:"string_set_hash,omitempty"`
	ImportHash         string            `json:"import_hash,omitempty"`
	SectionHash        string            `json:"section_hash,omitempty"`
	DEXStringHash      string            `json:"dex_string_hash,omitempty"`
	ArchiveContentHash string            `json:"archive_content_hash,omitempty"`
	RichHeaderHash     string            `json:"rich_header_hash,omitempty"`
	Matches            []SimilarityMatch `json:"matches,omitempty"`
}

// SimilarityMatch is a ranked match of the current sample against a record in
// the reference similarity store (v3 Task 4): a percent similarity and the
// hash dimensions that contributed.
type SimilarityMatch struct {
	Label             string   `json:"label"`
	Similarity        int      `json:"similarity"`
	MatchedDimensions []string `json:"matched_dimensions,omitempty"`
	SHA256            string   `json:"sha256,omitempty"`
}

// DGADomain records a domain that lexical analysis flags as likely
// algorithmically generated (DGA-based C2). Score is in [0,1].
type DGADomain struct {
	Domain  string   `json:"domain"`
	Score   float64  `json:"score"`
	Reasons []string `json:"reasons,omitempty"`
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
	PayloadTree        []PayloadNode        `json:"payload_tree,omitempty"`
	FamilyMatches      []FamilyMatch        `json:"family_matches,omitempty"`
	ConfigArtifacts    []ConfigArtifact     `json:"config_artifacts,omitempty"`
	CryptoConfig       CryptoConfigSummary  `json:"crypto_config,omitempty"`
	Similarity         SimilarityInfo       `json:"similarity,omitempty"`
	DGADomains         []DGADomain          `json:"dga_domains,omitempty"`
	ExternalTools      []ExternalToolResult `json:"external_tools,omitempty"`
	Case               *CaseRecord          `json:"case,omitempty"`
	PE                 *PEInfo              `json:"pe,omitempty"`
	ELF                *ELFInfo             `json:"elf,omitempty"`
	MachO              *MachOInfo           `json:"macho,omitempty"`
	Code               *CodeInfo            `json:"code,omitempty"`
	MalwareConfig      *MalwareConfig       `json:"malware_config,omitempty"`
	Enrichment         []EnrichmentMatch    `json:"enrichment,omitempty"`
	Findings           []Finding            `json:"findings,omitempty"`
	Profile            AnalysisProfile      `json:"profile"`
	RiskScore          int                  `json:"risk_score"`
	ScoreBreakdown     map[string]int       `json:"score_breakdown,omitempty"`
	Verdict            string               `json:"verdict"`
	BenignContext      *BenignContext       `json:"benign_context,omitempty"`
	DebugLog           []string             `json:"debug_log,omitempty"`
}

// BenignContext records evidence that a file is a detection/analysis artifact
// (an AV signature set, a YARA/Sigma rule pack, a sandbox, a malware-analysis
// tool, or a threat report) rather than a live malware specimen. When set, the
// indicator matches are treated as references, not behavior, and the risk score
// is capped so the verdict does not read as "Likely malicious".
type BenignContext struct {
	Reason        string   `json:"reason"`
	Archetypes    []string `json:"archetypes,omitempty"`
	ToolMarkers   []string `json:"tool_markers,omitempty"`
	MITRETechRefs int      `json:"mitre_technique_refs,omitempty"`
	ScoreCap      int      `json:"score_cap"`
	OriginalScore int      `json:"original_score"`
}
