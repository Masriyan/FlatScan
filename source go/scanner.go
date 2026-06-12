package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Analysis pipeline constants — avoid magic numbers throughout the codebase.
const (
	defaultMaxCorpusBytes     = 48 * 1024 * 1024 // max corpus size for pattern matching
	defaultReadBufSize        = 1024 * 1024      // 1 MiB read buffer for file hashing
	defaultMIMESniffBytes     = 512              // bytes fed to http.DetectContentType
	defaultEntropyWindow      = 64 * 1024        // sliding window for high-entropy region scan
	defaultEntropyStep        = 32 * 1024        // step size for entropy window
	defaultEntropyThreshold   = 7.20             // minimum entropy to flag a region
	defaultMaxEntropyRegions  = 25               // cap on reported high-entropy regions
	defaultMaxArchiveReadSize = 2 * 1024 * 1024  // max bytes read from a single archive entry
	defaultMaxCarveChunkSize  = 2 * 1024 * 1024  // max bytes carved per embedded artifact
	defaultXORScanLimit       = 256 * 1024       // max bytes scanned for single-byte XOR
	defaultXORMaxResults      = 8                // max XOR candidates reported
	defaultXORPrintableRatio  = 0.70             // min printable ratio for XOR candidate
)

type debugLogger func(format string, args ...any)

// findingsMu guards concurrent writes to ScanResult.Findings during
// parallelRun. A package-level mutex avoids embedding sync.Mutex in
// ScanResult (which would cause copy-lock issues across the codebase).
var findingsMu sync.Mutex

// pluginsMu guards concurrent appends to ScanResult.Plugins, mirroring
// findingsMu. Several analysis stages record a PluginResult, and some of
// them (carving, similarity hashing) run inside parallelRun, so every
// append goes through appendPlugin rather than touching the slice directly.
var pluginsMu sync.Mutex

func appendPlugin(result *ScanResult, plugin PluginResult) {
	if result == nil {
		return
	}
	pluginsMu.Lock()
	result.Plugins = append(result.Plugins, plugin)
	pluginsMu.Unlock()
}

func ScanFile(cfg Config, progress *Progress) (ScanResult, error) {
	progress.Set(1, "initializing scanner")

	stat, err := os.Stat(cfg.FilePath)
	if err != nil {
		return ScanResult{}, err
	}
	if stat.IsDir() {
		return ScanResult{}, fmt.Errorf("%s is a directory, expected a file", cfg.FilePath)
	}

	result := ScanResult{
		Tool:     "FlatScan",
		Version:  version,
		Mode:     cfg.Mode,
		Target:   cfg.FilePath,
		FileName: filepath.Base(cfg.FilePath),
		Size:     stat.Size(),
	}

	// Structured logger replaces the bare closure. All log entries are
	// captured and promoted to result.DebugLog at the end of the pipeline.
	// In debug mode, entries are also written to stderr in real-time.
	logger := NewScanLogger(cfg.Debug)
	debugf := logger.AsDebugLogger()
	debugf("scan started at %s", time.Now().UTC().Format(time.RFC3339))

	progress.Set(3, "reading and hashing file")

	// For large files, try memory-mapped I/O for zero-copy access.
	// Falls back to buffered read on failure or unsupported platforms.
	var data []byte
	var hashes Hashes
	var truncated bool

	if stat.Size() >= mmapThreshold {
		data, hashes, truncated, err = readSampleMmap(cfg.FilePath, stat.Size(), cfg.MaxAnalyzeBytes, progress)
		if err != nil {
			debugf("mmap failed, falling back to buffered read: %v", err)
			data, hashes, truncated, err = readSampleAndHashes(cfg.FilePath, stat.Size(), cfg.MaxAnalyzeBytes, progress)
		} else {
			debugf("using mmap for %s (%s)", cfg.FilePath, formatBytes(stat.Size()))
		}
	} else {
		data, hashes, truncated, err = readSampleAndHashes(cfg.FilePath, stat.Size(), cfg.MaxAnalyzeBytes, progress)
	}
	if err != nil {
		return ScanResult{}, err
	}
	result.Hashes = hashes
	result.AnalyzedBytes = int64(len(data))
	result.TruncatedAnalysis = truncated
	debugf("retained %d bytes for analysis; truncated=%v", len(data), truncated)

	progress.Set(18, "identifying file type")
	result.MIMEHint = http.DetectContentType(firstN(data, 512))
	result.FileType = DetectFileType(data, cfg.FilePath)
	debugf("detected file type: %s; mime hint: %s", result.FileType, result.MIMEHint)

	progress.Set(26, "calculating entropy")
	result.Entropy = ShannonEntropy(data)
	result.EntropyAssessment = EntropyAssessment(result.Entropy)
	if cfg.Mode != "quick" {
		result.HighEntropyRegions = HighEntropyRegions(data, defaultEntropyWindow, defaultEntropyStep, defaultEntropyThreshold, defaultMaxEntropyRegions)
	}

	progress.Set(38, "extracting strings")
	strLimit := stringLimitForMode(cfg.Mode)
	extracted, totalStrings, stringsTruncated := ExtractStrings(data, cfg.MinStringLen, strLimit)
	result.StringsTotal = totalStrings
	result.StringsTruncated = stringsTruncated
	debugf("extracted %d strings; total candidates=%d; truncated=%v", len(extracted), totalStrings, stringsTruncated)

	progress.Set(50, "extracting IOCs")
	result.IOCs = ExtractIOCsFromStrings(extracted)

	progress.Set(61, "decoding suspicious strings")
	result.DecodedArtifacts = DecodeSuspiciousStrings(extracted, cfg)
	for _, artifact := range result.DecodedArtifacts {
		MergeIOCSet(&result.IOCs, artifact.IOCs)
	}
	debugf("decoded artifacts: %d", len(result.DecodedArtifacts))
	ApplyIOCTriage(&result, cfg, debugf)

	// Build corpus once and share it across all pattern-matching stages.
	// Previously this was rebuilt independently by AnalyzePatterns,
	// ExtractCryptoAndConfig, ClassifyMalwareFamilies, EnrichAnalysisProfile,
	// and ApplyRulePacks — 5 redundant 32-48 MB string builds per scan.
	corpus := buildCorpus(extracted, result.DecodedArtifacts, defaultMaxCorpusBytes)
	debugf("corpus built once: %d bytes", len(corpus))

	progress.Set(71, "matching malicious indicators")
	AnalyzePatternsWithCorpus(&result, extracted, cfg, corpus)

	progress.Set(82, "inspecting file structure")

	// Format analysis must finish before the stages that follow: similarity
	// hashing reads the PE/ELF/Mach-O/DEX/archive structures it produces,
	// and crypto/config extraction reads the IOCs it merges from archive
	// entries. The previous design ran all four stages concurrently, which
	// both raced on those shared fields and yielded nondeterministic results
	// when format analysis had not yet populated them.
	if err := AnalyzeFormats(&result, cfg, data, debugf); err != nil {
		AddFinding(&result, "Low", "Format", "Format-specific parser error", err.Error(), 2, 0)
		debugf("format parser error: %v", err)
	}

	// Instruction-level disassembly pass — the code-level analysis layer beneath
	// the string corpus (API hashing, PEB walks, shellcode stubs, anti-VM, and
	// hash-database import resolution). Runs after format analysis so the entry
	// point/sections are known; self-gated to standard/deep modes.
	AnalyzeCode(&result, cfg, data)

	// Carving and similarity hashing are independent of each other: each
	// only reads the now-complete format output plus the immutable data and
	// strings inputs, and each writes a disjoint set of result fields. Their
	// one shared sink, result.Plugins, is appended via appendPlugin, which
	// serializes the writes under pluginsMu.
	parallelRun(
		func() { // Carving + payload promotion
			AnalyzeCarvedArtifacts(&result, data, cfg, debugf)
			PromoteCarvedPayloadIOCs(&result)
		},
		func() { // Similarity hashing
			BuildSimilarityInfo(&result, data, extracted)
		},
	)

	// Rank the sample against the optional reference similarity store
	// (--similarity-db). Runs after BuildSimilarityInfo, which produces the
	// hashes it compares.
	if refs, err := LoadSimilarityRefs(cfg.SimilarityDBPath); err != nil {
		debugf("similarity store load failed: %v", err)
	} else {
		MatchSimilarity(&result, refs, debugf)
	}

	// Crypto/config extraction reads result.IOCs, including the PE-hash IOCs
	// added by PromoteCarvedPayloadIOCs above, so it runs after the parallel
	// group rather than concurrently with it.
	ExtractCryptoAndConfigWithCorpus(&result, data, extracted, cfg, corpus)

	// Managed-code (.NET) behavioral detection. Runs after format analysis so
	// result.PE.ManagedRuntime is known, and before classification so family
	// hypotheses can react to the findings it adds.
	AnalyzeDotNet(&result, corpus)

	// Multi-evidence correlation: serious capability findings (credential
	// dumping, browser theft, keylogging) require corroborating evidence groups
	// and carry an evidence count + confidence, instead of firing on one string.
	RunCorrelationClusters(&result, corpus)

	// CAPA-style capability rules over the full feature set (strings, imports
	// incl. hashdb-resolved, disasm techniques, IOC categories) -> ATT&CK.
	RunCapabilityRules(&result, corpus)

	progress.Set(88, "running rules and classification")

	// Sequential group: stages that depend on format analysis results
	// or modify shared IOC state.
	RunExternalToolIntegrations(&result, cfg, debugf)
	ApplyRulePacksWithCorpus(&result, extracted, cfg, debugf, corpus)
	ApplyIOCTriage(&result, cfg, debugf)
	ClassifyMalwareFamiliesWithCorpus(&result, extracted, corpus)
	AnalyzeDGADomains(&result)

	// Recover structured operator config (C2/mutex/token/webhook/campaign), then
	// enrich against the optional offline threat-intel database. Both run after
	// family classification + IOC triage so they reuse the final IOC set.
	ExtractMalwareConfig(&result, corpus)
	if records, err := LoadIntelDB(cfg.IntelDBPath); err != nil {
		debugf("intel db load failed: %v", err)
	} else {
		EnrichFromIntel(&result, records, debugf)
	}

	progress.Set(90, "running analysis plugins")
	RunRegisteredPlugins(&result, data, extracted, corpus, cfg, debugf)

	progress.Set(92, "detecting behavioral chains and packers")
	DetectAPIChains(&result)
	DetectPackers(&result, data)

	progress.Set(94, "finalizing score")
	if result.TruncatedAnalysis {
		AddFinding(&result, "Info", "Coverage", "Analysis bytes were capped", fmt.Sprintf("retained %d of %d bytes", result.AnalyzedBytes, result.Size), 0, 0)
	}
	// Recognize detection/analysis artifacts (signature sets, rule packs,
	// analysis tools, reports) so their catalogued indicator strings are not
	// scored as live behavior. Must run before FinalizeRisk, which applies the
	// score cap this records.
	AssessResearchArtifact(&result, corpus)
	FinalizeRisk(&result)
	EnrichAnalysisProfileWithCorpus(&result, extracted, corpus)

	// Predict expected runtime behavior from the finalized static evidence so
	// analysts have a sandbox/EDR validation checklist. Runs last — after all
	// findings exist.
	PredictExpectedBehavior(&result)

	// Promote captured log entries to the result's debug log.
	if cfg.Debug {
		result.DebugLog = logger.Strings()
	}

	progress.Set(100, "complete")
	return result, nil
}

func readSampleAndHashes(path string, size int64, maxAnalyzeBytes int64, progress *Progress) ([]byte, Hashes, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, Hashes{}, false, err
	}
	defer f.Close()

	md5h := md5.New()
	sha1h := sha1.New()
	sha256h := sha256.New()
	sha512h := sha512.New()
	hashWriter := io.MultiWriter(md5h, sha1h, sha256h, sha512h)

	var sample bytes.Buffer
	if initialCap := minInt64(size, maxAnalyzeBytes); initialCap > 0 && initialCap < int64(int(^uint(0)>>1)) {
		sample.Grow(int(initialCap))
	}

	buf := make([]byte, 1024*1024)
	var readTotal int64
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if _, err := hashWriter.Write(chunk); err != nil {
				return nil, Hashes{}, false, err
			}
			if int64(sample.Len()) < maxAnalyzeBytes {
				remaining := maxAnalyzeBytes - int64(sample.Len())
				toWrite := int64(n)
				if toWrite > remaining {
					toWrite = remaining
				}
				sample.Write(chunk[:toWrite])
			}
			readTotal += int64(n)
			if size > 0 {
				pct := 3 + int((float64(readTotal)/float64(size))*13.0)
				progress.Set(pct, "reading and hashing file")
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, Hashes{}, false, readErr
		}
	}

	hashes := Hashes{
		MD5:    hex.EncodeToString(md5h.Sum(nil)),
		SHA1:   hex.EncodeToString(sha1h.Sum(nil)),
		SHA256: hex.EncodeToString(sha256h.Sum(nil)),
		SHA512: hex.EncodeToString(sha512h.Sum(nil)),
	}
	return sample.Bytes(), hashes, size > maxAnalyzeBytes, nil
}

func stringLimitForMode(mode string) int {
	switch mode {
	case "quick":
		return 30000
	case "standard":
		return 100000
	default:
		return 250000
	}
}

func AddFinding(result *ScanResult, severity, category, title, evidence string, score int, offset int64) {
	AddFindingDetailed(result, severity, category, title, evidence, score, offset, "", "", "")
}

func AddFindingDetailed(result *ScanResult, severity, category, title, evidence string, score int, offset int64, tactic, technique, recommendation string) {
	if result == nil {
		return
	}
	if score < 0 {
		score = 0
	}
	if score == 0 && severity != "Info" {
		score = DefaultSeverityScore(severity)
	}
	addFindingStruct(result, Finding{
		Severity:       severity,
		Category:       category,
		Title:          title,
		Evidence:       evidence,
		Score:          score,
		Offset:         offset,
		Tactic:         tactic,
		Technique:      technique,
		Recommendation: recommendation,
		Confidence:     DefaultSeverityConfidence(severity),
		EvidenceCount:  1,
	})
}

// AddCorrelatedFinding records a finding whose confidence and evidence count
// come from an evidence cluster (v3 Task 2) rather than from severity alone.
func AddCorrelatedFinding(result *ScanResult, severity, category, title, evidence string, score int, offset int64, tactic, technique, recommendation string, evidenceCount, confidence int) {
	if result == nil {
		return
	}
	if score < 0 {
		score = 0
	}
	if score == 0 && severity != "Info" {
		score = DefaultSeverityScore(severity)
	}
	addFindingStruct(result, Finding{
		Severity:       severity,
		Category:       category,
		Title:          title,
		Evidence:       evidence,
		Score:          score,
		Offset:         offset,
		Tactic:         tactic,
		Technique:      technique,
		Recommendation: recommendation,
		Confidence:     confidence,
		EvidenceCount:  evidenceCount,
	})
}

// addFindingStruct appends a finding with title+evidence dedup, under the mutex.
func addFindingStruct(result *ScanResult, f Finding) {
	findingsMu.Lock()
	defer findingsMu.Unlock()
	for _, existing := range result.Findings {
		if existing.Title == f.Title && existing.Evidence == f.Evidence {
			return
		}
	}
	result.Findings = append(result.Findings, f)
}

func FinalizeRisk(result *ScanResult) {
	sort.SliceStable(result.Findings, func(i, j int) bool {
		ri := severityRank(result.Findings[i].Severity)
		rj := severityRank(result.Findings[j].Severity)
		if ri == rj {
			return result.Findings[i].Score > result.Findings[j].Score
		}
		return ri > rj
	})

	score := 0
	breakdown := make(map[string]int)
	for _, finding := range result.Findings {
		score += finding.Score
		if finding.Score > 0 && finding.Category != "" {
			breakdown[finding.Category] += finding.Score
		}
	}
	if score > 100 {
		score = 100
	}
	// A recognized detection/analysis artifact carries indicator strings as
	// data, not behavior. Cap its aggregate score so the verdict reads as a
	// reference catalog rather than a live threat; the raw breakdown and
	// findings are preserved for transparency.
	if result.BenignContext != nil && score > result.BenignContext.ScoreCap {
		result.BenignContext.OriginalScore = score
		score = result.BenignContext.ScoreCap
	}
	result.RiskScore = score
	if len(breakdown) > 0 {
		result.ScoreBreakdown = breakdown
	}
	switch {
	case score >= 80:
		result.Verdict = "Likely malicious"
	case score >= 55:
		result.Verdict = "High suspicion"
	case score >= 30:
		result.Verdict = "Suspicious"
	case score >= 10:
		result.Verdict = "Low suspicion"
	default:
		result.Verdict = "No strong indicators"
	}
	if result.BenignContext != nil {
		result.Verdict += " (likely security tool or signature/analysis artifact)"
	}
}

func DefaultSeverityScore(severity string) int {
	switch severity {
	case "Critical":
		return 35
	case "High":
		return 22
	case "Medium":
		return 10
	case "Low":
		return 3
	default:
		return 0
	}
}

// DefaultSeverityConfidence is the baseline per-finding confidence when no
// evidence-cluster count is supplied. Single-evidence findings sit mid-range;
// correlated findings (AddCorrelatedFinding) override this with a computed value.
func DefaultSeverityConfidence(severity string) int {
	switch severity {
	case "Critical":
		return 85
	case "High":
		return 70
	case "Medium":
		return 55
	case "Low":
		return 40
	case "Info":
		return 30
	default:
		return 50
	}
}

func severityRank(severity string) int {
	switch severity {
	case "Critical":
		return 5
	case "High":
		return 4
	case "Medium":
		return 3
	case "Low":
		return 2
	case "Info":
		return 1
	default:
		return 0
	}
}

func firstN(data []byte, n int) []byte {
	if len(data) < n {
		return data
	}
	return data[:n]
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
