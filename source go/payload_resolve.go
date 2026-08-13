package main

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Recursive static payload resolution — roadmap Flagship Epic, Tier 1.
//
// A flat string/IOC pass can only see what malware leaves in cleartext. Real
// samples bury their next stage under one or more layers of encoding (base64/
// hex), compression (gzip/zlib), single-byte XOR, or plain appension (carving).
// This module peels those layers off by *pure data transformation* — the sample
// is never executed (no detonation) — and re-scans whatever structured payload
// emerges, producing a provenance-tagged payload tree. Each recovered stage is
// run through a bounded subset of the real detection engine (strings → IOCs →
// pattern/family/capability scoring) so a buried PE/ELF/DEX/archive is surfaced
// and scored instead of hiding behind its wrapper.
//
// It builds on carve.go (magic carving), decode.go (base64/hex), and
// config_extract.go (XOR/compression markers), making them recursive and
// exhaustive rather than single-pass.

const (
	// payloadMaxNodes caps the total number of resolved nodes per scan so a
	// pathological input (e.g. a file full of base64 fragments) cannot explode
	// the tree. Conservative — real multi-stage chains are a handful deep.
	payloadMaxNodes = 24
	// payloadMaxChildBytes bounds a single recovered payload. Larger recoveries
	// are truncated for the sub-scan; the full bytes are never retained.
	payloadMaxChildBytes = 6 * 1024 * 1024
	// payloadMinChildBytes ignores trivially small decodes (not real payloads).
	payloadMinChildBytes = 64
	// payloadXORScanLimit bounds the blob size we brute-force for an XOR-wrapped
	// executable header. Host binaries are large and start with a real magic, so
	// this mainly fires on already-recovered intermediate blobs.
	payloadXORScanLimit = 512 * 1024
	// payloadMaxBase64PerString limits base64 candidates pulled from one string.
	payloadMaxBase64PerString = 4
	// payloadMinB64Chars is the shortest base64 run worth decoding: a payload of
	// payloadMinChildBytes encodes to ~4/3 that many characters. Pre-filtering on
	// length keeps the resolver from attempting to decode every short token in a
	// large binary (the dominant cost on real samples).
	payloadMinB64Chars = (payloadMinChildBytes*4)/3 + 4
	// Global per-scan work budgets. These bound total effort across the whole
	// BFS so a large binary (hundreds of thousands of strings, many incidental
	// 0x78 bytes) cannot turn layer-peeling into a hot loop.
	payloadDecodeBudget  = 4000 // base64/hex decode attempts
	payloadInflateBudget = 96   // gzip/zlib inflate attempts (success or not)
)

// resolveBudget tracks remaining work across the whole scan so the cost of
// payload resolution stays bounded regardless of input shape.
type resolveBudget struct {
	decode  int
	inflate int
}

func (b *resolveBudget) takeDecode() bool {
	if b.decode <= 0 {
		return false
	}
	b.decode--
	return true
}

func (b *resolveBudget) takeInflate() bool {
	if b.inflate <= 0 {
		return false
	}
	b.inflate--
	return true
}

// payloadJob is a unit of pending work: a recovered byte buffer plus how it was
// obtained and where it sits in the tree.
type payloadJob struct {
	data     []byte
	parentID int
	depth    int
	method   string
	detail   string
}

// ResolvePayloads drives the BFS layer-peeling and attaches result.PayloadTree.
// Gated to standard/deep (cfg.Mode != "quick") and to cfg.MaxPayloadDepth > 0.
func ResolvePayloads(result *ScanResult, data []byte, extracted []ExtractedString, cfg Config, debugf debugLogger) {
	if result == nil || cfg.Mode == "quick" || cfg.MaxPayloadDepth <= 0 || len(data) == 0 {
		return
	}

	seen := map[string]struct{}{}
	rootSum := sha256.Sum256(data)
	seen[hex.EncodeToString(rootSum[:])] = struct{}{}

	var nodes []PayloadNode
	nextID := 1
	resolvedExec := 0
	obfuscatedExec := 0
	budget := &resolveBudget{decode: payloadDecodeBudget, inflate: payloadInflateBudget}

	queue := derivePayloads(data, extracted, 0, 0, cfg, budget)
	for len(queue) > 0 && len(nodes) < payloadMaxNodes {
		job := queue[0]
		queue = queue[1:]

		if len(job.data) < payloadMinChildBytes {
			continue
		}
		child := job.data
		if len(child) > payloadMaxChildBytes {
			child = child[:payloadMaxChildBytes]
		}
		sum := sha256.Sum256(child)
		digest := hex.EncodeToString(sum[:])
		if _, ok := seen[digest]; ok {
			continue
		}
		seen[digest] = struct{}{}

		ftype := DetectFileType(child, "")
		if !interestingPayloadType(ftype) {
			continue
		}

		sub := analyzePayloadBuffer(child, ftype, cfg)
		node := PayloadNode{
			ID:       nextID,
			ParentID: job.parentID,
			Depth:    job.depth,
			Method:   job.method,
			Detail:   job.detail,
			FileType: ftype,
			Size:     len(child),
			SHA256:   digest,
			Entropy:  ShannonEntropy(child),
			Score:    sub.RiskScore,
			Verdict:  sub.Verdict,
			Family:   topFamily(sub),
			IOCs:     topActionableIOCs(sub.IOCs, 6),
			Findings: topFindingTitles(sub, 4),
		}
		nodes = append(nodes, node)
		nextID++

		if isExecutablePayloadType(ftype) {
			resolvedExec++
			if isObfuscationMethod(job.method) {
				obfuscatedExec++
			}
		}

		// Recurse into the recovered bytes unless we have hit the depth cap.
		if job.depth+1 < cfg.MaxPayloadDepth && len(nodes) < payloadMaxNodes {
			grandStrings, _, _ := ExtractStrings(child, cfg.MinStringLen, stringLimitForMode(cfg.Mode))
			queue = append(queue, derivePayloads(child, grandStrings, node.ID, job.depth+1, cfg, budget)...)
		}
	}

	if len(nodes) == 0 {
		return
	}
	result.PayloadTree = nodes
	debugf("payload resolution surfaced %d buried stage(s)", len(nodes))
	addPayloadFindings(result, nodes, resolvedExec, obfuscatedExec)
	appendPlugin(result, PluginResult{
		Name:     "payload-resolver",
		Version:  version,
		Status:   "complete",
		Summary:  fmt.Sprintf("%d buried payload stage(s) resolved", len(nodes)),
		Findings: resolvedExec,
	})
}

// derivePayloads produces the next layer of candidate buffers from a parent
// buffer (and its extracted strings) via every supported peeling method.
func derivePayloads(data []byte, strs []ExtractedString, parentID, depth int, cfg Config, budget *resolveBudget) []payloadJob {
	var jobs []payloadJob
	// When the buffer is itself a ZIP-family archive, its many "ZIP container"
	// (PK\x03\x04) hits are just member-entry headers already enumerated by the
	// archive analyzer — carving them would flood the tree. Embedded PE/ELF/DEX/
	// PDF entries are still surfaced.
	hostIsZip := isZipFamily(DetectFileType(data, ""))

	// 1) Carved embedded executables & archives. Compression streams are skipped
	//    here and handled by decompressCandidates below, which actually inflates
	//    and validates them — carving a raw gzip/zlib blob as a node would just
	//    surface incidental 0x1f8b/0x78 byte-pairs as noise.
	zipCarves := 0
	for _, art := range carveArtifacts(data, cfg.MaxCarves) {
		if art.Offset <= 0 {
			continue // offset 0 == the parent itself
		}
		if isCompressionType(art.Type) {
			continue
		}
		if art.Type == "ZIP container" {
			// A long run of PK\x03\x04 hits is one appended archive's member
			// entries; cap them so they don't crowd out embedded executables in
			// the node budget. Skip entirely when the host is already an archive.
			if hostIsZip || zipCarves >= 3 {
				continue
			}
			zipCarves++
		}
		start := int(art.Offset)
		end := start + art.Length
		if start < 0 || start >= len(data) {
			continue
		}
		if end > len(data) {
			end = len(data)
		}
		jobs = append(jobs, payloadJob{
			data:     data[start:end],
			parentID: parentID,
			depth:    depth,
			method:   "carve",
			detail:   fmt.Sprintf("%s at 0x%x", art.Type, start),
		})
	}

	// 2) base64 / hex decoded blobs that yield *binary* payloads. The existing
	//    decode path keeps only mostly-printable decodes (scripts); a base64- or
	//    hex-encoded PE is dropped there, which is exactly what this recovers.
	for _, item := range strs {
		v := item.Value
		if len(v) < payloadMinB64Chars {
			continue
		}
		if budget.decode <= 0 {
			break
		}
		count := 0
		for _, cand := range base64CandidateRe.FindAllString(v, -1) {
			if count >= payloadMaxBase64PerString || len(cand) < payloadMinB64Chars {
				continue
			}
			if !budget.takeDecode() {
				break
			}
			if decoded, ok := tryBase64(cand); ok && len(decoded) >= payloadMinChildBytes {
				jobs = append(jobs, payloadJob{
					data:     decoded,
					parentID: parentID,
					depth:    depth,
					method:   "base64",
					detail:   fmt.Sprintf("%s string at 0x%x", item.Encoding, item.Offset),
				})
				count++
			}
		}
		for _, cand := range hexCandidateRe.FindAllString(v, -1) {
			s := strings.TrimPrefix(strings.TrimPrefix(cand, "0x"), "0X")
			if len(s)%2 != 0 || len(s) < payloadMinChildBytes*2 {
				continue
			}
			if !budget.takeDecode() {
				break
			}
			if decoded, err := hex.DecodeString(s); err == nil {
				jobs = append(jobs, payloadJob{
					data:     decoded,
					parentID: parentID,
					depth:    depth,
					method:   "hex",
					detail:   fmt.Sprintf("hex string at 0x%x", item.Offset),
				})
			}
		}
	}

	// 3) gzip / zlib compressed streams found anywhere in the buffer.
	jobs = append(jobs, decompressCandidates(data, parentID, depth, budget)...)

	// 4) single-byte-XOR-wrapped executables (common second layer after base64).
	jobs = append(jobs, xorExecutableCandidates(data, parentID, depth)...)

	return jobs
}

// decompressCandidates inflates gzip/zlib streams whose magic appears in data.
// Attempts are drawn from the shared inflate budget so an input riddled with
// incidental 0x78 ('x') bytes (common in any binary) cannot trigger an
// unbounded number of inflate attempts.
func decompressCandidates(data []byte, parentID, depth int, budget *resolveBudget) []payloadJob {
	var jobs []payloadJob
	add := func(off int, method string, raw []byte) {
		if len(raw) >= payloadMinChildBytes {
			jobs = append(jobs, payloadJob{
				data:     raw,
				parentID: parentID,
				depth:    depth,
				method:   method,
				detail:   fmt.Sprintf("%s stream at 0x%x", method, off),
			})
		}
	}
	// gzip (1f 8b 08)
	for off := 0; off+10 < len(data) && len(jobs) < 8; {
		idx := bytes.Index(data[off:], []byte{0x1f, 0x8b, 0x08})
		if idx < 0 {
			break
		}
		at := off + idx
		off = at + 1
		if !budget.takeInflate() {
			break
		}
		if raw, ok := inflate(data[at:], "gzip"); ok {
			add(at, "gzip", raw)
		}
	}
	// zlib (78 01/9c/da)
	for off := 0; off+2 < len(data) && len(jobs) < 16; {
		idx := bytes.IndexByte(data[off:], 0x78)
		if idx < 0 {
			break
		}
		at := off + idx
		off = at + 1
		if at+1 >= len(data) {
			break
		}
		switch data[at+1] {
		case 0x01, 0x9c, 0xda:
			if !budget.takeInflate() {
				return jobs
			}
			if raw, ok := inflate(data[at:], "zlib"); ok {
				add(at, "zlib", raw)
			}
		}
	}
	return jobs
}

func inflate(data []byte, kind string) ([]byte, bool) {
	var r io.ReadCloser
	var err error
	switch kind {
	case "gzip":
		r, err = gzip.NewReader(bytes.NewReader(data))
	case "zlib":
		r, err = zlib.NewReader(bytes.NewReader(data))
	default:
		return nil, false
	}
	if err != nil {
		return nil, false
	}
	defer r.Close() //nolint:errcheck // read-only handle: Close discards nothing
	out, err := io.ReadAll(io.LimitReader(r, payloadMaxChildBytes+1))
	if (err != nil && !errors.Is(err, io.ErrUnexpectedEOF)) || len(out) < payloadMinChildBytes {
		// A truncated stream still yields useful prefix bytes; only bail when we
		// got essentially nothing.
		if len(out) < payloadMinChildBytes {
			return nil, false
		}
	}
	return out, true
}

// xorExecutableCandidates brute-forces single-byte XOR keys looking for a PE or
// ELF header at offset 0 of the (bounded) buffer, then decodes the whole blob.
func xorExecutableCandidates(data []byte, parentID, depth int) []payloadJob {
	if len(data) < payloadMinChildBytes || len(data) > payloadXORScanLimit {
		return nil
	}
	if len(data) < 4 {
		return nil
	}
	var jobs []payloadJob
	for key := 1; key < 256; key++ {
		k := byte(key)
		b0, b1, b2, b3 := data[0]^k, data[1]^k, data[2]^k, data[3]^k
		isMZ := b0 == 'M' && b1 == 'Z'
		isELF := b0 == 0x7f && b1 == 'E' && b2 == 'L' && b3 == 'F'
		if !isMZ && !isELF {
			continue
		}
		decoded := make([]byte, len(data))
		for i, b := range data {
			decoded[i] = b ^ k
		}
		// Confirm the decode is a real executable, not a coincidental 2-byte hit.
		if t := DetectFileType(decoded, ""); isExecutablePayloadType(t) {
			jobs = append(jobs, payloadJob{
				data:     decoded,
				parentID: parentID,
				depth:    depth,
				method:   fmt.Sprintf("xor:0x%02x", key),
				detail:   "single-byte XOR-wrapped executable",
			})
		}
	}
	return jobs
}

// analyzePayloadBuffer runs a bounded, non-recursive subset of the detection
// engine over a recovered buffer. It deliberately does NOT call ResolvePayloads
// (the parent BFS owns recursion) or the heavy format/disasm parsers — it reuses
// the string → IOC → pattern/family/capability stages, which carry the bulk of
// the behavioral signal, then finalizes a score.
func analyzePayloadBuffer(data []byte, ftype string, cfg Config) ScanResult {
	sub := ScanResult{
		Tool:          "FlatScan",
		Version:       version,
		Mode:          cfg.Mode,
		FileType:      ftype,
		Size:          int64(len(data)),
		AnalyzedBytes: int64(len(data)),
		Entropy:       ShannonEntropy(data),
	}
	strs, total, trunc := ExtractStrings(data, cfg.MinStringLen, stringLimitForMode(cfg.Mode))
	sub.StringsTotal = total
	sub.StringsTruncated = trunc
	sub.IOCs = ExtractIOCsFromStrings(strs)
	corpus := buildCorpus(strs, nil, defaultMaxCorpusBytes)
	AnalyzePatternsWithCorpus(&sub, strs, cfg, corpus)
	ClassifyMalwareFamiliesWithCorpus(&sub, strs, corpus)
	RunCapabilityRules(&sub, corpus)
	ApplyIOCTriage(&sub, cfg, func(string, ...any) {})
	ClassifyIOCSet(&sub.IOCs)
	FinalizeRisk(&sub)
	return sub
}

// addPayloadFindings records the analyst-facing findings for the resolved tree,
// conservatively: a buried executable obtained through *obfuscation* is the
// strong signal (T1027), while a plainly-carved/compressed payload or a stage
// that itself scores Suspicious+ is reported at a lower weight. Plain embedded
// payloads with no malicious content stay informational so benign installers
// (which legitimately embed executables) are not over-scored.
func addPayloadFindings(result *ScanResult, nodes []PayloadNode, resolvedExec, obfuscatedExec int) {
	maxChildScore := 0
	var headline PayloadNode
	for _, n := range nodes {
		if n.Score > maxChildScore {
			maxChildScore = n.Score
			headline = n
		}
	}

	switch {
	case obfuscatedExec > 0:
		// Encoded/compressed/XOR-wrapped executable = classic staged payload.
		desc := fmt.Sprintf("%d executable stage(s) recovered by peeling encoding/compression/XOR layers (%s via %s)", obfuscatedExec, headline.FileType, headline.Method)
		AddCorrelatedFinding(result, "High", "Payload", "Obfuscated executable payload resolved", desc, 20, 0,
			"Defense Evasion", "Obfuscated Files or Information: Embedded Payloads (T1027.009)",
			"Extract the recovered stage(s) in an isolated lab; the buried executable is the real subject of analysis.",
			obfuscatedExec+1, 80)
	case resolvedExec > 0 && maxChildScore >= 30:
		desc := fmt.Sprintf("embedded executable stage scores %d (%s)", maxChildScore, headline.FileType)
		AddCorrelatedFinding(result, "Medium", "Payload", "Embedded executable stage scored suspicious", desc, 12, 0,
			"Defense Evasion", "Obfuscated Files or Information (T1027)",
			"Review the recovered stage; it carries its own malicious indicators.",
			2, 65)
	case maxChildScore >= 30:
		desc := fmt.Sprintf("buried %s stage scores %d", headline.FileType, maxChildScore)
		AddCorrelatedFinding(result, "Medium", "Payload", "Buried payload stage scored suspicious", desc, 10, 0,
			"Defense Evasion", "Obfuscated Files or Information (T1027)",
			"Review the recovered stage's indicators before disposition.",
			2, 60)
	default:
		// Record the tree without inflating the score.
		AddFinding(result, "Info", "Payload", "Static payload layers resolved",
			fmt.Sprintf("%d nested payload stage(s) recovered by static layer-peeling", len(nodes)), 0, 0)
	}
}

// interestingPayloadType reports whether a recovered buffer is a recognized,
// structured format worth surfacing. Plain text / undetermined bytes are noise
// (the existing string/decode path already covers cleartext scripts).
func interestingPayloadType(t string) bool {
	switch t {
	case "", "text", "unknown binary", "script/text":
		return false
	}
	return true
}

func isZipFamily(t string) bool {
	switch t {
	case "ZIP container", "APK package", "JAR package", "Office Open XML document":
		return true
	}
	return false
}

func isCompressionType(t string) bool {
	switch t {
	case "Gzip compressed data", "Bzip2 compressed data", "XZ compressed data":
		return true
	}
	return false
}

func isExecutablePayloadType(t string) bool {
	switch t {
	case "PE executable", "ELF binary", "Mach-O binary", "DEX bytecode", "Java class":
		return true
	}
	return false
}

func isObfuscationMethod(method string) bool {
	return method == "base64" || method == "hex" || strings.HasPrefix(method, "xor:")
}

func topFamily(sub ScanResult) string {
	if len(sub.FamilyMatches) > 0 {
		return sub.FamilyMatches[0].Family
	}
	return ""
}

func topFindingTitles(sub ScanResult, limit int) []string {
	var out []string
	for _, f := range sub.Findings {
		if f.Severity == "Info" {
			continue
		}
		out = append(out, f.Title)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// topActionableIOCs returns up to limit actionable indicator values (URLs first,
// then domains/IPs) from a recovered stage, using the v3 classification so build
// artifacts / namespaces / benign infra are not surfaced as payload IOCs.
func topActionableIOCs(iocs IOCSet, limit int) []string {
	var out []string
	for _, c := range iocs.Classified {
		if len(out) >= limit {
			break
		}
		if c.Category == iocCatActionable || c.Category == iocCatSuspInfra {
			out = appendUnique(out, c.Value)
		}
	}
	return out
}
