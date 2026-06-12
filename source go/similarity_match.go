package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Similarity matching against a reference store (improvementprompt-v3 Task 4).
//
// similarity.go computes structural hashes but never compared them to anything.
// This loads a local JSONL reference store of known samples/campaigns and ranks
// the current file against it: exact-match on the digest dimensions (imphash,
// section, string-set, byte-histogram, rich header) and chunk-overlap on the
// FlatHash (which is a per-chunk sequence, so it degrades gracefully across
// variants). The result is a weighted percent similarity per reference record.
// Offline JSONL only — no network, mirroring the case database.

// SimilarityRef is one record in the reference store.
type SimilarityRef struct {
	Label             string `json:"label"`
	SHA256            string `json:"sha256,omitempty"`
	FlatHash          string `json:"flat_hash,omitempty"`
	ByteHistogramHash string `json:"byte_histogram_hash,omitempty"`
	StringSetHash     string `json:"string_set_hash,omitempty"`
	ImportHash        string `json:"import_hash,omitempty"`
	SectionHash       string `json:"section_hash,omitempty"`
	RichHeaderHash    string `json:"rich_header_hash,omitempty"`
}

// dimension weights — strong structural dimensions outweigh coarse ones.
var simDimensionWeights = map[string]float64{
	"string-set":     35,
	"flat-hash":      40,
	"import-hash":    30,
	"section-hash":   25,
	"rich-header":    15,
	"byte-histogram": 10,
}

const similarityReportThreshold = 50 // minimum % to surface a match

// MatchSimilarity ranks result.Similarity against the reference store and
// records the top matches (and a finding for a strong one).
func MatchSimilarity(result *ScanResult, refs []SimilarityRef, debugf debugLogger) {
	if result == nil || len(refs) == 0 {
		return
	}
	self := result.Similarity
	var matches []SimilarityMatch
	for _, ref := range refs {
		if ref.SHA256 != "" && strings.EqualFold(ref.SHA256, result.Hashes.SHA256) {
			continue // don't match a sample against its own stored record
		}
		pct, dims := similarityScore(self, ref)
		if pct >= similarityReportThreshold {
			matches = append(matches, SimilarityMatch{
				Label:             ref.Label,
				Similarity:        pct,
				MatchedDimensions: dims,
				SHA256:            ref.SHA256,
			})
		}
	}
	if len(matches) == 0 {
		return
	}
	sort.SliceStable(matches, func(i, j int) bool { return matches[i].Similarity > matches[j].Similarity })
	if len(matches) > 5 {
		matches = matches[:5]
	}
	result.Similarity.Matches = matches

	top := matches[0]
	severity, score := "Low", 6
	if top.Similarity >= 85 {
		severity, score = "High", 20
	} else if top.Similarity >= 70 {
		severity, score = "Medium", 12
	}
	AddCorrelatedFinding(result, severity, "Similarity",
		"Structural similarity to a known sample",
		fmt.Sprintf("%d%% similar to %q (matched: %s)", top.Similarity, top.Label, strings.Join(top.MatchedDimensions, ", ")),
		score, 0, "", "",
		"Pivot on the matched family/campaign; review related samples and shared infrastructure.",
		len(top.MatchedDimensions), clampInt(top.Similarity, 0, 99))
	debugf("similarity: top match %s at %d%%", top.Label, top.Similarity)
}

// similarityScore returns a weighted percent similarity and the matched
// dimensions, computed only over dimensions present in BOTH records.
func similarityScore(self SimilarityInfo, ref SimilarityRef) (int, []string) {
	var available, matched float64
	var dims []string

	exact := func(name, a, b string) {
		if a == "" || b == "" {
			return
		}
		w := simDimensionWeights[name]
		available += w
		if strings.EqualFold(a, b) {
			matched += w
			dims = append(dims, name)
		}
	}
	exact("string-set", self.StringSetHash, ref.StringSetHash)
	exact("import-hash", self.ImportHash, ref.ImportHash)
	exact("section-hash", self.SectionHash, ref.SectionHash)
	exact("rich-header", self.RichHeaderHash, ref.RichHeaderHash)
	exact("byte-histogram", self.ByteHistogramHash, ref.ByteHistogramHash)

	if self.FlatHash != "" && ref.FlatHash != "" {
		w := simDimensionWeights["flat-hash"]
		available += w
		overlap := flatHashOverlap(self.FlatHash, ref.FlatHash)
		matched += w * overlap
		if overlap >= 0.5 {
			dims = append(dims, fmt.Sprintf("flat-hash(%d%%)", int(overlap*100)))
		}
	}

	if available == 0 {
		return 0, nil
	}
	return int(matched / available * 100), dims
}

// flatHashOverlap returns the Jaccard overlap of two FlatHash chunk sets
// ("FLS1:<chunk>:<concatenated 8-char chunk hashes>").
func flatHashOverlap(a, b string) float64 {
	sa, sb := flatHashChunks(a), flatHashChunks(b)
	if len(sa) == 0 || len(sb) == 0 {
		return 0
	}
	inter := 0
	for k := range sa {
		if sb[k] {
			inter++
		}
	}
	union := len(sa) + len(sb) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

func flatHashChunks(h string) map[string]bool {
	parts := strings.SplitN(h, ":", 3)
	if len(parts) != 3 {
		return nil
	}
	concat := parts[2]
	set := make(map[string]bool)
	for i := 0; i+8 <= len(concat); i += 8 {
		set[concat[i:i+8]] = true
	}
	return set
}

// LoadSimilarityRefs reads a JSONL reference store. Missing path or file is not
// an error (matching is simply skipped).
func LoadSimilarityRefs(path string) ([]SimilarityRef, error) {
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
	defer f.Close()

	var refs []SimilarityRef
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var ref SimilarityRef
		if err := json.Unmarshal([]byte(line), &ref); err != nil {
			continue // tolerate malformed lines
		}
		if ref.Label != "" {
			refs = append(refs, ref)
		}
	}
	return refs, scanner.Err()
}
