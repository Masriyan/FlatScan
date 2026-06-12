package main

import "testing"

func TestSimilarityExactDimensionMatch(t *testing.T) {
	self := SimilarityInfo{
		ImportHash:    "aaaa",
		SectionHash:   "bbbb",
		StringSetHash: "cccc",
	}
	ref := SimilarityRef{Label: "Lumma sample", ImportHash: "aaaa", SectionHash: "bbbb", StringSetHash: "dddd"}
	pct, dims := similarityScore(self, ref)
	// import+section match (30+25), string-set differs (35) => 55/90 ≈ 61%
	if pct < 55 || pct > 65 {
		t.Fatalf("expected ~61%% similarity, got %d (dims=%v)", pct, dims)
	}
	if len(dims) != 2 {
		t.Errorf("expected 2 matched dimensions, got %v", dims)
	}
}

func TestSimilarityFlatHashOverlap(t *testing.T) {
	a := "FLS1:4096:aaaaaaaabbbbbbbbcccccccc"
	b := "FLS1:4096:aaaaaaaabbbbbbbbdddddddd" // 2 of 3 chunks shared
	overlap := flatHashOverlap(a, b)
	if overlap < 0.4 || overlap > 0.6 {
		t.Fatalf("expected ~0.5 Jaccard overlap, got %.2f", overlap)
	}
}

func TestMatchSimilarityProducesFindingAndMatch(t *testing.T) {
	result := &ScanResult{
		Hashes: Hashes{SHA256: "self"},
		Similarity: SimilarityInfo{
			ImportHash:    "imp1",
			SectionHash:   "sec1",
			StringSetHash: "str1",
		},
	}
	refs := []SimilarityRef{
		{Label: "RedLine campaign A", SHA256: "other", ImportHash: "imp1", SectionHash: "sec1", StringSetHash: "str1"},
	}
	MatchSimilarity(result, refs, func(string, ...any) {})
	if len(result.Similarity.Matches) == 0 {
		t.Fatal("expected a similarity match")
	}
	if result.Similarity.Matches[0].Similarity != 100 {
		t.Errorf("identical hashes should be 100%%, got %d", result.Similarity.Matches[0].Similarity)
	}
	if !hasFindingTitle(result.Findings, "Structural similarity to a known sample") {
		t.Fatalf("expected similarity finding, got: %s", findingTitles(result))
	}
}

func TestMatchSimilaritySkipsSelf(t *testing.T) {
	result := &ScanResult{
		Hashes:     Hashes{SHA256: "abc"},
		Similarity: SimilarityInfo{ImportHash: "imp1"},
	}
	refs := []SimilarityRef{{Label: "self record", SHA256: "ABC", ImportHash: "imp1"}}
	MatchSimilarity(result, refs, func(string, ...any) {})
	if len(result.Similarity.Matches) != 0 {
		t.Fatalf("a sample must not match its own stored record: %#v", result.Similarity.Matches)
	}
}
