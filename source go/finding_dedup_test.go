package main

import (
	"fmt"
	"sync"
	"testing"
)

// TestAddFindingDedupSemantics pins the dedup contract: identical
// (Title, Evidence) pairs collapse, anything else is kept, and insertion order
// is preserved. The map-based index must behave exactly like the linear scan it
// replaced.
func TestAddFindingDedupSemantics(t *testing.T) {
	result := &ScanResult{}
	t.Cleanup(func() { releaseFindingIndex(result) })

	add := func(title, evidence string) {
		addFindingStruct(result, Finding{
			Severity: "Low",
			Category: "Test",
			Title:    title,
			Evidence: evidence,
			Score:    1,
		})
	}

	add("Alpha", "e1")
	add("Alpha", "e1") // exact duplicate — dropped
	add("Alpha", "e2") // same title, different evidence — kept
	add("Beta", "e1")  // different title, same evidence — kept
	add("Beta", "e1")  // exact duplicate — dropped

	want := []struct{ title, evidence string }{
		{"Alpha", "e1"},
		{"Alpha", "e2"},
		{"Beta", "e1"},
	}
	if len(result.Findings) != len(want) {
		t.Fatalf("got %d findings, want %d: %+v", len(result.Findings), len(want), result.Findings)
	}
	for i, w := range want {
		got := result.Findings[i]
		if got.Title != w.title || got.Evidence != w.evidence {
			t.Fatalf("finding[%d] = (%q,%q), want (%q,%q) — insertion order must be stable",
				i, got.Title, got.Evidence, w.title, w.evidence)
		}
	}
}

// TestAddFindingKeyIsUnambiguous guards the separator choice. Concatenating
// title and evidence without a delimiter would make ("ab","c") and ("a","bc")
// collide, silently dropping a distinct finding.
func TestAddFindingKeyIsUnambiguous(t *testing.T) {
	result := &ScanResult{}
	t.Cleanup(func() { releaseFindingIndex(result) })

	addFindingStruct(result, Finding{Title: "ab", Evidence: "c", Score: 1})
	addFindingStruct(result, Finding{Title: "a", Evidence: "bc", Score: 1})

	if len(result.Findings) != 2 {
		t.Fatalf("got %d findings, want 2 — the dedup key collided on a split boundary",
			len(result.Findings))
	}
}

// TestAddFindingSeedsIndexFromExistingFindings covers a result whose Findings
// were populated before the first addFindingStruct call: the index must be
// seeded from them, or a pre-existing finding would be duplicated.
func TestAddFindingSeedsIndexFromExistingFindings(t *testing.T) {
	result := &ScanResult{
		Findings: []Finding{{Title: "Preloaded", Evidence: "e1", Score: 1}},
	}
	t.Cleanup(func() { releaseFindingIndex(result) })

	addFindingStruct(result, Finding{Title: "Preloaded", Evidence: "e1", Score: 1})

	if len(result.Findings) != 1 {
		t.Fatalf("got %d findings, want 1 — index was not seeded from pre-existing findings",
			len(result.Findings))
	}
}

// TestReleaseFindingIndexPreventsLeak checks the per-result index does not
// accumulate. A --dir run scans thousands of files through this map; retaining
// an entry per file would hold every title and evidence string for the life of
// the process.
func TestReleaseFindingIndexPreventsLeak(t *testing.T) {
	findingsMu.Lock()
	before := len(findingSeen)
	findingsMu.Unlock()

	for i := 0; i < 50; i++ {
		result := &ScanResult{}
		addFindingStruct(result, Finding{Title: "T", Evidence: fmt.Sprint(i), Score: 1})
		releaseFindingIndex(result)
	}

	findingsMu.Lock()
	after := len(findingSeen)
	findingsMu.Unlock()

	if after != before {
		t.Fatalf("findingSeen grew from %d to %d entries; the index leaks per scan", before, after)
	}
}

// TestAddFindingConcurrentDedup exercises the index under concurrent writers,
// mirroring how the parallel analysis stages call AddFinding. Run with -race.
func TestAddFindingConcurrentDedup(t *testing.T) {
	result := &ScanResult{}
	t.Cleanup(func() { releaseFindingIndex(result) })

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				// Every goroutine emits the same 10 findings, so all but the
				// first 10 inserts must be deduped away.
				addFindingStruct(result, Finding{
					Title:    "Shared",
					Evidence: fmt.Sprint(i % 10),
					Score:    1,
				})
			}
		}()
	}
	wg.Wait()

	if len(result.Findings) != 10 {
		t.Fatalf("got %d findings, want 10 unique under concurrent insert", len(result.Findings))
	}
}

// BenchmarkAddFindingUnique measures the insert path that used to be quadratic:
// every finding is distinct, so the old implementation compared against all n
// predecessors on each insert while holding findingsMu.
//
// Compare across sizes — the per-op cost should stay roughly flat rather than
// growing with n:
//
//	go test -bench 'BenchmarkAddFindingUnique' -benchtime 1x -run '^$'
func BenchmarkAddFindingUnique(b *testing.B) {
	for _, n := range []int{100, 1000, 5000} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				result := &ScanResult{}
				for j := 0; j < n; j++ {
					addFindingStruct(result, Finding{
						Severity: "Low",
						Category: "Bench",
						Title:    "Finding",
						Evidence: fmt.Sprint(j),
						Score:    1,
					})
				}
				releaseFindingIndex(result)
			}
		})
	}
}
