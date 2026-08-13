package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeIntelDB writes a JSONL intel database fixture and returns its path.
func writeIntelDB(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "intel.jsonl")
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

// TestLoadIntelDBReportsMalformedLines pins the fix for a silent false
// negative: a typo in the analyst's intel database used to drop that indicator
// with no error and no warning, so a sample that should have matched a known
// threat was reported clean. The load still succeeds - one bad line must not
// cost the whole database - but the skipped lines are now reported.
func TestLoadIntelDBReportsMalformedLines(t *testing.T) {
	path := writeIntelDB(t,
		`{"indicator":"aaa","type":"sha256","family":"Emotet"}`,
		`{"indicator":"bbb","type":"sha256",}`, // trailing comma: invalid JSON
		`{"indicator":"ccc","type":"sha256","family":"Qakbot"}`,
		`{"type":"sha256","family":"NoIndicator"}`, // unusable: never matches
	)

	records, skipped, err := loadIntelDB(path)
	if err != nil {
		t.Fatalf("loadIntelDB() error = %v, want nil (a bad line must not fail the load)", err)
	}
	if len(records) != 2 {
		t.Fatalf("loaded %d records, want the 2 well-formed ones: %+v", len(records), records)
	}
	if len(skipped) != 2 {
		t.Fatalf("skipped = %v, want the malformed line and the indicator-less line reported", skipped)
	}
	// Line numbers are 1-based and must point at the offending lines.
	if skipped[0] != 2 || skipped[1] != 4 {
		t.Fatalf("skipped = %v, want [2 4]", skipped)
	}
}

// TestLoadIntelDBIgnoresCommentsAndBlanks confirms the documented format:
// comments and blank lines are legal and are not reported as errors.
func TestLoadIntelDBIgnoresCommentsAndBlanks(t *testing.T) {
	path := writeIntelDB(t,
		`# campaign feed export`,
		``,
		`{"indicator":"aaa","type":"sha256","family":"Emotet"}`,
		`   `,
	)

	records, skipped, err := loadIntelDB(path)
	if err != nil {
		t.Fatalf("loadIntelDB() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("loaded %d records, want 1", len(records))
	}
	if len(skipped) != 0 {
		t.Fatalf("skipped = %v, want none: comments and blanks are valid", skipped)
	}
}

// TestLoadIntelDBMissingFileIsNotAnError pins the documented behavior: an
// absent or unset database is a normal configuration, not a failure.
func TestLoadIntelDBMissingFileIsNotAnError(t *testing.T) {
	for _, path := range []string{"", "   ", filepath.Join(t.TempDir(), "absent.jsonl")} {
		records, skipped, err := loadIntelDB(path)
		if err != nil {
			t.Fatalf("loadIntelDB(%q) error = %v, want nil", path, err)
		}
		if records != nil || skipped != nil {
			t.Fatalf("loadIntelDB(%q) = (%v,%v), want no records", path, records, skipped)
		}
	}
}

// TestLoadIntelDBOversizedLineFailsLoudly covers the truncation case. A line
// beyond the scanner's 4 MB cap means the file was only partially read;
// returning the partial records would enrich against half a database, so the
// load must fail instead.
func TestLoadIntelDBOversizedLineFailsLoudly(t *testing.T) {
	huge := `{"indicator":"` + strings.Repeat("a", 5*1024*1024) + `","type":"sha256"}`
	path := writeIntelDB(t,
		`{"indicator":"aaa","type":"sha256","family":"Emotet"}`,
		huge,
	)

	records, _, err := loadIntelDB(path)
	if err == nil {
		t.Fatal("loadIntelDB() returned nil error on a truncated read; enrichment would run against a partial database")
	}
	if records != nil {
		t.Fatalf("loadIntelDB() returned %d partial records alongside an error", len(records))
	}
	if !strings.Contains(err.Error(), "intel db") {
		t.Fatalf("error %q should identify the intel database as the source", err)
	}
}

// TestEnrichFromIntelMatchesIndicators drives the enrichment path across every
// indicator dimension the loader indexes.
func TestEnrichFromIntelMatchesIndicators(t *testing.T) {
	tests := []struct {
		name   string
		result ScanResult
		record IntelRecord
		want   bool
	}{
		{
			name:   "sha256 match",
			result: ScanResult{Hashes: Hashes{SHA256: "ABC123"}},
			record: IntelRecord{Indicator: "abc123", Type: "sha256", Family: "Emotet"},
			want:   true,
		},
		{
			name:   "case-insensitive match",
			result: ScanResult{Hashes: Hashes{SHA256: "abc123"}},
			record: IntelRecord{Indicator: "ABC123", Type: "sha256", Family: "Emotet"},
			want:   true,
		},
		{
			name:   "domain match",
			result: ScanResult{IOCs: IOCSet{Domains: []string{"evil.example"}}},
			record: IntelRecord{Indicator: "evil.example", Type: "domain", Family: "Qakbot"},
			want:   true,
		},
		{
			name:   "ipv4 match",
			result: ScanResult{IOCs: IOCSet{IPv4: []string{"203.0.113.9"}}},
			record: IntelRecord{Indicator: "203.0.113.9", Type: "ipv4"},
			want:   true,
		},
		{
			name:   "untyped record matches any dimension",
			result: ScanResult{Hashes: Hashes{SHA256: "abc123"}},
			record: IntelRecord{Indicator: "abc123", Family: "Generic"},
			want:   true,
		},
		{
			name:   "type mismatch does not match",
			result: ScanResult{Hashes: Hashes{SHA256: "abc123"}},
			record: IntelRecord{Indicator: "abc123", Type: "domain"},
			want:   false,
		},
		{
			name:   "unrelated indicator does not match",
			result: ScanResult{Hashes: Hashes{SHA256: "abc123"}},
			record: IntelRecord{Indicator: "def456", Type: "sha256"},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.result
			t.Cleanup(func() { releaseFindingIndex(&result) })

			EnrichFromIntel(&result, []IntelRecord{tt.record}, func(string, ...any) {})

			got := len(result.Enrichment) > 0
			if got != tt.want {
				t.Fatalf("enrichment matched = %v, want %v (enrichment=%+v)", got, tt.want, result.Enrichment)
			}
			if !tt.want {
				return
			}
			var found bool
			for _, f := range result.Findings {
				if strings.Contains(f.Title, "threat-intel") {
					found = true
					if f.Severity != "High" {
						t.Fatalf("intel finding severity = %q, want High", f.Severity)
					}
				}
			}
			if !found {
				t.Fatalf("no threat-intel finding recorded; findings=%+v", result.Findings)
			}
		})
	}
}

// TestEnrichFromIntelDegenerateInput covers the nil/empty paths; this runs
// inside the scan pipeline and must not panic.
func TestEnrichFromIntelDegenerateInput(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("EnrichFromIntel panicked: %v", r)
		}
	}()

	noop := func(string, ...any) {}
	EnrichFromIntel(nil, []IntelRecord{{Indicator: "a"}}, noop)

	result := &ScanResult{Hashes: Hashes{SHA256: "abc"}}
	t.Cleanup(func() { releaseFindingIndex(result) })
	EnrichFromIntel(result, nil, noop)
	EnrichFromIntel(result, []IntelRecord{}, noop)
	// A record with an empty indicator must never match the empty-string key.
	EnrichFromIntel(result, []IntelRecord{{Indicator: ""}}, noop)

	if len(result.Enrichment) != 0 {
		t.Fatalf("degenerate input produced enrichment: %+v", result.Enrichment)
	}
}

// TestEnrichFromIntelEmptyIndicatorCannotMatchEmptyField guards a subtle
// indexing hazard: the sample's own indicator map is keyed by value, so a
// record with an empty indicator must not match a sample whose imphash or
// flat-hash is also empty.
func TestEnrichFromIntelEmptyIndicatorCannotMatchEmptyField(t *testing.T) {
	// No PE, no similarity hash: importHashOf and FlatHash are both "".
	result := &ScanResult{Hashes: Hashes{SHA256: "abc123"}}
	t.Cleanup(func() { releaseFindingIndex(result) })

	EnrichFromIntel(result, []IntelRecord{{Indicator: "", Type: "imphash", Family: "Bogus"}},
		func(string, ...any) {})

	if len(result.Enrichment) != 0 {
		t.Fatalf("an empty indicator matched an absent hash field: %+v", result.Enrichment)
	}
}
