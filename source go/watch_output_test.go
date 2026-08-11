package main

import (
	"path/filepath"
	"testing"
)

func TestWatchOutputPath(t *testing.T) {
	tests := []struct {
		name     string
		template string
		sample   string
		want     string
	}{
		{"simple extension", "reports/out.json", "evil.exe", "reports/evil.exe.json"},
		{"multi-part suffix survives", "reports/a.stix.json", "evil.exe", "reports/evil.exe.stix.json"},
		{"iocs suffix survives", "reports/a.iocs.txt", "evil.exe", "reports/evil.exe.iocs.txt"},
		{"bare directory template", "out/report.txt", "s.bin", "out/s.bin.txt"},
		{"no directory component", "out.json", "evil.exe", "evil.exe.json"},
		{"template without extension", "reports/dump", "evil.exe", "reports/evil.exe"},
		{"sample name already has dots", "reports/o.json", "a.b.c.exe", "reports/a.b.c.exe.json"},
		{"unset stays unset", "", "evil.exe", ""},
		{"stdout stays stdout", "-", "evil.exe", "-"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := watchOutputPath(tt.template, tt.sample)
			if got != filepath.Clean(tt.want) && got != tt.want {
				t.Fatalf("watchOutputPath(%q, %q) = %q, want %q", tt.template, tt.sample, got, tt.want)
			}
		})
	}
}

// TestWatchOutputPathsAreDistinct is the regression test for BUG-1: two
// different samples must never resolve to the same artifact path.
func TestWatchOutputPathsAreDistinct(t *testing.T) {
	base := Config{
		ReportPath: "out/r.txt",
		JSONPath:   "out/r.json",
		HTMLPath:   "out/r.html",
		PDFPath:    "out/r.pdf",
		YARAPath:   "out/r.yar",
		SigmaPath:  "out/r.yml",
		STIXPath:   "out/r.stix.json",
		IOCPath:    "out/r.iocs.txt",
	}

	var a, b Config
	applyWatchOutputPaths(&a, base, "first.exe")
	applyWatchOutputPaths(&b, base, "second.exe")

	pathsOf := func(c Config) []string {
		return []string{c.ReportPath, c.JSONPath, c.HTMLPath, c.PDFPath,
			c.YARAPath, c.SigmaPath, c.STIXPath, c.IOCPath}
	}
	pa, pb := pathsOf(a), pathsOf(b)
	for i := range pa {
		if pa[i] == "" {
			t.Fatalf("output %d was not populated", i)
		}
		if pa[i] == pb[i] {
			t.Errorf("two samples collide on the same path: %q", pa[i])
		}
		if pa[i] == pathsOf(base)[i] {
			t.Errorf("output %d still uses the raw template %q", i, pa[i])
		}
	}
}

// TestWatchOutputPathsLeaveInputsAndLedgerAlone pins the deliberate
// exclusions: the case ledger is append-only, and rule/plugin/db paths are
// inputs that must not be rewritten per sample.
func TestWatchOutputPathsLeaveInputsAndLedgerAlone(t *testing.T) {
	base := Config{
		ReportPackPath:   "out/pack",
		CaseDBPath:       "cases/all.jsonl",
		CaseID:           "CASE-1",
		RulePaths:        "rules",
		PluginPaths:      "plugins",
		IntelDBPath:      "intel.jsonl",
		SimilarityDBPath: "sim.jsonl",
		IOCAllowlistPath: "allow.txt",
	}
	dst := base
	applyWatchOutputPaths(&dst, base, "evil.exe")

	// WriteReportPack already names files "<sample>_<hash8>.<kind>", so packs
	// from different samples coexist in one directory without collision.
	if dst.ReportPackPath != base.ReportPackPath {
		t.Errorf("ReportPackPath was rewritten to %q; pack filenames are already per-sample", dst.ReportPackPath)
	}
	if dst.CaseDBPath != base.CaseDBPath {
		t.Errorf("CaseDBPath was rewritten to %q; the case ledger is append-only", dst.CaseDBPath)
	}
	for _, p := range []struct{ name, got, want string }{
		{"RulePaths", dst.RulePaths, base.RulePaths},
		{"PluginPaths", dst.PluginPaths, base.PluginPaths},
		{"IntelDBPath", dst.IntelDBPath, base.IntelDBPath},
		{"SimilarityDBPath", dst.SimilarityDBPath, base.SimilarityDBPath},
		{"IOCAllowlistPath", dst.IOCAllowlistPath, base.IOCAllowlistPath},
	} {
		if p.got != p.want {
			t.Errorf("%s is an input and was rewritten: %q != %q", p.name, p.got, p.want)
		}
	}
}

// TestWatchOutputPathsSkipUnset confirms unrequested artifacts stay unrequested
// — rewriting "" into a bare directory would make watch write files the
// operator never asked for.
func TestWatchOutputPathsSkipUnset(t *testing.T) {
	base := Config{JSONPath: "out/r.json"} // only JSON requested
	var dst Config
	applyWatchOutputPaths(&dst, base, "evil.exe")

	if dst.JSONPath == "" {
		t.Fatal("requested JSON output was dropped")
	}
	for name, got := range map[string]string{
		"ReportPath": dst.ReportPath, "HTMLPath": dst.HTMLPath, "PDFPath": dst.PDFPath,
		"YARAPath": dst.YARAPath, "SigmaPath": dst.SigmaPath, "STIXPath": dst.STIXPath,
		"IOCPath": dst.IOCPath,
	} {
		if got != "" {
			t.Errorf("%s was unset but became %q", name, got)
		}
	}
}

func TestWatchWritesPerFile(t *testing.T) {
	if watchWritesPerFile(Config{}) {
		t.Error("no outputs configured, but watchWritesPerFile reported true")
	}
	if !watchWritesPerFile(Config{JSONPath: "out.json"}) {
		t.Error("JSON output configured, but watchWritesPerFile reported false")
	}
	if !watchWritesPerFile(Config{ReportPackPath: "pack"}) {
		t.Error("report pack configured, but watchWritesPerFile reported false")
	}
}
