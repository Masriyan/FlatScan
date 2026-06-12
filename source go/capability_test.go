package main

import (
	"strings"
	"testing"
)

func TestCapabilityInjectionFromResolvedHashes(t *testing.T) {
	// The killer feature: APIs resolved by hash (no cleartext string) still
	// satisfy the injection capability because hashdb-recovered names are in the
	// feature set.
	result := &ScanResult{
		Code: &CodeInfo{ResolvedHashedAPIs: []string{"WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx"}},
	}
	RunCapabilityRules(result, "") // empty corpus on purpose
	if !hasFindingTitle(result.Findings, "Capability: Process injection") {
		t.Fatalf("injection capability should fire from resolved hashes, got: %s", findingTitles(result))
	}
}

func TestCapabilityInjectionNeedsAllGroups(t *testing.T) {
	result := &ScanResult{Code: &CodeInfo{ResolvedHashedAPIs: []string{"VirtualAllocEx"}}}
	RunCapabilityRules(result, "")
	if hasFindingTitle(result.Findings, "Capability: Process injection") {
		t.Fatalf("injection must require all 3 groups, not 1: %s", findingTitles(result))
	}
}

func TestCapabilityDisableSecurity(t *testing.T) {
	result := &ScanResult{}
	RunCapabilityRules(result, "set-mppreference -disablerealtimemonitoring $true ... windows defender")
	if !hasFindingTitle(result.Findings, "Capability: Disable security tooling") {
		t.Fatalf("expected disable-security capability, got: %s", findingTitles(result))
	}
}

func TestYARAQualityScoring(t *testing.T) {
	// Strong rule: URLs + registry keys + PE imphash.
	strong := ScanResult{
		FileType: "PE executable",
		PE:       &PEInfo{ImportHash: "abc"},
		IOCs: IOCSet{
			URLs:         []string{"http://evil.example.com/a", "http://evil.example.com/b"},
			RegistryKeys: []string{`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\x`},
		},
		SuspiciousStrings: []string{"inject payload here"},
	}
	entries := yaraStringEntries(strong)
	score, risk := yaraRuleQuality(strong, entries)
	if score < 40 || risk == "high" {
		t.Errorf("strong rule should score well / low-medium risk, got score=%d risk=%s", score, risk)
	}

	// Weak rule: nothing useful.
	weak := ScanResult{FileType: "unknown binary"}
	wEntries := yaraStringEntries(weak)
	_, wRisk := yaraRuleQuality(weak, wEntries)
	if wRisk != "high" {
		t.Errorf("empty rule should be high FP risk, got %s", wRisk)
	}
}

func TestYARAExcludesCompilerStrings(t *testing.T) {
	if !isCompilerOrLibraryString("GCC: (Ubuntu 11.4.0)") {
		t.Error("GCC toolchain string should be excluded")
	}
	if !isCompilerOrLibraryString("/root/.cargo/registry/src/foo/lib.rs") {
		t.Error("cargo source path should be excluded")
	}
	if isCompilerOrLibraryString("http://evil-c2.top/gate.php") {
		t.Error("a real C2 URL must not be excluded")
	}
}

func TestRenderYARAIncludesQualityMeta(t *testing.T) {
	result := ScanResult{FileName: "x.exe", FileType: "PE executable", Hashes: Hashes{SHA256: "ab"}}
	out := RenderYARARule(result)
	if !strings.Contains(out, "rule_quality_score") || !strings.Contains(out, "expected_fp_risk") {
		t.Fatalf("YARA rule missing quality meta:\n%s", out)
	}
}
