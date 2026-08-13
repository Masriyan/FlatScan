package main

import (
	"strings"
	"testing"
)

// The API-hash tables are the kind of code that fails silently: if a hash
// constant or a rotation is wrong, no test crashes and no output looks broken —
// FlatScan simply stops recovering hashed imports, and loaders that resolve
// APIs by hash quietly lose their strongest finding. The expected values below
// are therefore pinned literals, computed independently from the algorithm
// definitions rather than captured from this implementation's own output.

// TestROR13HashKnownVectors pins ROR13, the algorithm used by Metasploit
// block_api shellcode and a large share of commodity loaders.
func TestROR13HashKnownVectors(t *testing.T) {
	// Reference values for the classic ROR13 construction over the name's bytes
	// only: h = ror(h, 13) + c.
	//
	// Note these are NOT the hashes commonly published alongside Metasploit
	// block_api (LoadLibraryA = 0x0726774C etc.) — those fold the terminating
	// NUL byte and correspond to ror13HashNull, covered separately below. Do not
	// "correct" these to the published values; they pin a different variant.
	tests := []struct {
		name string
		want uint32
	}{
		{"LoadLibraryA", 0xEC0E4E8E},
		{"GetProcAddress", 0x7C0DFCAA},
		{"VirtualAlloc", 0x91AFCA54},
		{"WinExec", 0x0E8AFE98},
		{"ExitProcess", 0x73E2D87E},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ror13Hash(tt.name); got != tt.want {
				t.Fatalf("ror13Hash(%q) = 0x%08X, want 0x%08X", tt.name, got, tt.want)
			}
		})
	}
}

// TestDJB2HashKnownVectors pins DJB2 (h = h*33 + c, seeded at 5381).
func TestDJB2HashKnownVectors(t *testing.T) {
	tests := []struct {
		name string
		want uint32
	}{
		{"", 5381},
		{"a", 177670},
		{"LoadLibraryA", 0x5FBFF0FB},
	}
	for _, tt := range tests {
		t.Run("djb2/"+tt.name, func(t *testing.T) {
			if got := djb2Hash(tt.name); got != tt.want {
				t.Fatalf("djb2Hash(%q) = 0x%08X (%d), want 0x%08X (%d)",
					tt.name, got, got, tt.want, tt.want)
			}
		})
	}
}

// TestSDBMHashKnownVectors pins SDBM (h = c + (h<<6) + (h<<16) - h).
func TestSDBMHashKnownVectors(t *testing.T) {
	tests := []struct {
		name string
		want uint32
	}{
		{"", 0},
		{"a", 97},
		{"ab", 6363201},
	}
	for _, tt := range tests {
		t.Run("sdbm/"+tt.name, func(t *testing.T) {
			if got := sdbmHash(tt.name); got != tt.want {
				t.Fatalf("sdbmHash(%q) = %d, want %d", tt.name, got, tt.want)
			}
		})
	}
}

// TestROR13NullVariantDiffersFromPlain guards the distinction between the two
// ROR13 variants. Folding the terminating NUL is a real difference used by
// different loader families; if the two produced identical tables, one of the
// variants would be dead weight and half the ROR13 samples would go unmatched.
func TestROR13NullVariantDiffersFromPlain(t *testing.T) {
	const name = "LoadLibraryA"
	plain, withNull := ror13Hash(name), ror13HashNull(name)
	if plain == withNull {
		t.Fatalf("ror13Hash and ror13HashNull both returned 0x%08X; the NUL-folding variant is not distinct", plain)
	}
	// The NUL variant is one extra rotate of the plain result.
	want := (plain >> 13) | (plain << 19)
	if withNull != want {
		t.Fatalf("ror13HashNull(%q) = 0x%08X, want 0x%08X (one further rotation of the plain hash)",
			name, withNull, want)
	}
}

// TestAPIHashTablesAreCollisionFree checks the premise the whole approach rests
// on: "a 32-bit collision against a fixed small dictionary is astronomically
// unlikely". If two dictionary entries ever collide under an algorithm, one name
// silently shadows the other and the wrong API is reported.
func TestAPIHashTablesAreCollisionFree(t *testing.T) {
	// The dictionary intentionally contains a duplicate ("GetProcAddress"
	// appears twice), which is not a collision — count distinct names.
	distinct := make(map[string]struct{}, len(apiHashDictionary))
	for _, n := range apiHashDictionary {
		distinct[n] = struct{}{}
	}

	for _, algo := range apiHashAlgos {
		if len(algo.hashes) != len(distinct) {
			t.Errorf("%s table holds %d entries for %d distinct API names — two names hash alike and one is unreachable",
				algo.name, len(algo.hashes), len(distinct))
		}
	}
}

// TestResolveHashedAPIsRecoversNames drives the positive path: immediates that
// are ROR13 hashes of real API names must resolve back to those names, be
// recorded on the CodeInfo, and produce a finding.
func TestResolveHashedAPIsRecoversNames(t *testing.T) {
	result := &ScanResult{}
	t.Cleanup(func() { releaseFindingIndex(result) })
	info := &CodeInfo{}

	immediates := map[uint32]struct{}{
		ror13Hash("VirtualAlloc"):       {},
		ror13Hash("WriteProcessMemory"): {},
		ror13Hash("CreateRemoteThread"): {},
		0xDEADBEEF:                      {}, // unrelated constant — must be ignored
	}

	resolveHashedAPIs(result, info, immediates)

	if len(info.ResolvedHashedAPIs) != 3 {
		t.Fatalf("ResolvedHashedAPIs = %v, want the 3 seeded names", info.ResolvedHashedAPIs)
	}
	for _, want := range []string{"CreateRemoteThread", "VirtualAlloc", "WriteProcessMemory"} {
		if !anyNameFold(info.ResolvedHashedAPIs, want) {
			t.Fatalf("ResolvedHashedAPIs = %v, missing %q", info.ResolvedHashedAPIs, want)
		}
	}
	// Sorted output keeps reports stable across runs (map iteration is random).
	for i := 1; i < len(info.ResolvedHashedAPIs); i++ {
		if info.ResolvedHashedAPIs[i-1] > info.ResolvedHashedAPIs[i] {
			t.Fatalf("ResolvedHashedAPIs not sorted: %v", info.ResolvedHashedAPIs)
		}
	}

	if len(result.Functions) != 3 {
		t.Fatalf("Functions = %+v, want 3 recovered entries", result.Functions)
	}
	for _, fn := range result.Functions {
		if !strings.Contains(fn.Source, "resolved-hash") || !strings.Contains(fn.Source, "ROR13") {
			t.Fatalf("Function %q Source = %q, want it to name the resolving algorithm", fn.Name, fn.Source)
		}
	}

	var finding *Finding
	for i := range result.Findings {
		if strings.Contains(result.Findings[i].Title, "Resolved hash-obfuscated API") {
			finding = &result.Findings[i]
			break
		}
	}
	if finding == nil {
		t.Fatal("no finding recorded for recovered hashed imports")
	}
	// The injection toolkit (WriteProcessMemory + CreateRemoteThread) scores
	// higher than a generic recovery.
	if finding.Score != 26 {
		t.Fatalf("finding score = %d, want 26 for a resolved injection toolkit", finding.Score)
	}
}

// TestResolveHashedAPIsRequiresCorroboration pins the anti-false-positive rule:
// a single match with no independent evidence of a hashing loop is treated as a
// possible coincidence and ignored.
func TestResolveHashedAPIsRequiresCorroboration(t *testing.T) {
	t.Run("single match without hashing loop is ignored", func(t *testing.T) {
		result := &ScanResult{}
		t.Cleanup(func() { releaseFindingIndex(result) })
		info := &CodeInfo{}
		resolveHashedAPIs(result, info, map[uint32]struct{}{ror13Hash("VirtualAlloc"): {}})

		if len(info.ResolvedHashedAPIs) != 0 {
			t.Fatalf("ResolvedHashedAPIs = %v, want none: one match alone is not evidence",
				info.ResolvedHashedAPIs)
		}
		if len(result.Findings) != 0 {
			t.Fatalf("Findings = %+v, want none", result.Findings)
		}
	})

	t.Run("single match is accepted when a hashing loop was detected", func(t *testing.T) {
		result := &ScanResult{}
		t.Cleanup(func() { releaseFindingIndex(result) })
		info := &CodeInfo{Techniques: []string{"API hashing (ROR13) loop"}}
		resolveHashedAPIs(result, info, map[uint32]struct{}{ror13Hash("VirtualAlloc"): {}})

		if len(info.ResolvedHashedAPIs) != 1 {
			t.Fatalf("ResolvedHashedAPIs = %v, want the single corroborated match",
				info.ResolvedHashedAPIs)
		}
	})
}

// TestResolveHashedAPIsDegenerateInput covers the nil/empty paths — this runs
// inside the scan pipeline, so it must not panic on absent disassembly.
func TestResolveHashedAPIsDegenerateInput(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("resolveHashedAPIs panicked on degenerate input: %v", r)
		}
	}()

	info := &CodeInfo{}
	resolveHashedAPIs(nil, info, map[uint32]struct{}{1: {}})
	resolveHashedAPIs(&ScanResult{}, nil, map[uint32]struct{}{1: {}})
	resolveHashedAPIs(&ScanResult{}, info, nil)
	resolveHashedAPIs(&ScanResult{}, info, map[uint32]struct{}{})

	if len(info.ResolvedHashedAPIs) != 0 {
		t.Fatalf("degenerate input produced results: %v", info.ResolvedHashedAPIs)
	}
}

// TestResolveHashedAPIsPicksBestAlgorithm confirms the algorithm with the most
// matches wins, rather than whichever happens to be checked first.
func TestResolveHashedAPIsPicksBestAlgorithm(t *testing.T) {
	result := &ScanResult{}
	t.Cleanup(func() { releaseFindingIndex(result) })
	info := &CodeInfo{}

	// Three DJB2 hashes against a single ROR13 hash.
	immediates := map[uint32]struct{}{
		djb2Hash("LoadLibraryA"):   {},
		djb2Hash("GetProcAddress"): {},
		djb2Hash("VirtualAlloc"):   {},
		ror13Hash("WinExec"):       {},
	}
	resolveHashedAPIs(result, info, immediates)

	if len(info.ResolvedHashedAPIs) != 3 {
		t.Fatalf("ResolvedHashedAPIs = %v, want the 3 DJB2 matches", info.ResolvedHashedAPIs)
	}
	for _, fn := range result.Functions {
		if !strings.Contains(fn.Source, "DJB2") {
			t.Fatalf("Function %q resolved via %q, want the DJB2 table to win", fn.Name, fn.Source)
		}
	}
}

// TestAPINameFamilyClassification pins the behavior families that drive
// severity in the report.
func TestAPINameFamilyClassification(t *testing.T) {
	tests := []struct {
		name       string
		wantFamily string
		wantSev    string
	}{
		{"WriteProcessMemory", "process injection", "High"},
		{"NtCreateThreadEx", "process injection", "High"},
		{"URLDownloadToFileA", "downloader", "High"},
		{"WinHttpOpen", "downloader", "High"},
		{"LoadLibraryA", "dynamic loading", "Medium"},
		{"GetProcAddress", "dynamic loading", "Medium"},
		{"WinExec", "execution", "Medium"},
		{"RegSetValueExA", "persistence", "Medium"},
		{"IsDebuggerPresent", "anti-analysis", "Medium"},
		{"Sleep", "api", "Low"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fam, sev := apiNameFamily(tt.name)
			if fam != tt.wantFamily || sev != tt.wantSev {
				t.Fatalf("apiNameFamily(%q) = (%q,%q), want (%q,%q)",
					tt.name, fam, sev, tt.wantFamily, tt.wantSev)
			}
		})
	}
}
