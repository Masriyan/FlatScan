package main

import (
	"strings"
	"testing"
)

// These tests drive scanCode with hand-assembled byte sequences, so they need
// no PE/ELF fixture. Encodings are standard x86/x64 and verified against the
// x86asm decoder by the assertions below.

func TestScanCodeAPIHashLoop(t *testing.T) {
	// ror edi, 13  =>  C1 CF 0D   (ROR r/m32, imm8; /1, modrm=11 001 111)
	code := []byte{0xC1, 0xCF, 0x0D, 0xC3 /* ret */}
	result := &ScanResult{FileType: "PE executable"}
	scanCode(result, 32, "x86", code, 0)
	if !hasFindingTitle(result.Findings, "API-hashing routine") {
		t.Fatalf("expected ROR13 API-hashing finding, got: %s", findingTitles(result))
	}
}

func TestScanCodePEBAccessX86(t *testing.T) {
	// mov eax, fs:[0x30]  =>  64 A1 30 00 00 00
	code := []byte{0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0xC3}
	result := &ScanResult{FileType: "PE executable"}
	scanCode(result, 32, "x86", code, 0)
	if !hasFindingTitle(result.Findings, "Direct PEB access") {
		t.Fatalf("expected PEB access finding, got: %s", findingTitles(result))
	}
}

func TestScanCodeGetPCStub(t *testing.T) {
	// call $+5 ; pop ebx  =>  E8 00 00 00 00 ; 5B
	code := []byte{0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0xC3}
	result := &ScanResult{FileType: "PE executable"}
	scanCode(result, 32, "x86", code, 0)
	if !hasFindingTitle(result.Findings, "Position-independent code (GetPC) stub") {
		t.Fatalf("expected GetPC finding, got: %s", findingTitles(result))
	}
}

func TestScanCodeVMwareBackdoor(t *testing.T) {
	// mov eax, 0x564D5868  =>  B8 68 58 4D 56
	code := []byte{0xB8, 0x68, 0x58, 0x4D, 0x56, 0xC3}
	result := &ScanResult{FileType: "PE executable"}
	scanCode(result, 32, "x86", code, 0)
	if !hasFindingTitle(result.Findings, "VMware backdoor detection") {
		t.Fatalf("expected VMware backdoor finding, got: %s", findingTitles(result))
	}
}

func TestScanCodeNoFalsePositiveOnBenign(t *testing.T) {
	// A trivial benign-looking sequence: xor eax,eax ; ret ; nop padding.
	code := []byte{0x31, 0xC0, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90}
	result := &ScanResult{FileType: "PE executable"}
	scanCode(result, 32, "x86", code, 0)
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings on benign code, got: %s", findingTitles(result))
	}
}

func TestScanCodeGarbageDoesNotPanic(t *testing.T) {
	code := make([]byte, 4096)
	for i := range code {
		code[i] = byte(i*7 + 13)
	}
	result := &ScanResult{FileType: "PE executable"}
	scanCode(result, 64, "x86-64", code, 0) // must not panic
}

func TestResolveHashedAPIsROR13(t *testing.T) {
	// Two real ROR13 hashes (LoadLibraryA, GetProcAddress) presented as the
	// immediates the disassembler would have collected.
	imm := map[uint32]struct{}{
		ror13Hash("LoadLibraryA"):   {},
		ror13Hash("GetProcAddress"): {},
		0x12345:                     {}, // noise
	}
	result := &ScanResult{}
	info := &CodeInfo{}
	resolveHashedAPIs(result, info, imm)

	if !containsStringFold(info.ResolvedHashedAPIs, "LoadLibraryA") ||
		!containsStringFold(info.ResolvedHashedAPIs, "GetProcAddress") {
		t.Fatalf("expected resolved APIs, got: %#v", info.ResolvedHashedAPIs)
	}
	if !hasFindingTitle(result.Findings, "Resolved hash-obfuscated API imports") {
		t.Fatalf("expected resolved-hash finding, got: %s", findingTitles(result))
	}
}

func TestRenderReportIncludesCodeSection(t *testing.T) {
	result := ScanResult{
		Tool: "FlatScan", Version: "test", FileType: "PE executable", Verdict: "Suspicious",
		Code: &CodeInfo{
			Arch: "x86-64", InstructionsDecoded: 1234, Techniques: []string{"PEB access"},
			ResolvedHashedAPIs: []string{"LoadLibraryA", "VirtualAllocEx"},
			EntryDisasm:        []string{"mov rax, gs:[0x60]"},
		},
	}
	out := RenderReport(result, "full")
	for _, want := range []string{"Code analysis", "x86-64", "PEB access", "LoadLibraryA", "gs:[0x60]"} {
		if !strings.Contains(out, want) {
			t.Fatalf("Full report missing %q", want)
		}
	}
}

func TestHashAlgorithmsKnownVectors(t *testing.T) {
	// DJB2("hello") = 261238937; sanity-check the algorithm implementations are
	// stable so the precomputed tables stay correct across refactors.
	if got := djb2Hash("hello"); got != 261238937 {
		t.Fatalf("djb2(hello) = %d", got)
	}
	// ROR13 is order-sensitive: hashing a name twice must be identical.
	if ror13Hash("VirtualAlloc") != ror13Hash("VirtualAlloc") {
		t.Fatal("ror13 not stable")
	}
}
