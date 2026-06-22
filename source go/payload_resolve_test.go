package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"strings"
	"testing"
)

// minimalValidPE builds a small but structurally valid PE (MZ header, e_lfanew
// at 0x3c pointing to a "PE\0\0" signature) with caller-supplied marker strings
// appended so the recovered-stage sub-scan has indicators to find. Valid enough
// to satisfy both DetectFileType and the carver's validCarveAt check.
func minimalValidPE(markers ...string) []byte {
	buf := make([]byte, 0, 1024)
	buf = append(buf, 'M', 'Z')
	for len(buf) < 0x3c {
		buf = append(buf, 0)
	}
	buf = append(buf, 0x80, 0x00, 0x00, 0x00) // e_lfanew = 0x80
	for len(buf) < 0x80 {
		buf = append(buf, 0)
	}
	buf = append(buf, 'P', 'E', 0, 0)
	for len(buf) < 0x100 {
		buf = append(buf, 0)
	}
	for _, m := range markers {
		buf = append(buf, []byte(m)...)
		buf = append(buf, 0)
	}
	for len(buf) < 512 {
		buf = append(buf, 0)
	}
	return buf
}

func resolveTestConfig() Config {
	return Config{Mode: "standard", MinStringLen: 5, MaxDecodeDepth: 2, MaxCarves: 80, MaxPayloadDepth: 3}
}

func runResolve(t *testing.T, data []byte) *ScanResult {
	t.Helper()
	cfg := resolveTestConfig()
	res := &ScanResult{Mode: cfg.Mode, FileType: DetectFileType(data, "")}
	extracted, _, _ := ExtractStrings(data, cfg.MinStringLen, stringLimitForMode(cfg.Mode))
	ResolvePayloads(res, data, extracted, cfg, func(string, ...any) {})
	return res
}

func findNode(res *ScanResult, predicate func(PayloadNode) bool) (PayloadNode, bool) {
	for _, n := range res.PayloadTree {
		if predicate(n) {
			return n, true
		}
	}
	return PayloadNode{}, false
}

func TestResolveBase64PEInScript(t *testing.T) {
	pe := minimalValidPE("http://evil.example.com/gate.php", "InternetOpenUrlA")
	b64 := base64.StdEncoding.EncodeToString(pe)
	script := []byte("$p = '" + b64 + "'; IEX([System.Convert]::FromBase64String($p))")

	res := runResolve(t, script)
	node, ok := findNode(res, func(n PayloadNode) bool {
		return n.Method == "base64" && n.FileType == "PE executable"
	})
	if !ok {
		t.Fatalf("expected a base64-decoded PE node, got tree: %#v", res.PayloadTree)
	}
	if !containsString(node.IOCs, "http://evil.example.com/gate.php") {
		t.Errorf("recovered PE stage did not surface its C2 URL, IOCs=%v", node.IOCs)
	}
	if !hasFindingTitle(res.Findings, "Obfuscated executable payload resolved") {
		t.Errorf("expected obfuscated-payload finding, findings=%v", findingTitles(res))
	}
}

func TestResolveGzipPE(t *testing.T) {
	pe := minimalValidPE("http://gz.example.com/p")
	var gzbuf bytes.Buffer
	gw := gzip.NewWriter(&gzbuf)
	gw.Write(pe)
	gw.Close()
	// Embed the gzip stream after a benign prefix so it is found mid-buffer.
	data := append([]byte("benign header bytes padding padding padding\n"), gzbuf.Bytes()...)

	res := runResolve(t, data)
	if _, ok := findNode(res, func(n PayloadNode) bool {
		return n.Method == "gzip" && n.FileType == "PE executable"
	}); !ok {
		t.Fatalf("expected a gzip-inflated PE node, got tree: %#v", res.PayloadTree)
	}
}

func TestResolveXORPE(t *testing.T) {
	pe := minimalValidPE("http://xor.example.com/c2")
	const key = 0x5a
	xored := make([]byte, len(pe))
	for i, b := range pe {
		xored[i] = b ^ key
	}
	res := runResolve(t, xored)
	node, ok := findNode(res, func(n PayloadNode) bool {
		return strings.HasPrefix(n.Method, "xor:") && n.FileType == "PE executable"
	})
	if !ok {
		t.Fatalf("expected an XOR-decoded PE node, got tree: %#v", res.PayloadTree)
	}
	if node.Method != "xor:0x5a" {
		t.Errorf("expected method xor:0x5a, got %q", node.Method)
	}
}

func TestResolveNestedBase64ThenGzip(t *testing.T) {
	pe := minimalValidPE("http://nested.example.com/stage2")
	var gzbuf bytes.Buffer
	gw := gzip.NewWriter(&gzbuf)
	gw.Write(pe)
	gw.Close()
	b64 := base64.StdEncoding.EncodeToString(gzbuf.Bytes())
	data := []byte("config='" + b64 + "'")

	res := runResolve(t, data)
	// The inner PE should be reached at depth >= 1 after base64 -> gzip peeling.
	if _, ok := findNode(res, func(n PayloadNode) bool {
		return n.FileType == "PE executable" && n.Depth >= 1
	}); !ok {
		t.Fatalf("expected nested PE recovered after base64->gzip, tree: %#v", res.PayloadTree)
	}
}

func TestResolveQuickModeSkipped(t *testing.T) {
	pe := minimalValidPE("http://evil.example.com/x")
	b64 := base64.StdEncoding.EncodeToString(pe)
	data := []byte("x='" + b64 + "'")
	cfg := resolveTestConfig()
	cfg.Mode = "quick"
	res := &ScanResult{Mode: cfg.Mode}
	extracted, _, _ := ExtractStrings(data, cfg.MinStringLen, stringLimitForMode(cfg.Mode))
	ResolvePayloads(res, data, extracted, cfg, func(string, ...any) {})
	if len(res.PayloadTree) != 0 {
		t.Fatalf("payload resolution must be gated off in quick mode, got %d nodes", len(res.PayloadTree))
	}
}

func TestResolveNoFalsePositiveOnText(t *testing.T) {
	data := []byte("This is an ordinary configuration file with some words and numbers 12345 and a path /etc/hosts and nothing encoded here at all.")
	res := runResolve(t, data)
	if len(res.PayloadTree) != 0 {
		t.Fatalf("expected no buried payloads in plain text, got %#v", res.PayloadTree)
	}
}

// --- small local helpers ---

func containsString(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}
