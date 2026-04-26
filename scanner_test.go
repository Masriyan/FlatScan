package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractIOCs(t *testing.T) {
	text := `hxxp://evil.example.com/payload.exe 192.168.1.10 CVE-2025-12345 HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	iocs := ExtractIOCs(text)
	if len(iocs.URLs) != 1 || iocs.URLs[0] != "http://evil.example.com/payload.exe" {
		t.Fatalf("unexpected URLs: %#v", iocs.URLs)
	}
	if len(iocs.IPv4) != 1 || iocs.IPv4[0] != "192.168.1.10" {
		t.Fatalf("unexpected IPv4 values: %#v", iocs.IPv4)
	}
	if len(iocs.CVEs) != 1 || iocs.CVEs[0] != "CVE-2025-12345" {
		t.Fatalf("unexpected CVEs: %#v", iocs.CVEs)
	}
	if len(iocs.RegistryKeys) != 1 {
		t.Fatalf("expected registry key IOC, got %#v", iocs.RegistryKeys)
	}
}

func TestDecodeSuspiciousStringsExtractsNestedIOC(t *testing.T) {
	cfg := Config{Mode: "quick", MaxDecodeDepth: 2}
	items := []ExtractedString{
		{Value: "aHR0cDovL2V2aWwuZXhhbXBsZS5jb20vYw==", Offset: 10, Encoding: "ascii"},
	}
	decoded := DecodeSuspiciousStrings(items, cfg)
	if len(decoded) == 0 {
		t.Fatal("expected decoded artifact")
	}
	if len(decoded[0].IOCs.URLs) != 1 || decoded[0].IOCs.URLs[0] != "http://evil.example.com/c" {
		t.Fatalf("unexpected decoded IOCs: %#v", decoded[0].IOCs)
	}
}

func TestDetectFileType(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		path string
		want string
	}{
		{"pe", []byte("MZ\x90\x00"), "a.exe", "PE executable"},
		{"elf", []byte("\x7fELF\x02\x01"), "a", "ELF binary"},
		{"pdf", []byte("%PDF-1.7"), "a.pdf", "PDF document"},
		{"zip", []byte{'P', 'K', 0x03, 0x04}, "a.zip", "ZIP container"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectFileType(tt.data, tt.path); got != tt.want {
				t.Fatalf("DetectFileType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWritePDFReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.pdf")
	result := ScanResult{
		Tool:      "FlatScan",
		Version:   version,
		Mode:      "deep",
		Target:    "sample.bin",
		FileName:  "sample.bin",
		FileType:  "PE executable",
		Size:      1234,
		RiskScore: 75,
		Verdict:   "High suspicion",
		Hashes: Hashes{
			MD5:    "d41d8cd98f00b204e9800998ecf8427e",
			SHA1:   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
			SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			SHA512: strings.Repeat("a", 128),
		},
		Findings: []Finding{
			{
				Severity:       "High",
				Category:       "Exfiltration",
				Title:          "Discord webhook exfiltration endpoint",
				Evidence:       "https://discord.com/api/webhooks/example",
				Score:          28,
				Tactic:         "Exfiltration",
				Technique:      "Exfiltration Over Web Service (T1567)",
				Recommendation: "Revoke the webhook and hunt for POST traffic.",
			},
		},
		IOCs: IOCSet{URLs: []string{"https://discord.com/api/webhooks/example"}},
	}
	if err := WritePDFReport(path, result); err != nil {
		t.Fatalf("WritePDFReport() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.HasPrefix(string(data), "%PDF-1.4") {
		t.Fatalf("PDF header missing: %q", string(data[:8]))
	}
}

func TestRenderYARARule(t *testing.T) {
	result := ScanResult{
		Version:   version,
		FileName:  "sample.exe",
		FileType:  "PE executable",
		Verdict:   "Likely malicious",
		RiskScore: 90,
		Hashes: Hashes{
			SHA256: "ee77c05139a72dc3f1c86391c2bb0c16f198249ae4f099adf3f27ec3a7f0cf4b",
		},
		IOCs: IOCSet{
			URLs:    []string{"https://discord.com/api/webhooks/example"},
			Domains: []string{"discord.com"},
		},
		SuspiciousStrings: []string{"encrypted_key", "BCryptDecrypt"},
	}
	rule := RenderYARARule(result)
	for _, want := range []string{
		"rule FlatScan_sample_ee77c051",
		`sha256 = "ee77c05139a72dc3f1c86391c2bb0c16f198249ae4f099adf3f27ec3a7f0cf4b"`,
		`$url001 = "https://discord.com/api/webhooks/example" ascii wide`,
		"uint16(0) == 0x5a4d",
	} {
		if !strings.Contains(rule, want) {
			t.Fatalf("YARA rule missing %q:\n%s", want, rule)
		}
	}
}
