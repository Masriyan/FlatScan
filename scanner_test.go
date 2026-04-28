package main

import (
	"archive/zip"
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

func TestIOCTriageSuppressesPKIAndFormatNoise(t *testing.T) {
	raw := ExtractIOCs(`http://crl3.digicert.com/sha2.crl http://schemas.microsoft.com/appx/manifest/foundation/windows10 evil.example.com 1.3.6.1 8.8.8.8`)
	triaged := TriageIOCSet(raw, defaultIOCAllowlist(), func(string, ...any) {})
	if containsStringFold(triaged.Domains, "crl3.digicert.com") || containsStringFold(triaged.Domains, "schemas.microsoft.com") {
		t.Fatalf("expected PKI/schema domains to be suppressed: %#v", triaged.Domains)
	}
	if !containsStringFold(triaged.Domains, "evil.example.com") {
		t.Fatalf("expected evil.example.com to remain: %#v", triaged.Domains)
	}
	if containsStringFold(triaged.IPv4, "1.3.6.1") || !containsStringFold(triaged.IPv4, "8.8.8.8") {
		t.Fatalf("unexpected IPv4 triage result: %#v", triaged.IPv4)
	}
	if triaged.SuppressedCount < 3 || len(triaged.SuppressionLog) == 0 {
		t.Fatalf("expected suppression audit log, got count=%d log=%#v", triaged.SuppressedCount, triaged.SuppressionLog)
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
		{"java-class", []byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34}, "DebugProbesKt.bin", "Java class"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectFileType(tt.data, tt.path); got != tt.want {
				t.Fatalf("DetectFileType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseFlagsInteractiveModesDoNotRequireFile(t *testing.T) {
	for _, args := range [][]string{{"--interactive"}, {"--shell"}} {
		cfg, err := parseFlags(args)
		if err != nil {
			t.Fatalf("parseFlags(%v) error = %v", args, err)
		}
		if !cfg.Interactive && !cfg.CommandShell {
			t.Fatalf("expected interactive or shell mode for args %v: %#v", args, cfg)
		}
	}
}

func TestSplitInteractiveArgs(t *testing.T) {
	args, err := splitInteractiveArgs(`./flatscan -m deep -f "sample with spaces.bin" --report-mode Full --json reports/sample.json --carve`)
	if err != nil {
		t.Fatalf("splitInteractiveArgs() error = %v", err)
	}
	args = stripFlatScanCommand(args)
	want := []string{"-m", "deep", "-f", "sample with spaces.bin", "--report-mode", "Full", "--json", "reports/sample.json", "--carve"}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("unexpected args:\n got %#v\nwant %#v", args, want)
	}
	if _, err := splitInteractiveArgs(`-f "unterminated`); err == nil {
		t.Fatal("expected unterminated quote error")
	}
}

func TestAnalyzeFormatsDetectsMSIXAndPromotesPayloadHashes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "magniber.msix")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	zw := zip.NewWriter(file)
	addZipEntry := func(name string, data []byte) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s error = %v", name, err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("zip write %s error = %v", name, err)
		}
	}
	addZipEntry("AppxManifest.xml", []byte(`<Package><Identity Name="Fake.Package" Publisher="CN=Unknown" Version="1.0.0.0"/><Applications><Application Id="App" Executable="declared.exe"/></Applications><Capabilities><Capability Name="runFullTrust"/></Capabilities></Package>`))
	addZipEntry("AppxSignature.p7x", []byte("dummy-signature"))
	addZipEntry("AppxBlockMap.xml", []byte("<BlockMap/>"))
	addZipEntry("[Content_Types].xml", []byte("<Types/>"))
	addZipEntry("nhmkrt/nhmkrt.exe", append([]byte("MZ"), strings.Repeat("A", 128)...))
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close error = %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("file close error = %v", err)
	}

	result := ScanResult{Target: path, FileName: filepath.Base(path), FileType: "ZIP container"}
	cfg := Config{Mode: "deep", MinStringLen: 5, MaxArchiveFiles: 100}
	if err := AnalyzeFormats(&result, cfg, nil, func(string, ...any) {}); err != nil {
		t.Fatalf("AnalyzeFormats() error = %v", err)
	}
	if result.FileType != "MSIX/AppX package" || result.MSIX == nil {
		t.Fatalf("expected MSIX metadata, got type=%q msix=%#v", result.FileType, result.MSIX)
	}
	if result.MSIX.IdentityName != "Fake.Package" || !containsStringFold(result.MSIX.Capabilities, "runFullTrust") {
		t.Fatalf("unexpected MSIX metadata: %#v", result.MSIX)
	}
	if !containsStringFold(result.MSIX.UndeclaredExecutables, "nhmkrt/nhmkrt.exe") {
		t.Fatalf("expected undeclared payload, got %#v", result.MSIX.UndeclaredExecutables)
	}
	if len(result.IOCs.PEHashes) != 1 || result.IOCs.PEHashes[0].Path != "nhmkrt/nhmkrt.exe" {
		t.Fatalf("expected promoted PE hash, got %#v", result.IOCs.PEHashes)
	}
	if !hasFindingTitle(result.Findings, "Hidden executable payloads not declared in manifest") {
		t.Fatalf("expected hidden payload finding, got %#v", result.Findings)
	}
	if !hasFindingTitle(result.Findings, "Obfuscated identical-name executable directory") {
		t.Fatalf("expected obfuscated name finding, got %#v", result.Findings)
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

func TestRenderSigmaRule(t *testing.T) {
	result := ScanResult{
		Version:   version,
		FileName:  "sample.apk",
		FileType:  "APK package",
		Verdict:   "Suspicious",
		RiskScore: 45,
		Hashes: Hashes{
			SHA256: "ee77c05139a72dc3f1c86391c2bb0c16f198249ae4f099adf3f27ec3a7f0cf4b",
		},
		APK: &APKInfo{
			PackageName: "com.example.test",
			Permissions: []AndroidPermission{
				{Name: "android.permission.SEND_SMS", Risk: "Medium", Category: "sms"},
			},
			ExportedComponents: []AndroidComponent{
				{Type: "receiver", Name: "com.example.test.BootReceiver", Exported: true},
			},
		},
	}
	rule := RenderSigmaRule(result)
	for _, want := range []string{
		`title: "FlatScan Hunt - sample.apk"`,
		`product: android`,
		`PackageName: "com.example.test"`,
		`Permissions|contains:`,
		`level: medium`,
	} {
		if !strings.Contains(rule, want) {
			t.Fatalf("Sigma rule missing %q:\n%s", want, rule)
		}
	}
}

func TestApplyRulePacks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.rule")
	content := strings.Join([]string{
		"id: test.exec",
		"name: Test Exec Rule",
		"severity: Medium",
		"category: Test",
		"score: 7",
		"strings_any: Runtime.exec, CreateRemoteThread",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	result := ScanResult{FileType: "unknown binary"}
	cfg := Config{RulePaths: path}
	items := []ExtractedString{{Value: "java.lang.Runtime.exec", Encoding: "ascii"}}
	ApplyRulePacks(&result, items, cfg, func(string, ...any) {})
	if len(result.RuleMatches) != 1 {
		t.Fatalf("expected one rule match, got %#v", result.RuleMatches)
	}
	if len(result.Findings) != 1 || result.Findings[0].Title != "Test Exec Rule" {
		t.Fatalf("unexpected findings: %#v", result.Findings)
	}
}

func TestRenderHTMLReport(t *testing.T) {
	result := ScanResult{
		Version:   version,
		FileName:  "sample.bin",
		Target:    "sample.bin",
		FileType:  "unknown binary",
		Verdict:   "Suspicious",
		RiskScore: 42,
		Hashes:    Hashes{SHA256: strings.Repeat("a", 64)},
		Findings:  []Finding{{Severity: "Medium", Category: "Test", Title: "HTML finding", Score: 10}},
	}
	html := RenderHTMLReport(result)
	for _, want := range []string{"FlatScan Malware Analysis Report", "HTML finding", "Raw JSON"} {
		if !strings.Contains(html, want) {
			t.Fatalf("HTML report missing %q:\n%s", want, html)
		}
	}
}
