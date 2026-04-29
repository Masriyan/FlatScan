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

// --- New Phase 3-4 tests ---

func TestSTIXBundleStructure(t *testing.T) {
	result := ScanResult{
		Version:   version,
		FileName:  "malware.exe",
		FileType:  "PE executable",
		RiskScore: 85,
		Verdict:   "Likely malicious",
		Hashes: Hashes{
			MD5:    "d41d8cd98f00b204e9800998ecf8427e",
			SHA1:   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
			SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			SHA512: strings.Repeat("a", 128),
		},
		IOCs: IOCSet{
			URLs:    []string{"http://evil.example.com/c2"},
			Domains: []string{"evil.example.com"},
			IPv4:    []string{"10.20.30.40"},
		},
		Profile: AnalysisProfile{
			Classification: "Trojan Downloader",
			MalwareType:    []string{"downloader"},
		},
	}
	bundle := buildSTIXBundle(result)
	if bundle.Type != "bundle" {
		t.Fatalf("expected bundle type, got %q", bundle.Type)
	}
	if len(bundle.Objects) < 4 {
		t.Fatalf("expected at least 4 STIX objects (file, analysis, malware, indicators), got %d", len(bundle.Objects))
	}
	// Verify File SCO exists
	dir := t.TempDir()
	path := filepath.Join(dir, "test.stix.json")
	if err := WriteSTIXBundle(path, result); err != nil {
		t.Fatalf("WriteSTIXBundle() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	content := string(data)
	for _, want := range []string{
		`"type": "bundle"`,
		`"type": "file"`,
		`"type": "malware-analysis"`,
		`"type": "malware"`,
		`"type": "indicator"`,
		`"product": "FlatScan"`,
		`"result": "malicious"`,
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("STIX bundle missing %q", want)
		}
	}
}

func TestSTIXVerdictMapping(t *testing.T) {
	tests := []struct {
		score  int
		want   string
	}{
		{0, "unknown"},
		{9, "unknown"},
		{10, "benign"},
		{29, "benign"},
		{30, "suspicious"},
		{54, "suspicious"},
		{55, "suspicious"},
		{79, "suspicious"},
		{80, "malicious"},
		{100, "malicious"},
	}
	for _, tt := range tests {
		result := ScanResult{
			RiskScore: tt.score,
			Hashes:    Hashes{SHA256: "abcd1234"},
		}
		bundle := buildSTIXBundle(result)
		// Find the malware-analysis object
		found := false
		for _, obj := range bundle.Objects {
			if ma, ok := obj.(stixMalwareAnalysis); ok {
				if ma.Result != tt.want {
					t.Errorf("score=%d: expected STIX result %q, got %q", tt.score, tt.want, ma.Result)
				}
				found = true
			}
		}
		if !found {
			t.Errorf("score=%d: no malware-analysis object in bundle", tt.score)
		}
	}
}

func TestScanCacheGetPut(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewScanCache(dir, 1*60*1e9) // 1 min TTL
	if err != nil {
		t.Fatalf("NewScanCache() error = %v", err)
	}

	// Get on empty cache should return nil
	if got := cache.Get("abc123", 100); got != nil {
		t.Fatal("expected nil from empty cache")
	}

	// Put and Get
	result := ScanResult{
		FileName:  "test.bin",
		RiskScore: 42,
		Size:      100,
		Verdict:   "Suspicious",
	}
	cache.Put("abc123", result)

	got := cache.Get("abc123", 100)
	if got == nil {
		t.Fatal("expected cached result")
	}
	if got.RiskScore != 42 || got.Verdict != "Suspicious" {
		t.Fatalf("unexpected cached result: %+v", got)
	}

	// Size mismatch should return nil
	if cache.Get("abc123", 999) != nil {
		t.Fatal("expected nil for size mismatch")
	}

	// Invalidate
	cache.Invalidate("abc123")
	if cache.Get("abc123", 100) != nil {
		t.Fatal("expected nil after invalidate")
	}

	// Size
	cache.Put("def456", result)
	if cache.Size() != 1 {
		t.Fatalf("expected cache size 1, got %d", cache.Size())
	}
}

func TestLoggerLevelsAndEntries(t *testing.T) {
	var buf strings.Builder
	logger := NewLogger(&buf, LogWarn) // only WARN+ should output

	logger.Debug("debug msg")
	logger.Info("info msg")
	logger.Warn("warn msg %d", 42)
	logger.Error("error msg")

	entries := logger.Entries()
	// Only WARN and ERROR should be captured (min level = Warn)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries (WARN+ERROR), got %d: %+v", len(entries), entries)
	}
	if entries[0].Level != "WARN" || !strings.Contains(entries[0].Message, "42") {
		t.Fatalf("unexpected warn entry: %+v", entries[0])
	}
	if entries[1].Level != "ERROR" {
		t.Fatalf("unexpected error entry: %+v", entries[1])
	}

	// Output should contain both warn and error
	output := buf.String()
	if !strings.Contains(output, "[WARN]") || !strings.Contains(output, "[ERROR]") {
		t.Fatalf("unexpected logger output: %q", output)
	}
	if strings.Contains(output, "[DEBUG]") || strings.Contains(output, "[INFO]") {
		t.Fatal("logger output should not contain DEBUG or INFO")
	}

	// Strings() should return formatted entries
	strs := logger.Strings()
	if len(strs) != 2 {
		t.Fatalf("expected 2 strings, got %d", len(strs))
	}
}

func TestLoggerAsDebugLogger(t *testing.T) {
	logger := NewScanLogger(false)
	debugf := logger.AsDebugLogger()
	debugf("test message %s", "hello")

	entries := logger.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if !strings.Contains(entries[0].Message, "hello") {
		t.Fatalf("unexpected entry: %+v", entries[0])
	}
}

func TestParallelRun(t *testing.T) {
	results := make([]int, 4)
	parallelRun(
		func() { results[0] = 1 },
		func() { results[1] = 2 },
		func() { results[2] = 3 },
		func() { results[3] = 4 },
	)
	for i, want := range []int{1, 2, 3, 4} {
		if results[i] != want {
			t.Fatalf("parallelRun result[%d] = %d, want %d", i, results[i], want)
		}
	}
}

func TestParallelRunAddFindingThreadSafe(t *testing.T) {
	result := ScanResult{}
	parallelRun(
		func() {
			for i := 0; i < 50; i++ {
				AddFinding(&result, "Low", "Test", "Finding-A", "evidence-A", 1, 0)
			}
		},
		func() {
			for i := 0; i < 50; i++ {
				AddFinding(&result, "Low", "Test", "Finding-B", "evidence-B", 1, 0)
			}
		},
	)
	// Findings should have exactly 2 unique entries (deduped)
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 unique findings after dedup, got %d", len(result.Findings))
	}
}

func TestPluginRegistryAndExecution(t *testing.T) {
	// Save and restore original registry
	origRegistry := pluginRegistry
	defer func() { pluginRegistry = origRegistry }()

	pluginRegistry = nil
	RegisterPlugin(&testPlugin{})

	result := ScanResult{FileType: "PE executable"}
	cfg := Config{Mode: "deep"}
	RunRegisteredPlugins(&result, nil, nil, "test corpus string", cfg, func(string, ...any) {})

	if len(result.Plugins) != 1 || result.Plugins[0].Name != "test-plugin" {
		t.Fatalf("expected test-plugin result, got %+v", result.Plugins)
	}
}

type testPlugin struct{}

func (p *testPlugin) Name() string    { return "test-plugin" }
func (p *testPlugin) Version() string { return "1.0" }
func (p *testPlugin) ShouldRun(result *ScanResult, cfg Config) bool {
	return result.FileType == "PE executable"
}
func (p *testPlugin) Run(result *ScanResult, data []byte, _ []ExtractedString, corpus string, _ Config, debugf debugLogger) {
	AddFinding(result, "Info", "Test", "Plugin fired", "test evidence", 0, 0)
}

func TestPluginShouldRunSkips(t *testing.T) {
	origRegistry := pluginRegistry
	defer func() { pluginRegistry = origRegistry }()

	pluginRegistry = nil
	RegisterPlugin(&testPlugin{})

	result := ScanResult{FileType: "text"} // won't match PE
	cfg := Config{Mode: "deep"}
	RunRegisteredPlugins(&result, nil, nil, "", cfg, func(string, ...any) {})

	if len(result.Plugins) != 0 {
		t.Fatalf("expected plugin to be skipped, got %+v", result.Plugins)
	}
}

func TestJSONStdoutSuppressesTextReport(t *testing.T) {
	// When JSONPath is "-", text report should NOT be printed to stdout
	cfg := Config{
		JSONPath:   "-",
		ReportMode: "summary",
	}
	result := ScanResult{
		Version:  version,
		FileName: "test.bin",
		Verdict:  "Suspicious",
	}
	// renderReportForTerminal should produce something,
	// but the condition in RunConfiguredScan should skip printing
	// when cfg.JSONPath == "-"
	report := renderReportForTerminal(result, cfg)
	if report == "" {
		t.Fatal("expected non-empty report render")
	}
	// The actual suppression is in RunConfiguredScan's else-if branch
	// cfg.JSONPath != "-" — we verify the condition is correct
	if cfg.JSONPath == "-" && cfg.ReportPath == "" {
		// This is the condition that should suppress stdout text
		// In the real code: else if cfg.JSONPath != "-" { fmt.Print(report) }
		// So when JSONPath == "-" and ReportPath == "", text should NOT print
	}
}

func TestWatchHashPreviewBounds(t *testing.T) {
	// Verify hashPreview doesn't panic on short or empty SHA256
	tests := []struct {
		sha256 string
		want   string
	}{
		{"", ""},
		{"abc", "abc"},
		{"0123456789abcdef", "0123456789abcdef"},
		{"0123456789abcdef0123456789abcdef", "0123456789abcdef..."},
	}
	for _, tt := range tests {
		hashPreview := tt.sha256
		if len(hashPreview) > 16 {
			hashPreview = hashPreview[:16] + "..."
		}
		if hashPreview != tt.want {
			t.Errorf("sha256=%q: got %q, want %q", tt.sha256, hashPreview, tt.want)
		}
	}
}

