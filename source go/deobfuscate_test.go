package main

import (
	"strings"
	"testing"
)

func TestResolveSplitLiteralsRebuildsVBScriptTokens(t *testing.T) {
	// The shape used by the live sample: a token assembled from fragments so it
	// never appears literally in the file.
	script := `
confronthJo = ""
confronthJo = confronthJo + "a"
confronthJo = confronthJo + "do"
confronthJo = confronthJo + "db"
confronthJo = confronthJo + "."
confronthJo = confronthJo + "stream"
`
	got := resolveSplitLiterals(script)
	if got.Assignments != 5 {
		t.Fatalf("Assignments = %d, want 5", got.Assignments)
	}
	if len(got.Values) != 1 || got.Values[0] != "adodb.stream" {
		t.Fatalf("Values = %q, want [adodb.stream]", got.Values)
	}
	if strings.Contains(strings.ToLower(script), "adodb.stream") {
		t.Fatal("test script should not contain the literal token")
	}
}

func TestResolveSplitLiteralsHandlesDialects(t *testing.T) {
	cases := []struct {
		name   string
		script string
		want   string
	}{
		{"powershell", "$u = \"\"\n$u = $u + \"http\"\n$u = $u + \"://evil.test\"\n", "http://evil.test"},
		{"compound", "u = \"\"\nu += \"http\"\nu += \"://evil.test\"\n", "http://evil.test"},
		{"vbscript amp", "u = \"\"\nu = u & \"http\"\nu = u & \"://evil.test\"\n", "http://evil.test"},
		{"seeded", "u = \"ht\"\nu = u + \"tp://evil\"\nu = u + \".test\"\n", "http://evil.test"},
		{"single quotes", "u = ''\nu = u + 'http'\nu = u + '://evil.test'\n", "http://evil.test"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveSplitLiterals(tc.script)
			if len(got.Values) != 1 || got.Values[0] != tc.want {
				t.Fatalf("Values = %q, want [%s]", got.Values, tc.want)
			}
		})
	}
}

func TestResolveSplitLiteralsReseedsOnPlainAssignment(t *testing.T) {
	// A plain assignment discards the old value; carrying it forward would
	// synthesize a string the script never builds.
	script := "u = \"\"\nu = u + \"discardme\"\nu = \"\"\nu = u + \"realvalue\"\n"
	got := resolveSplitLiterals(script)
	if len(got.Values) != 1 || got.Values[0] != "realvalue" {
		t.Fatalf("Values = %q, want [realvalue]", got.Values)
	}
}

func TestResolveSplitLiteralsSkipsVariableOperands(t *testing.T) {
	// Appending another variable must not be treated as a literal: emitting a
	// partial reconstruction would feed the matcher a string that does not
	// exist in the payload.
	script := "u = \"\"\nu = u + \"abcdef\"\nu = u + other\n"
	got := resolveSplitLiterals(script)
	if got.Assignments != 1 {
		t.Fatalf("Assignments = %d, want 1 (variable operand must be skipped)", got.Assignments)
	}
	if len(got.Values) != 1 || got.Values[0] != "abcdef" {
		t.Fatalf("Values = %q, want [abcdef]", got.Values)
	}
}

func TestResolveSplitLiteralsIgnoresOrdinaryConcatenation(t *testing.T) {
	// Ordinary code concatenates strings; only self-append chains count, and
	// short results are dropped as noise.
	script := "total = subtotal + tax\nname = first + \" \" + last\nx = y + \"z\"\n"
	got := resolveSplitLiterals(script)
	if len(got.Values) != 0 {
		t.Fatalf("Values = %q, want none", got.Values)
	}
	if got.Density() != 0 {
		t.Fatalf("Density = %d, want 0", got.Density())
	}
}

func TestSplitLiteralDensity(t *testing.T) {
	got := SplitLiteralResult{Assignments: 25, Lines: 100}
	if got.Density() != 25 {
		t.Fatalf("Density = %d, want 25", got.Density())
	}
	if (SplitLiteralResult{}).Density() != 0 {
		t.Fatal("zero-line density must not divide by zero")
	}
}

func TestDetectExtensionMismatch(t *testing.T) {
	cases := []struct {
		name           string
		file           string
		fileType       string
		wantClaimed    string
		wantExecutable bool
	}{
		{"html named pdf", "invoice.pdf", "HTML application", ".pdf", true},
		{"pe named pdf", "statement.pdf", "PE executable", ".pdf", true},
		{"real pdf", "report.pdf", "PDF document", "", false},
		{"real jpeg", "photo.jpg", "JPEG image", "", false},
		{"text named pdf", "notes.pdf", "text", ".pdf", false},
		{"docx is a zip", "report.docx", "ZIP container", "", false},
		{"unknown sniff is not evidence", "photo.png", "unknown binary", "", false},
		{"untracked extension", "tool.exe", "PE executable", "", false},
		{"no extension", "payload", "PE executable", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claimed, executable := DetectExtensionMismatch(tc.file, tc.fileType)
			if claimed != tc.wantClaimed || executable != tc.wantExecutable {
				t.Fatalf("DetectExtensionMismatch(%q, %q) = (%q, %v), want (%q, %v)",
					tc.file, tc.fileType, claimed, executable, tc.wantClaimed, tc.wantExecutable)
			}
		})
	}
}

func TestDetectFileTypeHTML(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			"vbscript host",
			"<!DOCTYPE html>\r\n<html>\r\n<head>\r\n<script type=\"text/vbscript\">\r\nSub Go\r\nend sub\r\n</script>",
			"HTML application",
		},
		{
			"plain page",
			"<!DOCTYPE html>\n<html>\n<head><title>hello</title></head>\n<body><p>hi</p></body>\n</html>",
			"HTML document",
		},
		{
			"plain text",
			"just some notes\nwith no markup at all\n",
			"text",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectFileType([]byte(tc.body), "sample.bin"); got != tc.want {
				t.Fatalf("DetectFileType = %q, want %q", got, tc.want)
			}
		})
	}
}
