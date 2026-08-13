package main

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
)

// TestWriteCSVRowQuotesSpecialFileNames guards the machine-readable CSV row
// against sample file names containing commas or quotes. Sample names are
// attacker-controlled, and an unescaped comma used to shift every later column,
// so a downstream pipeline read the wrong risk score.
func TestWriteCSVRowQuotesSpecialFileNames(t *testing.T) {
	cases := []struct {
		name     string
		fileName string
	}{
		{"comma", `in,voice2024.txt`},
		{"double quote", `in"voice.txt`},
		{"comma and quote", `in,voice"2024.txt`},
		{"newline", "in\nvoice.txt"},
		{"plain", "sample.bin"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := ScanResult{
				FileName:  tc.fileName,
				RiskScore: 38,
				Verdict:   "Suspicious",
				Findings:  []Finding{{Title: "a"}, {Title: "b"}, {Title: "c"}},
				Hashes:    Hashes{SHA256: "336341d4f58dbe7edefddaaa8b658926a47d59b26d3110e37e631459c7e3c67d"},
			}

			var buf bytes.Buffer
			if err := writeCSVRow(&buf, result); err != nil {
				t.Fatalf("writeCSVRow: %v", err)
			}

			records, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
			if err != nil {
				t.Fatalf("output is not valid CSV: %v (%q)", err, buf.String())
			}
			if len(records) != 1 {
				t.Fatalf("got %d records, want 1: %q", len(records), buf.String())
			}
			row := records[0]
			if len(row) != len(csvColumns) {
				t.Fatalf("got %d fields, want %d: %#v", len(row), len(csvColumns), row)
			}
			if row[0] != tc.fileName {
				t.Errorf("file_name = %q, want %q", row[0], tc.fileName)
			}
			// The score must stay in its own column no matter what the name holds.
			if row[1] != "38" {
				t.Errorf("risk_score = %q, want \"38\"", row[1])
			}
			if row[2] != "Suspicious" {
				t.Errorf("verdict = %q, want \"Suspicious\"", row[2])
			}
			if row[3] != "3" {
				t.Errorf("findings = %q, want \"3\"", row[3])
			}
		})
	}
}
