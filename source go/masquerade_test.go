package main

import (
	"strings"
	"testing"
)

// TestDetectFilenameMasqueradeHits covers the four deceptive-naming techniques.
func TestDetectFilenameMasqueradeHits(t *testing.T) {
	cases := []struct {
		name      string
		fileName  string
		technique string
		looksLike string
	}{
		// The case from the real tax-lure sample: lowercase L for capital I.
		{"lowercase L for I", "lnstaller.msi", "homoglyph", "installer"},
		{"zero for O", "Micros0ft.exe", "homoglyph", "microsoft"},
		{"five for S", "5etup.exe", "homoglyph", "setup"},
		{"rn for m", "Tearns.exe", "homoglyph", "teams"},
		{"one for l", "1nvoice.scr", "homoglyph", "invoice"},
		{"double extension", "invoice.pdf.exe", "double extension", ".pdf"},
		{"padded double extension", "report.doc            .scr", "double extension", ".doc"},
		{"rtl override", "annexe\u202ecod.exe", "bidirectional", ""},
		{"cyrillic mix", "Miсrosoft.exe", "Cyrillic", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits := DetectFilenameMasquerade(tc.fileName)
			if len(hits) == 0 {
				t.Fatalf("DetectFilenameMasquerade(%q) found nothing", tc.fileName)
			}
			matched := false
			for _, hit := range hits {
				if strings.Contains(hit.Technique, tc.technique) {
					matched = true
					if tc.looksLike != "" && hit.LooksLike != tc.looksLike {
						t.Errorf("LooksLike = %q, want %q", hit.LooksLike, tc.looksLike)
					}
				}
			}
			if !matched {
				t.Errorf("no hit mentioned %q; got %+v", tc.technique, hits)
			}
		})
	}
}

// TestDetectFilenameMasqueradeBenign is the false-positive guard. These names
// must stay silent, including non-English ones: a Chinese or Arabic file name
// with an ASCII extension is entirely ordinary, and flagging it would punish
// non-English users rather than attackers.
func TestDetectFilenameMasqueradeBenign(t *testing.T) {
	benign := []string{
		// Genuinely named files — an exact match is not a disguise.
		"installer.msi", "Installer.msi", "setup.exe", "update.exe",
		"microsoft.com", "invoice.pdf", "document.docx", "reader.exe",
		// Ordinary words that must not collide with a target skeleton.
		"leader.pdf", "modern.exe", "corner.zip", "release-notes.txt",
		"README.md", "libssl.so.3", "archive.tar.gz", "photo.jpeg",
		"report_2024_final.pdf", "data-export-v2.csv",
		// Non-Latin names with ASCII extensions: normal worldwide. The Latin
		// extension must not count as script mixing.
		"涉稅企業名單.zip", "税务抽查名单公示.7z", "отчет.pdf", "αναφορά.pdf",
		"日本語ファイル.docx", "ملف.pdf",
		// Bilingual names: two scripts in one file name, but never inside one
		// word. Only intra-word substitution is deceptive.
		"отчет_report.pdf", "报告_report_2024.xlsx", "αναφορά-final.docx",
	}
	for _, name := range benign {
		if hits := DetectFilenameMasquerade(name); len(hits) != 0 {
			t.Errorf("benign name %q flagged as masquerade: %+v", name, hits)
		}
	}
}

// TestConfusableSkeletonCollapses pins that visually identical spellings share
// a skeleton while genuinely different words do not.
func TestConfusableSkeletonCollapses(t *testing.T) {
	same := [][2]string{
		{"installer", "lnstaller"},
		{"installer", "1nsta11er"},
		{"setup", "5etup"},
		{"microsoft", "micros0ft"},
		{"teams", "tearns"},
	}
	for _, pair := range same {
		if confusableSkeleton(pair[0]) != confusableSkeleton(pair[1]) {
			t.Errorf("skeleton(%q) != skeleton(%q); want equal", pair[0], pair[1])
		}
	}

	different := [][2]string{
		{"installer", "uninstaller"},
		{"reader", "leader"},
		{"document", "documents"},
		{"invoice", "invoices"},
	}
	for _, pair := range different {
		if confusableSkeleton(pair[0]) == confusableSkeleton(pair[1]) {
			t.Errorf("skeleton(%q) == skeleton(%q); want different", pair[0], pair[1])
		}
	}
}

// TestMixedConfusableScriptOnlyLatinLookalikes pins that only Cyrillic and
// Greek — the scripts with Latin look-alikes — count as mixed-script.
func TestMixedConfusableScriptOnlyLatinLookalikes(t *testing.T) {
	if _, ok := mixedConfusableScript("Miсrosoft.exe"); !ok { // Cyrillic с
		t.Error("Latin + Cyrillic was not detected")
	}
	if _, ok := mixedConfusableScript("Νotepad.exe"); !ok { // Greek Nu
		t.Error("Latin + Greek was not detected")
	}
	for _, name := range []string{"涉稅企業名單.zip", "日本語.docx", "ملف.pdf", "plain.exe"} {
		if script, ok := mixedConfusableScript(name); ok {
			t.Errorf("%q flagged as mixed script (%s); non-confusable scripts must be ignored", name, script)
		}
	}
}
