package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
)

// Filename masquerading detection.
//
// A payload named to look like something the victim already trusts is an
// intent signal that almost never occurs by accident. A real tax-lure PDF
// linked to "lnstaller.msi" — a lowercase L standing in for the capital I of
// "Installer". Nothing about the download is technically unusual; the deception
// lives entirely in the name, so a scanner that only inspects structure and
// content scores it as ordinary.
//
// Four techniques are recognized, each chosen because benign files essentially
// never exhibit it:
//
//   - bidirectional control characters, which reverse how the name renders
//     ("annexe‮cod.exe" displays as "annexe.exe.doc")
//   - Latin text mixed with Cyrillic or Greek letters that look identical
//   - a document extension followed by an executable one ("invoice.pdf.exe")
//   - homoglyph spelling of a commonly impersonated name ("lnstaller",
//     "Micros0ft", "setup" as "5etup")
//
// The homoglyph check deliberately compares against a fixed vocabulary rather
// than guessing. Reporting "this name resembles a real word" would fire
// constantly; reporting "this name is a visually identical spelling of
// 'installer' that is not 'installer'" is precise.

// MasqueradeHit describes one deceptive-naming technique found in a name.
type MasqueradeHit struct {
	Value     string `json:"value"`
	Technique string `json:"technique"`
	LooksLike string `json:"looks_like,omitempty"`
}

// masqueradeTargets are names attackers imitate. Each is stored in skeleton
// form at init so lookups are a single map hit.
var masqueradeTargets = []string{
	"installer", "install", "setup", "update", "updater", "upgrade",
	"adobe", "acrobat", "reader", "microsoft", "windows", "office",
	"word", "excel", "powerpoint", "outlook", "onedrive", "teams",
	"chrome", "firefox", "edge", "safari", "zoom", "skype", "telegram",
	"invoice", "receipt", "statement", "payment", "document", "scanner",
	"driver", "java", "flash", "player", "security", "antivirus",
	"defender", "activate", "license", "password", "account", "verify",
}

// masqueradeSkeletons maps a confusable skeleton back to its canonical target.
var masqueradeSkeletons = func() map[string]string {
	out := make(map[string]string, len(masqueradeTargets))
	for _, target := range masqueradeTargets {
		out[confusableSkeleton(target)] = target
	}
	return out
}()

// documentExtensions are the extensions a lure pretends to be.
var documentExtensions = []string{
	".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt",
	".rtf", ".jpg", ".jpeg", ".png", ".gif", ".csv", ".htm", ".html",
}

// bidiControlRunes reorder rendered text. In a file name they exist only to
// deceive: U+202E is the classic "right-to-left override" extension flip.
var bidiControlRunes = []rune{
	'‪', '‫', '‬', '‭', '‮',
	'⁦', '⁧', '⁨', '⁩', '‏', '‎',
}

// confusableSkeleton reduces a string to a form shared by visually identical
// spellings, so "lnstaller", "Installer" and "1nstaller" collapse together.
//
// This is a deliberately small, ASCII-focused approximation of the Unicode
// confusables mapping — enough for the substitutions actually used in file
// names, without pulling in a full confusables table.
func confusableSkeleton(value string) string {
	lower := strings.ToLower(value)
	// "rn" renders almost identically to "m" at small sizes; collapse it first
	// so the per-rune pass sees the same shape a reader would.
	lower = strings.ReplaceAll(lower, "rn", "m")
	lower = strings.ReplaceAll(lower, "vv", "w")

	var b strings.Builder
	for _, r := range lower {
		switch r {
		case 'i', 'l', '1', '|', '!':
			b.WriteRune('1')
		case 'o', '0':
			b.WriteRune('0')
		case 's', '5', '$':
			b.WriteRune('s')
		case 'e', '3':
			b.WriteRune('e')
		case 'a', '@', '4':
			b.WriteRune('a')
		case 't', '7':
			b.WriteRune('t')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// DetectFilenameMasquerade reports the deceptive-naming techniques present in
// name. An empty result means the name is unremarkable.
func DetectFilenameMasquerade(name string) []MasqueradeHit {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	var hits []MasqueradeHit

	if r, ok := firstBidiControl(name); ok {
		hits = append(hits, MasqueradeHit{
			Value:     name,
			Technique: "bidirectional control character (U+" + strings.ToUpper(runeHex(r)) + ") reverses how the name renders",
		})
	}
	if script, ok := mixedConfusableScript(name); ok {
		hits = append(hits, MasqueradeHit{
			Value:     name,
			Technique: "Latin text mixed with " + script + " look-alike letters",
		})
	}
	if masked, ok := doubleExtension(name); ok {
		hits = append(hits, MasqueradeHit{
			Value:     name,
			Technique: "double extension hiding an executable",
			LooksLike: masked,
		})
	}
	if target, ok := homoglyphTarget(name); ok {
		hits = append(hits, MasqueradeHit{
			Value:     name,
			Technique: "homoglyph spelling of a commonly impersonated name",
			LooksLike: target,
		})
	}
	return hits
}

// firstBidiControl returns the first bidirectional control rune in name.
func firstBidiControl(name string) (rune, bool) {
	for _, r := range name {
		for _, bad := range bidiControlRunes {
			if r == bad {
				return r, true
			}
		}
	}
	return 0, false
}

// runeHex renders a rune as a lowercase hex code point.
func runeHex(r rune) string {
	const digits = "0123456789abcdef"
	var out []byte
	for value := int(r); value > 0; value /= 16 {
		out = append([]byte{digits[value%16]}, out...)
	}
	if len(out) < 4 {
		out = append([]byte(strings.Repeat("0", 4-len(out))), out...)
	}
	return string(out)
}

// mixedConfusableScript reports a single word that mixes Latin letters with
// Cyrillic or Greek look-alikes.
//
// Two restrictions keep this from punishing ordinary international file names:
//
//   - Only Cyrillic and Greek count. Han, Arabic, Hebrew and the rest are not
//     visually confusable with Latin, so "涉稅企業名單.zip" is just a file name.
//   - The scripts must mix *inside one word*. Checking the whole name flagged
//     "отчет.pdf" and "αναφορά.pdf", because the extension is Latin — and it
//     would equally flag a bilingual name like "отчет_report.pdf". The attack
//     is intra-word substitution ("Miсrosoft" with one Cyrillic с), not the
//     coexistence of two languages in one file name.
func mixedConfusableScript(name string) (string, bool) {
	for _, word := range splitLetterRuns(name) {
		var latin, cyrillic, greek bool
		for _, r := range word {
			switch {
			case unicode.Is(unicode.Latin, r):
				latin = true
			case unicode.Is(unicode.Cyrillic, r):
				cyrillic = true
			case unicode.Is(unicode.Greek, r):
				greek = true
			}
		}
		if !latin {
			continue
		}
		switch {
		case cyrillic:
			return "Cyrillic", true
		case greek:
			return "Greek", true
		}
	}
	return "", false
}

// splitLetterRuns breaks a name into maximal runs of letters, discarding
// digits, separators and punctuation. Each run is one "word" for script-mixing
// purposes.
func splitLetterRuns(name string) []string {
	var runs []string
	var current strings.Builder
	for _, r := range name {
		if unicode.IsLetter(r) {
			current.WriteRune(r)
			continue
		}
		if current.Len() > 0 {
			runs = append(runs, current.String())
			current.Reset()
		}
	}
	if current.Len() > 0 {
		runs = append(runs, current.String())
	}
	return runs
}

// doubleExtension reports a document extension followed by an executable one,
// returning the document extension the name pretends to carry.
func doubleExtension(name string) (string, bool) {
	lower := strings.ToLower(name)
	isExecutable := false
	for _, ext := range pdfDirectExecutableExtensions {
		if strings.HasSuffix(lower, ext) {
			isExecutable = true
			lower = strings.TrimSuffix(lower, ext)
			break
		}
	}
	if !isExecutable {
		return "", false
	}
	// Whitespace padding between the two extensions is itself a hiding trick.
	lower = strings.TrimRight(lower, " \t")
	for _, ext := range documentExtensions {
		if strings.HasSuffix(lower, ext) {
			return ext, true
		}
	}
	return "", false
}

// homoglyphTarget reports whether the name's base spells a commonly
// impersonated word using visually identical substitutes.
//
// An exact match is not a hit: "installer.msi" is just a file called installer.
// Only a different spelling that renders the same way is deceptive.
func homoglyphTarget(name string) (string, bool) {
	base := name
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	if i := strings.LastIndex(base, "."); i > 0 {
		base = base[:i]
	}
	base = strings.TrimSpace(base)
	if base == "" {
		return "", false
	}
	// Compare the alphabetic core so version numbers and separators in names
	// like "setup_v2" do not defeat the lookup.
	core := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return r
		}
		return -1
	}, base)
	if core == "" {
		return "", false
	}
	target, ok := masqueradeSkeletons[confusableSkeleton(core)]
	if !ok {
		return "", false
	}
	if strings.EqualFold(core, target) {
		return "", false // genuinely named "installer", not a look-alike
	}
	return target, true
}

// Extension/content mismatch.
//
// A file named .pdf whose bytes are an HTML script host is lying about what it
// is, and that lie is the delivery mechanism: the victim double-clicks what
// their file manager shows as a document. A live sample (SHA256 5095c647…)
// shipped a 90KB obfuscated VBScript RAT loader under a .pdf name and never
// contained a %PDF header at all.
//
// The check is deliberately one-directional. It fires only when a *document*
// extension covers *executable or script* content — the direction that
// constitutes a lure. The reverse (an .exe that really is a PE, or a .txt
// holding JSON) is ordinary and stays silent.

// contentBearingExtensions maps a claimed extension to the file types that
// legitimately back it. A type not in the list is a mismatch.
var contentBearingExtensions = map[string][]string{
	".pdf":  {"PDF document"},
	".doc":  {"Office document", "Office Open XML document", "OLE compound document"},
	".docx": {"Office Open XML document", "ZIP container"},
	".xls":  {"Office document", "Office Open XML document", "OLE compound document"},
	".xlsx": {"Office Open XML document", "ZIP container"},
	".ppt":  {"Office document", "Office Open XML document", "OLE compound document"},
	".pptx": {"Office Open XML document", "ZIP container"},
	".rtf":  {"Rich Text Format", "text"},
	".txt":  {"text", "script/text"},
	".csv":  {"text", "script/text"},
	".jpg":  {"JPEG image"},
	".jpeg": {"JPEG image"},
	".png":  {"PNG image"},
	".gif":  {"GIF image"},
}

// executableContentTypes are the detected types that make a document-extension
// mismatch a delivery lure rather than a mislabeled file.
var executableContentTypes = map[string]bool{
	"PE executable": true, "ELF binary": true, "Mach-O binary": true,
	"Windows shortcut": true, "HTML application": true, "PowerShell script": true,
	"Batch script": true, "VBScript": true, "JScript": true,
	"Windows Script File": true, "HTA application": true, "Shell script": true,
	"Java class": true, "DEX bytecode": true,
}

// DetectExtensionMismatch reports whether name claims a document extension that
// its detected content type does not back, and whether that content is
// executable. An empty claimed value means there is nothing to report.
func DetectExtensionMismatch(name, fileType string) (claimed string, executable bool) {
	base := strings.ToLower(name)
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	dot := strings.LastIndex(base, ".")
	if dot < 0 {
		return "", false
	}
	ext := base[dot:]
	allowed, tracked := contentBearingExtensions[ext]
	if !tracked {
		return "", false
	}
	for _, ok := range allowed {
		if fileType == ok {
			return "", false
		}
	}
	// "unknown binary" is the sniffer giving up, not evidence of deception:
	// plenty of real formats fall through it. Reporting on it would fire on
	// every image variant FlatScan does not parse.
	if fileType == "unknown binary" {
		return "", false
	}
	return ext, executableContentTypes[fileType]
}

// reportExtensionMismatch scores a file whose name claims one format and whose
// content is another, and separately reports a deceptive name.
func reportExtensionMismatch(result *ScanResult, path string) {
	if result == nil {
		return
	}
	name := filepath.Base(path)

	if claimed, executable := DetectExtensionMismatch(name, result.FileType); claimed != "" {
		if executable {
			AddFindingDetailed(result, "High", "Masquerade",
				"File content does not match its extension",
				fmt.Sprintf("the name claims %s but the content is %s — a document extension covering executable content is a delivery lure, not a mislabeled file",
					claimed, result.FileType),
				28, 0,
				"Defense Evasion", "Masquerading: Masquerade File Type (T1036.008)",
				"Treat the file as the type its content says it is. Hunt for the name across mail and download telemetry; users were shown a document icon.")
		} else {
			AddFindingDetailed(result, "Low", "Masquerade",
				"Extension does not match detected content",
				fmt.Sprintf("the name claims %s but the content is %s", claimed, result.FileType),
				5, 0,
				"Defense Evasion", "Masquerading: Masquerade File Type (T1036.008)",
				"Confirm whether the mismatch is a renamed file or a deliberate lure.")
		}
	}

	if hits := DetectFilenameMasquerade(name); len(hits) > 0 {
		var parts []string
		for _, hit := range hits {
			part := hit.Value + " — " + hit.Technique
			if hit.LooksLike != "" {
				part += " (reads as \"" + hit.LooksLike + "\")"
			}
			parts = append(parts, part)
		}
		AddFindingDetailed(result, "High", "Masquerade",
			"Sample name is disguised",
			previewString(strings.Join(parts, "; "), 300),
			26, 0,
			"Defense Evasion", "Masquerading: Match Legitimate Name or Location (T1036.005)",
			"Deceptive naming is deliberate: use the name as a hunting pivot across mail, download, and endpoint telemetry.")
	}
}
