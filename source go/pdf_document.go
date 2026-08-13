package main

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// PDF document analysis.
//
// FlatScan detected "PDF document" as a file type but had no analyzer for it:
// AnalyzeFormats had no PDF case, so a malicious PDF fell through to the generic
// string pipeline and a document carrying an auto-executing /OpenAction
// JavaScript payload scored 0 with zero findings. PDF is a primary malware
// delivery vector, so that was the single largest detection gap in the tool.
//
// This is a focused structural parser, not a complete PDF implementation. It
// recovers the document catalog features that matter for triage — automatic
// actions, embedded JavaScript, launch/embedded-file payloads, and the encoding
// tricks used to hide them — and feeds recovered script bodies back through the
// shared analysis engines.
//
// Two behaviors distinguish it from a keyword grep, and both are required to
// catch real samples:
//
//  1. PDF names may be written with #xx hex escapes, so /JavaScript can appear
//     as /J#61vaScript. Every keyword scan therefore runs against a normalized
//     copy, and any keyword that was only reachable after decoding is reported
//     as deliberate obfuscation.
//  2. Malicious payloads normally live inside FlateDecode streams, invisible to
//     a scan of the raw bytes. Streams are decompressed (under strict bomb
//     limits) and the recovered content is scanned as well.

// PDF analysis limits. A PDF is attacker-controlled input, so every loop that
// walks it is bounded: a malformed or hostile document must cost bounded time
// and memory, never the whole address space.
const (
	pdfMaxStreams          = 256              // max streams decompressed per document
	pdfMaxStreamOutput     = 2 * 1024 * 1024  // max bytes taken from one stream
	pdfMaxTotalStreamBytes = 16 * 1024 * 1024 // max decompressed bytes overall
	pdfMaxJSSnippets       = 8                // max JavaScript excerpts retained
	pdfJSSnippetLen        = 400              // characters kept per excerpt
	pdfMaxReportedNames    = 24               // max obfuscated names listed
)

// PDFKeywordHit records one structural keyword and how it was written. A hit
// marked Obfuscated was only found after #xx hex-escape decoding, which is a
// deliberate evasion rather than an artifact of normal PDF production.
type PDFKeywordHit struct {
	Keyword    string `json:"keyword"`
	Count      int    `json:"count"`
	Obfuscated bool   `json:"obfuscated,omitempty"`
}

// PDFInfo is the recovered structure of a PDF document.
type PDFInfo struct {
	Version             string          `json:"version,omitempty"`
	ObjectCount         int             `json:"object_count"`
	StreamCount         int             `json:"stream_count"`
	StreamsDecompressed int             `json:"streams_decompressed"`
	IncrementalUpdates  int             `json:"incremental_updates,omitempty"`
	Encrypted           bool            `json:"encrypted,omitempty"`
	Linearized          bool            `json:"linearized,omitempty"`
	Keywords            []PDFKeywordHit `json:"keywords,omitempty"`
	ObfuscatedNames     []string        `json:"obfuscated_names,omitempty"`
	EmbeddedFiles       []string        `json:"embedded_files,omitempty"`
	EmbeddedPayloads    []string        `json:"embedded_payloads,omitempty"`
	LaunchTargets       []string        `json:"launch_targets,omitempty"`
	LinkedURLs          []string        `json:"linked_urls,omitempty"`
	ExecutableLinks     []string        `json:"executable_links,omitempty"`
	ArchiveLinks        []string        `json:"archive_links,omitempty"`
	Masquerades         []MasqueradeHit `json:"masquerades,omitempty"`
	JavaScript          []string        `json:"javascript,omitempty"`
}

// pdfDirectExecutableExtensions are link targets that download something
// directly runnable. A document linking straight to one of these is a delivery
// lure: the PDF itself is inert, and the payload arrives when the reader
// clicks.
var pdfDirectExecutableExtensions = []string{
	".exe", ".msi", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs",
	".jse", ".wsf", ".hta", ".jar", ".lnk", ".dll", ".apk", ".msix", ".appx",
}

// pdfArchiveLinkExtensions are container downloads. These carry real signal —
// archive-wrapped payloads defeat mail scanners — but legitimate documents do
// link to software archives, so they are scored lower than a direct executable.
var pdfArchiveLinkExtensions = []string{
	".zip", ".7z", ".rar", ".iso", ".img", ".cab", ".gz", ".tar", ".vhd", ".ace",
}

// pdfExecutableExtensions are attachment extensions that make a PDF a delivery
// wrapper rather than a document. The "invoice.exe" attachment is one of the
// most common phishing shapes.
var pdfExecutableExtensions = []string{
	".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs",
	".js", ".jse", ".wsf", ".hta", ".jar", ".msi", ".lnk", ".apk", ".elf",
}

// pdfWatchKeywords are the structural markers worth counting. The comment on
// each records why it matters for triage.
var pdfWatchKeywords = []string{
	"/OpenAction",   // action executed automatically when the document opens
	"/AA",           // additional actions (page open/close, field focus...)
	"/JavaScript",   // JavaScript action
	"/JS",           // JavaScript body
	"/Launch",       // launches an external program
	"/EmbeddedFile", // file attachment carrying a payload
	"/Filespec",     // file specification, usually paired with /EmbeddedFile
	"/URI",          // external link
	"/SubmitForm",   // posts form data to a URL
	"/GoToE",        // go to an embedded document
	"/GoToR",        // go to a remote document
	"/RichMedia",    // Flash/rich-media annotation
	"/XFA",          // XFA form (historically exploit-prone)
	"/ObjStm",       // object stream; can hide objects from naive parsers
	"/JBIG2Decode",  // decoder tied to several memory-corruption CVEs
	"/AcroForm",     // interactive form
	"/Encrypt",      // encrypted document
}

// pdfSuspiciousJS are JavaScript constructs that are rare in benign document
// scripts and common in exploit/dropper code.
var pdfSuspiciousJS = []string{
	"eval(", "unescape(", "fromcharcode", "app.launchurl", "exportdataobject",
	"getannots", "util.printf", "this.submitform", "importdataobject",
	"createdataobject", "spawn(", "collab.gettcon", "media.newplayer",
	"heapspray", "%u9090", "\\x90\\x90",
}

var (
	// "12 0 obj" — an indirect object header.
	pdfObjectRe = regexp.MustCompile(`(?m)^\s*\d+\s+\d+\s+obj\b`)
	// A #xx hex escape inside a PDF name.
	pdfHexEscapeRe = regexp.MustCompile(`#([0-9A-Fa-f]{2})`)
	// A PDF name token, used to report which names were obfuscated.
	pdfNameRe = regexp.MustCompile(`/[A-Za-z0-9#]{2,40}`)
	// An attachment name: /F or /UF followed by a literal string.
	pdfFileNameRe = regexp.MustCompile(`(?i)/(?:F|UF)\s*\(([^)]{1,500})\)`)
	// The program a /Launch action targets.
	pdfLaunchTargetRe = regexp.MustCompile(`(?i)/Launch\b[^>]{0,200}?/(?:F|Win)\s*(?:<<[^>]{0,100}?/F\s*)?\(([^)]{1,500})\)`)
	// The target of a /URI link action.
	pdfURIRe = regexp.MustCompile(`(?i)/URI\s*\(([^)]{1,900})\)`)
	// A /JS entry holding either a literal string or a hex string. Go's regexp
	// caps a repeat count at 1000, and the snippet is truncated to
	// pdfJSSnippetLen anyway, so a 1000-unit bound is both legal and sufficient.
	pdfJSBodyRe = regexp.MustCompile(`(?is)/JS\s*(?:\(([^)]{1,1000})\)|<([0-9A-Fa-f\s]{1,1000})>)`)
)

// analyzePDFDocument parses a PDF sample and records structure plus findings.
func analyzePDFDocument(result *ScanResult, cfg Config, data []byte, debugf debugLogger) error {
	if len(data) < 5 || !bytes.HasPrefix(data, []byte("%PDF-")) {
		return nil
	}

	info := &PDFInfo{
		Version:            pdfHeaderVersion(data),
		ObjectCount:        len(pdfObjectRe.FindAllIndex(data, -1)),
		StreamCount:        bytes.Count(data, []byte("stream")),
		Linearized:         bytes.Contains(data, []byte("/Linearized")),
		IncrementalUpdates: pdfIncrementalUpdates(data),
	}

	// Structural keywords must be counted over document structure only, never
	// over raw stream bytes. A compressed font or image is high-entropy binary
	// in which short names like /AA, /JS or /URI occur by chance: counting them
	// there reported JavaScript in ordinary system PDFs that contain none.
	// pdfStripStreamData removes stream payloads, and only decompressed streams
	// that actually look like PDF object text are added back.
	structure := pdfStripStreamData(data)

	// Recover stream contents; malicious JavaScript is almost always compressed.
	streamText, objectText, decompressed, payloads := pdfDecompressStreams(data, debugf)
	info.StreamsDecompressed = decompressed
	info.EmbeddedPayloads = payloads

	// Normalize #xx escapes so /J#61vaScript reads as /JavaScript.
	normalizedStructure := string(pdfDecodeHexEscapes(append(structure, []byte("\n"+objectText)...)))
	rawStructure := string(structure) + "\n" + objectText

	// The haystack for script-body and IOC analysis is the structure plus all
	// recovered stream text; JavaScript bodies legitimately live in streams.
	haystack := normalizedStructure + "\n" + streamText

	for _, keyword := range pdfWatchKeywords {
		count := pdfCountKeyword(normalizedStructure, keyword)
		if count == 0 {
			continue
		}
		info.Keywords = append(info.Keywords, PDFKeywordHit{
			Keyword: keyword,
			Count:   count,
			// Present after normalization but absent before it means the name
			// reached us only through hex escaping.
			Obfuscated: pdfCountKeyword(rawStructure, keyword) == 0,
		})
	}

	// Report hex-escaped names only when the decoded name is one FlatScan cares
	// about. Ordinary PDFs legitimately hex-escape spaces and punctuation in
	// font and resource names (/Arial#20Bold), so escaping alone is not evasion
	// — hiding /JavaScript or /OpenAction with it is.
	info.ObfuscatedNames = pdfObfuscatedNames(structure)
	info.Encrypted = pdfHasKeyword(info, "/Encrypt")
	info.LaunchTargets = pdfLaunchTargets(haystack)
	// Attachment names are only meaningful when the document actually declares
	// an attachment. A /Launch action also carries an /F entry naming the
	// program it runs (/F(cmd.exe)), which is a launch target, not an embedded
	// file — collecting it here would mislabel it and double-count the payload.
	if pdfHasKeyword(info, "/EmbeddedFile") || pdfHasKeyword(info, "/Filespec") {
		info.EmbeddedFiles = pdfExcludeValues(pdfEmbeddedFileNames(haystack), info.LaunchTargets)
	}
	info.JavaScript = pdfJavaScriptSnippets(haystack)
	info.LinkedURLs = pdfLinkedURLs(haystack)
	info.ExecutableLinks = pdfLinksWithExtension(info.LinkedURLs, pdfDirectExecutableExtensions)
	info.ArchiveLinks = pdfLinksWithExtension(info.LinkedURLs, pdfArchiveLinkExtensions)
	info.Masquerades = pdfMasqueradeHits(info)

	result.PDF = info
	debugf("pdf: %d objects, %d streams (%d decompressed), %d keywords, %d js snippets",
		info.ObjectCount, info.StreamCount, info.StreamsDecompressed, len(info.Keywords), len(info.JavaScript))

	pdfEmitFindings(result, cfg, info, haystack)

	// Feed recovered script bodies through the shared script engine so PDF
	// JavaScript benefits from the same download-cradle, obfuscation and
	// reversed-string detection used for standalone scripts, and through IOC
	// extraction so C2 URLs inside compressed streams reach the IOC set.
	if len(info.JavaScript) > 0 {
		scanScriptContent(result, cfg, strings.Join(info.JavaScript, "\n"), "PDF JavaScript")
	}
	if streamText != "" {
		MergeIOCSet(&result.IOCs, ExtractIOCs(streamText))
	}
	return nil
}

// pdfEmitFindings turns recovered structure into scored findings.
//
// Calibration note: benign PDFs routinely carry /URI, /AcroForm and /Encrypt,
// so those alone are recorded but not scored. Weight is placed on constructs
// that are rare outside malicious documents (/Launch, hex-obfuscated names) and
// on combinations that imply automatic execution.
func pdfEmitFindings(result *ScanResult, cfg Config, info *PDFInfo, haystack string) {
	hasJS := pdfHasKeyword(info, "/JavaScript") || pdfHasKeyword(info, "/JS")
	hasOpenAction := pdfHasKeyword(info, "/OpenAction")
	hasAutoAction := pdfHasKeyword(info, "/AA")

	// Automatically executed JavaScript: the classic malicious-PDF shape.
	switch {
	case hasJS && (hasOpenAction || hasAutoAction):
		AddFindingDetailed(result, "High", "Document",
			"PDF executes JavaScript automatically on open",
			"the document combines an automatic action (/OpenAction or /AA) with an embedded JavaScript action",
			26, 0,
			"Execution", "User Execution: Malicious File (T1204.002)",
			"Treat as an active exploit or dropper: extract the JavaScript, detonate only in an isolated lab, and hunt for the URLs it contacts.")
	case hasJS:
		AddFindingDetailed(result, "Medium", "Document",
			"PDF contains embedded JavaScript",
			"a /JavaScript or /JS action is present in the document",
			14, 0,
			"Execution", "User Execution: Malicious File (T1204.002)",
			"Extract and review the embedded script; document JavaScript is uncommon outside interactive forms.")
	case hasOpenAction || hasAutoAction:
		AddFinding(result, "Low", "Document",
			"PDF defines an automatic action",
			"an /OpenAction or /AA entry runs when the document is opened or a page is displayed",
			5, 0)
	}

	// /Launch runs an external program. Effectively never legitimate in a
	// document received from outside.
	if pdfHasKeyword(info, "/Launch") {
		evidence := "a /Launch action is present"
		if len(info.LaunchTargets) > 0 {
			evidence += ": " + previewString(strings.Join(info.LaunchTargets, ", "), 160)
		}
		AddFindingDetailed(result, "High", "Document",
			"PDF launches an external program",
			evidence,
			25, 0,
			"Execution", "User Execution: Malicious File (T1204.002)",
			"A /Launch action in a delivered document is hostile by default; identify the target binary and hunt for its execution.")
	}

	// Hex-escaped names are an evasion technique, not a production artifact.
	if len(info.ObfuscatedNames) > 0 {
		AddFindingDetailed(result, "High", "Document",
			"PDF uses hex-escaped names to hide structure",
			"names written with #xx escapes (e.g. /J#61vaScript) defeat naive keyword scanning: "+
				previewString(strings.Join(info.ObfuscatedNames, ", "), 200),
			20, 0,
			"Defense Evasion", "Obfuscated Files or Information (T1027)",
			"Hex-escaped PDF names indicate deliberate evasion; analyze the decoded structure and treat the document as suspicious regardless of other findings.")
	}

	// An executable attachment — recognized either by its name or by the magic
	// bytes recovered from the stream — makes the PDF a delivery wrapper. This
	// outranks the generic embedded-file finding below.
	execAttachments := pdfExecutableAttachments(info.EmbeddedFiles)
	if len(execAttachments) > 0 || len(info.EmbeddedPayloads) > 0 {
		var parts []string
		if len(execAttachments) > 0 {
			parts = append(parts, "attachment name(s): "+strings.Join(execAttachments, ", "))
		}
		if len(info.EmbeddedPayloads) > 0 {
			parts = append(parts, "recovered stream content identified as "+strings.Join(info.EmbeddedPayloads, ", "))
		}
		AddFindingDetailed(result, "High", "Document",
			"PDF carries an executable payload",
			strings.Join(parts, "; "),
			24, 0,
			"Execution", "User Execution: Malicious File (T1204.002)",
			"The document is a delivery wrapper: extract the embedded payload, hash it, and treat it as the primary sample.")
	}

	// Embedded payloads.
	if pdfHasKeyword(info, "/EmbeddedFile") {
		evidence := "the document carries an embedded file attachment"
		if len(info.EmbeddedFiles) > 0 {
			evidence += ": " + previewString(strings.Join(info.EmbeddedFiles, ", "), 160)
		}
		AddFindingDetailed(result, "Medium", "Document",
			"PDF contains an embedded file",
			evidence,
			15, 0,
			"Defense Evasion", "Obfuscated Files or Information (T1027)",
			"Extract the attachment and analyze it as a separate sample; embedded files are a common way to smuggle executables past mail filters.")
	}

	// Exploit-prone decoders and rich-media handlers.
	if pdfHasKeyword(info, "/JBIG2Decode") {
		AddFindingDetailed(result, "Medium", "Document",
			"PDF uses the JBIG2 decoder",
			"/JBIG2Decode is present; this decoder is associated with multiple memory-corruption vulnerabilities",
			12, 0,
			"Execution", "Exploitation for Client Execution (T1203)",
			"Check the reader version against known JBIG2 CVEs and treat the document as a possible exploit carrier.")
	}
	if pdfHasKeyword(info, "/RichMedia") {
		AddFindingDetailed(result, "Medium", "Document",
			"PDF embeds rich media content",
			"/RichMedia is present, historically used to embed Flash exploits",
			12, 0,
			"Execution", "Exploitation for Client Execution (T1203)",
			"Extract the rich-media object and analyze it separately.")
	}
	if pdfHasKeyword(info, "/XFA") {
		AddFinding(result, "Low", "Document",
			"PDF contains an XFA form",
			"/XFA is present; XFA parsing has a history of exploitable defects",
			6, 0)
	}

	// A link straight to a runnable file. This is the modern "lure document"
	// shape: the PDF carries no active content at all — no JavaScript, no
	// /OpenAction — and exists only to get the reader to click through to the
	// payload. Scanners looking solely for active content score it as clean.
	if len(info.ExecutableLinks) > 0 {
		AddFindingDetailed(result, "High", "Document",
			"PDF links directly to an executable download",
			"link target(s) resolve to a runnable file: "+previewString(strings.Join(info.ExecutableLinks, ", "), 240),
			26, 0,
			"Execution", "User Execution: Malicious Link (T1204.001)",
			"Treat the document as a phishing lure: block the URLs, retrieve the payload for analysis, and check proxy logs for hosts that fetched it.")
	}
	if len(info.ArchiveLinks) > 0 {
		AddFindingDetailed(result, "Medium", "Document",
			"PDF links to an archive download",
			"link target(s) resolve to an archive, a common wrapper for payloads that must evade mail scanning: "+
				previewString(strings.Join(info.ArchiveLinks, ", "), 240),
			14, 0,
			"Execution", "User Execution: Malicious Link (T1204.001)",
			"Retrieve and unpack the linked archive in an isolated environment; archive-wrapped executables are a standard mail-filter bypass.")
	}

	// A payload named to impersonate something trusted. This is an intent
	// signal rather than a capability one: nothing about the download is
	// technically unusual, but no benign pipeline produces "lnstaller.msi".
	if len(info.Masquerades) > 0 {
		var parts []string
		for _, hit := range info.Masquerades {
			part := hit.Value + " — " + hit.Technique
			if hit.LooksLike != "" {
				part += " (reads as \"" + hit.LooksLike + "\")"
			}
			parts = append(parts, part)
		}
		AddFindingDetailed(result, "High", "Document",
			"PDF payload name is disguised",
			previewString(strings.Join(parts, "; "), 300),
			26, 0,
			"Defense Evasion", "Masquerading: Match Legitimate Name or Location (T1036.005)",
			"Deceptive naming is deliberate: treat the document as a confirmed lure, block the URLs, and use the payload name as a hunting pivot.")
	}

	// Remote/embedded navigation and form submission: data can leave the host.
	if pdfHasKeyword(info, "/SubmitForm") || pdfHasKeyword(info, "/GoToR") || pdfHasKeyword(info, "/GoToE") {
		AddFindingDetailed(result, "Low", "Document",
			"PDF references remote or embedded targets",
			"/SubmitForm, /GoToR or /GoToE can send data to, or fetch content from, a location outside the document",
			6, 0,
			"Exfiltration", "Exfiltration Over Web Service (T1567)",
			"Review the referenced URLs and confirm whether the document is expected to contact them.")
	}

	// Suspicious JavaScript constructs recovered from the document or streams.
	if hits := pdfSuspiciousJSHits(haystack); len(hits) > 0 {
		AddFindingDetailed(result, "High", "Document",
			"PDF JavaScript uses obfuscation or exploit primitives",
			"suspicious constructs present: "+strings.Join(hits, ", "),
			22, 0,
			"Defense Evasion", "Obfuscated Files or Information (T1027)",
			"Deobfuscate the script before judging it; these constructs are used to stage shellcode or hide the real payload.")
	}

	// An encrypted document that still auto-executes deserves attention; on its
	// own, encryption is normal and is only recorded.
	if info.Encrypted && (hasJS || hasOpenAction) {
		AddFinding(result, "Medium", "Document",
			"Encrypted PDF with active content",
			"the document is encrypted and also defines JavaScript or an automatic action, which hinders inspection",
			10, 0)
	}

	// Many incremental updates can indicate a benign edit history, but also a
	// malicious object appended to a legitimate document. Informational only.
	if info.IncrementalUpdates > 2 {
		AddFinding(result, "Info", "Document",
			"PDF has multiple incremental updates",
			fmt.Sprintf("%d %%%%EOF markers suggest appended revisions; confirm the final revision is the one rendered", info.IncrementalUpdates),
			0, 0)
	}
}

// pdfHeaderVersion returns the version from the "%PDF-x.y" header.
func pdfHeaderVersion(data []byte) string {
	end := len(data)
	if end > 16 {
		end = 16
	}
	header := string(data[:end])
	header = strings.TrimPrefix(header, "%PDF-")
	if i := strings.IndexAny(header, "\r\n \t"); i >= 0 {
		header = header[:i]
	}
	return strings.TrimSpace(header)
}

// pdfIncrementalUpdates counts %%EOF markers. A single-revision document has
// one; more indicate appended revisions.
func pdfIncrementalUpdates(data []byte) int {
	return bytes.Count(data, []byte("%%EOF"))
}

// pdfDecodeHexEscapes rewrites #xx escapes to the bytes they denote, so that
// /J#61vaScript reads as /JavaScript for keyword matching. Decoding is applied
// document-wide rather than only inside name tokens: this is a matching aid,
// not a re-serialization of the file, and over-decoding cannot hide a keyword.
func pdfDecodeHexEscapes(data []byte) []byte {
	if !bytes.ContainsRune(data, '#') {
		return data
	}
	return pdfHexEscapeRe.ReplaceAllFunc(data, func(match []byte) []byte {
		if len(match) != 3 {
			return match
		}
		hi, ok1 := pdfHexValue(match[1])
		lo, ok2 := pdfHexValue(match[2])
		if !ok1 || !ok2 {
			return match
		}
		return []byte{hi<<4 | lo}
	})
}

func pdfHexValue(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// pdfObfuscatedNames returns hex-escaped name tokens whose decoded form is one
// of the watched structural keywords.
//
// The decoded-keyword requirement is what makes this a reliable evasion signal.
// An earlier version reported any name containing #xx, which fired on ordinary
// documents for two reasons: real PDFs escape spaces in resource names, and
// random bytes inside compressed streams match the name pattern by chance
// (/5#ca in a font blob). Only a hidden /JavaScript, /OpenAction or /Launch is
// evidence of intent.
func pdfObfuscatedNames(structure []byte) []string {
	var out []string
	seen := make(map[string]bool)
	for _, match := range pdfNameRe.FindAll(structure, -1) {
		if !bytes.ContainsRune(match, '#') {
			continue
		}
		decoded := string(pdfDecodeHexEscapes(match))
		if decoded == string(match) || seen[decoded] {
			continue
		}
		if !pdfIsWatchedName(decoded) {
			continue
		}
		seen[decoded] = true
		out = append(out, fmt.Sprintf("%s -> %s", match, decoded))
		if len(out) >= pdfMaxReportedNames {
			break
		}
	}
	sort.Strings(out)
	return out
}

// pdfIsWatchedName reports whether a decoded name is a watched keyword.
func pdfIsWatchedName(name string) bool {
	for _, keyword := range pdfWatchKeywords {
		if strings.EqualFold(name, keyword) {
			return true
		}
	}
	return false
}

// pdfCountKeyword counts occurrences of a PDF name keyword, requiring a name
// delimiter after it. Without the boundary check, the two-character /AA matches
// inside /AAPL and the three-character /JS inside /JSName.
func pdfCountKeyword(text, keyword string) int {
	lowerText := strings.ToLower(text)
	lowerKeyword := strings.ToLower(keyword)
	count := 0
	for offset := 0; ; {
		index := strings.Index(lowerText[offset:], lowerKeyword)
		if index < 0 {
			break
		}
		start := offset + index
		end := start + len(lowerKeyword)
		if !pdfIsNameByte(lowerText, end) {
			count++
		}
		offset = start + 1
	}
	return count
}

// pdfIsNameByte reports whether text[i] can continue a PDF name token. A name
// ends at whitespace or any delimiter, so anything else continues it.
func pdfIsNameByte(text string, i int) bool {
	if i < 0 || i >= len(text) {
		return false
	}
	c := text[i]
	return c == '_' || c == '-' || c == '.' || c == '#' ||
		c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// pdfStripStreamData returns the document with the bytes between "stream" and
// "endstream" removed, leaving only object structure. Structural keyword
// analysis runs on this, so compressed font/image payloads cannot contribute
// chance matches.
func pdfStripStreamData(data []byte) []byte {
	out := make([]byte, 0, len(data))
	offset := 0
	for {
		index := bytes.Index(data[offset:], []byte("stream"))
		if index < 0 {
			break
		}
		start := offset + index + len("stream")
		end := bytes.Index(data[start:], []byte("endstream"))
		if end < 0 {
			break
		}
		// Keep the structure preceding the stream, drop the payload, and resume
		// *past* the "endstream" keyword.
		//
		// Resuming at the start of "endstream" would be a subtle bug: the word
		// "endstream" itself contains "stream", so the next iteration would
		// match inside it and then scan forward to the *following* stream's
		// terminator — discarding every object between the two. That silently
		// removed the link annotations of a real phishing PDF, leaving the
		// keyword scan with nothing to find.
		out = append(out, data[offset:offset+index]...)
		out = append(out, ' ')
		offset = start + end + len("endstream")
	}
	return append(out, data[offset:]...)
}

// pdfLooksLikeObjectText reports whether recovered stream bytes are PDF object
// text (an /ObjStm, a content stream) rather than a binary blob. Only object
// text may contribute to structural keyword counting.
func pdfLooksLikeObjectText(content []byte) bool {
	if len(content) == 0 {
		return false
	}
	sample := content
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	printable := 0
	for _, c := range sample {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7f) {
			printable++
		}
	}
	return float64(printable)/float64(len(sample)) >= 0.90
}

// pdfDecompressStreams inflates FlateDecode streams and returns their combined
// text plus the number successfully decompressed.
//
// Limits matter here: a PDF can declare thousands of streams, and a small
// compressed stream can inflate to gigabytes. Every stream is capped
// individually, the total is capped, and the stream count is capped.
func pdfDecompressStreams(data []byte, debugf debugLogger) (string, string, int, []string) {
	var builder strings.Builder
	var objects strings.Builder
	var payloads []string
	seenPayload := make(map[string]bool)
	decompressed := 0
	offset := 0
	streams := 0

	// notePayload records a stream whose recovered bytes are themselves an
	// executable/container format — a payload smuggled inside the document.
	notePayload := func(content []byte) {
		kind := DetectFileType(content, "")
		switch kind {
		case "PE executable", "ELF binary", "Mach-O binary", "DEX bytecode",
			"APK package", "ZIP container", "JAR package":
			if !seenPayload[kind] {
				seenPayload[kind] = true
				payloads = append(payloads, kind)
			}
		}
	}

	for streams < pdfMaxStreams && builder.Len() < pdfMaxTotalStreamBytes {
		index := bytes.Index(data[offset:], []byte("stream"))
		if index < 0 {
			break
		}
		start := offset + index + len("stream")
		// Skip the EOL that must follow the "stream" keyword.
		if start < len(data) && data[start] == '\r' {
			start++
		}
		if start < len(data) && data[start] == '\n' {
			start++
		}
		end := bytes.Index(data[start:], []byte("endstream"))
		if end < 0 {
			break
		}
		raw := data[start : start+end]
		offset = start + end + len("endstream")
		streams++

		if len(raw) == 0 {
			continue
		}
		remaining := pdfMaxTotalStreamBytes - builder.Len()
		if remaining <= 0 {
			break
		}
		limit := pdfMaxStreamOutput
		if remaining < limit {
			limit = remaining
		}
		// keep records a recovered stream: always into the text haystack, and
		// into the structural haystack only when it is PDF object text.
		keep := func(content []byte) {
			notePayload(content)
			builder.Write(content)
			builder.WriteByte('\n')
			if pdfLooksLikeObjectText(content) {
				objects.Write(content)
				objects.WriteByte('\n')
			}
		}

		if out, ok := pdfInflate(raw, limit); ok {
			decompressed++
			keep(out)
			continue
		}
		// Not compressed (or an unsupported filter): keep the raw bytes, which
		// still carry plaintext JavaScript in uncompressed documents.
		if len(raw) > limit {
			raw = raw[:limit]
		}
		keep(raw)
	}
	if streams >= pdfMaxStreams {
		debugf("pdf: stream inspection capped at %d streams", pdfMaxStreams)
	}
	return builder.String(), objects.String(), decompressed, payloads
}

// pdfExecutableAttachments returns the attachment names whose extension marks
// them as executable content.
func pdfExecutableAttachments(names []string) []string {
	var out []string
	for _, name := range names {
		lower := strings.ToLower(strings.TrimSpace(name))
		for _, ext := range pdfExecutableExtensions {
			if strings.HasSuffix(lower, ext) {
				out = append(out, name)
				break
			}
		}
	}
	return out
}

// pdfInflate zlib-decompresses raw, returning at most limit bytes. ok is false
// when the data is not zlib/deflate compressed.
func pdfInflate(raw []byte, limit int) ([]byte, bool) {
	reader, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, false
	}
	defer reader.Close() //nolint:errcheck // read-only handle: Close discards nothing
	out, err := io.ReadAll(io.LimitReader(reader, int64(limit)))
	// A truncated read still yields usable plaintext, so partial output counts
	// as success as long as something came back.
	if len(out) == 0 {
		return nil, false
	}
	_ = err
	return out, true
}

// pdfHasKeyword reports whether the recovered structure includes keyword.
func pdfHasKeyword(info *PDFInfo, keyword string) bool {
	for _, hit := range info.Keywords {
		if strings.EqualFold(hit.Keyword, keyword) {
			return true
		}
	}
	return false
}

// pdfEmbeddedFileNames extracts attachment names near /EmbeddedFile entries.
func pdfEmbeddedFileNames(haystack string) []string {
	return pdfCapturedValues(haystack, pdfFileNameRe, 8)
}

// pdfLaunchTargets extracts the program a /Launch action points at.
func pdfLaunchTargets(haystack string) []string {
	if !strings.Contains(strings.ToLower(haystack), "/launch") {
		return nil
	}
	return pdfCapturedValues(haystack, pdfLaunchTargetRe, 6)
}

// pdfMasqueradeHits checks every name the document points at — link targets,
// attachments and launch targets — for deceptive naming.
func pdfMasqueradeHits(info *PDFInfo) []MasqueradeHit {
	var names []string
	for _, raw := range append(append([]string{}, info.ExecutableLinks...), info.ArchiveLinks...) {
		names = append(names, urlFileName(raw))
	}
	names = append(names, info.EmbeddedFiles...)
	names = append(names, info.LaunchTargets...)

	var hits []MasqueradeHit
	seen := make(map[string]bool)
	for _, name := range names {
		for _, hit := range DetectFilenameMasquerade(name) {
			key := hit.Value + "|" + hit.Technique
			if seen[key] {
				continue
			}
			seen[key] = true
			hits = append(hits, hit)
		}
	}
	return hits
}

// urlFileName returns the final path segment of a URL, percent-decoded.
func urlFileName(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return raw
	}
	path := parsed.Path
	if decoded, err := url.PathUnescape(path); err == nil {
		path = decoded
	}
	if i := strings.LastIndex(path, "/"); i >= 0 {
		path = path[i+1:]
	}
	return path
}

// pdfLinkedURLs returns the distinct targets of /URI link actions.
func pdfLinkedURLs(haystack string) []string {
	return pdfCapturedValues(haystack, pdfURIRe, 64)
}

// pdfLinksWithExtension returns the URLs whose path ends in one of exts.
//
// Only the parsed path is examined, never the host. Several of these
// extensions are also top-level domains — ".com" most of all, but ".zip" too —
// so matching the whole URL classified every link to "www.baidu.com" as an
// executable download. A host is not a file name; a payload link must have a
// path.
func pdfLinksWithExtension(urls, exts []string) []string {
	var out []string
	for _, raw := range urls {
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		path := strings.ToLower(strings.TrimRight(parsed.Path, "/"))
		if path == "" {
			continue
		}
		// Percent-encoded names are the norm for non-ASCII lures; decode so the
		// real extension is visible.
		if decoded, err := url.PathUnescape(path); err == nil {
			path = decoded
		}
		for _, ext := range exts {
			if strings.HasSuffix(path, ext) {
				out = append(out, raw)
				break
			}
		}
	}
	return out
}

// pdfExcludeValues returns values with every entry of exclude removed.
func pdfExcludeValues(values, exclude []string) []string {
	if len(exclude) == 0 {
		return values
	}
	skip := make(map[string]bool, len(exclude))
	for _, e := range exclude {
		skip[strings.ToLower(strings.TrimSpace(e))] = true
	}
	var out []string
	for _, v := range values {
		if !skip[strings.ToLower(strings.TrimSpace(v))] {
			out = append(out, v)
		}
	}
	return out
}

// pdfCapturedValues returns up to limit distinct first-group captures.
func pdfCapturedValues(haystack string, re *regexp.Regexp, limit int) []string {
	var out []string
	seen := make(map[string]bool)
	for _, match := range re.FindAllStringSubmatch(haystack, limit*4) {
		if len(match) < 2 {
			continue
		}
		value := strings.TrimSpace(match[1])
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// pdfJavaScriptSnippets recovers JavaScript bodies attached to /JS entries.
func pdfJavaScriptSnippets(haystack string) []string {
	var out []string
	for _, match := range pdfJSBodyRe.FindAllStringSubmatch(haystack, pdfMaxJSSnippets*3) {
		var body string
		switch {
		case len(match) > 1 && match[1] != "":
			body = match[1]
		case len(match) > 2 && match[2] != "":
			body = pdfDecodeHexString(match[2])
		}
		body = strings.TrimSpace(body)
		if body == "" {
			continue
		}
		out = append(out, previewString(body, pdfJSSnippetLen))
		if len(out) >= pdfMaxJSSnippets {
			break
		}
	}
	return out
}

// pdfDecodeHexString decodes a PDF hex string body ("48656C6C6F") to text.
func pdfDecodeHexString(hexBody string) string {
	var buf bytes.Buffer
	var hi byte
	haveHi := false
	for i := 0; i < len(hexBody); i++ {
		value, ok := pdfHexValue(hexBody[i])
		if !ok {
			continue // skip whitespace and stray characters
		}
		if !haveHi {
			hi, haveHi = value, true
			continue
		}
		buf.WriteByte(hi<<4 | value)
		haveHi = false
		if buf.Len() >= pdfJSSnippetLen*2 {
			break
		}
	}
	return buf.String()
}

// pdfSuspiciousJSHits returns the suspicious JavaScript constructs present.
func pdfSuspiciousJSHits(haystack string) []string {
	lower := strings.ToLower(haystack)
	var out []string
	for _, needle := range pdfSuspiciousJS {
		if strings.Contains(lower, needle) {
			out = append(out, needle)
		}
	}
	return out
}
