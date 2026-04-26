package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	pdfPageWidth  = 612.0
	pdfPageHeight = 792.0
	pdfMargin     = 48.0
	pdfContentW   = pdfPageWidth - 2*pdfMargin
)

type pdfReport struct {
	pages    []string
	current  strings.Builder
	y        float64
	pageNo   int
	fileName string
}

func WritePDFReport(path string, result ScanResult) error {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	doc := newPDFReport(result.FileName)
	doc.titlePage(result)
	doc.executiveDashboard(result)
	doc.managementActions(result)
	doc.mitreMatrix(result)
	doc.priorityFindings(result)
	doc.cryptoAssessment(result)
	doc.huntingGuidance(result)

	doc.section("Sample Metadata")
	doc.kv("MD5", result.Hashes.MD5)
	doc.kv("SHA1", result.Hashes.SHA1)
	doc.kv("SHA256", result.Hashes.SHA256)
	doc.kv("SHA512", result.Hashes.SHA512)
	if result.PE != nil && result.PE.ImportHash != "" {
		doc.kv("PE import hash", result.PE.ImportHash)
	}

	doc.section("Indicators of Compromise")
	doc.iocSection("URLs", result.IOCs.URLs)
	doc.iocSection("Domains", result.IOCs.Domains)
	doc.iocSection("IPv4", result.IOCs.IPv4)
	doc.iocSection("IPv6", result.IOCs.IPv6)
	doc.iocSection("Emails", result.IOCs.Emails)
	doc.iocSection("MD5", result.IOCs.MD5)
	doc.iocSection("SHA1", result.IOCs.SHA1)
	doc.iocSection("SHA256", result.IOCs.SHA256)
	doc.iocSection("SHA512", result.IOCs.SHA512)
	doc.iocSection("CVEs", result.IOCs.CVEs)
	doc.iocSection("Registry keys", result.IOCs.RegistryKeys)
	doc.iocSection("Windows paths", result.IOCs.WindowsPaths)
	doc.iocSection("Unix paths", result.IOCs.UnixPaths)

	doc.section("Executable and Container Details")
	doc.formatDetails(result)

	if len(result.Functions) > 0 {
		doc.section("Suspicious Functions and APIs")
		seen := map[string]struct{}{}
		for _, fn := range result.Functions {
			key := fn.Name + "|" + fn.Family + "|" + fn.Source
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			doc.bullet(fmt.Sprintf("[%s] %s - %s (%s)", fn.Severity, fn.Name, fn.Family, fn.Source))
			if len(seen) >= 120 {
				doc.bullet("Function list capped at 120 unique entries.")
				break
			}
		}
	}

	if len(result.SuspiciousStrings) > 0 {
		doc.section("Suspicious String Highlights")
		for i, value := range result.SuspiciousStrings {
			if i >= 80 {
				doc.bullet(fmt.Sprintf("%d additional strings omitted from PDF.", len(result.SuspiciousStrings)-i))
				break
			}
			doc.bullet(value)
		}
	}

	if len(result.DecodedArtifacts) > 0 {
		doc.section("Decoded Artifacts")
		for i, artifact := range result.DecodedArtifacts {
			if i >= 60 {
				doc.bullet(fmt.Sprintf("%d additional decoded artifacts omitted from PDF.", len(result.DecodedArtifacts)-i))
				break
			}
			doc.bullet(fmt.Sprintf("%s from %s: %s", artifact.Encoding, artifact.Source, artifact.Preview))
		}
	}

	return os.WriteFile(path, buildPDF(doc.finish()), 0o644)
}

func newPDFReport(fileName string) *pdfReport {
	doc := &pdfReport{fileName: fileName}
	doc.newPage()
	return doc
}

func (p *pdfReport) titlePage(result ScanResult) {
	p.drawFilledRect(0, 720, pdfPageWidth, 72, 0.10, 0.13, 0.18)
	p.drawTextColor("F2", 22, pdfMargin, 760, "FlatScan Malware Analysis Report", 1, 1, 1)
	p.drawTextColor("F1", 10.5, pdfMargin, 742, "Executive and Technical Static Analysis", 0.82, 0.86, 0.92)
	p.drawRiskBadge(pdfPageWidth-170, 744, result.Verdict, result.RiskScore)

	p.drawText("F2", 17, pdfMargin, 678, result.FileName)
	p.drawText("F1", 10.5, pdfMargin, 658, "Generated "+time.Now().UTC().Format(time.RFC3339)+" UTC")
	p.drawText("F1", 10.5, pdfMargin, 640, "SHA256: "+result.Hashes.SHA256)
	p.y = 600
	p.scoreCard(result)
	p.subsection("Report scope")
	p.paragraph("FlatScan performs static analysis only. The sample is not executed. Findings are heuristic indicators intended to support triage, containment, and deeper reverse engineering.")
	p.subsection("Executive assessment")
	p.paragraph(nonEmpty(result.Profile.ExecutiveAssessment, executiveNarrative(result)))
	p.newPage()
}

func (p *pdfReport) section(title string) {
	p.ensure(34)
	p.y -= 8
	p.drawFilledRect(pdfMargin, p.y-4, 5, 18, 0.70, 0.12, 0.12)
	p.drawTextColor("F2", 15, pdfMargin+14, p.y, title, 0.10, 0.13, 0.18)
	p.y -= 10
	p.drawRule(p.y)
	p.y -= 18
}

func (p *pdfReport) subsection(title string) {
	p.ensure(24)
	p.drawTextColor("F2", 11, pdfMargin, p.y, title, 0.16, 0.22, 0.30)
	p.y -= 16
}

func (p *pdfReport) kv(key, value string) {
	if value == "" {
		return
	}
	p.ensure(16)
	p.drawTextColor("F2", 9.2, pdfMargin, p.y, key+":", 0.24, 0.28, 0.34)
	for index, line := range wrapPDFText(value, 70) {
		x := pdfMargin + 118
		if index > 0 {
			x = pdfMargin + 118
			p.y -= 12
			p.ensure(14)
		}
		p.drawText("F1", 9.5, x, p.y, line)
	}
	p.y -= 14
}

func (p *pdfReport) paragraph(text string) {
	for _, line := range wrapPDFText(text, 92) {
		p.ensure(14)
		p.drawTextColor("F1", 9.3, pdfMargin, p.y, line, 0.12, 0.14, 0.18)
		p.y -= 13
	}
	p.y -= 6
}

func (p *pdfReport) bullet(text string) {
	for index, line := range wrapPDFText(text, 88) {
		p.ensure(14)
		if index == 0 {
			p.drawFilledRect(pdfMargin+2, p.y-3, 3.5, 3.5, 0.70, 0.12, 0.12)
		}
		p.drawTextColor("F1", 9.2, pdfMargin+14, p.y, line, 0.12, 0.14, 0.18)
		p.y -= 13
	}
}

func (p *pdfReport) finding(finding Finding) {
	p.ensure(40)
	header := fmt.Sprintf("[%s] %s: %s", finding.Severity, finding.Category, finding.Title)
	if finding.Score > 0 {
		header += fmt.Sprintf(" (score %d)", finding.Score)
	}
	r, g, b := severityColor(finding.Severity)
	p.drawFilledRect(pdfMargin, p.y-4, 7, 12, r, g, b)
	p.drawTextColor("F2", 10.3, pdfMargin+13, p.y, header, 0.10, 0.13, 0.18)
	p.y -= 14
	if finding.Evidence != "" {
		p.bullet("Evidence: " + finding.Evidence)
	}
	if finding.Tactic != "" || finding.Technique != "" {
		mapping := strings.TrimSpace(finding.Tactic + " / " + finding.Technique)
		mapping = strings.Trim(mapping, " /")
		p.bullet("ATT&CK: " + mapping)
	}
	if finding.Recommendation != "" {
		p.bullet("Recommendation: " + finding.Recommendation)
	}
	p.y -= 5
}

func (p *pdfReport) iocSection(name string, values []string) {
	if len(values) == 0 {
		return
	}
	p.subsection(fmt.Sprintf("%s (%d)", name, len(values)))
	for i, value := range values {
		if i >= 80 {
			p.bullet(fmt.Sprintf("%d additional values omitted from PDF.", len(values)-i))
			break
		}
		p.monoBullet(value)
	}
	p.y -= 3
}

func (p *pdfReport) monoBullet(text string) {
	for index, line := range wrapPDFText(text, 82) {
		p.ensure(14)
		if index == 0 {
			p.drawFilledRect(pdfMargin+2, p.y-3, 3.5, 3.5, 0.28, 0.33, 0.40)
		}
		p.drawTextColor("F3", 7.4, pdfMargin+14, p.y, line, 0.10, 0.13, 0.18)
		p.y -= 11
	}
}

func (p *pdfReport) formatDetails(result ScanResult) {
	if result.PE != nil {
		p.subsection("PE details")
		p.kv("Machine", result.PE.Machine)
		p.kv("Timestamp", result.PE.Timestamp)
		p.kv("Subsystem", result.PE.Subsystem)
		p.kv("Image base", result.PE.ImageBase)
		p.kv("Entry point", result.PE.EntryPoint)
		p.kv("Managed .NET runtime", fmt.Sprintf("%v", result.PE.ManagedRuntime))
		p.kv("Certificate table", fmt.Sprintf("%v", result.PE.HasCertificate))
		if result.PE.OverlaySize > 0 {
			p.kv("Overlay", fmt.Sprintf("offset=0x%x size=%s", result.PE.OverlayOffset, formatBytes(result.PE.OverlaySize)))
		}
		p.subsection("PE sections")
		for _, section := range result.PE.Sections {
			p.bullet(fmt.Sprintf("%s raw=0x%x size=%d entropy=%.2f executable=%v writable=%v", section.Name, section.RawOffset, section.RawSize, section.Entropy, section.Executable, section.Writable))
		}
		if len(result.PE.Imports) > 0 {
			p.subsection(fmt.Sprintf("PE imports (%d stored)", len(result.PE.Imports)))
			for i, imported := range result.PE.Imports {
				if i >= 80 {
					p.bullet(fmt.Sprintf("%d additional imports omitted from PDF.", len(result.PE.Imports)-i))
					break
				}
				p.bullet(imported)
			}
		}
	}
	if result.ELF != nil {
		p.subsection("ELF details")
		p.kv("Class", result.ELF.Class)
		p.kv("Machine", result.ELF.Machine)
		p.kv("Type", result.ELF.Type)
	}
	if result.MachO != nil {
		p.subsection("Mach-O details")
		p.kv("CPU", result.MachO.CPU)
		p.kv("Type", result.MachO.Type)
	}
	if len(result.ArchiveEntries) > 0 {
		p.subsection(fmt.Sprintf("Archive entries (%d)", len(result.ArchiveEntries)))
		for i, entry := range result.ArchiveEntries {
			if i >= 80 {
				p.bullet(fmt.Sprintf("%d additional archive entries omitted from PDF.", len(result.ArchiveEntries)-i))
				break
			}
			line := fmt.Sprintf("%s size=%d compressed=%d", entry.Name, entry.Size, entry.CompressedSize)
			if entry.SuspiciousReason != "" {
				line += " reason=" + entry.SuspiciousReason
			}
			p.bullet(line)
		}
	}
	if len(result.HighEntropyRegions) > 0 {
		p.subsection("High entropy regions")
		for _, region := range result.HighEntropyRegions {
			p.bullet(fmt.Sprintf("offset=0x%x length=%d entropy=%.2f", region.Offset, region.Length, region.Entropy))
		}
	}
}

func (p *pdfReport) executiveDashboard(result ScanResult) {
	p.section("CISO Decision Summary")
	p.metricCards([]metricCard{
		{"Risk", fmt.Sprintf("%d/100", result.RiskScore), result.Verdict},
		{"Confidence", nonEmpty(result.Profile.Confidence, confidenceLabel(result.RiskScore)), fmt.Sprintf("%d/100", result.Profile.ConfidenceScore)},
		{"Findings", fmt.Sprintf("%d", len(result.Findings)), severitySummary(result.Findings)},
		{"TTPs", fmt.Sprintf("%d", len(result.Profile.TTPs)), "MITRE mapped"},
	})
	p.kv("Classification", nonEmpty(result.Profile.Classification, reportClassification(result)))
	if len(result.Profile.MalwareType) > 0 {
		p.kv("Likely malware type", strings.Join(result.Profile.MalwareType, ", "))
	}
	if len(result.Profile.KeyCapabilities) > 0 {
		p.subsection("Key capabilities")
		for _, item := range result.Profile.KeyCapabilities {
			p.bullet(item)
		}
	}
	if len(result.Profile.BusinessImpact) > 0 {
		p.subsection("Business impact")
		for _, item := range result.Profile.BusinessImpact {
			p.bullet(item)
		}
	} else {
		p.paragraph(executiveNarrative(result))
	}
}

func (p *pdfReport) managementActions(result ScanResult) {
	p.section("Management Actions")
	actions := result.Profile.RecommendedActions
	if len(actions) == 0 {
		actions = findingRecommendations(result.Findings)
	}
	if result.RiskScore >= 80 {
		actions = append(actions,
			"Treat the sample as malicious until proven otherwise and preserve evidence for incident response.",
			"Block extracted IOCs at proxy, DNS, EDR, and email security controls where operationally safe.",
			"Identify exposed hosts and rotate credentials/tokens used on those endpoints.",
		)
	}
	actions = uniqueSorted(actions)
	if len(actions) == 0 {
		p.bullet("No urgent management action was inferred from the current static findings.")
		return
	}
	for i, action := range actions {
		if i >= 10 {
			p.bullet(fmt.Sprintf("%d additional actions omitted from PDF.", len(actions)-i))
			break
		}
		p.bullet(action)
	}
}

func (p *pdfReport) mitreMatrix(result ScanResult) {
	p.section("MITRE ATT&CK TTP Matrix")
	if len(result.Profile.TTPs) == 0 {
		p.bullet("No mapped ATT&CK techniques were recorded for this sample.")
		return
	}
	p.paragraph("The matrix below maps static evidence to ATT&CK-style tactics and techniques. Confidence reflects static-evidence strength, not confirmed runtime execution.")
	header := []string{"Tactic", "Technique", "Conf.", "Evidence"}
	widths := []float64{92, 150, 48, 226}
	p.tableHeader(header, widths)
	for i, entry := range result.Profile.TTPs {
		if i >= 35 {
			p.tableRow([]string{"", "", "", fmt.Sprintf("%d additional TTP rows omitted from PDF.", len(result.Profile.TTPs)-i)}, widths, i)
			break
		}
		technique := entry.Technique
		if entry.ID != "" && !strings.Contains(technique, entry.ID) {
			technique = entry.ID + " " + technique
		}
		evidence := entry.Finding
		if entry.Evidence != "" {
			evidence += " - " + entry.Evidence
		}
		p.tableRow([]string{entry.Tactic, technique, entry.Confidence, evidence}, widths, i)
	}
	p.y -= 6
}

func (p *pdfReport) priorityFindings(result ScanResult) {
	p.section("Priority Findings")
	if len(result.Findings) == 0 {
		p.bullet("No strong static indicators were found.")
		return
	}
	for i, finding := range result.Findings {
		if i >= 16 {
			p.bullet(fmt.Sprintf("%d additional findings omitted from PDF. See JSON/text report for full detail.", len(result.Findings)-i))
			break
		}
		p.finding(finding)
	}
}

func (p *pdfReport) cryptoAssessment(result ScanResult) {
	p.section("Cryptography and Secret Handling Assessment")
	if len(result.Profile.CryptoIndicators) == 0 {
		p.bullet("No explicit cryptographic API, secret-decryption, or decoded-obfuscation indicators were identified.")
		return
	}
	p.paragraph("Cryptography indicators are interpreted as capability clues. Malware may use crypto for legitimate protocol handling, payload decryption, credential theft, or string/configuration obfuscation.")
	header := []string{"Primitive", "Purpose", "Conf.", "Evidence"}
	widths := []float64{118, 176, 48, 174}
	p.tableHeader(header, widths)
	for i, indicator := range result.Profile.CryptoIndicators {
		p.tableRow([]string{indicator.Primitive, indicator.Purpose, indicator.Confidence, indicator.Evidence}, widths, i)
	}
	p.y -= 8
}

func (p *pdfReport) huntingGuidance(result ScanResult) {
	p.section("Hunting Guidance")
	p.paragraph("Use these points to operationalize the static findings in EDR, SIEM, proxy, DNS, and malware repository searches.")
	points := []string{
		"Search for SHA256 " + result.Hashes.SHA256 + " and any matching execution events.",
	}
	if len(result.IOCs.URLs) > 0 {
		points = append(points, "Hunt for outbound HTTP(S) traffic to extracted URLs, especially webhook or API endpoints.")
	}
	if len(result.IOCs.Domains) > 0 {
		points = append(points, "Review DNS and proxy logs for the extracted domains and adjacent subdomains.")
	}
	if hasFinding(result.Findings, "Credential Access") {
		points = append(points, "Correlate browser credential store access, token theft indicators, and suspicious process ancestry around first-seen time.")
	}
	if hasFinding(result.Findings, "Persistence") {
		points = append(points, "Check Run keys, startup folders, scheduled tasks, and service creation events on exposed endpoints.")
	}
	if result.PE != nil && result.PE.ManagedRuntime {
		points = append(points, "For .NET samples, inspect resources and managed strings for embedded configuration or second-stage payloads.")
	}
	for _, point := range uniqueSorted(points) {
		p.bullet(point)
	}
}

type metricCard struct {
	Label string
	Value string
	Note  string
}

func (p *pdfReport) metricCards(cards []metricCard) {
	if len(cards) == 0 {
		return
	}
	p.ensure(78)
	gap := 8.0
	width := (pdfPageWidth - 2*pdfMargin - gap*float64(len(cards)-1)) / float64(len(cards))
	height := 58.0
	x := pdfMargin
	for _, card := range cards {
		p.drawFilledRect(x, p.y-height+8, width, height, 0.96, 0.97, 0.99)
		p.drawStrokeRect(x, p.y-height+8, width, height, 0.74, 0.78, 0.84)
		p.drawFilledRect(x, p.y-height+8, width, 4, 0.70, 0.12, 0.12)
		p.drawTextColor("F2", 8, x+8, p.y-8, strings.ToUpper(card.Label), 0.26, 0.30, 0.36)
		p.drawTextColor("F2", 14, x+8, p.y-28, card.Value, 0.08, 0.10, 0.14)
		for i, line := range wrapPDFText(card.Note, 18) {
			if i > 1 {
				break
			}
			p.drawTextColor("F1", 7.8, x+8, p.y-43-float64(i*10), line, 0.30, 0.34, 0.40)
		}
		x += width + gap
	}
	p.y -= height + 12
}

func (p *pdfReport) scoreCard(result ScanResult) {
	p.metricCards([]metricCard{
		{"Verdict", result.Verdict, reportClassification(result)},
		{"Risk score", fmt.Sprintf("%d/100", result.RiskScore), riskBand(result.RiskScore)},
		{"Confidence", nonEmpty(result.Profile.Confidence, confidenceLabel(result.RiskScore)), "static analysis"},
	})
}

func (p *pdfReport) tableHeader(headers []string, widths []float64) {
	p.ensure(28)
	x := pdfMargin
	height := 20.0
	p.drawFilledRect(pdfMargin, p.y-height+4, sumFloat(widths), height, 0.11, 0.14, 0.20)
	for i, header := range headers {
		p.drawTextColor("F2", 8.2, x+4, p.y-10, header, 1, 1, 1)
		x += widths[i]
	}
	p.y -= height
}

func (p *pdfReport) tableRow(values []string, widths []float64, index int) {
	lineSets := make([][]string, len(values))
	maxLines := 1
	for i, value := range values {
		limit := int(widths[i] / 4.3)
		if limit < 8 {
			limit = 8
		}
		lineSets[i] = wrapPDFText(value, limit)
		if len(lineSets[i]) > 7 {
			lineSets[i] = append(lineSets[i][:6], "...")
		}
		if len(lineSets[i]) > maxLines {
			maxLines = len(lineSets[i])
		}
	}
	height := float64(maxLines)*10 + 10
	p.ensure(height + 6)
	if index%2 == 0 {
		p.drawFilledRect(pdfMargin, p.y-height+4, sumFloat(widths), height, 0.98, 0.99, 1.00)
	} else {
		p.drawFilledRect(pdfMargin, p.y-height+4, sumFloat(widths), height, 1.00, 1.00, 1.00)
	}
	p.drawStrokeRect(pdfMargin, p.y-height+4, sumFloat(widths), height, 0.86, 0.88, 0.92)
	x := pdfMargin
	for i, lines := range lineSets {
		if i > 0 {
			p.drawVerticalLine(x, p.y-height+4, p.y+4, 0.88, 0.90, 0.94)
		}
		for lineIndex, line := range lines {
			font := "F1"
			size := 7.5
			if looksHashLike(line) || strings.Contains(line, "://") {
				font = "F3"
				size = 6.8
			}
			p.drawTextColor(font, size, x+4, p.y-8-float64(lineIndex*10), line, 0.10, 0.13, 0.18)
		}
		x += widths[i]
	}
	p.y -= height
}

func (p *pdfReport) drawRiskBadge(x, y float64, verdict string, score int) {
	r, g, b := riskColor(score)
	p.drawFilledRect(x, y-20, 122, 30, r, g, b)
	p.drawTextColor("F2", 9, x+8, y-2, riskBand(score), 1, 1, 1)
	p.drawTextColor("F1", 7.8, x+8, y-14, verdict, 1, 1, 1)
}

func (p *pdfReport) drawTextColor(font string, size, x, y float64, text string, r, g, b float64) {
	fmt.Fprintf(&p.current, "%.3f %.3f %.3f rg BT /%s %.2f Tf %.2f %.2f Td (%s) Tj ET 0 0 0 rg\n", r, g, b, font, size, x, y, escapePDFText(text))
}

func (p *pdfReport) drawFilledRect(x, y, width, height, r, g, b float64) {
	fmt.Fprintf(&p.current, "%.3f %.3f %.3f rg %.2f %.2f %.2f %.2f re f 0 0 0 rg\n", r, g, b, x, y, width, height)
}

func (p *pdfReport) drawStrokeRect(x, y, width, height, r, g, b float64) {
	fmt.Fprintf(&p.current, "%.3f %.3f %.3f RG 0.6 w %.2f %.2f %.2f %.2f re S 0 0 0 RG\n", r, g, b, x, y, width, height)
}

func (p *pdfReport) ensure(height float64) {
	if p.y-height < 52 {
		p.newPage()
	}
}

func (p *pdfReport) newPage() {
	if p.current.Len() > 0 {
		p.pages = append(p.pages, p.current.String())
		p.current.Reset()
	}
	p.pageNo++
	p.y = 724
	p.drawFilledRect(0, 748, pdfPageWidth, 44, 0.10, 0.13, 0.18)
	p.drawTextColor("F2", 9.2, pdfMargin, 772, "FlatScan Malware Analysis Report", 1, 1, 1)
	if p.fileName != "" {
		p.drawTextColor("F1", 7.8, pdfMargin, 758, p.fileName, 0.82, 0.86, 0.92)
	}
	p.drawRule(742)
	p.drawRule(42)
	p.drawTextColor("F1", 7.3, pdfMargin, 28, "Static analysis only. Validate findings with runtime telemetry before containment decisions.", 0.38, 0.42, 0.48)
	p.drawTextColor("F1", 7.6, 512, 28, fmt.Sprintf("Page %d", p.pageNo), 0.38, 0.42, 0.48)
}

func (p *pdfReport) finish() []string {
	if p.current.Len() > 0 {
		p.pages = append(p.pages, p.current.String())
		p.current.Reset()
	}
	return p.pages
}

func (p *pdfReport) drawText(font string, size, x, y float64, text string) {
	fmt.Fprintf(&p.current, "BT /%s %.2f Tf %.2f %.2f Td (%s) Tj ET\n", font, size, x, y, escapePDFText(text))
}

func (p *pdfReport) drawRule(y float64) {
	fmt.Fprintf(&p.current, "0.70 0.72 0.76 RG 0.6 w %.2f %.2f m %.2f %.2f l S 0 0 0 RG\n", pdfMargin, y, pdfPageWidth-pdfMargin, y)
}

func (p *pdfReport) drawVerticalLine(x, y1, y2, r, g, b float64) {
	fmt.Fprintf(&p.current, "%.3f %.3f %.3f RG 0.4 w %.2f %.2f m %.2f %.2f l S 0 0 0 RG\n", r, g, b, x, y1, x, y2)
}

func buildPDF(pages []string) []byte {
	var out bytes.Buffer
	offsets := []int{0}
	write := func(format string, args ...any) {
		fmt.Fprintf(&out, format, args...)
	}
	writeObject := func(id int, body string) {
		offsets = append(offsets, out.Len())
		write("%d 0 obj\n%s\nendobj\n", id, body)
	}

	out.WriteString("%PDF-1.4\n")
	out.Write([]byte{'%', 0xe2, 0xe3, 0xcf, 0xd3, '\n'})

	pageCount := len(pages)
	firstPageID := 6
	kids := make([]string, 0, pageCount)
	for i := 0; i < pageCount; i++ {
		kids = append(kids, fmt.Sprintf("%d 0 R", firstPageID+i*2))
	}

	writeObject(1, "<< /Type /Catalog /Pages 2 0 R >>")
	writeObject(2, fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), pageCount))
	writeObject(3, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	writeObject(4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
	writeObject(5, "<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

	for i, page := range pages {
		pageID := firstPageID + i*2
		contentID := pageID + 1
		writeObject(pageID, fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.0f %.0f] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents %d 0 R >>", pdfPageWidth, pdfPageHeight, contentID))
		writeObject(contentID, fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(page), page))
	}

	xrefOffset := out.Len()
	write("xref\n0 %d\n", len(offsets))
	write("0000000000 65535 f \n")
	for _, offset := range offsets[1:] {
		write("%010d 00000 n \n", offset)
	}
	write("trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets), xrefOffset)
	return out.Bytes()
}

func escapePDFText(text string) string {
	var b strings.Builder
	for _, r := range text {
		switch r {
		case '\\', '(', ')':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n', '\r', '\t':
			b.WriteByte(' ')
		default:
			if r < 32 || r > 126 {
				b.WriteByte('?')
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

func wrapPDFText(text string, limit int) []string {
	text = strings.Join(strings.Fields(text), " ")
	if text == "" {
		return []string{""}
	}
	words := strings.Fields(text)
	var lines []string
	current := ""
	for _, word := range words {
		for runeLen(word) > limit {
			prefix, rest := splitRunes(word, limit)
			if current != "" {
				lines = append(lines, current)
				current = ""
			}
			lines = append(lines, prefix)
			word = rest
		}
		if current == "" {
			current = word
			continue
		}
		if runeLen(current)+1+runeLen(word) <= limit {
			current += " " + word
		} else {
			lines = append(lines, current)
			current = word
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

func runeLen(value string) int {
	return len([]rune(value))
}

func splitRunes(value string, limit int) (string, string) {
	runes := []rune(value)
	if len(runes) <= limit {
		return value, ""
	}
	return string(runes[:limit]), string(runes[limit:])
}

func executiveNarrative(result ScanResult) string {
	switch {
	case result.RiskScore >= 80:
		return "The sample contains multiple high-confidence malicious indicators. Prioritize containment, IOC blocking, credential rotation, and dynamic analysis in an isolated malware lab."
	case result.RiskScore >= 55:
		return "The sample contains several strong suspicious indicators. Treat it as high risk until deeper reverse engineering or sandbox telemetry proves otherwise."
	case result.RiskScore >= 30:
		return "The sample contains meaningful suspicious static indicators. The findings should be correlated with endpoint, network, and sandbox telemetry before final disposition."
	case result.RiskScore >= 10:
		return "The sample contains limited suspicious indicators. Continue triage if the file came from an untrusted source or appeared in an incident timeline."
	default:
		return "The static scan did not find strong malicious indicators. This is not a clean verdict; static analysis can miss packed, staged, or environment-gated behavior."
	}
}

func reportClassification(result ScanResult) string {
	if result.RiskScore >= 80 {
		return "Likely malicious"
	}
	if result.RiskScore >= 55 {
		return "High risk suspicious"
	}
	if result.RiskScore >= 30 {
		return "Suspicious"
	}
	if result.RiskScore >= 10 {
		return "Low confidence suspicious"
	}
	return "No strong static indicators"
}

func findingTechniques(findings []Finding) []string {
	seen := map[string]struct{}{}
	for _, finding := range findings {
		if finding.Tactic == "" && finding.Technique == "" {
			continue
		}
		value := strings.Trim(strings.TrimSpace(finding.Tactic+" / "+finding.Technique), " /")
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func findingRecommendations(findings []Finding) []string {
	seen := map[string]struct{}{}
	for _, finding := range findings {
		if finding.Recommendation != "" {
			seen[finding.Recommendation] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func riskBand(score int) string {
	switch {
	case score >= 80:
		return "Critical Risk"
	case score >= 55:
		return "High Risk"
	case score >= 30:
		return "Elevated Risk"
	case score >= 10:
		return "Low Risk"
	default:
		return "Informational"
	}
}

func riskColor(score int) (float64, float64, float64) {
	switch {
	case score >= 80:
		return 0.70, 0.12, 0.12
	case score >= 55:
		return 0.86, 0.36, 0.10
	case score >= 30:
		return 0.79, 0.58, 0.12
	case score >= 10:
		return 0.18, 0.43, 0.72
	default:
		return 0.25, 0.48, 0.32
	}
}

func severityColor(severity string) (float64, float64, float64) {
	switch severity {
	case "Critical":
		return 0.50, 0.06, 0.10
	case "High":
		return 0.70, 0.12, 0.12
	case "Medium":
		return 0.79, 0.50, 0.12
	case "Low":
		return 0.18, 0.43, 0.72
	default:
		return 0.42, 0.46, 0.52
	}
}

func looksHashLike(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 16 {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func severitySummary(findings []Finding) string {
	counts := map[string]int{}
	for _, finding := range findings {
		counts[finding.Severity]++
	}
	var parts []string
	for _, severity := range []string{"Critical", "High", "Medium", "Low", "Info"} {
		if counts[severity] > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d", severity, counts[severity]))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " ")
}

func sumFloat(values []float64) float64 {
	var sum float64
	for _, value := range values {
		sum += value
	}
	return sum
}

func nonEmpty(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}
