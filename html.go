package main

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
)

func WriteHTMLReport(path string, result ScanResult) error {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(RenderHTMLReport(result)), 0o644)
}

func RenderHTMLReport(result ScanResult) string {
	var b strings.Builder
	writeHTMLHeader(&b, result)
	htmlHero(&b, result)
	htmlMetricGrid(&b, result)
	htmlFindings(&b, result)
	htmlMITRE(&b, result)
	htmlFamiliesAndConfig(&b, result)
	htmlIOCs(&b, result)
	htmlTechnical(&b, result)
	htmlRawJSON(&b, result)
	b.WriteString(`<script>document.querySelectorAll('[data-filter]').forEach(b=>b.addEventListener('click',()=>{const f=b.dataset.filter;document.querySelectorAll('.finding').forEach(x=>x.style.display=(f==='all'||x.dataset.sev===f)?'block':'none')}));</script>`)
	b.WriteString("</body></html>\n")
	return b.String()
}

func writeHTMLHeader(b *strings.Builder, result ScanResult) {
	fmt.Fprintf(b, "<!doctype html><html><head><meta charset=\"utf-8\"><title>FlatScan - %s</title>", h(result.FileName))
	b.WriteString(`<style>
:root{--bg:#f6f8fb;--panel:#fff;--ink:#17202c;--muted:#5d6775;--line:#d9dee8;--accent:#9d1f2f;--blue:#235789;--amber:#a36b00;--green:#26734d}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 Arial,Helvetica,sans-serif}
header{background:#151b26;color:#fff;padding:28px 42px}
h1{margin:0 0 8px;font-size:28px;letter-spacing:0} h2{margin:24px 0 12px;font-size:18px} h3{margin:18px 0 8px;font-size:14px}
main{max-width:1180px;margin:0 auto;padding:28px 28px 48px}.muted{color:var(--muted)}.sha{font-family:ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px}
.metric .label{font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:bold}.metric .value{font-size:24px;font-weight:bold;margin-top:4px}
.finding{border-left:5px solid var(--line);margin:10px 0}.Critical,.High{border-left-color:#a5162a}.Medium{border-left-color:#b87900}.Low{border-left-color:#2369a1}.Info{border-left-color:#4f657a}
button{border:1px solid var(--line);background:#fff;border-radius:6px;padding:7px 10px;margin:0 6px 8px 0;cursor:pointer}
table{border-collapse:collapse;width:100%;background:#fff;border:1px solid var(--line)}th,td{border-bottom:1px solid var(--line);padding:8px;text-align:left;vertical-align:top}th{background:#eef2f7;font-size:12px;text-transform:uppercase}
code,pre{font-family:ui-monospace,Consolas,monospace;font-size:12px}pre{white-space:pre-wrap;background:#101722;color:#dfe7f3;padding:14px;border-radius:8px;overflow:auto}
details{background:#fff;border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin:10px 0}summary{cursor:pointer;font-weight:bold}
ul{margin:8px 0 0 18px;padding:0}
</style></head><body>`)
}

func htmlHero(b *strings.Builder, result ScanResult) {
	fmt.Fprintf(b, "<header><h1>FlatScan Malware Analysis Report</h1><div>%s</div><div class=\"sha\">SHA256: %s</div></header><main>", h(result.FileName), h(result.Hashes.SHA256))
	fmt.Fprintf(b, "<p class=\"muted\">Static analysis only. Generated report for %s.</p>", h(result.Target))
}

func htmlMetricGrid(b *strings.Builder, result ScanResult) {
	fmt.Fprint(b, `<section class="grid">`)
	metric := func(label, value, note string) {
		fmt.Fprintf(b, `<div class="card metric"><div class="label">%s</div><div class="value">%s</div><div class="muted">%s</div></div>`, h(label), h(value), h(note))
	}
	metric("Verdict", result.Verdict, reportClassification(result))
	metric("Risk", fmt.Sprintf("%d/100", result.RiskScore), riskBand(result.RiskScore))
	metric("Findings", fmt.Sprintf("%d", len(result.Findings)), severitySummary(result.Findings))
	metric("IOCs", fmt.Sprintf("%d", IOCCount(result.IOCs)), "extracted indicators")
	metric("TTPs", fmt.Sprintf("%d", len(result.Profile.TTPs)), "mapped techniques")
	metric("Family", firstFamily(result), "classifier")
	fmt.Fprint(b, `</section>`)
	if result.Profile.ExecutiveAssessment != "" {
		fmt.Fprintf(b, `<section><h2>Executive Assessment</h2><div class="card">%s</div></section>`, h(result.Profile.ExecutiveAssessment))
	}
}

func htmlFindings(b *strings.Builder, result ScanResult) {
	fmt.Fprint(b, `<section><h2>Findings</h2><div>`)
	for _, sev := range []string{"all", "Critical", "High", "Medium", "Low", "Info"} {
		fmt.Fprintf(b, `<button data-filter="%s">%s</button>`, h(sev), h(sev))
	}
	fmt.Fprint(b, `</div>`)
	for _, finding := range result.Findings {
		fmt.Fprintf(b, `<div class="card finding %s" data-sev="%s"><strong>[%s] %s: %s</strong>`, h(finding.Severity), h(finding.Severity), h(finding.Severity), h(finding.Category), h(finding.Title))
		if finding.Evidence != "" {
			fmt.Fprintf(b, `<div>%s</div>`, h(finding.Evidence))
		}
		if finding.Technique != "" || finding.Tactic != "" {
			fmt.Fprintf(b, `<div class="muted">ATT&CK: %s / %s</div>`, h(finding.Tactic), h(finding.Technique))
		}
		if finding.Recommendation != "" {
			fmt.Fprintf(b, `<div class="muted">Recommendation: %s</div>`, h(finding.Recommendation))
		}
		fmt.Fprint(b, `</div>`)
	}
	fmt.Fprint(b, `</section>`)
}

func htmlMITRE(b *strings.Builder, result ScanResult) {
	if len(result.Profile.TTPs) == 0 {
		return
	}
	fmt.Fprint(b, `<section><h2>MITRE TTP Matrix</h2><table><tr><th>Tactic</th><th>Technique</th><th>Confidence</th><th>Evidence</th></tr>`)
	for _, ttp := range result.Profile.TTPs {
		fmt.Fprintf(b, `<tr><td>%s</td><td>%s %s</td><td>%s</td><td>%s</td></tr>`, h(ttp.Tactic), h(ttp.ID), h(ttp.Technique), h(ttp.Confidence), h(nonEmpty(ttp.Evidence, ttp.Finding)))
	}
	fmt.Fprint(b, `</table></section>`)
}

func htmlFamiliesAndConfig(b *strings.Builder, result ScanResult) {
	if len(result.FamilyMatches) > 0 {
		fmt.Fprint(b, `<section><h2>Family Classifier</h2><table><tr><th>Family</th><th>Category</th><th>Confidence</th><th>Evidence</th></tr>`)
		for _, family := range result.FamilyMatches {
			fmt.Fprintf(b, `<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`, h(family.Family), h(family.Category), h(family.Confidence), h(strings.Join(family.Evidence, ", ")))
		}
		fmt.Fprint(b, `</table></section>`)
	}
	if len(result.ConfigArtifacts) > 0 {
		fmt.Fprint(b, `<section><h2>Crypto and Config Extraction</h2><table><tr><th>Type</th><th>Confidence</th><th>Evidence</th><th>Preview</th></tr>`)
		for _, artifact := range result.ConfigArtifacts {
			fmt.Fprintf(b, `<tr><td>%s</td><td>%s</td><td>%s</td><td><code>%s</code></td></tr>`, h(artifact.Type), h(artifact.Confidence), h(artifact.Evidence), h(artifact.Preview))
		}
		fmt.Fprint(b, `</table></section>`)
	}
}

func htmlIOCs(b *strings.Builder, result ScanResult) {
	fmt.Fprint(b, `<section><h2>Indicators</h2><div class="grid">`)
	htmlPEHashCard(b, result.IOCs.PEHashes, 30)
	htmlListCard(b, "URLs", result.IOCs.URLs, 50)
	htmlListCard(b, "Domains", result.IOCs.Domains, 50)
	htmlListCard(b, "IPv4", result.IOCs.IPv4, 50)
	htmlListCard(b, "Hashes", append(append(append(append([]string{}, result.IOCs.MD5...), result.IOCs.SHA1...), result.IOCs.SHA256...), result.IOCs.SHA512...), 50)
	fmt.Fprint(b, `</div></section>`)
	if result.IOCs.SuppressedCount > 0 {
		fmt.Fprintf(b, `<p class="muted">%d contextual IOC values were suppressed by triage and remain available in Raw JSON.</p>`, result.IOCs.SuppressedCount)
	}
}

func htmlTechnical(b *strings.Builder, result ScanResult) {
	fmt.Fprint(b, `<section><h2>Technical Details</h2>`)
	if result.MSIX != nil {
		fmt.Fprint(b, `<details open><summary>MSIX/AppX Metadata</summary><table><tr><th>Field</th><th>Value</th></tr>`)
		htmlKVRow(b, "Identity", result.MSIX.IdentityName)
		htmlKVRow(b, "Publisher", fmt.Sprintf("%s trusted=%v", result.MSIX.IdentityPublisher, result.MSIX.PublisherTrusted))
		htmlKVRow(b, "Version", result.MSIX.IdentityVersion)
		htmlKVRow(b, "Declared executables", strings.Join(result.MSIX.DeclaredExecutables, ", "))
		htmlKVRow(b, "Undeclared executables", strings.Join(result.MSIX.UndeclaredExecutables, ", "))
		htmlKVRow(b, "Capabilities", strings.Join(result.MSIX.Capabilities, ", "))
		htmlKVRow(b, "Signature", fmt.Sprintf("sha256=%s size=%d status=%s", result.MSIX.SignatureSHA256, result.MSIX.SignatureSize, result.MSIX.SignatureParseStatus))
		fmt.Fprint(b, `</table></details>`)
	}
	if len(result.CarvedArtifacts) > 0 {
		fmt.Fprint(b, `<details open><summary>Carved Artifacts</summary><table><tr><th>Type</th><th>Offset</th><th>SHA256</th><th>Entropy</th></tr>`)
		for _, artifact := range result.CarvedArtifacts {
			fmt.Fprintf(b, `<tr><td>%s</td><td>0x%x</td><td><code>%s</code></td><td>%.2f</td></tr>`, h(artifact.Type), artifact.Offset, h(artifact.SHA256), artifact.Entropy)
		}
		fmt.Fprint(b, `</table></details>`)
	}
	if result.Similarity.FlatHash != "" {
		fmt.Fprintf(b, `<details open><summary>Similarity Hashes</summary><pre>%s</pre></details>`, h(formatSimilarity(result.Similarity)))
	}
	if len(result.ExternalTools) > 0 {
		fmt.Fprint(b, `<details><summary>External Tool Integration</summary><table><tr><th>Tool</th><th>Status</th><th>Output</th></tr>`)
		for _, tool := range result.ExternalTools {
			fmt.Fprintf(b, `<tr><td>%s</td><td>%s</td><td><code>%s</code></td></tr>`, h(tool.Name), h(tool.Status), h(tool.Output))
		}
		fmt.Fprint(b, `</table></details>`)
	}
	fmt.Fprint(b, `</section>`)
}

func htmlPEHashCard(b *strings.Builder, values []PEHashIOC, limit int) {
	fmt.Fprintf(b, `<div class="card"><strong>Embedded PE Hashes (%d)</strong><ul>`, len(values))
	for i, value := range values {
		if i >= limit {
			fmt.Fprintf(b, `<li class="muted">%d more omitted</li>`, len(values)-i)
			break
		}
		fmt.Fprintf(b, `<li><code>%s</code><br><span class="muted">%s | %s | entropy %.2f</span></li>`, h(value.SHA256), h(value.Path), h(value.Tier), value.Entropy)
	}
	fmt.Fprint(b, `</ul></div>`)
}

func htmlKVRow(b *strings.Builder, key, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	fmt.Fprintf(b, `<tr><td>%s</td><td><code>%s</code></td></tr>`, h(key), h(value))
}

func htmlRawJSON(b *strings.Builder, result ScanResult) {
	data, _ := json.MarshalIndent(result, "", "  ")
	fmt.Fprintf(b, `<details><summary>Raw JSON</summary><pre>%s</pre></details>`, h(string(data)))
}

func htmlListCard(b *strings.Builder, title string, values []string, limit int) {
	fmt.Fprintf(b, `<div class="card"><strong>%s (%d)</strong><ul>`, h(title), len(values))
	for i, value := range values {
		if i >= limit {
			fmt.Fprintf(b, `<li class="muted">%d more omitted</li>`, len(values)-i)
			break
		}
		fmt.Fprintf(b, `<li><code>%s</code></li>`, h(value))
	}
	fmt.Fprint(b, `</ul></div>`)
}

func h(value string) string {
	return html.EscapeString(value)
}

func firstFamily(result ScanResult) string {
	if len(result.FamilyMatches) == 0 {
		return "none"
	}
	return result.FamilyMatches[0].Family
}

func formatSimilarity(info SimilarityInfo) string {
	var b strings.Builder
	if info.FlatHash != "" {
		fmt.Fprintf(&b, "FlatHash: %s\n", info.FlatHash)
	}
	if info.ByteHistogramHash != "" {
		fmt.Fprintf(&b, "Byte histogram: %s\n", info.ByteHistogramHash)
	}
	if info.StringSetHash != "" {
		fmt.Fprintf(&b, "String set: %s\n", info.StringSetHash)
	}
	if info.ImportHash != "" {
		fmt.Fprintf(&b, "Import hash: %s\n", info.ImportHash)
	}
	if info.SectionHash != "" {
		fmt.Fprintf(&b, "Section hash: %s\n", info.SectionHash)
	}
	if info.DEXStringHash != "" {
		fmt.Fprintf(&b, "DEX string hash: %s\n", info.DEXStringHash)
	}
	if info.ArchiveContentHash != "" {
		fmt.Fprintf(&b, "Archive content: %s\n", info.ArchiveContentHash)
	}
	return b.String()
}
