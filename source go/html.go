package main

import (
	"encoding/json"
	"fmt"
	"html"
	"math"
	"os"
	"path/filepath"
	"sort"
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
	htmlHead(&b, result)
	htmlNavBar(&b, result)
	b.WriteString(`<main>`)
	htmlOverview(&b, result)
	htmlFindings(&b, result)
	htmlIOCTabs(&b, result)
	htmlMITREHeatmap(&b, result)
	htmlFamiliesConfig(&b, result)
	htmlTechnical(&b, result)
	htmlRawJSON(&b, result)
	b.WriteString(`</main>`)
	htmlInlineJS(&b)
	b.WriteString("</body></html>\n")
	return b.String()
}

// ── CSS ─────────────────────────────────────────────────────────────────────

func htmlHead(b *strings.Builder, result ScanResult) {
	fmt.Fprintf(b, `<!doctype html><html data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>FlatScan Malware Analysis Report — %s</title>`, h(result.FileName))
	b.WriteString("<style>")
	b.WriteString(htmlCSS())
	b.WriteString("</style></head><body>")
}

func htmlCSS() string {
	return `
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2128;--border:#30363d;
  --ink:#e6edf3;--muted:#7d8590;--accent:#f78166;
  --red:#f85149;--orange:#d18616;--amber:#e3b341;--green:#3fb950;--blue:#58a6ff;--purple:#bc8cff;
  --nav-h:52px;--radius:8px;
  --crit:#f85149;--high:#d18616;--med:#e3b341;--low:#58a6ff;--info:#7d8590;
}
[data-theme="light"]{
  --bg:#f6f8fa;--surface:#ffffff;--surface2:#f0f2f5;--border:#d0d7de;
  --ink:#1f2328;--muted:#636c76;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--ink);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;padding-top:var(--nav-h)}
a{color:var(--blue);text-decoration:none}
code,pre{font-family:"JetBrains Mono","Fira Code",ui-monospace,Consolas,monospace;font-size:12px}

/* Nav */
nav{position:fixed;top:0;left:0;right:0;height:var(--nav-h);background:var(--surface);border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 20px;gap:16px;z-index:100}
.nav-brand{font-weight:700;font-size:15px;color:var(--ink);white-space:nowrap}
.nav-file{color:var(--muted);font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;min-width:0}
.nav-links{display:flex;gap:12px;white-space:nowrap}
.nav-links a{color:var(--muted);font-size:12px;padding:4px 0;border-bottom:2px solid transparent}
.nav-links a:hover{color:var(--ink);border-color:var(--accent)}
.nav-right{display:flex;align-items:center;gap:8px;white-space:nowrap}
.theme-btn{background:var(--surface2);border:1px solid var(--border);color:var(--muted);border-radius:6px;padding:4px 10px;cursor:pointer;font-size:12px}
.theme-btn:hover{color:var(--ink)}

/* Layout */
main{max-width:1200px;margin:0 auto;padding:28px 20px 64px}
section{margin-bottom:32px}
.section-title{font-size:16px;font-weight:700;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px}
.section-title .cnt{font-size:12px;font-weight:400;color:var(--muted);background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:1px 8px}

/* Cards & Grid */
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:20px}
.metric{border-top:3px solid var(--border)}
.metric.crit{border-color:var(--crit)}
.metric.high{border-color:var(--high)}
.metric.med{border-color:var(--amber)}
.metric.low{border-color:var(--low)}
.metric.ok{border-color:var(--green)}
.metric .lbl{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);font-weight:600;margin-bottom:4px}
.metric .val{font-size:22px;font-weight:700}
.metric .sub{font-size:11px;color:var(--muted);margin-top:2px}

/* Risk gauge */
.gauge-wrap{display:flex;flex-direction:column;align-items:center;margin-bottom:20px}
.gauge-label{font-size:12px;color:var(--muted);margin-top:6px}

/* Executive assessment */
.exec-box{background:var(--surface2);border-left:4px solid var(--accent);border-radius:0 var(--radius) var(--radius) 0;padding:14px 16px;line-height:1.6;margin-bottom:20px}

/* Findings */
.filter-row{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px}
.filter-btn{border:1px solid var(--border);background:var(--surface2);color:var(--muted);border-radius:20px;padding:4px 12px;cursor:pointer;font-size:12px;transition:all .15s}
.filter-btn.active,.filter-btn:hover{color:var(--ink);border-color:var(--ink)}
.filter-btn.sev-Critical.active{background:var(--crit);border-color:var(--crit);color:#fff}
.filter-btn.sev-High.active{background:var(--high);border-color:var(--high);color:#fff}
.filter-btn.sev-Medium.active{background:var(--amber);border-color:var(--amber);color:#1f2328}
.filter-btn.sev-Low.active{background:var(--low);border-color:var(--low);color:#fff}

.finding-card{border:1px solid var(--border);border-left:4px solid var(--border);border-radius:var(--radius);padding:14px 16px;margin-bottom:10px;background:var(--surface)}
.finding-card[data-sev="Critical"]{border-left-color:var(--crit)}
.finding-card[data-sev="High"]{border-left-color:var(--high)}
.finding-card[data-sev="Medium"]{border-left-color:var(--amber)}
.finding-card[data-sev="Low"]{border-left-color:var(--low)}
.finding-card[data-sev="Info"]{border-left-color:var(--info)}
.finding-header{display:flex;align-items:flex-start;gap:10px;flex-wrap:wrap}
.sev-badge{font-size:11px;font-weight:700;padding:2px 8px;border-radius:4px;white-space:nowrap}
.sev-badge.Critical{background:var(--crit);color:#fff}
.sev-badge.High{background:var(--high);color:#fff}
.sev-badge.Medium{background:var(--amber);color:#1f2328}
.sev-badge.Low{background:var(--low);color:#fff}
.sev-badge.Info{background:var(--surface2);color:var(--muted);border:1px solid var(--border)}
.finding-title{font-weight:600;font-size:13px;flex:1}
.finding-cat{font-size:11px;color:var(--muted)}
.finding-body{margin-top:10px;display:flex;flex-direction:column;gap:6px}
.finding-evidence{background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:8px 10px;font-family:monospace;font-size:11px;word-break:break-all;color:var(--ink)}
.finding-tags{display:flex;gap:6px;flex-wrap:wrap}
.tag{font-size:11px;padding:2px 8px;border-radius:4px;border:1px solid var(--border);color:var(--muted);background:var(--surface2)}
.tag.mitre{border-color:var(--purple);color:var(--purple)}
.finding-rec{font-size:12px;color:var(--muted);margin-top:4px}

/* IOC Tabs */
.tab-row{display:flex;flex-wrap:wrap;gap:0;border-bottom:1px solid var(--border);margin-bottom:16px}
.tab-btn{background:none;border:none;border-bottom:2px solid transparent;color:var(--muted);padding:8px 16px;cursor:pointer;font-size:13px;margin-bottom:-1px}
.tab-btn.active{color:var(--ink);border-color:var(--accent);font-weight:600}
.tab-btn:hover{color:var(--ink)}
.tab-panel{display:none}
.tab-panel.active{display:block}
.ioc-toolbar{display:flex;gap:8px;margin-bottom:12px}
.ioc-search{flex:1;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:6px 10px;color:var(--ink);font-size:13px}
.ioc-search::placeholder{color:var(--muted)}
.ioc-list{display:flex;flex-direction:column;gap:4px;max-height:320px;overflow-y:auto}
.ioc-row{display:flex;align-items:center;gap:8px;padding:5px 8px;border-radius:4px;background:var(--surface2);border:1px solid var(--border)}
.ioc-row:hover{border-color:var(--muted)}
.ioc-val{flex:1;font-family:monospace;font-size:11px;word-break:break-all;color:var(--ink)}
.copy-btn{background:none;border:1px solid var(--border);color:var(--muted);border-radius:4px;padding:2px 6px;cursor:pointer;font-size:10px;white-space:nowrap;flex-shrink:0}
.copy-btn:hover{color:var(--ink);border-color:var(--muted)}
.copy-btn.copied{color:var(--green);border-color:var(--green)}

/* MITRE heatmap */
.mitre-grid{display:flex;flex-wrap:wrap;gap:12px}
.mitre-col{flex:1;min-width:140px;max-width:200px}
.mitre-tactic{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin-bottom:8px;padding-bottom:4px;border-bottom:1px solid var(--border)}
.mitre-cell{font-size:11px;padding:4px 8px;border-radius:4px;margin-bottom:4px;border:1px solid var(--border);background:var(--surface2)}
.mitre-cell.conf-High{border-color:var(--red);color:var(--red)}
.mitre-cell.conf-Medium{border-color:var(--amber);color:var(--amber)}
.mitre-cell.conf-Low{border-color:var(--blue);color:var(--blue)}
.mitre-id{font-weight:700;margin-right:4px}

/* Tables */
table{border-collapse:collapse;width:100%;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}
th{background:var(--surface2);border-bottom:1px solid var(--border);padding:8px 12px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);font-weight:600}
td{border-bottom:1px solid var(--border);padding:8px 12px;vertical-align:top;font-size:12px}
tr:last-child td{border-bottom:none}
tr:hover td{background:var(--surface2)}

/* Technical details */
details{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:10px;overflow:hidden}
summary{cursor:pointer;padding:12px 16px;font-weight:600;font-size:13px;list-style:none;display:flex;align-items:center;gap:8px}
summary::before{content:"›";font-size:16px;transition:transform .15s;display:inline-block}
details[open] summary::before{transform:rotate(90deg)}
.details-body{padding:0 16px 16px}

/* Raw JSON */
.json-wrap{position:relative}
.json-copy{position:absolute;top:8px;right:8px}
pre.json{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:16px;overflow:auto;max-height:600px;white-space:pre-wrap;word-break:break-all;font-size:11px;line-height:1.6}
.j-key{color:var(--blue)}
.j-str{color:var(--green)}
.j-num{color:var(--amber)}
.j-bool{color:var(--orange)}
.j-null{color:var(--muted)}

.muted{color:var(--muted)}
.sha{font-family:monospace;font-size:11px;word-break:break-all}
`
}

// ── Nav ──────────────────────────────────────────────────────────────────────

func htmlNavBar(b *strings.Builder, result ScanResult) {
	vClass := htmlVerdictClass(result.RiskScore)
	fmt.Fprintf(b, `<nav>
<span class="nav-brand">FlatScan</span>
<span class="nav-file" title="%s">%s</span>
<span class="sev-badge %s" style="font-size:12px">%s</span>
<span class="nav-links">
  <a href="#overview">Overview</a>
  <a href="#findings">Findings</a>
  <a href="#iocs">IOCs</a>
  <a href="#mitre">MITRE</a>
  <a href="#technical">Technical</a>
  <a href="#raw">JSON</a>
</span>
<div class="nav-right">
  <input id="global-search" type="search" placeholder="Search findings, IOCs…" oninput="globalSearch(this.value)" style="background:var(--surface2);border:1px solid var(--border);color:var(--ink);border-radius:6px;padding:4px 10px;font-size:13px;width:220px;outline:none">
  <button class="theme-btn" onclick="toggleTheme()">☀ / ☾</button>
</div>
</nav>`,
		h(result.Target), h(result.FileName), vClass, h(result.Verdict))
}

func htmlVerdictClass(score int) string {
	switch {
	case score >= 80:
		return "Critical"
	case score >= 55:
		return "High"
	case score >= 30:
		return "Medium"
	case score >= 10:
		return "Low"
	default:
		return "Info"
	}
}

// ── Overview ─────────────────────────────────────────────────────────────────

func htmlOverview(b *strings.Builder, result ScanResult) {
	b.WriteString(`<section id="overview">`)
	b.WriteString(`<div class="section-title">Overview</div>`)

	// Risk gauge + metric grid side by side
	b.WriteString(`<div style="display:flex;flex-wrap:wrap;gap:20px;margin-bottom:20px;align-items:flex-start">`)

	// SVG gauge
	b.WriteString(`<div class="gauge-wrap">`)
	htmlRiskGauge(b, result.RiskScore)
	fmt.Fprintf(b, `<div class="gauge-label">Risk Score: <strong>%d/100</strong> — %s</div>`, result.RiskScore, h(riskBand(result.RiskScore)))
	b.WriteString(`</div>`)

	// Metric cards
	b.WriteString(`<div style="flex:1;display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px">`)
	mClass := htmlVerdictClass(result.RiskScore)
	htmlMetricCard(b, "Verdict", h(result.Verdict), "", mClass)
	htmlMetricCard(b, "Findings", fmt.Sprintf("%d", len(result.Findings)), h(severitySummary(result.Findings)), mClass)
	htmlMetricCard(b, "IOCs", fmt.Sprintf("%d", IOCCount(result.IOCs)), "extracted indicators", "")
	htmlMetricCard(b, "TTPs", fmt.Sprintf("%d", len(result.Profile.TTPs)), "MITRE techniques", "")
	htmlMetricCard(b, "Family", h(firstFamily(result)), "classifier", "")
	htmlMetricCard(b, "File", h(formatBytes(result.Size)), h(result.FileType), "")
	b.WriteString(`</div>`)
	b.WriteString(`</div>`)

	// Executive assessment
	assessment := result.Profile.ExecutiveAssessment
	if assessment == "" {
		assessment = executiveNarrative(result)
	}
	fmt.Fprintf(b, `<div class="exec-box">%s</div>`, h(assessment))

	// Hashes
	if result.Hashes.SHA256 != "" {
		b.WriteString(`<div class="card" style="margin-bottom:12px"><div class="lbl muted" style="font-size:11px;text-transform:uppercase;margin-bottom:6px">Sample Hashes</div>`)
		for _, row := range [][2]string{
			{"MD5", result.Hashes.MD5}, {"SHA1", result.Hashes.SHA1},
			{"SHA256", result.Hashes.SHA256}, {"SHA512", result.Hashes.SHA512},
		} {
			if row[1] != "" {
				fmt.Fprintf(b, `<div style="display:flex;gap:8px;margin-bottom:4px"><span class="muted" style="font-size:11px;width:48px;flex-shrink:0">%s</span><code class="sha" style="flex:1">%s</code></div>`, row[0], h(row[1]))
			}
		}
		b.WriteString(`</div>`)
	}

	b.WriteString(`</section>`)
}

func htmlRiskGauge(b *strings.Builder, score int) {
	const (
		cx, cy, r = 120.0, 110.0, 90.0
	)
	// Background arc: semicircle from left (180°) to right (0°) going through top.
	// Fill arc: from left to the score angle, along the same top semicircle.
	//
	// large-arc-flag is always 0. Both arcs run from the left endpoint to a point
	// on the top semicircle, so the sweep is never more than 180° and the minor
	// arc is always the one we want. Setting the flag to 1 above score 50 — the
	// rule for a full-circle progress ring, not a semicircular gauge — made SVG
	// draw the major arc the long way round through the bottom instead. The
	// viewBox is only 130 tall, so that detour was clipped and the gauge rendered
	// as two disconnected stubs on every report scoring over 50.
	const largeArc = 0
	angle := math.Pi * (1.0 - float64(score)/100.0)
	ex := cx + r*math.Cos(angle)
	ey := cy - r*math.Sin(angle)

	fillColor := "#3fb950"
	switch {
	case score >= 80:
		fillColor = "#f85149"
	case score >= 55:
		fillColor = "#d18616"
	case score >= 30:
		fillColor = "#e3b341"
	}

	fmt.Fprintf(b, `<svg width="240" height="130" viewBox="0 0 240 130" xmlns="http://www.w3.org/2000/svg">
  <path d="M %g,%g A %g,%g 0 1 1 %g,%g" fill="none" stroke="#30363d" stroke-width="14" stroke-linecap="round"/>
  <path d="M %g,%g A %g,%g 0 %d 1 %g,%g" fill="none" stroke="%s" stroke-width="14" stroke-linecap="round"/>
  <text x="%g" y="%g" text-anchor="middle" font-size="28" font-weight="bold" fill="#e6edf3">%d</text>
  <text x="%g" y="%g" text-anchor="middle" font-size="11" fill="#7d8590">/ 100</text>
</svg>`,
		cx-r, cy, r, r, cx+r, cy,
		cx-r, cy, r, r, largeArc, ex, ey, fillColor,
		cx, cy-4, score,
		cx, cy+18)
}

func htmlMetricCard(b *strings.Builder, label, value, sub, extra string) {
	cls := "card metric"
	if extra != "" {
		cls += " " + extra
	}
	fmt.Fprintf(b, `<div class="%s"><div class="lbl">%s</div><div class="val">%s</div>`, cls, label, value)
	if sub != "" {
		fmt.Fprintf(b, `<div class="sub">%s</div>`, sub)
	}
	b.WriteString(`</div>`)
}

// ── Findings ─────────────────────────────────────────────────────────────────

func htmlFindings(b *strings.Builder, result ScanResult) {
	cnt := fmt.Sprintf(`<span class="cnt">%d</span>`, len(result.Findings))
	fmt.Fprintf(b, `<section id="findings"><div class="section-title">Findings %s</div>`, cnt)

	b.WriteString(`<div class="filter-row">`)
	for _, sev := range []string{"All", "Critical", "High", "Medium", "Low", "Info"} {
		active := ""
		if sev == "All" {
			active = " active"
		}
		cls := "filter-btn"
		if sev != "All" {
			cls += " sev-" + sev
		}
		fmt.Fprintf(b, `<button class="%s%s" onclick="filterFindings('%s')">%s</button>`, cls, active, sev, sev)
	}
	b.WriteString(`</div>`)

	if len(result.Findings) == 0 {
		b.WriteString(`<div class="card muted" style="padding:20px;text-align:center">No findings were recorded for this sample.</div>`)
	}

	for _, finding := range result.Findings {
		fmt.Fprintf(b, `<div class="finding-card" data-sev="%s">`, h(finding.Severity))
		b.WriteString(`<div class="finding-header">`)
		fmt.Fprintf(b, `<span class="sev-badge %s">%s</span>`, h(finding.Severity), h(finding.Severity))
		fmt.Fprintf(b, `<span class="finding-title">%s</span>`, h(finding.Title))
		fmt.Fprintf(b, `<span class="finding-cat muted">%s</span>`, h(finding.Category))
		b.WriteString(`</div><div class="finding-body">`)
		if finding.Evidence != "" {
			fmt.Fprintf(b, `<div class="finding-evidence">%s</div>`, h(finding.Evidence))
		}
		if finding.Tactic != "" || finding.Technique != "" {
			b.WriteString(`<div class="finding-tags">`)
			if finding.Tactic != "" {
				fmt.Fprintf(b, `<span class="tag mitre">%s</span>`, h(finding.Tactic))
			}
			if finding.Technique != "" {
				fmt.Fprintf(b, `<span class="tag mitre">%s</span>`, h(finding.Technique))
			}
			b.WriteString(`</div>`)
		}
		if finding.Recommendation != "" {
			fmt.Fprintf(b, `<div class="finding-rec muted">→ %s</div>`, h(finding.Recommendation))
		}
		b.WriteString(`</div></div>`)
	}
	b.WriteString(`</section>`)
}

// ── IOC Tabs ─────────────────────────────────────────────────────────────────

func htmlIOCTabs(b *strings.Builder, result ScanResult) {
	type iocTab struct {
		id    string
		label string
		items []string
	}
	tabs := []iocTab{}
	if len(result.IOCs.URLs) > 0 {
		tabs = append(tabs, iocTab{"urls", fmt.Sprintf("URLs (%d)", len(result.IOCs.URLs)), result.IOCs.URLs})
	}
	if len(result.IOCs.Domains) > 0 {
		tabs = append(tabs, iocTab{"domains", fmt.Sprintf("Domains (%d)", len(result.IOCs.Domains)), result.IOCs.Domains})
	}
	if len(result.IOCs.IPv4)+len(result.IOCs.IPv6) > 0 {
		ips := append(append([]string{}, result.IOCs.IPv4...), result.IOCs.IPv6...)
		tabs = append(tabs, iocTab{"ips", fmt.Sprintf("IPs (%d)", len(ips)), ips})
	}
	allHashes := append(append(append(append([]string{}, result.IOCs.MD5...), result.IOCs.SHA1...), result.IOCs.SHA256...), result.IOCs.SHA512...)
	if len(allHashes) > 0 {
		tabs = append(tabs, iocTab{"hashes", fmt.Sprintf("Hashes (%d)", len(allHashes)), allHashes})
	}
	if len(result.IOCs.RegistryKeys) > 0 {
		tabs = append(tabs, iocTab{"reg", fmt.Sprintf("Registry (%d)", len(result.IOCs.RegistryKeys)), result.IOCs.RegistryKeys})
	}
	paths := append(append([]string{}, result.IOCs.WindowsPaths...), result.IOCs.UnixPaths...)
	if len(paths) > 0 {
		tabs = append(tabs, iocTab{"paths", fmt.Sprintf("Paths (%d)", len(paths)), paths})
	}
	if len(result.IOCs.Emails) > 0 {
		tabs = append(tabs, iocTab{"emails", fmt.Sprintf("Emails (%d)", len(result.IOCs.Emails)), result.IOCs.Emails})
	}
	if len(result.IOCs.CVEs) > 0 {
		tabs = append(tabs, iocTab{"cves", fmt.Sprintf("CVEs (%d)", len(result.IOCs.CVEs)), result.IOCs.CVEs})
	}
	if len(result.IOCs.Mutexes) > 0 {
		tabs = append(tabs, iocTab{"mutexes", fmt.Sprintf("Mutexes (%d)", len(result.IOCs.Mutexes)), result.IOCs.Mutexes})
	}
	if len(result.IOCs.NamedPipes) > 0 {
		tabs = append(tabs, iocTab{"pipes", fmt.Sprintf("Named Pipes (%d)", len(result.IOCs.NamedPipes)), result.IOCs.NamedPipes})
	}
	if len(result.IOCs.CryptoWallets) > 0 {
		tabs = append(tabs, iocTab{"wallets", fmt.Sprintf("Crypto Wallets (%d)", len(result.IOCs.CryptoWallets)), result.IOCs.CryptoWallets})
	}

	total := IOCCount(result.IOCs)
	cnt := fmt.Sprintf(`<span class="cnt">%d</span>`, total)
	fmt.Fprintf(b, `<section id="iocs"><div class="section-title">Indicators of Compromise %s</div>`, cnt)

	if len(tabs) == 0 {
		b.WriteString(`<div class="card muted" style="padding:20px;text-align:center">No indicators were extracted for this sample.</div></section>`)
		return
	}

	b.WriteString(`<div class="card" style="padding:0 16px 16px">`)
	b.WriteString(`<div class="tab-row">`)
	for i, tab := range tabs {
		active := ""
		if i == 0 {
			active = " active"
		}
		fmt.Fprintf(b, `<button class="tab-btn%s" onclick="switchTab('%s')">%s</button>`, active, tab.id, tab.label)
	}
	b.WriteString(`</div>`)

	for i, tab := range tabs {
		active := ""
		if i == 0 {
			active = " active"
		}
		fmt.Fprintf(b, `<div class="tab-panel%s" id="tab-%s">`, active, tab.id)
		fmt.Fprintf(b, `<div class="ioc-toolbar"><input class="ioc-search" type="text" placeholder="Filter..." oninput="filterIOCs(this,'ioc-list-%s')"></div>`, tab.id)
		fmt.Fprintf(b, `<div class="ioc-list" id="ioc-list-%s">`, tab.id)
		for _, item := range tab.items {
			fmt.Fprintf(b, `<div class="ioc-row"><span class="ioc-val">%s</span><button class="copy-btn" onclick="copyIOC(this,'%s')">copy</button></div>`,
				h(item), h(item))
		}
		b.WriteString(`</div></div>`)
	}
	b.WriteString(`</div>`)

	if result.IOCs.SuppressedCount > 0 {
		fmt.Fprintf(b, `<p class="muted" style="font-size:12px;margin-top:8px">%d contextual IOC values suppressed by triage — available in Raw JSON.</p>`, result.IOCs.SuppressedCount)
	}

	// PE hash panel
	if len(result.IOCs.PEHashes) > 0 {
		fmt.Fprintf(b, `<div style="margin-top:16px"><div class="section-title" style="font-size:14px">Embedded PE Payload Hashes <span class="cnt">%d</span></div>`, len(result.IOCs.PEHashes))
		b.WriteString(`<table><tr><th>Tier</th><th>Path</th><th>SHA256</th><th>Entropy</th></tr>`)
		for _, ph := range result.IOCs.PEHashes {
			fmt.Fprintf(b, `<tr><td>%s</td><td><code>%s</code></td><td><code>%s</code></td><td>%.2f</td></tr>`,
				h(ph.Tier), h(ph.Path), h(ph.SHA256), ph.Entropy)
		}
		b.WriteString(`</table></div>`)
	}

	b.WriteString(`</section>`)
}

// ── MITRE Heatmap ─────────────────────────────────────────────────────────────

func htmlMITREHeatmap(b *strings.Builder, result ScanResult) {
	if len(result.Profile.TTPs) == 0 {
		return
	}

	// Group by tactic
	tacticOrder := []string{
		"Initial Access", "Execution", "Persistence", "Privilege Escalation",
		"Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
		"Collection", "Command and Control", "Exfiltration", "Impact",
	}
	grouped := map[string][]TTPEntry{}
	for _, ttp := range result.Profile.TTPs {
		grouped[ttp.Tactic] = append(grouped[ttp.Tactic], ttp)
	}
	// Also include tactics not in the standard order
	for tactic := range grouped {
		found := false
		for _, t := range tacticOrder {
			if t == tactic {
				found = true
				break
			}
		}
		if !found {
			tacticOrder = append(tacticOrder, tactic)
		}
	}

	cnt := fmt.Sprintf(`<span class="cnt">%d</span>`, len(result.Profile.TTPs))
	fmt.Fprintf(b, `<section id="mitre"><div class="section-title">MITRE ATT&amp;CK TTPs %s</div>`, cnt)
	b.WriteString(`<div class="mitre-grid">`)

	for _, tactic := range tacticOrder {
		entries := grouped[tactic]
		if len(entries) == 0 {
			continue
		}
		fmt.Fprintf(b, `<div class="mitre-col"><div class="mitre-tactic">%s</div>`, h(tactic))
		for _, ttp := range entries {
			conf := ttp.Confidence
			if conf == "" {
				conf = "Low"
			}
			tech := ttp.Technique
			label := tech
			if ttp.ID != "" {
				label = ttp.ID
			}
			tooltip := tech
			if ttp.Evidence != "" {
				tooltip = ttp.Evidence
			}
			fmt.Fprintf(b, `<div class="mitre-cell conf-%s" title="%s"><span class="mitre-id">%s</span>%s</div>`,
				h(conf), h(tooltip), h(label), h(tech))
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div></section>`)
}

// ── Family / Config ───────────────────────────────────────────────────────────

func htmlFamiliesConfig(b *strings.Builder, result ScanResult) {
	if len(result.FamilyMatches) == 0 && len(result.ConfigArtifacts) == 0 {
		return
	}
	if len(result.FamilyMatches) > 0 {
		b.WriteString(`<section><div class="section-title">Family Classifier</div><table><tr><th>Family</th><th>Category</th><th>Confidence</th><th>Evidence</th></tr>`)
		for _, fm := range result.FamilyMatches {
			fmt.Fprintf(b, `<tr><td><strong>%s</strong></td><td>%s</td><td>%s</td><td>%s</td></tr>`,
				h(fm.Family), h(fm.Category), h(fm.Confidence), h(strings.Join(fm.Evidence, ", ")))
		}
		b.WriteString(`</table></section>`)
	}
	if len(result.ConfigArtifacts) > 0 {
		b.WriteString(`<section><div class="section-title">Crypto &amp; Config Extraction</div><table><tr><th>Type</th><th>Confidence</th><th>Evidence</th><th>Preview</th></tr>`)
		for _, ca := range result.ConfigArtifacts {
			fmt.Fprintf(b, `<tr><td>%s</td><td>%s</td><td>%s</td><td><code>%s</code></td></tr>`,
				h(ca.Type), h(ca.Confidence), h(ca.Evidence), h(ca.Preview))
		}
		b.WriteString(`</table></section>`)
	}
}

// ── Technical Details ─────────────────────────────────────────────────────────

func htmlTechnical(b *strings.Builder, result ScanResult) {
	b.WriteString(`<section id="technical"><div class="section-title">Technical Details</div>`)

	if result.MSIX != nil {
		b.WriteString(`<details open><summary>MSIX/AppX Metadata</summary><div class="details-body"><table>`)
		htmlKVRow(b, "Identity", result.MSIX.IdentityName)
		htmlKVRow(b, "Publisher", fmt.Sprintf("%s  trusted=%v", result.MSIX.IdentityPublisher, result.MSIX.PublisherTrusted))
		htmlKVRow(b, "Version", result.MSIX.IdentityVersion)
		if len(result.MSIX.DeclaredExecutables) > 0 {
			htmlKVRow(b, "Declared executables", strings.Join(result.MSIX.DeclaredExecutables, ", "))
		}
		if len(result.MSIX.UndeclaredExecutables) > 0 {
			htmlKVRow(b, "Undeclared executables", strings.Join(result.MSIX.UndeclaredExecutables, ", "))
		}
		if len(result.MSIX.Capabilities) > 0 {
			htmlKVRow(b, "Capabilities", strings.Join(result.MSIX.Capabilities, ", "))
		}
		b.WriteString(`</table></div></details>`)
	}

	if result.PE != nil {
		b.WriteString(`<details open><summary>PE Details</summary><div class="details-body"><table>`)
		htmlKVRow(b, "Machine", result.PE.Machine)
		htmlKVRow(b, "Timestamp", result.PE.Timestamp)
		htmlKVRow(b, "Subsystem", result.PE.Subsystem)
		htmlKVRow(b, "Entry point", result.PE.EntryPoint)
		htmlKVRow(b, "Image base", result.PE.ImageBase)
		htmlKVRow(b, "Import hash", result.PE.ImportHash)
		htmlKVRow(b, "Managed (.NET)", fmt.Sprintf("%v", result.PE.ManagedRuntime))
		htmlKVRow(b, "Certificate table", fmt.Sprintf("%v", result.PE.HasCertificate))
		if result.PE.SignatureStatus != "" {
			htmlKVRow(b, "Signature", result.PE.SignatureStatus)
		}
		if len(result.PE.CertificateSubjects) > 0 {
			htmlKVRow(b, "Signer subject(s)", strings.Join(result.PE.CertificateSubjects, "; "))
		}
		if result.PE.SelfSigned {
			htmlKVRow(b, "Self-signed", "true")
		}
		if len(result.PE.SecurityFeatures) > 0 {
			htmlKVRow(b, "Security mitigations", strings.Join(result.PE.SecurityFeatures, ", "))
		}
		if len(result.PE.MissingMitigations) > 0 {
			htmlKVRow(b, "Missing mitigations", strings.Join(result.PE.MissingMitigations, ", "))
		}
		if len(result.PE.ImageCharacteristics) > 0 {
			htmlKVRow(b, "Image characteristics", strings.Join(result.PE.ImageCharacteristics, ", "))
		}
		if result.PE.HasTLSCallbacks {
			htmlKVRow(b, "TLS callbacks", fmt.Sprintf("%d", result.PE.TLSCallbackCount))
		}
		if result.PE.EntryPointAnomaly != "" {
			htmlKVRow(b, "Entry point", fmt.Sprintf("%s (%s)", result.PE.EntryPointSection, result.PE.EntryPointAnomaly))
		}
		if result.PE.RichHeaderHash != "" {
			htmlKVRow(b, "Rich header hash", result.PE.RichHeaderHash)
		}
		b.WriteString(`</table>`)
		if len(result.PE.Sections) > 0 {
			b.WriteString(`<table style="margin-top:8px"><tr><th>Section</th><th>Raw offset</th><th>Raw size</th><th>Entropy</th><th>Exec</th><th>Write</th></tr>`)
			for _, sec := range result.PE.Sections {
				fmt.Fprintf(b, `<tr><td><code>%s</code></td><td>0x%x</td><td>%d</td><td>%.2f</td><td>%v</td><td>%v</td></tr>`,
					h(sec.Name), sec.RawOffset, sec.RawSize, sec.Entropy, sec.Executable, sec.Writable)
			}
			b.WriteString(`</table>`)
		}
		b.WriteString(`</div></details>`)
	}

	if result.ELF != nil {
		b.WriteString(`<details open><summary>ELF Details</summary><div class="details-body"><table>`)
		htmlKVRow(b, "Class", result.ELF.Class)
		htmlKVRow(b, "Machine", result.ELF.Machine)
		htmlKVRow(b, "Type", result.ELF.Type)
		b.WriteString(`</table></div></details>`)
	}

	if result.MachO != nil {
		b.WriteString(`<details open><summary>Mach-O Details</summary><div class="details-body"><table>`)
		htmlKVRow(b, "CPU", result.MachO.CPU)
		htmlKVRow(b, "Type", result.MachO.Type)
		b.WriteString(`</table></div></details>`)
	}

	if len(result.DGADomains) > 0 {
		b.WriteString(`<details open><summary>Algorithmically-Generated Domains (DGA)</summary><div class="details-body"><table><tr><th>Domain</th><th>Score</th><th>Signals</th></tr>`)
		for _, d := range result.DGADomains {
			fmt.Fprintf(b, `<tr><td><code>%s</code></td><td>%.2f</td><td>%s</td></tr>`, h(d.Domain), d.Score, h(strings.Join(d.Reasons, ", ")))
		}
		b.WriteString(`</table></div></details>`)
	}

	if result.APK != nil {
		b.WriteString(`<details open><summary>Android APK</summary><div class="details-body"><table>`)
		htmlKVRow(b, "Package", result.APK.PackageName)
		htmlKVRow(b, "Version", fmt.Sprintf("name=%s code=%s", result.APK.VersionName, result.APK.VersionCode))
		htmlKVRow(b, "SDK", fmt.Sprintf("min=%s target=%s", result.APK.MinSDK, result.APK.TargetSDK))
		htmlKVRow(b, "Files", fmt.Sprintf("%d", result.APK.FileCount))
		b.WriteString(`</table>`)
		if len(result.APK.Permissions) > 0 {
			fmt.Fprintf(b, `<p style="margin:10px 0 4px;font-size:12px;color:var(--muted)">Permissions (%d)</p><table><tr><th>Name</th><th>Risk</th><th>Category</th></tr>`, len(result.APK.Permissions))
			for _, p := range result.APK.Permissions {
				fmt.Fprintf(b, `<tr><td><code>%s</code></td><td>%s</td><td>%s</td></tr>`, h(p.Name), h(p.Risk), h(p.Category))
			}
			b.WriteString(`</table>`)
		}
		b.WriteString(`</div></details>`)
	}

	if len(result.CarvedArtifacts) > 0 {
		fmt.Fprintf(b, `<details open><summary>Carved Artifacts <span class="cnt">%d</span></summary><div class="details-body">`, len(result.CarvedArtifacts))
		b.WriteString(`<table><tr><th>Type</th><th>Offset</th><th>SHA256</th><th>Entropy</th></tr>`)
		for _, ca := range result.CarvedArtifacts {
			fmt.Fprintf(b, `<tr><td>%s</td><td>0x%x</td><td><code>%s</code></td><td>%.2f</td></tr>`,
				h(ca.Type), ca.Offset, h(ca.SHA256), ca.Entropy)
		}
		b.WriteString(`</table></div></details>`)
	}

	if result.Similarity.FlatHash != "" {
		fmt.Fprintf(b, `<details open><summary>Similarity Hashes</summary><div class="details-body"><pre style="background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:10px;font-size:11px">%s</pre></div></details>`,
			h(formatSimilarity(result.Similarity)))
	}

	if len(result.ArchiveEntries) > 0 {
		fmt.Fprintf(b, `<details><summary>Archive Entries <span class="cnt">%d</span></summary><div class="details-body">`, len(result.ArchiveEntries))
		b.WriteString(`<table><tr><th>Name</th><th>Size</th><th>Compressed</th><th>Reason</th></tr>`)
		for _, ae := range result.ArchiveEntries {
			fmt.Fprintf(b, `<tr><td><code>%s</code></td><td>%d</td><td>%d</td><td>%s</td></tr>`,
				h(ae.Name), ae.Size, ae.CompressedSize, h(ae.SuspiciousReason))
		}
		b.WriteString(`</table></div></details>`)
	}

	if len(result.ExternalTools) > 0 {
		b.WriteString(`<details><summary>External Tool Output</summary><div class="details-body"><table><tr><th>Tool</th><th>Status</th><th>Output</th></tr>`)
		for _, et := range result.ExternalTools {
			fmt.Fprintf(b, `<tr><td>%s</td><td>%s</td><td><code>%s</code></td></tr>`, h(et.Name), h(et.Status), h(et.Output))
		}
		b.WriteString(`</table></div></details>`)
	}

	b.WriteString(`</section>`)
}

// ── Raw JSON ─────────────────────────────────────────────────────────────────

func htmlRawJSON(b *strings.Builder, result ScanResult) {
	data, _ := json.MarshalIndent(result, "", "  ")
	highlighted := htmlSyntaxJSON(string(data))
	b.WriteString(`<section id="raw"><div class="section-title">Raw JSON</div>`)
	b.WriteString(`<div class="json-wrap">`)
	b.WriteString(`<button class="copy-btn json-copy" onclick="copyAll()">Copy all</button>`)
	fmt.Fprintf(b, `<pre class="json" id="raw-json">%s</pre>`, highlighted)
	b.WriteString(`</div></section>`)
}

func htmlSyntaxJSON(raw string) string {
	// Simple token-by-token highlighting without regex
	var b strings.Builder
	i := 0
	runes := []rune(raw)
	n := len(runes)

	for i < n {
		ch := runes[i]
		switch {
		case ch == '"':
			// Determine if this is a key or value
			j := i + 1
			for j < n && !(runes[j] == '"' && runes[j-1] != '\\') {
				j++
			}
			str := string(runes[i : j+1])
			// Look ahead past whitespace for ':'
			k := j + 1
			for k < n && (runes[k] == ' ' || runes[k] == '\t' || runes[k] == '\n') {
				k++
			}
			if k < n && runes[k] == ':' {
				fmt.Fprintf(&b, `<span class="j-key">%s</span>`, html.EscapeString(str))
			} else {
				fmt.Fprintf(&b, `<span class="j-str">%s</span>`, html.EscapeString(str))
			}
			i = j + 1
		case ch == 't' && i+3 < n && string(runes[i:i+4]) == "true":
			b.WriteString(`<span class="j-bool">true</span>`)
			i += 4
		case ch == 'f' && i+4 < n && string(runes[i:i+5]) == "false":
			b.WriteString(`<span class="j-bool">false</span>`)
			i += 5
		case ch == 'n' && i+3 < n && string(runes[i:i+4]) == "null":
			b.WriteString(`<span class="j-null">null</span>`)
			i += 4
		case (ch >= '0' && ch <= '9') || ch == '-':
			j := i + 1
			for j < n && (runes[j] >= '0' && runes[j] <= '9' || runes[j] == '.' || runes[j] == 'e' || runes[j] == 'E' || runes[j] == '+' || runes[j] == '-') {
				j++
			}
			fmt.Fprintf(&b, `<span class="j-num">%s</span>`, html.EscapeString(string(runes[i:j])))
			i = j
		default:
			b.WriteString(html.EscapeString(string(ch)))
			i++
		}
	}
	return b.String()
}

// ── Inline JS ────────────────────────────────────────────────────────────────

func htmlInlineJS(b *strings.Builder) {
	b.WriteString(`<script>
function toggleTheme(){
  var h=document.documentElement;
  h.setAttribute('data-theme', h.getAttribute('data-theme')==='dark'?'light':'dark');
}
function filterFindings(sev){
  document.querySelectorAll('.filter-btn').forEach(function(btn){
    btn.classList.toggle('active', btn.textContent===sev);
  });
  document.querySelectorAll('.finding-card').forEach(function(card){
    card.style.display=(sev==='All'||card.dataset.sev===sev)?'block':'none';
  });
}
function switchTab(id){
  document.querySelectorAll('.tab-btn').forEach(function(btn){
    btn.classList.toggle('active', btn.getAttribute('onclick').indexOf("'"+id+"'")>-1);
  });
  document.querySelectorAll('.tab-panel').forEach(function(p){
    p.classList.toggle('active', p.id==='tab-'+id);
  });
}
function filterIOCs(input, listId){
  var q=input.value.toLowerCase();
  document.querySelectorAll('#'+listId+' .ioc-row').forEach(function(row){
    row.style.display=row.querySelector('.ioc-val').textContent.toLowerCase().indexOf(q)>-1?'':'none';
  });
}
function copyIOC(btn, val){
  navigator.clipboard.writeText(val).then(function(){
    btn.textContent='✓';
    btn.classList.add('copied');
    setTimeout(function(){btn.textContent='copy';btn.classList.remove('copied');},1500);
  });
}
function copyAll(){
  var el=document.getElementById('raw-json');
  navigator.clipboard.writeText(el.innerText);
}
function globalSearch(q){
  q=q.toLowerCase().trim();
  var count=0;
  document.querySelectorAll('.finding-card').forEach(function(card){
    var text=card.textContent.toLowerCase();
    var show=!q||text.indexOf(q)>-1;
    card.style.display=show?'block':'none';
    if(show&&q) count++;
  });
  document.querySelectorAll('.ioc-row').forEach(function(row){
    var text=row.textContent.toLowerCase();
    var show=!q||text.indexOf(q)>-1;
    row.style.display=show?'':'none';
    if(show&&q) count++;
  });
  var counter=document.getElementById('search-count');
  if(counter){counter.textContent=q?'Matches: '+count:'';}
}
</script>`)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func htmlKVRow(b *strings.Builder, key, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	fmt.Fprintf(b, `<tr><td class="muted" style="white-space:nowrap;width:140px">%s</td><td><code>%s</code></td></tr>`, h(key), h(value))
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
		fmt.Fprintf(&b, "FlatHash:          %s\n", info.FlatHash)
	}
	if info.ByteHistogramHash != "" {
		fmt.Fprintf(&b, "Byte histogram:    %s\n", info.ByteHistogramHash)
	}
	if info.StringSetHash != "" {
		fmt.Fprintf(&b, "String set:        %s\n", info.StringSetHash)
	}
	if info.ImportHash != "" {
		fmt.Fprintf(&b, "Import hash:       %s\n", info.ImportHash)
	}
	if info.RichHeaderHash != "" {
		fmt.Fprintf(&b, "Rich header:       %s\n", info.RichHeaderHash)
	}
	if info.SectionHash != "" {
		fmt.Fprintf(&b, "Section hash:      %s\n", info.SectionHash)
	}
	if info.DEXStringHash != "" {
		fmt.Fprintf(&b, "DEX string hash:   %s\n", info.DEXStringHash)
	}
	if info.ArchiveContentHash != "" {
		fmt.Fprintf(&b, "Archive content:   %s\n", info.ArchiveContentHash)
	}
	return b.String()
}

// Keep sort imported
var _ = sort.Strings
