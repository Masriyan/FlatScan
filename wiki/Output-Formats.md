# Output Formats

FlatScan can emit many artifacts from a single scan. This page describes each one, its shape, and when to reach for it. Output selection is controlled by the OUTPUT flags in the [CLI Reference](CLI-Reference#output).

## Terminal Report

The default human-readable report printed to stdout. Its verbosity is set with `--report-mode`:

- **Full** — every finding, IOC set, PE/ELF/Mach-O details, capabilities, payload tree, and recommendations.
- **Summary** (default) — the verdict, risk score, top findings, and headline IOCs.
- **minimal** — a compact verdict line and score, ideal for terse console use.

Use `--report <path>` to also save the text report to a file. `-q`/`--quiet` suppresses everything except the verdict line; `--no-color` strips ANSI styling (also honored via `NO_COLOR`).

## JSON (`--json <path>`, `-` for stdout)

The complete machine-readable result. Use `--json -` to stream to stdout for piping into `jq` or other tooling. Schema highlights (top-level fields):

| Field | Meaning |
|-------|---------|
| `risk_score` | Integer 0–100 weighted score. |
| `verdict` | Human verdict string derived from the score. |
| `score_breakdown` | Per-category score contributions (`map[string]int`). |
| `file_type` | Detected format. |
| `hashes` | `md5`, `sha1`, `sha256`, `sha512`. |
| `entropy`, `entropy_assessment`, `high_entropy_regions` | Whole-file and regional entropy. |
| `findings[]` | Array of findings: `severity`, `category`, `title`, `evidence`, `score`, `offset`, `tactic`, `technique`, `recommendation`, `confidence`, `evidence_count`. |
| `iocs` | Structured IOC set: `urls`, `domains`, `ipv4`, `ipv6`, `emails`, hashes, `cves`, `registry_keys`, `windows_paths`, `unix_paths`, `mutexes`, `named_pipes`, `crypto_wallets`, plus `classified[]` (type/value/category/confidence) and suppression log. |
| `pe` | PE header intelligence (ASLR/DEP/CFG posture, Rich hash, TLS callbacks, Authenticode). Also `elf`, `macho`, `code`. |
| `payload_tree[]` | Recursively resolved payload nodes (encoding/source/preview + nested IOCs). |
| `similarity` | Similarity match info against the corpus. |
| `family_matches[]` | Family hypotheses: named-family fingerprint hits plus generic buckets, ranked by `score`. |
| `benign_context` | Present only when the false-positive guard identifies the file as a signature set, rule pack, or analysis tool: `reason`, `archetypes`, `tool_markers`, `score_cap`, `original_score`, and `suppressed_families` (family hypotheses withdrawn because this file quotes family names as references rather than exhibiting them). |
| `profile` | Analyst profile: `classification`, `malware_type`, `confidence`, `confidence_score`, `business_impact`, `key_capabilities`. |
| `carved_artifacts[]`, `config_artifacts[]`, `dga_domains[]`, `rule_matches[]`, `plugins[]` | Supporting evidence collections. |

Use JSON when you need the full result programmatically or to feed downstream systems.

## CSV / JSONL (`--output-format csv|jsonl`)

- **CSV** — one row per file with headline fields (name, hash, score, verdict). Ideal for spreadsheets and batch triage.
- **JSONL** — one JSON object per line, one line per file. Ideal for streaming batch results into log pipelines or `jq -c` processing.

## PDF (`--pdf <path>`) — Management

A polished, management-oriented PDF: verdict, risk score, business impact, key capabilities, and a concise findings summary. Use it for incident tickets, escalations, and non-technical stakeholders.

## HTML (`--html <path>`) — Analyst

A rich, analyst-oriented HTML report with the full finding set, IOC tables, PE intelligence, and the payload tree. All attacker-controlled data is HTML-escaped (XSS-safe). Use it for deep review and sharing within a SOC.

## YARA (`--yara <path>`)

A generated YARA rule derived from the sample's distinctive strings/attributes for hunting similar samples across a corpus or EDR.

## Sigma (`--sigma <path>`)

A generated Sigma rule for detection-engineering pipelines and SIEM correlation.

## STIX 2.1 Bundle (`--stix <path>`)

A STIX 2.1 JSON bundle of the extracted indicators for sharing via threat-intel platforms (MISP, OpenCTI, TAXII).

## IOC Text Export (`--extract-ioc <path>`)

A flat, deduplicated text list of extracted IOCs (URLs, domains, IPs, hashes, etc.) for quick blocklist ingestion or grepping.

## Zipped Report-Pack (`--report-pack <dir>`)

A one-shot bundle that packages the JSON, PDF, HTML, IOC export, and generated YARA/Sigma into a single zipped directory. Use it when you want a complete, portable evidence package from one command — ideal for case handoff and archival.

## Choosing an Output

| Goal | Use |
|------|-----|
| Quick human review | Terminal report (Summary) |
| Programmatic / piping | `--json -` |
| Batch triage spreadsheet | `--output-format csv` |
| Log/stream pipeline | `--output-format jsonl` |
| Executive/ticket | `--pdf` |
| Deep SOC analysis | `--html` |
| Corpus hunting | `--yara` |
| SIEM detection | `--sigma` |
| Intel sharing | `--stix` |
| Blocklists | `--extract-ioc` |
| Full evidence package | `--report-pack` |

Related: [Detection Engine](Detection-Engine) · [CI/CD Integration](CI-CD-Integration).
