# FlatScan

> **Static malware analysis and reporting — for analysts and CISO audiences alike.**

[![Go Version](https://img.shields.io/badge/go-1.22%2B-blue)](https://golang.org/dl/)
[![License](https://img.shields.io/badge/license-see%20repo-lightgrey)](https://github.com/Masriyan/FlatScan)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-informational)](https://github.com/Masriyan/FlatScan)
[![Static Analysis](https://img.shields.io/badge/analysis-static%20only-green)](https://github.com/Masriyan/FlatScan)

Repository: [https://github.com/Masriyan/FlatScan](https://github.com/Masriyan/FlatScan)

---

FlatScan is a static malware analysis and reporting tool written in Go. It is built for analysts who need fast triage, IOC extraction, suspicious capability detection, executive reporting, and hunting-rule handoff — **without executing the sample**.

FlatScan reads a file, hashes it, identifies the format, extracts strings, decodes suspicious encoded data, extracts IOCs, inspects executable and container metadata, scores findings, enriches them into a malware profile, and produces text, JSON, PDF, IOC, and YARA outputs.

---

## Why FlatScan

Malware triage typically has two audiences with competing needs:

| Audience | What They Need |
|---|---|
| **Analyst / IR engineer** | Hashes, strings, imports, IOCs, entropy, sections, decoded data, TTPs, hunting content |
| **CISO / management** | Risk context, likely malware type, business impact, recommended actions |

FlatScan serves both. Static analysis keeps it safe and fast. The enriched malware profile converts raw evidence into management-ready reporting — in the same tool, from the same run.

---

## Safety Notice

> FlatScan performs **static analysis only**. It does not execute samples.

That reduces risk, but does not make malware handling safe by itself. Always work inside an isolated VM, do not execute samples, and store reports separately from live malware. See [security.md](security.md) for the full safe-handling workflow.

---

## Features

### Hashing and Identification
- Full-file MD5, SHA1, SHA256, and SHA512
- File type and MIME hint detection
- Import hash (PE)

### String and IOC Extraction
- ASCII and UTF-16LE string extraction
- IOC extraction: URLs, domains, IPv4, IPv6, emails, MD5, SHA1, SHA256, SHA512, CVEs, registry keys, Windows paths, Unix paths

### Decoding and Deobfuscation
- Suspicious base64, hex, and URL-percent decoding
- Nested decode depth control (up to 5 layers)
- Secondary IOC extraction from decoded artifacts

### Entropy and Packing
- Full-file entropy scoring
- High-entropy region detection

### Executable and Container Parsing

| Format | Details Extracted |
|---|---|
| **PE (Windows)** | Imports, sections, timestamp, subsystem, image base, entry point, import hash, certificate table presence, overlay, .NET detection |
| **ELF (Linux)** | Class, machine type, imports, sections |
| **Mach-O (macOS)** | CPU type, imports, sections |
| **ZIP / APK / JAR / Office** | Entry inspection without disk extraction, path traversal detection, macro indicators, archive bomb heuristics |

### Behavioral Signatures
- Process injection API chains
- Dynamic API resolution
- Downloader and C2 network strings
- Discord webhook exfiltration
- Browser credential decryption (Chromium DPAPI)
- Windows and Linux persistence indicators
- Suspicious PowerShell, script host, and LOLBin use
- Ransomware-style strings
- Credential and crypto wallet theft
- VM / sandbox awareness and anti-debugging
- Security tooling bypass indicators
- Packer and protector markers
- High IOC density scoring

### Malware Profile Enrichment
- Likely malware type and confidence score
- Key capabilities summary
- Business impact assessment
- Recommended response actions
- MITRE-style TTP entries
- Cryptography and secret-handling indicators (BCrypt, DPAPI, Chromium encrypted_key, AES/GCM markers)

### Output Formats
- Text report: `minimal`, `Summary`, `Full`
- JSON for automation pipelines
- PDF for CISO and analyst handoff
- IOC text export for quick triage handoff
- YARA hunting rule export

---

## Quick Start

### Build

```bash
git clone https://github.com/Masriyan/FlatScan
cd FlatScan
go build -o flatscan .
```

### Verify

```bash
./flatscan --version
./flatscan --help
```

### Fast Triage

```bash
./flatscan -m quick -f sample.bin --report-mode Summary
```

### Full Analyst Run

```bash
./flatscan -m deep \
  -f sample.exe \
  --report-mode Full \
  --report reports/sample.full.txt \
  --json reports/sample.report.json \
  --pdf reports/sample.ciso.pdf \
  --yara reports/sample.yar \
  --extract-ioc reports/sample.iocs.txt \
  --debug
```

### Automation / CI

```bash
./flatscan -m deep -f sample.exe \
  --report-mode minimal \
  --json reports/sample.json \
  --no-progress
```

---

## Output Types

| Output | Flag | Audience | Purpose |
|---|---|---|---|
| Text report | `--report PATH` | Analyst | Human-readable triage report. Honors `--report-mode`. |
| JSON report | `--json PATH` | Automation | Structured result for pipelines, SIEMs, ticketing. |
| PDF report | `--pdf PATH` | CISO / leadership | Executive summary, MITRE matrix, business impact, IOCs. |
| IOC export | `--extract-ioc PATH` | Analyst | Categorized IOC text file for quick handoff. |
| YARA rule | `--yara PATH` | Threat hunter | Auto-generated hunting rule from high-signal strings. |
| Stdout | *(default)* | Analyst | Text report printed when `--report` is not set. |

---

## Scan Modes

| Mode | Use Case | Depth |
|---|---|---|
| `quick` | Fast triage, first pass | Hashes, strings, IOCs, key signatures |
| `standard` | Normal analyst review | Adds entropy regions, ZIP-family entry inspection |
| `deep` | Final report, high-priority sample | Largest import/string/decode limits, richest profile |

---

## Report Modes

| Mode | Use Case | Contents |
|---|---|---|
| `minimal` | Shell scripts, CI output | Verdict, score, file type, SHA256, finding count |
| `Summary` | Terminal triage | Top findings, IOC overview, suspicious strings |
| `Full` | Analyst handoff | All hashes, full findings, IOCs, decoded artifacts, format details, debug log |

---

## How FlatScan Works Internally

FlatScan uses a linear static analysis pipeline:

```
CLI parse → File read + Hash → File type detect → Entropy
→ String extract → IOC extract → Decode artifacts → IOC extract (decoded)
→ Behavioral signatures → Format parse (PE/ELF/Mach-O/Archive)
→ Score + Verdict → Profile enrich (TTPs, crypto, impact)
→ Render outputs (text / JSON / PDF / IOC / YARA)
```

All stages read bytes. No stage executes the target.

---

## Score Reference

| Score | Verdict | Recommended Action |
|---|---|---|
| 0–9 | No strong indicators | Not a clean verdict. Review context. |
| 10–29 | Low suspicion | Weak indicators. Correlate with endpoint telemetry. |
| 30–54 | Suspicious | Meaningful evidence. Correlate before escalating. |
| 55–79 | High suspicion | Treat as high risk. Escalate and monitor. |
| 80–100 | Likely malicious | Multiple high-confidence indicators. Prioritize containment. |

> A low score is **not a clean verdict**. Static analysis can miss packed, staged, or encrypted behavior.

---

## Limitations

- Static analysis cannot detect environment-gated, packed, staged, encrypted, or dynamically generated behavior.
- Hashes are classified as IOCs but cannot be reversed.
- YARA rules are hunting starting points and must be reviewed before production deployment.
- MITRE mappings reflect static evidence, not confirmed executed behavior.
- PDF generation uses FlatScan's internal writer with no external dependencies.

---

## Documentation

| Document | Purpose |
|---|---|
| [install.md](install.md) | Build, install, cross-compile, lab setup |
| [usage.md](usage.md) | Flags, modes, outputs, interpretation |
| [security.md](security.md) | Safe sample handling, responsible use, reporting security issues |
| [contributing.md](contributing.md) | Dev workflow, adding detections, PR guidance |
| [changelog.md](changelog.md) | Release history |

---

## Recommended Analyst Workflow

```
1. Receive sample → hash and verify receipt
2. Transfer to isolated malware-analysis VM
3. Run FlatScan quick scan → triage verdict
4. If suspicious/high: run FlatScan deep scan → full outputs
5. Review IOC export → pivot in threat intel platform
6. Review YARA rule → validate, tune, deploy to hunting stack
7. Share PDF with CISO/management if escalation is needed
8. Continue with sandbox, RE, or endpoint telemetry as warranted
```

---

## Project URL

Issues, releases, documentation, and source:

[https://github.com/Masriyan/FlatScan](https://github.com/Masriyan/FlatScan)
