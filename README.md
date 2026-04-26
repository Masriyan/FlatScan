# FlatScan

Repository: https://github.com/Masriyan/FlatScan

FlatScan is a static malware analysis and reporting tool written in Go. It is designed for analysts who need fast triage, IOC extraction, suspicious capability detection, executive reporting, and hunting-rule handoff without executing the sample.

FlatScan reads a file, hashes it, identifies the format, extracts strings, decodes suspicious encoded data, extracts IOCs, inspects executable/container metadata, scores findings, enriches them into a malware profile, and produces text, JSON, PDF, IOC, and YARA outputs.

## Why FlatScan Exists

Malware triage often has two audiences:

- Analysts need technical evidence: hashes, strings, imports, IOCs, entropy, sections, decoded data, TTPs, and hunting content.
- CISO/management readers need concise risk context: what it likely is, why it matters, what business impact exists, and what actions are recommended.

FlatScan tries to serve both. It does static analysis for safety and speed, then converts the result into both machine-readable output and management-ready reporting.

## Important Safety Note

FlatScan performs static analysis only. It does not execute samples. That reduces risk, but it does not make malware handling safe by itself.

Recommended handling:

- Work inside an isolated malware-analysis VM.
- Do not double-click or execute samples.
- Keep samples password-protected when sharing.
- Store reports separately from live malware.
- Treat generated findings as triage evidence, not a final clean/malicious verdict by themselves.

## Features

- Full-file MD5, SHA1, SHA256, and SHA512 hashing.
- File type and MIME hint detection.
- ASCII and UTF-16LE string extraction.
- IOC extraction for URLs, domains, IPv4, IPv6, emails, hashes, CVEs, registry keys, Windows paths, and Unix paths.
- Suspicious base64, hex, and URL-percent decoding with nested decode depth control.
- Entropy scoring and high-entropy region detection.
- PE analysis: imports, sections, timestamp, subsystem, certificate table presence, overlay, import hash, and .NET runtime detection.
- ELF and Mach-O import/section inspection.
- ZIP/APK/JAR/Office Open XML entry inspection without extracting entries to disk.
- Behavioral signatures for injection, downloader behavior, persistence, Discord webhook exfiltration, browser credential theft, VM/sandbox awareness, script obfuscation, credential access, ransomware strings, packers, and high IOC density.
- Malware profile enrichment with likely malware type, confidence, key capabilities, business impact, recommended actions, MITRE-style TTPs, and cryptography indicators.
- CISO/management-ready PDF report.
- Text report modes: `minimal`, `Summary`, and `Full`.
- JSON output for automation.
- IOC text export for quick handoff.
- YARA hunting rule export.
- Startup ASCII banner and progress display, with automation-friendly disable flags.

## Quick Start

Build:

```bash
go build -o flatscan .
```

Run a deep scan with all useful outputs:

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

Automation-friendly run without splash/progress:

```bash
./flatscan -m deep -f sample.exe --report-mode Full --json reports/sample.json --no-progress
```

## Output Types

| Output | Flag | Purpose |
| --- | --- | --- |
| Text report | `--report PATH` | Human-readable report. Honors `--report-mode`. |
| JSON report | `--json PATH` | Complete structured result for automation and pipelines. |
| PDF report | `--pdf PATH` | CISO/management-ready report with executive summary, MITRE matrix, impact, actions, IOCs, crypto notes, and technical appendix. |
| IOC export | `--extract-ioc PATH` | Categorized IOC text file. |
| YARA rule | `--yara PATH` | Auto-generated hunting rule from high-signal strings, IOCs, hashes, and malware profile. |
| Stdout | default | Text report is printed to stdout when `--report` is not supplied. |

## Scan Modes

| Mode | Purpose |
| --- | --- |
| `quick` | Fast triage. Hashes, type, strings, IOCs, decoding, and key signatures. |
| `standard` | More complete static scan with entropy regions and ZIP-family entry inspection. |
| `deep` | Highest built-in static depth. Larger import/string/decode limits and richer profile/reporting results. |

## Report Modes

| Report Mode | Use Case |
| --- | --- |
| `minimal` | Short verdict, score, file type, SHA256, finding count, IOC count. |
| `Summary` | Analyst-friendly triage summary with top findings and IOC overview. |
| `Full` | Full report with hashes, findings, IOCs, decoded artifacts, executable/container details, suspicious strings, and debug log when enabled. |

## Example: Deep Malware Report

```bash
./flatscan -m deep \
  -f /path/to/suspicious.bin \
  --report-mode Full \
  --report reports/suspicious.full.txt \
  --extract-ioc reports/suspicious.iocs.txt \
  --json reports/suspicious.report.json \
  --pdf reports/suspicious.ciso.pdf \
  --yara reports/suspicious.yar \
  --debug
```

## How FlatScan Works Internally

FlatScan uses a static pipeline:

1. Parse CLI options and initialize progress output.
2. Read the target file safely and compute full-file hashes.
3. Retain up to `--max-analyze-bytes` for in-memory analysis while hashing the full file.
4. Detect file type and MIME hint.
5. Calculate full-file entropy and optional high-entropy regions.
6. Extract ASCII and UTF-16LE strings.
7. Extract IOCs from raw strings.
8. Decode suspicious base64, hex, and URL-percent artifacts.
9. Extract IOCs again from decoded artifacts.
10. Match behavioral and malware-family-style static indicators.
11. Inspect supported executable/container formats.
12. Score findings and assign a verdict.
13. Build an enriched malware profile with likely type, confidence, business impact, key capabilities, MITRE-style TTPs, crypto indicators, and response recommendations.
14. Render requested outputs.

## Limitations

- Static analysis can miss environment-gated, packed, staged, encrypted, or dynamically generated behavior.
- Hashes cannot be decoded or reversed. FlatScan can classify hash-looking values as IOCs, but it cannot recover original data from a real cryptographic hash.
- The generated YARA rule is a starting point for hunting and should be reviewed before deployment.
- MITRE mapping is static-evidence mapping, not proof that the behavior executed.
- PDF reports are generated by FlatScan's internal PDF writer and intentionally avoid external dependencies.

## Documentation

- Installation: [install.md](install.md)
- Usage guide: [usage.md](usage.md)
- Contributing: [contributing.md](contributing.md)
- Security policy: [security.md](security.md)
- Changelog: [changelog.md](changelog.md)

## Project URL

Use this URL for issues, releases, documentation, and source references:

https://github.com/Masriyan/FlatScan
