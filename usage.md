# Usage

Repository: https://github.com/Masriyan/FlatScan

This guide explains how to run FlatScan, what each mode does, what each output means, and how to interpret the results.

## Basic Command Shape

```bash
./flatscan -m <mode> -f <target-file> --report-mode <mode>
```

Example:

```bash
./flatscan -m deep -f sample.exe --report-mode Full
```

## Full Command With All Outputs

```bash
./flatscan -m deep \
  -f sample.exe \
  --report-mode Full \
  --report reports/sample.full.txt \
  --extract-ioc reports/sample.iocs.txt \
  --json reports/sample.report.json \
  --pdf reports/sample.ciso.pdf \
  --yara reports/sample.yar \
  --debug
```

## Flags

| Flag | Default | Description |
| --- | --- | --- |
| `-f`, `--file` | required | Target file to scan. |
| `-m`, `--mode` | `quick` | Scan mode: `quick`, `standard`, or `deep`. |
| `--report-mode` | `summary` | Text report mode: `Full`, `Summary`, or `minimal`. |
| `--report` | none | Write text report to this path. If omitted, report prints to stdout. |
| `--extract-ioc` | none | Write categorized IOC text export. |
| `--json` | none | Write complete structured JSON report. |
| `--pdf` | none | Write CISO/management-ready PDF report. |
| `--yara` | none | Write generated YARA hunting rule. |
| `--debug` | false | Include debug log in full report and stronger error context. |
| `--no-progress` | false | Disable progress output and startup splash. Useful for automation. |
| `--no-splash` | false | Disable startup ASCII banner/loading bar only. |
| `--splash-seconds` | `20` | Startup splash duration in interactive terminals. |
| `--min-string` | `5` | Minimum string length extracted from sample bytes. |
| `--decode-depth` | `2` | Nested base64/hex/URL decode depth. Allowed range: `0` to `5`. |
| `--max-analyze-bytes` | `268435456` | Maximum bytes retained for in-memory analysis. Full file is still hashed. |
| `--max-archive-files` | `500` | Maximum ZIP/APK/JAR/Office entries inspected. |
| `--version` | none | Print FlatScan version. |

## Scan Modes

### quick

Use for fast triage:

```bash
./flatscan -m quick -f sample.bin --report-mode Summary
```

Includes:

- Hashes
- File type
- Entropy
- String extraction
- IOC extraction
- Suspicious decoder pass
- Main behavioral signatures

### standard

Use for normal analyst triage:

```bash
./flatscan -m standard -f sample.bin --report-mode Full
```

Adds deeper checks such as high-entropy regions and ZIP-family entry inspection.

### deep

Use when producing final reports or analyzing a high-priority sample:

```bash
./flatscan -m deep -f sample.bin --report-mode Full --pdf reports/sample.pdf --json reports/sample.json
```

Uses larger string/import/decode limits and produces the richest profile.

## Text Report Modes

### minimal

Small output for shell scripts:

```bash
./flatscan -m quick -f sample.bin --report-mode minimal --no-progress
```

Contains:

- Tool version
- Target
- Verdict and score
- File type
- SHA256
- Finding/IOC counts

### Summary

Good for terminal triage:

```bash
./flatscan -m standard -f sample.bin --report-mode Summary
```

Contains:

- Metadata
- Malware profile
- Top findings
- IOC summary
- Suspicious strings
- Decoded artifact highlights

### Full

Best for analyst handoff:

```bash
./flatscan -m deep -f sample.bin --report-mode Full --report reports/sample.full.txt --debug
```

Contains:

- Full hashes
- Malware profile
- Full findings
- Suspicious functions/APIs
- Full IOC sections
- Decoded artifacts
- PE/ELF/Mach-O/container details
- Suspicious strings
- Debug log when enabled

## PDF Report

The PDF is intended for leadership and analyst handoff.

```bash
./flatscan -m deep -f sample.exe --pdf reports/sample.ciso.pdf --report-mode Full
```

PDF sections include:

- Cover page
- Executive assessment
- CISO decision summary
- Risk and confidence cards
- Likely malware type
- Key capabilities
- Business impact
- Management actions
- MITRE ATT&CK TTP matrix
- Priority findings
- Cryptography and secret-handling assessment
- Hunting guidance
- Sample metadata
- IOCs
- Executable/container details
- Suspicious strings and decoded artifacts when present

## JSON Report

Use JSON for automation:

```bash
./flatscan -m deep -f sample.exe --json reports/sample.json --no-progress
```

The JSON includes the complete `ScanResult` structure:

- Target metadata
- Hashes
- Entropy
- Strings summary
- IOCs
- Decoded artifacts
- PE/ELF/Mach-O/archive metadata
- Findings
- Malware profile
- MITRE-style TTP entries
- Cryptography indicators
- Verdict and score

## IOC Export

```bash
./flatscan -m deep -f sample.exe --extract-ioc reports/sample.iocs.txt
```

IOC categories may include:

- URLs
- Domains
- IPv4
- IPv6
- Emails
- MD5
- SHA1
- SHA256
- SHA512
- CVEs
- Registry keys
- Windows paths
- Unix paths

## YARA Export

```bash
./flatscan -m deep -f sample.exe --yara reports/sample.yar
```

The generated YARA rule uses high-signal material:

- URLs
- Domains
- Registry keys
- Paths
- Suspicious strings
- Malware type labels
- SHA256 metadata
- PE import hash metadata when available

Generated YARA rules should be reviewed before production deployment. They are designed as hunting starting points, not guaranteed family signatures.

## Example: Ransomware Sample

```bash
./flatscan -m deep \
  -f /path/to/magniber-sample.bin \
  --report-mode Full \
  --report reports/magniber.full.txt \
  --extract-ioc reports/magniber.iocs.txt \
  --json reports/magniber.report.json \
  --pdf reports/magniber.ciso.report.pdf \
  --yara reports/magniber.yar \
  --debug
```

## Example: CI or Scripted Mode

```bash
./flatscan -m deep \
  -f sample.exe \
  --report-mode minimal \
  --json reports/sample.json \
  --yara reports/sample.yar \
  --no-progress
```

## Interpreting Scores

| Score | Verdict Band | Meaning |
| --- | --- | --- |
| `0-9` | No strong indicators | Static scan did not find strong evidence. Not a clean verdict. |
| `10-29` | Low suspicion | Weak or limited indicators. Review context. |
| `30-54` | Suspicious | Meaningful suspicious static evidence. Correlate with telemetry. |
| `55-79` | High suspicion | Strong suspicious indicators. Treat as high risk. |
| `80-100` | Likely malicious | Multiple high-confidence indicators. Prioritize containment and response. |

## How Findings Are Built

Findings are generated from several sources:

- IOC density and network indicators
- Suspicious API/function strings
- Cryptography and secret-handling strings
- Entropy and packing indicators
- PE/ELF/Mach-O structural anomalies
- Archive/container contents
- Persistence paths or registry keys
- Anti-debugging or sandbox-awareness artifacts
- Malware-type heuristics such as browser credential theft or webhook exfiltration

## How Cryptography Analysis Works

FlatScan does not break encryption or reverse hashes. It identifies crypto usage patterns, such as:

- Windows CNG `BCrypt*` strings
- Windows CryptoAPI/DPAPI-style strings
- Chromium `encrypted_key` workflows
- AES/GCM/tag/IV/nonce style markers
- Encoded or decoded obfuscation artifacts

These indicators help infer whether a sample may decrypt browser secrets, unwrap configuration, decrypt payloads, or handle encrypted exfiltration content.

## Automation Tips

- Use `--json` for structured ingestion.
- Use `--no-progress` when running in scripts.
- Store all outputs under a sample-specific report directory.
- Keep generated YARA rules under review before deployment.
- Keep raw malware samples out of normal source repositories.
