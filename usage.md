# Usage

Repository: [https://github.com/Masriyan/FlatScan](https://github.com/Masriyan/FlatScan)

---

## Basic Command Shape

```bash
./flatscan -m <mode> -f <target-file> --report-mode <mode>
```

Minimal example:

```bash
./flatscan -m deep -f sample.exe --report-mode Full
```

Full example with all outputs:

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

---

## Flag Reference

| Flag | Default | Description |
|---|---|---|
| `-f`, `--file` | *(required)* | Target file to scan. |
| `-m`, `--mode` | `quick` | Scan depth: `quick`, `standard`, or `deep`. |
| `--report-mode` | `summary` | Text report verbosity: `Full`, `Summary`, or `minimal`. |
| `--report` | *(none)* | Write text report to this path. Omit to print to stdout. |
| `--extract-ioc` | *(none)* | Write categorized IOC text export. |
| `--json` | *(none)* | Write complete structured JSON report. |
| `--pdf` | *(none)* | Write CISO/management-ready PDF report. |
| `--yara` | *(none)* | Write generated YARA hunting rule. |
| `--debug` | `false` | Include debug log in full report and richer error context. |
| `--no-progress` | `false` | Disable all progress output. Use in scripts and automation. |
| `--no-splash` | `false` | Disable startup banner and loading bar only. |
| `--splash-seconds` | `20` | Duration of startup splash in interactive terminals. |
| `--min-string` | `5` | Minimum extracted string length (bytes). |
| `--decode-depth` | `2` | Nested base64/hex/URL decode depth. Range: `0`–`5`. |
| `--max-analyze-bytes` | `268435456` | Max bytes retained for in-memory analysis (256 MB). Full file is always hashed. |
| `--max-archive-files` | `500` | Max ZIP/APK/JAR/Office entries inspected. |
| `--version` | — | Print FlatScan version and exit. |

---

## Scan Modes

### `quick` — Fast triage

Use for initial pass on a new sample when you need a verdict in seconds.

```bash
./flatscan -m quick -f sample.bin --report-mode Summary
```

Includes:
- Hashes (MD5, SHA1, SHA256, SHA512)
- File type and MIME detection
- Entropy scoring
- ASCII and UTF-16LE string extraction
- IOC extraction
- Suspicious decoder pass (base64, hex, URL-percent)
- Main behavioral signatures

### `standard` — Normal analyst triage

Use for routine sample review when time allows deeper inspection.

```bash
./flatscan -m standard -f sample.bin --report-mode Full
```

Adds over `quick`:
- High-entropy region detection
- ZIP-family entry inspection (ZIP/APK/JAR/Office)
- Expanded import coverage

### `deep` — Final report / high-priority sample

Use when producing a deliverable or analyzing a high-priority incident sample.

```bash
./flatscan -m deep -f sample.bin \
  --report-mode Full \
  --pdf reports/sample.pdf \
  --json reports/sample.json
```

Adds over `standard`:
- Larger string, import, and decode limits
- Richest malware profile enrichment
- Full MITRE TTP mapping
- Full cryptography indicator assessment

---

## Text Report Modes

### `minimal` — Shell and automation output

```bash
./flatscan -m quick -f sample.bin --report-mode minimal --no-progress
```

Output includes:
- Tool version
- Target path
- Verdict and score
- File type
- SHA256
- Finding count and IOC count

### `Summary` — Terminal triage

```bash
./flatscan -m standard -f sample.bin --report-mode Summary
```

Output includes:
- File metadata
- Malware profile (type, confidence)
- Top findings
- IOC summary
- Suspicious string highlights
- Decoded artifact highlights

### `Full` — Analyst handoff

```bash
./flatscan -m deep -f sample.bin \
  --report-mode Full \
  --report reports/sample.full.txt \
  --debug
```

Output includes:
- Full hash table
- Malware profile
- Complete findings with severity and evidence
- Suspicious API/function strings
- Full IOC sections (all categories)
- Decoded artifacts
- PE/ELF/Mach-O/container details
- Suspicious string list
- Debug log (when `--debug` is set)

---

## PDF Report

The PDF is designed for CISO and leadership audiences, and for analyst handoff in escalation workflows.

```bash
./flatscan -m deep -f sample.exe \
  --pdf reports/sample.ciso.pdf \
  --report-mode Full
```

PDF sections:

| Section | Audience |
|---|---|
| Cover page | All |
| Executive assessment | CISO / management |
| CISO decision summary | CISO / management |
| Risk and confidence cards | CISO / management |
| Likely malware type | All |
| Key capabilities | All |
| Business impact | CISO / management |
| Management actions | CISO / management |
| MITRE ATT&CK TTP matrix | Analyst / SOC |
| Priority findings | Analyst |
| Cryptography and secret-handling assessment | Analyst |
| Hunting guidance | Analyst / threat hunter |
| Sample metadata | Analyst |
| IOCs | Analyst / threat hunter |
| Executable/container details | Analyst |
| Suspicious strings and decoded artifacts | Analyst |

> Do not click URLs inside PDF reports on production systems. Reports may contain live C2 URLs extracted from the sample.

---

## JSON Report

Use JSON for SIEM ingestion, ticketing integrations, or custom pipeline processing.

```bash
./flatscan -m deep -f sample.exe \
  --json reports/sample.json \
  --no-progress
```

The JSON `ScanResult` structure includes:

- Target metadata (path, file size, type, MIME)
- Full hashes (MD5/SHA1/SHA256/SHA512)
- Entropy and high-entropy regions
- String extraction summary
- IOCs (all categories, deduped)
- Decoded artifacts
- PE/ELF/Mach-O/archive metadata
- Findings (severity, category, evidence, recommendation)
- Malware profile (type, confidence, capabilities, impact)
- MITRE-style TTP entries
- Cryptography indicators
- Verdict and score

Suggested pipeline use:

```bash
./flatscan -m deep -f sample.exe --json - --no-progress | jq '.verdict, .score, .malware_profile.likely_type'
```

---

## IOC Export

```bash
./flatscan -m deep -f sample.exe --extract-ioc reports/sample.iocs.txt
```

IOC categories extracted:

| Category | Examples |
|---|---|
| URLs | `http://c2.example.com/beacon` |
| Domains | `c2.example.com` |
| IPv4 | `192.168.1.1` |
| IPv6 | `2001:db8::1` |
| Emails | `attacker@domain.com` |
| MD5 | 32-character hex strings |
| SHA1 | 40-character hex strings |
| SHA256 | 64-character hex strings |
| SHA512 | 128-character hex strings |
| CVEs | `CVE-2023-XXXX` |
| Registry keys | `HKCU\Software\Microsoft\Windows\Run` |
| Windows paths | `C:\Users\Public\malware.exe` |
| Unix paths | `/tmp/.hidden_payload` |

Feed extracted IOCs directly into your threat intel platform, EDR blocklist, or SIEM enrichment pipeline.

---

## YARA Export

```bash
./flatscan -m deep -f sample.exe --yara reports/sample.yar
```

Generated YARA rules use high-signal material from:

- Extracted URLs and domains
- Registry keys
- Windows and Unix paths
- Suspicious strings
- Malware type labels from profile enrichment
- SHA256 hash metadata (as rule metadata, not a hash match)
- PE import hash metadata (when available)

**Review before deployment.** Generated rules are hunting starting points, not guaranteed family signatures. Validate against known-good corpora before using for blocking decisions.

Example validation:

```bash
yara -r reports/sample.yar /path/to/clean-samples/
```

---

## Interpreting Scores

| Score | Verdict | Analyst Action |
|---|---|---|
| 0–9 | No strong indicators | Not a clean verdict. Check context, file origin, and delivery chain. |
| 10–29 | Low suspicion | Weak or limited indicators. Correlate with endpoint/network telemetry. |
| 30–54 | Suspicious | Meaningful static evidence. Escalate for sandbox or RE review. |
| 55–79 | High suspicion | Strong indicators. Treat as high risk. Isolate if on a live host. |
| 80–100 | Likely malicious | Multiple high-confidence indicators. Prioritize containment and response. |

> **A score of 0 is not a clean verdict.** Packed, staged, or heavily obfuscated samples may score low on static analysis. Always correlate with behavioral and telemetry data.

---

## How Findings Are Generated

Findings are produced from multiple evidence sources:

| Source | Examples |
|---|---|
| IOC density | High volume of network indicators in strings |
| Suspicious API strings | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` |
| Cryptography strings | `BCryptEncrypt`, `CryptUnprotectData`, `encrypted_key` |
| Entropy and packing | Sections with entropy > 7.0, known packer signatures |
| Executable structure anomalies | Missing headers, overlay data, no imports |
| Archive contents | Executable entries, macro files, path traversal names |
| Persistence artifacts | Run keys, scheduled task paths, startup folder paths |
| Anti-analysis artifacts | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, CPUID timing |
| Malware-family heuristics | Browser credential theft patterns, webhook exfiltration strings |

Finding severity levels:

| Severity | Meaning |
|---|---|
| **Critical** | High-confidence indicator of active malicious capability |
| **High** | Strong evidence of malicious intent or dangerous capability |
| **Medium** | Notable indicator that warrants investigation |
| **Low** | Weak indicator or context-dependent behavior |
| **Informational** | Metadata or context that aids analysis without implying malice |

---

## How Cryptography Analysis Works

FlatScan identifies cryptographic usage patterns from strings and imports — it does not break encryption or reverse hashes.

Patterns detected:

| Indicator | Implication |
|---|---|
| `BCryptEncrypt`, `BCryptDecrypt` | Windows CNG encryption — may wrap payload or config decryption |
| `CryptUnprotectData`, `CryptProtectData` | DPAPI usage — often used by infostealers for credential decryption |
| `encrypted_key` | Chromium-style key handling — browser credential theft |
| AES/GCM/IV/nonce strings | Symmetric encryption — payload, config, or data at rest |
| Encoded/decoded artifact overlap | Obfuscation layers — suggests staged or packed content |

Cryptography indicators inform whether a sample may:
- Decrypt browser secrets
- Unwrap embedded configuration
- Decrypt additional payload stages
- Handle encrypted exfiltration

---

## Analyst Workflow Examples

### Ransomware Sample

```bash
./flatscan -m deep \
  -f /path/to/magniber-sample.bin \
  --report-mode Full \
  --report reports/magniber.full.txt \
  --extract-ioc reports/magniber.iocs.txt \
  --json reports/magniber.report.json \
  --pdf reports/magniber.ciso.pdf \
  --yara reports/magniber.yar \
  --debug
```

### Infostealer / Credential Theft Sample

```bash
./flatscan -m deep \
  -f stealer.exe \
  --report-mode Full \
  --report reports/stealer.full.txt \
  --extract-ioc reports/stealer.iocs.txt \
  --json reports/stealer.json \
  --debug
```

Focus on: cryptography indicators, browser credential strings, webhook exfiltration URLs, registry key IOCs.

### Suspicious Office Document (Macro)

```bash
./flatscan -m deep \
  -f suspicious.docm \
  --report-mode Full \
  --json reports/docm.json \
  --extract-ioc reports/docm.iocs.txt
```

Focus on: archive entry names, macro indicators, URLs and domains in decoded artifacts, PowerShell strings.

### APK / Android Sample

```bash
./flatscan -m deep \
  -f suspicious.apk \
  --report-mode Full \
  --json reports/apk.json \
  --extract-ioc reports/apk.iocs.txt
```

Focus on: archive entry names, Android permission indicators, URLs and domains, certificate table presence.

### CI / Scripted Pipeline

```bash
./flatscan -m deep \
  -f sample.exe \
  --report-mode minimal \
  --json reports/sample.json \
  --yara reports/sample.yar \
  --no-progress
echo "Exit: $?"
```

---

## Automation Tips

- Use `--json` for structured ingestion into SIEMs, ticketing, or orchestration.
- Use `--no-progress` when running in scripts or CI to suppress terminal output.
- Store all outputs in a sample-specific directory (`reports/<sha256>/`).
- Review and validate generated YARA rules before deployment.
- Keep raw malware samples out of version control.
- Feed extracted IOC files directly into your threat intel platform.
- Use `--decode-depth 4` or `5` on heavily obfuscated samples where default depth misses nested encoding layers.
- Tune `--min-string` down to `4` to catch short registry key fragments; tune up to `8` to reduce noise on string-heavy files.
