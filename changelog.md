# Changelog

Repository: [https://github.com/Masriyan/FlatScan](https://github.com/Masriyan/FlatScan)

All notable project changes are documented here. This project follows a chronological changelog format.

---

## [0.1.0] — Current Development Build

Initial public release. Establishes the core static analysis pipeline, all output formats, and the full documentation set.

---

### Core Scanner

**Added:**

- Go CLI scanner: `flatscan`
- Scan modes: `quick`, `standard`, `deep`
- Text report modes: `minimal`, `Summary`, `Full`
- Full-file hashing: MD5, SHA1, SHA256, SHA512
- File type and MIME hint detection
- ASCII string extraction
- UTF-16LE string extraction (Windows-encoded binary strings)
- Configurable minimum string length (`--min-string`, default: 5)
- Configurable in-memory analysis limit (`--max-analyze-bytes`, default: 256 MB); full file is always hashed regardless

---

### IOC Extraction

**Added:**

IOC categories extracted from raw strings and decoded artifacts:

| Category | Details |
|---|---|
| URLs | Full HTTP/HTTPS URLs |
| Domains | Bare domain strings |
| IPv4 | Dotted-decimal addresses |
| IPv6 | Colon-hex addresses |
| Emails | RFC-style email addresses |
| MD5 | 32-character hex strings |
| SHA1 | 40-character hex strings |
| SHA256 | 64-character hex strings |
| SHA512 | 128-character hex strings |
| CVEs | `CVE-YYYY-NNNN` format |
| Registry keys | `HKLM\`, `HKCU\`, `HKEY_*` paths |
| Windows paths | `C:\`, `%APPDATA%`, `%TEMP%`, etc. |
| Unix paths | `/etc/`, `/tmp/`, `/home/`, etc. |

---

### Decoding and Deobfuscation

**Added:**

- Suspicious base64 decoding
- Suspicious hex decoding
- URL-percent decoding
- Nested decode depth control: `--decode-depth` (range: 0–5, default: 2)
- Secondary IOC extraction pass on decoded artifacts

---

### Entropy Analysis

**Added:**

- Full-file entropy scoring (Shannon entropy, 0.0–8.0 scale)
- High-entropy region detection (identifies sections/regions above packing threshold)

---

### Executable and Container Parsing

**Added — PE (Windows Portable Executable):**
- Machine type and subsystem
- Compile timestamp
- Image base and entry point
- Import table (DLL and function names)
- Approximate import hash (imphash-style)
- Section table: name, virtual size, raw size, entropy, executable/writable flags
- Certificate table presence detection
- Overlay size detection
- .NET runtime detection via `_CorExeMain` / `mscoree.dll`

**Added — ELF (Linux):**
- ELF class (32/64-bit), machine type, and file type
- Imported shared libraries
- Section names

**Added — Mach-O (macOS):**
- CPU type and binary type
- Imported libraries
- Section names

**Added — Archive/Container (ZIP/APK/JAR/Office Open XML):**
- Entry listing without disk extraction (in-memory only)
- Configurable entry inspection limit (`--max-archive-files`, default: 500)
- Suspicious entry heuristics:
  - Path traversal names (`../`, absolute paths)
  - Executable and script extensions (`.exe`, `.ps1`, `.sh`, `.vbs`, etc.)
  - Office macro indicators (`vbaProject.bin`, `macros/`)
  - Android package indicators (`AndroidManifest.xml`, `classes.dex`)
  - Archive bomb heuristic (extreme compression ratio detection)

---

### Behavioral Signatures

**Added — Execution and Injection:**
- Process injection API chains (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`)
- Dynamic API resolution (`GetProcAddress`, `LoadLibraryA` patterns)
- Command-and-control style network strings

**Added — Downloaders and Stagers:**
- Downloader behavior strings (`URLDownloadToFile`, `WinHttpOpen`, `InternetOpenUrl`)
- Suspicious PowerShell execution (`-EncodedCommand`, `-WindowStyle Hidden`, `IEX`, `Invoke-Expression`)
- Script host and LOLBin abuse (`wscript.exe`, `cscript.exe`, `mshta.exe`, `certutil.exe`)

**Added — Credential and Data Theft:**
- Discord webhook exfiltration strings and API endpoints
- Discord account/token access indicators
- Browser credential decryption indicators (Chromium DPAPI patterns)
- Credential and crypto wallet theft strings

**Added — Persistence:**
- Windows persistence strings (Run keys, Startup folder, scheduled tasks, service creation)
- Linux persistence strings (cron, `.bashrc`, `/etc/rc.local`, systemd unit paths)

**Added — Evasion and Anti-Analysis:**
- VM and sandbox awareness strings (CPUID tricks, registry checks, process name checks)
- Anti-debugging references (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, timing checks)
- Security tooling bypass indicators (AV/EDR name strings, patch targets)
- Packer and protector markers (UPX, Themida, VMProtect, MPRESS signatures)

**Added — Impact:**
- Ransomware-style strings (file extension lists, ransom note paths, key generation patterns)

**Added — Density:**
- High IOC density finding (automatic when IOC volume exceeds threshold)

---

### Malware Profile Enrichment

**Added:**

- Classification: likely malware type (ransomware, infostealer, RAT, downloader, etc.)
- Confidence score with supporting evidence chain
- Key capabilities summary (human-readable list)
- Business impact assessment
- Recommended response actions
- MITRE-style TTP entries (tactic, technique, evidence snippet)
- Executive assessment narrative
- Cryptography and secret-handling indicators:
  - Windows CNG: `BCryptEncrypt`, `BCryptDecrypt`, `BCryptGenerateSymmetricKey`
  - Windows CryptoAPI/DPAPI: `CryptUnprotectData`, `CryptProtectData`
  - Chromium `encrypted_key` workflow
  - Symmetric crypto markers: AES, GCM, IV, nonce, tag
  - Decoded-obfuscation layer indicators

---

### Output Formats

**Added — PDF (CISO/management-ready report):**
- Cover page with sample metadata and scan timestamp
- Executive assessment narrative
- CISO decision summary
- Risk and confidence indicator cards
- Likely malware type with supporting evidence
- Key capabilities
- Business impact assessment
- Management-recommended actions
- MITRE ATT&CK TTP matrix
- Priority findings table
- Cryptography and secret-handling assessment
- Hunting guidance
- Sample metadata (hashes, file type, size, entropy)
- IOC sections
- Executable/container details
- Suspicious strings and decoded artifacts appendix

**Added — JSON:**
- Complete `ScanResult` structure for automation, SIEM ingestion, and pipeline processing
- Stable field naming across all scan modes

**Added — IOC text export:**
- Categorized plain-text IOC file via `--extract-ioc`

**Added — YARA hunting rule:**
- Auto-generated hunting rule via `--yara`
- Sources: URLs, domains, registry keys, paths, suspicious strings, malware type labels, SHA256 and imphash metadata

---

### CLI and UX

**Added:**

- Startup ASCII banner and animated loading bar
- Progress display with percentage updates during scan stages
- `--no-progress`: suppress all progress output (automation-friendly)
- `--no-splash`: suppress startup banner/loading bar only
- `--splash-seconds`: configure splash display duration (default: 20s)
- `--debug`: include debug log in Full report; stronger error context

---

### Tests

**Added:**

- Unit tests: IOC extraction
- Unit tests: base64/hex/URL decoding
- Unit tests: file type detection
- Unit tests: PDF generation (output validity)
- Unit tests: YARA rule rendering

---

### Documentation

**Added:**

Full documentation set:

| File | Contents |
|---|---|
| `README.md` | Overview, features, quick start, scan/report mode reference, pipeline diagram |
| `install.md` | Build, install, cross-compile, Docker setup, troubleshooting |
| `usage.md` | Flag reference, modes, outputs, score interpretation, analyst workflow examples |
| `security.md` | Threat model, safe handling checklist, output security, responsible use |
| `contributing.md` | Dev setup, code style, detection quality guide, PR checklist, wanted areas |
| `changelog.md` | This file |

---

### Fixes and Improvements

**Changed:**

- Progress renderer: clears leftover terminal characters when shorter progress messages overwrite longer ones
- PDF layout: improved alignment, wrapping, section styling, table grids, long IOC handling, headers, and footers

---

### Notes

- FlatScan is static-only and does not execute target samples at any point in the pipeline.
- Generated YARA rules are hunting starting points and must be reviewed and validated before production deployment.
- Cryptographic hashes are classified as IOCs but cannot be reversed by FlatScan.
- A score of 0–9 does not indicate a clean file — it indicates no strong static indicators were found.

---

## Planned / Under Consideration

The following are not committed but represent areas of active interest:

- Sigma rule export for SIEM-native hunting queries
- Deeper ELF symbol and section analysis
- Deeper Mach-O load command and code signature inspection
- Enhanced Office macro string extraction (OLE/OOXML VBA)
- PDF malware heuristics (JavaScript, embedded streams, `/Launch`)
- Additional MITRE ATT&CK sub-technique coverage
- GitHub Actions CI workflow for automated build and test
- Integration tests with synthetic malware-pattern fixtures
