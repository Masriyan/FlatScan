# FlatScan Report Pack — Reference Output

This directory is the default output location used by the examples in
[README.md](../README.md), [usage.md](../usage.md), [USECASE.md](../USECASE.md) and
[contributing.md](../contributing.md) (e.g. `--report reports/scan.txt`). FlatScan does not create
parent directories, so it is kept in the repository for those examples to work on a fresh clone.

It also holds **one published reference report pack** — [`vidar.exe.pack/`](vidar.exe.pack) — so you
can inspect every output format FlatScan produces without building the tool or supplying a sample.

> Everything else written here is ignored by [`.gitignore`](../.gitignore). Do not commit your own
> scan output, analysed samples, or anything derived from them.

---

## The published pack

| | |
| --- | --- |
| Sample | `vidar.exe` (Windows PE, amd64, `windows-gui`, 4.3 MiB) |
| SHA-256 | `a758ff0a172386bd3d1efaba38bc94cd899080eb53039097c1b043c2c8c8bafc` |
| MD5 | `b971e00a0514a9dd90ae4147fd2be083` |
| Imphash | `5292ba861fbedd8ccd6f23c56196bc91` |
| Scanner | FlatScan **0.10.2**, `deep` mode, `--carve --debug` |
| Scanned | 2026-08-13T18:18:27Z · 1.31 s · 15,759 strings |
| Verdict | **Likely malicious — 100/100** (exit code `20`) |

Reproduce the whole directory with a single command:

```bash
./flatscan -m deep -f vidar.exe --report-pack reports/vidar.exe.pack --carve --debug
```

Files in a pack are named `<sample>_<sha256[:8]>.<kind>`, so packs from different samples can share
one output directory without colliding.

### Files

| File | Format | Read it when you want |
| --- | --- | --- |
| [`vidar_a758ff0a.full.txt`](vidar.exe.pack/vidar_a758ff0a.full.txt) | Text (Full mode) | Everything: findings, APIs, IOCs, config artifacts, carved blobs, similarity hashes, PE header intel, sections, imports, disassembly, debug log |
| [`vidar_a758ff0a.summary.txt`](vidar.exe.pack/vidar_a758ff0a.summary.txt) | Text (Summary mode) | Fast triage — verdict, profile, top findings, IOC counts |
| [`vidar_a758ff0a.report.json`](vidar.exe.pack/vidar_a758ff0a.report.json) | JSON | Automation: the complete `ScanResult` for SOAR, pipelines, `jq` |
| [`vidar_a758ff0a.ciso.pdf`](vidar.exe.pack/vidar_a758ff0a.ciso.pdf) | PDF | Management handoff — executive summary, MITRE matrix, risk bar, impact |
| [`vidar_a758ff0a.analyst.html`](vidar.exe.pack/vidar_a758ff0a.analyst.html) | HTML | Deep analyst review — global search, MITRE heatmap, IOC tabs, theme toggle |
| [`vidar_a758ff0a.executive.md`](vidar.exe.pack/vidar_a758ff0a.executive.md) | Markdown | Pasting into a ticket, incident channel, or wiki |
| [`vidar_a758ff0a.iocs.txt`](vidar.exe.pack/vidar_a758ff0a.iocs.txt) | IOC text | Blocklist ingestion — categorized, deduplicated |
| [`vidar_a758ff0a.yar`](vidar.exe.pack/vidar_a758ff0a.yar) | YARA | Corpus hunting (`uint16(0) == 0x5a4d` guard + string/IOC conditions) |
| [`vidar_a758ff0a.sigma.yml`](vidar.exe.pack/vidar_a758ff0a.sigma.yml) | Sigma | SIEM/EDR detection, tagged with the mapped ATT&CK techniques |
| [`vidar_a758ff0a.stix.json`](vidar.exe.pack/vidar_a758ff0a.stix.json) | STIX 2.1 | Intel sharing via MISP / OpenCTI / TAXII |

The web GUI serves the same ten files zipped from `GET /api/download/{id}/pack`.

---

## What the scan found

**Score breakdown**

```
[Chain:166 Cryptominer:26 Wiper:26 Packing:18 Behavior:12 Persistence:12 IOC:7 Configuration:4 Obfuscation:4 PE Posture:3]
```

**19 findings** — the two `Critical` ones are behavioral API chains:

| Severity | Finding | ATT&CK | Score | Confidence |
| --- | --- | --- | ---: | ---: |
| Critical | Classic DLL injection chain | T1055 | 40 | 85 |
| Critical | Process hollowing chain | T1055.012 | 38 | 85 |
| High | Keylogger with exfiltration | T1056 | 30 | 70 |
| High | Named pipe C2 with code injection | T1095 | 30 | 70 |
| High | Credential theft + webhook exfiltration | T1555.003 | 28 | 70 |
| High | Low-level disk write / file deletion chain | T1485 | 26 | 70 |
| High | Mining pool connection strings | T1496 | 26 | 70 |
| Medium | Dynamic API resolution with executable memory | — | 12 | 55 |
| Medium | Linux persistence indicator | — | 12 | 55 |
| Medium | Multiple high-entropy regions (25 found) | — | 10 | 55 |
| Medium | Large high-entropy blob at `0x422000` (8.00/8.00) | T1027 | 8 | 55 |
| Low | Encoded data decoded successfully | — | 4 | 40 |
| Low | High IOC density (10 IOCs) | — | 4 | 40 |
| Low | Static configuration artifacts extracted (36) | — | 4 | 40 |
| Low | Embedded hash-like indicators | — | 3 | 40 |
| Low | Self-signed certificate (`CN=blobalkas.tv`) | — | 3 | 40 |
| Info | PE missing exploit mitigations (CFG) | — | — | 30 |
| Info | Family hypothesis: Generic ransomware (High) | — | — | 30 |
| Info | AsyncRAT configuration recovered (5 C2, 1 campaign-id) | T1071 | — | 80 |

**Family hypotheses (5):** Generic ransomware (High, 90) · AsyncRAT (Medium-High, 89) ·
FormBook/XLoader (Medium-High, 89) · XWorm (Medium-High, 89) · Packed or bundled payload
(Medium, 55).

**PE posture:** signed but **self-signed** (`CN=blobalkas.tv, O=JzyswPRF0wWV30, L=VfLufa, ST=6IVuYA8H6, C=US`),
zeroed compile timestamp, ASLR/DEP/HighEntropyVA/TerminalServerAware present but **CFG missing**,
2.4 KiB overlay, 8 sections, 46 imports (all `kernel32.dll`).

**Static extraction:** 9 carved gzip artifacts, 36 crypto/config artifacts, 25 high-entropy regions,
1 decoded artifact, 10 MITRE TTPs mapped, and the full FlatHash / byte-histogram / string-set /
import-hash / section-hash similarity set.

---

## Read this pack critically

It is published as a **format reference**, not as ground truth about the sample. FlatScan is a
static engine: it reports what is present in the bytes and scores it. Several artifacts in this pack
are exactly the false positives documented in the [Limitations](../README.md#limitations) section:

- The sample is a **Go-compiled binary**, so `go.dev` and `godebugs.info` are toolchain strings, not
  C2 infrastructure — yet they land in the IOC export, the YARA rule, and the recovered "AsyncRAT
  C2" list.
- The `dddddddd…`, `eddddddd…`, `0000…` and `aaaa…bbbb…cccc…` hashes are runtime test vectors picked
  up by the hash-like-indicator extractor.
- The `crypto/internal/fips140/aes.*` symbols are the Go standard library, and they are what drives
  the "Cryptographic secret handling" capability and the ransomware family hypothesis.
- The generated YARA rule carries `rule_quality_score = 68` and `expected_fp_risk = "medium"` in its
  metadata for this reason, and the Sigma rule lists its own false-positive conditions.

**Every generated rule and IOC list is a starting point for an analyst, not a production artifact.**
Validate before deploying, and re-read [security.md](../security.md) before sharing any report
outside your team — reports embed recovered strings, paths, and configuration values from the
sample.
