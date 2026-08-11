# FlatScan

FlatScan is an **offline, single-binary static malware analysis tool** written in Go (v0.10.0). It ingests a suspect file (or a directory of them), parses its format, extracts strings/entropy/IOCs, disassembles code, resolves obfuscated payloads recursively, correlates evidence into a weighted risk score, and produces analyst- and management-ready reports — **without ever executing the sample and without making any network calls in default mode.** It is designed to safely ingest live malware in an isolated environment.

## Feature Highlights

- **Pure static analysis** — samples are never run; carving reports offsets/hashes only.
- **Multi-format parsing** — PE, ELF, Mach-O, APK/DEX, PDF, Office (docm/xlsm/pptm/MSIX), archives (zip/7z/rar/gz), scripts, `.lnk`.
- **Deep code intelligence** — x86/x64 disassembly, PE header posture (ASLR/DEP/CFG, Rich hash, TLS callbacks, Authenticode), hashdb import resolution (ROR13/DJB2/SDBM).
- **Recursive payload resolution** — peels base64/hex/gzip/zlib/XOR/carving layers into a `payload_tree`.
- **Named-family fingerprints** — RedLine, LummaC2, StealC, Vidar, Raccoon, Agent Tesla, FormBook, XLoader, AsyncRAT, Quasar, Remcos, XWorm, njRAT, and more.
- **IOC extraction, triage & categorization** with confidence scoring and multi-evidence correlation.
- **CAPA-style capability rules**, malware-config extraction, DGA scoring, similarity matching, offline threat-intel enrichment.
- **Many outputs** — terminal report, JSON, CSV/JSONL, PDF, HTML, YARA, Sigma, STIX 2.1, IOC text export, zipped report-pack.
- **Five run modes** — single-file, batch, watch, interactive wizard, manual shell, plus a localhost-only web GUI.
- **CI/CD ready** — machine-readable stderr line and a deterministic exit-code contract for gating builds.
- **Zero third-party dependencies** except `golang.org/x/arch` (used for disassembly).

## Documentation

| Page | What it covers |
|------|----------------|
| [Installation](Installation) | Prerequisites, building from source, cross-compilation, completions, safe lab setup |
| [Quick Start](Quick-Start) | First scan, reading the verdict, scan modes, copy-paste examples |
| [CLI Reference](CLI-Reference) | Every flag grouped by section, exit-code matrix, rejected flag combinations |
| [Output Formats](Output-Formats) | Terminal/JSON/CSV/PDF/HTML/YARA/Sigma/STIX/IOC/report-pack, when to use each |
| [Detection Engine](Detection-Engine) | Scoring model, analysis layers, MITRE ATT&CK mapping |
| [Web UI](Web-UI) | Launching, security model, upload limits, hardening |
| [CI/CD Integration](CI-CD-Integration) | `--ci`, thresholds, stderr contract, GitHub/GitLab snippets |
| [Rules and Plugins](Rules-and-Plugins) | `.rule` pack syntax, allowlists, similarity/intel DBs |
| [Architecture](Architecture) | Pipeline, source layout, concurrency, performance |
| [Troubleshooting](Troubleshooting) | Build errors, exit codes, color/port issues, `--debug` |
| [FAQ](FAQ) | Common questions answered |

## Quick Start

```bash
# Build (Go 1.25+)
cd 'source go' && go build -ldflags "-X main.version=0.10.0" -o ../flatscan .

# Scan a single file
./flatscan -f suspicious.exe

# Deep scan with JSON to stdout
./flatscan -f suspicious.exe -m deep --json -
```

## Safety at a Glance

- **Offline by design** — zero network calls in default mode. No sample submission, no cloud lookups.
- **Samples are NEVER executed** — FlatScan is a pure static analyzer. It reads bytes; it does not run them.
- **Carving is non-destructive** — embedded payloads are reported by offset and hash only; nothing is written to disk from the sample.
- **Bounded resource use** — memory caps, archive-bomb caps, and per-scan work budgets protect the analysis host.
- **Web mode is localhost-only** — binds `127.0.0.1` with an upload cap and strict HTTP hardening.

> Always analyze live malware in an isolated VM or container. See [Installation](Installation#safe-isolated-analysis-environment).
