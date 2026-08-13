# FAQ

### Does FlatScan execute the samples it analyzes?

**No.** FlatScan is a pure static analyzer. It reads and parses bytes, disassembles code, and decodes obfuscation mathematically — it never runs the sample. Even recursive payload resolution is byte transformation, not execution.

### Is it offline? Does it phone home?

**Yes, it is offline.** In default mode FlatScan makes **zero network calls** — no sample submission, no cloud lookups, no telemetry. Threat-intel enrichment uses a local JSONL store (`--intel-db`). It is safe to run air-gapped.

### What file formats can it analyze?

PE, ELF, Mach-O, APK/DEX, PDF, Office documents (docm/xlsm/pptm/MSIX), archives (zip/7z/rar/gz), scripts, and Windows `.lnk` files.

### How is the risk score computed?

Each analysis layer emits weighted findings that aggregate into per-category contributions (`score_breakdown`), which combine into a 0–100 `risk_score`. Multi-evidence correlation raises confidence for corroborated detections, and a benign-context guard caps the score for detection artifacts (rule packs, AV signatures, sandboxes). See [Detection Engine](Detection-Engine).

### What do the verdicts mean?

Score `>= 80` = Malicious (exit 20), `>= 30` = Suspicious for single files (exit 10; in CI the boundary is `--ci-threshold`, default 55), otherwise Clean (exit 0).

### Can I use it in CI/CD?

**Yes.** Use `--ci` (optionally with `--ci-threshold`). It prints a parseable `FLATSCAN:` stderr line and returns gating exit codes. Batch mode returns the worst file's code. See [CI/CD Integration](CI-CD-Integration).

### Is the web UI safe to expose to the network?

**No — do not expose it.** The web GUI binds `127.0.0.1` only and has no authentication because it is meant for the local operator. It is hardened (CSP, X-Frame-Options, HTTP timeouts, filename sanitization, XSS-safe rendering, 256 MB upload cap) but is not designed to be internet-facing. See [Web UI](Web-UI).

### Does carving extract malware to my disk?

**No.** Carving reports embedded artifacts by **offset and hash only**. Nothing from the sample is written out. This keeps the analysis host clean.

### What are the scan modes?

Single-file (`-f`), batch (`--dir`), watch (`--dir --watch`), interactive wizard (`--interactive`/`-i`), manual shell (`--shell`), and the local web GUI (`--web`). Depth is set with `-m quick|standard|deep`.

### What dependencies does it need?

None. `go.mod` requires nothing and there is no `go.sum`, so the build needs no network. The x86/x64 disassembler is vendored in-tree as `internal/x86asm` (an unmodified copy of `golang.org/x/arch/x86/x86asm`, BSD-3-Clause); everything else is the Go standard library. No cgo, no runtime install — a single binary.

### Which Go version is required to build it?

Go **1.25.0 or newer**. Build with `cd 'source go' && go build -ldflags "-X main.version=0.10.2" -o ../flatscan .`.

### Can it detect known malware families?

Yes — named-family fingerprints cover RedLine, LummaC2, StealC, Vidar, Raccoon, Agent Tesla, FormBook, XLoader, AsyncRAT, Quasar, Remcos, XWorm, njRAT, and more, alongside CAPA-style capability rules and malware-config extraction.

Attribution is deliberately conservative: naming a family requires a family-name marker in the sample **and** a corroborating evidence group, so generic stealer behavior alone never produces a family name. A **packed or obfuscated** sample whose name markers are unrecoverable is reported with a generic bucket ("Information stealer", "Remote access trojan") instead of a guessed family — expect this on heavily packed samples. See [Detection Engine](Detection-Engine#analysis-layers).

### What outputs can it produce?

Terminal report (Full/Summary/minimal), JSON, CSV, JSONL, PDF, HTML, YARA, Sigma, STIX 2.1, a flat IOC export, and a zipped report-pack. See [Output Formats](Output-Formats).

### Can I add my own detection rules?

Yes — write `.rule` packs and load them with `--rules` or `--plugins`. You can also supply an IOC allowlist, a similarity DB, and an intel DB. See [Rules and Plugins](Rules-and-Plugins).

### How do I debug an unexpected verdict?

Run with `--debug` to emit a verbose `debug_log` showing which passes ran and why rules matched or didn't. See [Troubleshooting](Troubleshooting#how---debug-helps).

Related: [Home](Home) · [Quick Start](Quick-Start) · [Detection Engine](Detection-Engine).
