# FlatScan — Use Cases & Deployment Guide

**Repository:** https://github.com/Masriyan/FlatScan

> A fast, offline, single-binary **static** malicious-file scanner. FlatScan triages files,
> extracts IOCs, maps behavior to MITRE ATT&CK, and generates analyst/management reports —
> without executing the sample, without network calls, and without leaking the file anywhere.

This document explains **what FlatScan is for, where it fits, where it does *not* fit**, and
gives concrete, copy-pasteable workflows for each scenario. Read the "Positioning" section
first — it frames every use case below.

---

## 1. Positioning — what FlatScan is (and is not)

FlatScan is a **first-stage static triage and IOC-extraction engine**. Its job is to cut the
volume of files that reach your expensive resources (dynamic sandboxes, senior reverse
engineers) by quickly answering: *"How suspicious is this, what indicators does it carry, and
what should I do next?"*

| FlatScan **is** | FlatScan **is not** |
|---|---|
| A fast static triage CLI (seconds per file / per directory) | A dynamic sandbox (it never executes the sample) |
| An offline, single static binary (no network, no telemetry) | An endpoint AV / EDR agent |
| An IOC extractor + hunting-rule generator (YARA/Sigma/STIX) | A full reverse-engineering platform (no decompiler) |
| A multi-format parser (PE/ELF/Mach-O/APK/LNK/scripts/PDF/archives) | A ground-truth verdict oracle — its score is a heuristic |
| A report generator (text/JSON/CSV/PDF/HTML) | A runtime unpacker / C2 emulator |

**Mental model — where it sits in the funnel:**

```
inbound files ─▶ FlatScan (fast static triage, fully offline)
                   ├─ clean / low      → log verdict + IOCs to SIEM, archive
                   ├─ suspicious        → enrich, route to analyst
                   └─ malicious/packed  → escalate to sandbox + RE (Ghidra/capa/IDA)
```

Used at the **front of the funnel**, it is excellent. Used as the *only* stage, it will miss
runtime-only / heavily-packed threats by design — that is the correct division of labor, not a
defect.

---

## 2. Verdict model & exit codes

FlatScan sums weighted findings into a 0–100 risk score and assigns a verdict tier:

| Score | Verdict | Typical action |
|------:|---------|----------------|
| ≥ 80 | **Likely malicious** | Contain, escalate, harvest IOCs |
| ≥ 55 | **High suspicion** | Sandbox / analyst review |
| ≥ 30 | **Suspicious** | Triage, correlate with telemetry |
| ≥ 10 | **Low suspicion** | Note, low priority |
| < 10 | **No strong indicators** | Likely benign (still log hashes) |

A detection/analysis-artifact guard caps the score for files that merely *contain* indicators as
data (AV signature sets, rule packs, threat reports, the scanner's own binary), annotating the
verdict as a security-tool/signature artifact rather than a live specimen.

**CI/CD exit codes** (`--ci`): `0` clean · `10` suspicious · `20` malicious · `1` error.

---

## 3. Primary use cases

### 3.1 High-volume SOC / IR / MSSP triage  *(the flagship use case)*

**Problem:** an analyst has a quarantine folder, a malware-collection drop, or a batch of
email attachments and needs to know *which ones matter* before spending sandbox time.

**Why FlatScan fits:** batch scanning, per-file verdicts, IOCs, ATT&CK mapping, and a full
report pack in seconds — entirely offline.

```bash
# Batch-triage a directory, machine-readable summary for the queue
flatscan --dir ./quarantine -m deep --batch-json triage.json

# Continuously watch an ingest folder, only surface high-score files
flatscan --dir ./inbox --watch --watch-alert-only --watch-interval 5

# Full evidence pack per case (text + JSON + PDF + HTML + IOC + YARA + Sigma + STIX)
flatscan -f suspicious.bin -m deep --report-pack ./cases/CASE-1042
```

**Output to act on:** the batch summary table (verdict/score/finds/IOCs/type per file) plus
`triage.json` for piping into a ticketing/queue system.

---

### 3.2 Air-gapped / sensitive / offline analysis  *(the key differentiator)*

**Problem:** you cannot upload the sample anywhere — classified network, legal-hold / IR
evidence, or PII-laden files — so VirusTotal and cloud sandboxes are off the table.

**Why FlatScan fits:** one static binary, runs nothing, makes no network calls, emits no
telemetry. The sample never leaves the host.

```bash
# Self-contained scan on an isolated host; deterministic, no external lookups
flatscan -f evidence.exe -m deep --report ./report.txt --json ./report.json

# Optional local web GUI for analysts on the same isolated box (no internet needed)
flatscan --web --web-port 5000
```

> **Note:** `--external-tools` is the *only* path that shells out to optional local helpers
> (e.g. `rabin2`) and is **off by default**. Leave it off in air-gapped/forensic settings to
> keep the run fully self-contained and reproducible.

---

### 3.3 Initial-access / phishing-payload analysis

**Problem:** the files that actually land in inboxes — malicious shortcuts, obfuscated
PowerShell/JS/VBS, script-based downloaders — need fast triage and IOC recovery.

**Why FlatScan fits:** it parses `.lnk` shortcuts (target/LOLBin + embedded command line),
runs a script behavioral engine (Defender/AMSI tampering, download-and-execute cradles), and
performs multi-layer deobfuscation (base64 → delimited-hex → reversed-string), recovering
hidden/reversed C2 URLs as IOCs. For staged droppers, **recursive payload resolution**
(0.10.0) goes one step further: it peels base64/hex, gzip/zlib, and single-byte-XOR layers
off the file and **re-scans the buried executable that emerges**, surfacing a `payload_tree`
where the recovered stage carries its own score, family, and C2 — all by pure data
transformation, without ever executing the sample.

```bash
# Analyze a malicious shortcut — recovers the embedded PowerShell + reversed C2 URL
flatscan -f invoice.lnk -m deep --extract-ioc iocs.txt

# Deobfuscate a staged PowerShell dropper and resolve the buried PE it carries
flatscan -f stage1.ps1 -m deep --decode-depth 4 --resolve-depth 4 --html report.html
```

---

### 3.4 CI/CD & supply-chain artifact gating

**Problem:** prevent a poisoned dependency, installer, or build artifact from shipping.

**Why FlatScan fits:** `--ci` suppresses UI and returns semantic exit codes you can branch on
in a pipeline.

```bash
# Fail the build if any artifact scores at/above the malicious-ish threshold
flatscan -f ./dist/installer.exe --ci --ci-threshold 55
# exit 0 = clean, 10 = suspicious, 20 = malicious  → gate the pipeline accordingly
```

```yaml
# Example GitHub Actions step
- name: Static malware gate
  run: flatscan -f ./dist/app.exe --ci --ci-threshold 55
```

---

### 3.5 Threat-intel / IOC harvesting & hunting-rule generation

**Problem:** turn a sample into actionable indicators and detections for a SIEM/EDR hunt.

**Why FlatScan fits:** it extracts URLs, domains, IPv4/6, hashes, registry keys, mutexes,
named pipes, wallets, CVEs — now **categorized** (actionable IOC vs build-artifact / source-path /
namespace / benign-infra) so exports stay trustworthy — recovers a structured **malware-config**
view (C2/mutex/token/webhook/campaign), and exports ready-to-deploy **YARA** (with a
quality/FP-risk score), **Sigma**, and **STIX 2.1** artifacts. It can also rank a sample against a
local **similarity reference store** and enrich its indicators from an **offline threat-intel DB**.

```bash
# Generate a hunting bundle from a confirmed-bad sample
flatscan -f badsample.bin -m deep \
  --extract-ioc iocs.txt \
  --yara hunt.yar \
  --sigma hunt.yml \
  --stix bundle.json

# Suppress your own infrastructure / known-benign hosts from the IOC set
flatscan -f sample.bin --ioc-allowlist ./allowlist.txt --json -

# Cluster against known samples and enrich from a local intel database (both offline JSONL)
flatscan -f sample.bin -m deep --similarity-db ./refs.jsonl --intel-db ./intel.jsonl --json -
```

> **0.9.0 precision additions:** every finding carries a numeric `confidence` and
> `evidence_count` (serious capabilities require multiple corroborating signals, so a lone
> generic string never reads as high-confidence); named-family fingerprints attribute
> RedLine/Lumma/StealC/AsyncRAT/… when corroborated; and CAPA-style capability rules detect
> behaviors (e.g. process injection) even when APIs are resolved by hash.

---

### 3.6 Repeatable case work, education & documentation

**Problem:** you need consistent, shareable analysis records — for tickets, training, or
hand-offs.

**Why FlatScan fits:** the analyst HTML report and management PDF are presentation-ready, and
a JSONL case database links related samples by hash.

```bash
# Record into a case database for cross-sample correlation
flatscan -f sample.bin -m deep --case CASE-1042 --case-db ./cases.jsonl

# Guided wizard for less-experienced analysts
flatscan --interactive
```

---

## 4. Format coverage (what to throw at it)

| Family | What FlatScan does |
|---|---|
| **PE (EXE/DLL/SYS)** | imports, sections, overlay, import hash, **DllCharacteristics/exploit-mitigation posture, Rich-header hash, TLS callbacks, Authenticode signer, entry-point sanity**, .NET detection |
| **Code-level (x86/x64 PE+ELF)** | entry-point disassembly: **API-hashing (ROR13) loops, PEB walks, GetPC/shellcode stubs, instruction-level anti-VM** (VMware backdoor, hypervisor CPUID, Red Pill), and **hash-database resolution of hash-obfuscated imports** |
| **ELF** | class/machine/type, imports, sections, **static+stripped posture, legacy/IoT-architecture profile, high-entropy code packing** |
| **Mach-O** | CPU, type, imports, sections |
| **Windows shortcut (.lnk)** | ShellLinkHeader + StringData parsing, LOLBin target detection, embedded command-line extraction & deobfuscation, reversed-URL C2 recovery |
| **Scripts** | `.ps1/.psm1/.bat/.cmd/.vbs/.js/.wsf/.hta/.sh` — Defender/AMSI tampering, download-and-execute cradles, persistence, multi-layer deobfuscation |
| **Android APK / DEX** | manifest, permissions, exported components, native libs, embedded payloads, DEX string/API scanning |
| **Archives & containers** | ZIP/JAR/Office OOXML/MSIX/AppX entry inspection (no disk extraction); RAR/7z/gzip/bzip2/xz detection; recursive safe carving (`--carve`) |
| **PDF** | structural analysis |

---

## 5. Mode & performance guidance

| Mode | Use when | Trade-off |
|---|---|---|
| `quick` | Bulk first-pass over very large sets; watch folders | Skips entropy-region scan, code disassembly, deep decode |
| `standard` | Default analyst triage | Balanced depth/speed; enables disassembly pass |
| `deep` | Single suspicious file / final triage | Maximum depth (largest decode/disasm windows, full strings) |

A 12-file deep batch typically completes in **a few seconds**. The disassembly pass and
nested decoding are gated to `standard`/`deep`; the `quick` path stays fast for volume.

---

## 6. When **not** to use FlatScan (anti-patterns)

- **As a replacement for a dynamic sandbox.** Packed/runtime-unpacked malware will read as
  "packed, high-entropy, suspicious" and stop there — that's a hand-off signal, not a verdict.
- **As the sole arbiter for auto-blocking.** The score is a heuristic *prioritization* signal.
  Keep an analyst in the loop; correlate with EDR/network telemetry before automated action.
- **For deep reverse engineering of .NET threats.** The native disassembler is blind to CIL,
  so managed loaders/stealers get string-level analysis only (use dnSpy/ILSpy for IL).
- **As an endpoint/runtime detection product.** It is an analysis CLI, not an agent.
- **For runtime unpacking / C2 interaction.** No emulation or execution — escalate to a sandbox.

---

## 7. Recommended reference workflows

**A. Quarantine-folder auto-triage (SOC):**
```bash
flatscan --dir /var/quarantine --watch --watch-alert-only \
  --batch-json /var/log/flatscan/triage.json --no-progress
```

**B. Single high-priority specimen (IR, offline):**
```bash
flatscan -f specimen.bin -m deep --carve \
  --report-pack ./cases/IR-2099 --case IR-2099 --case-db ./cases.jsonl
```

**C. Build-pipeline gate (CI):**
```bash
flatscan -f ./artifacts/release.exe --ci --ci-threshold 55 --no-color
```

**D. Intel enrichment → SIEM hunt:**
```bash
flatscan -f ioc-source.bin -m deep \
  --extract-ioc iocs.txt --sigma hunt.yml --stix bundle.json --output-format jsonl
```

---

## 8. Summary

FlatScan is the **cheap, fast, offline first stage** of a layered malware-analysis pipeline.
Its best owner is a **triage analyst, IR responder, MSSP operator, or detection/threat-intel
engineer** who needs to process volume, harvest indicators, and decide what to escalate —
especially in environments where uploading or executing the sample is not an option. Pair it
with a dynamic sandbox and a reverse-engineering toolkit for the minority of samples that
warrant deeper work, and it earns its place in every analysis workflow.

For installation, full flag reference, and contribution guidelines, see the repository:
**https://github.com/Masriyan/FlatScan**
