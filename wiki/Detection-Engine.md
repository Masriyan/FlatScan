# Detection Engine

FlatScan's verdict is the output of a weighted, evidence-correlated scoring model fed by many independent static-analysis layers. This page explains how the score is built and what each layer contributes.

## How Scoring Works

1. **Per-category contributions.** Each analysis layer emits findings with a severity and a numeric weight. Contributions are aggregated per category into `score_breakdown` (a `map[string]int`), then combined into a single 0–100 `risk_score`.
2. **Multi-evidence correlation.** Independent signals that point at the same behavior are correlated. A finding backed by several distinct pieces of evidence carries a higher `confidence` and a larger `evidence_count`, and correlated clusters weigh more than isolated hits — this reduces both false negatives (one weak hit) and false positives (coincidental single strings).
3. **Confidence & evidence count.** Findings expose `confidence` and `evidence_count` so analysts (and downstream automation) can distinguish a high-confidence, multiply-corroborated detection from a speculative one.
4. **YARA-quality false-positive guard.** A benign-context guard recognizes when a file is itself a *detection artifact* — an AV signature set, a YARA/Sigma rule pack, a sandbox, a malware-analysis tool, or a threat report — rather than live malware. When triggered it treats indicator matches as *references, not behavior*, and caps the score so the verdict does not read as malicious (`benign_context` records the reason, cap, and original score).

### Verdict Thresholds

| Score | Verdict | Exit code |
|-------|---------|-----------|
| `>= 80` | Malicious | 20 |
| `>= 30` (single-file) / `>= --ci-threshold` (CI) | Suspicious | 10 |
| below threshold | Clean | 0 |

## Analysis Layers

Each layer runs statically over the file's bytes — nothing is executed.

- **Format parsing** — identifies and structurally parses PE, ELF, Mach-O, APK/DEX, PDF, Office (docm/xlsm/pptm/MSIX), archives (zip/7z/rar/gz), scripts, and `.lnk`.
- **String extraction** — pulls ASCII/UTF-16 strings (min length via `--min-string`, default 5), surfacing suspicious tokens.
- **Entropy analysis** — whole-file and regional (incremental) entropy to flag packed/encrypted regions; `entropy_assessment` and `high_entropy_regions` capture the result.
- **PE header intelligence** — ASLR/DEP/CFG posture, Rich hash, TLS callbacks, Authenticode signature state, section anomalies.
- **Disassembly** — x86/x64 decoding (via `golang.org/x/arch`) to spot API-hashing loops, PEB walks, GetPC stubs, and anti-VM checks.
- **hashdb import resolution** — resolves API-hashed imports using ROR13/DJB2/SDBM to recover the real Windows API names an obfuscated loader calls.
- **IOC extraction, triage & categorization** — extracts URLs, domains, IPv4/IPv6, emails, hashes, CVEs, registry keys, file paths, mutexes, named pipes, and crypto wallets; triages and classifies them with per-IOC `confidence`; an allowlist (`--ioc-allowlist`) suppresses known-good values with a logged reason.
- **DGA scoring** — scores domains for algorithmic (domain-generation-algorithm) characteristics.
- **Named-family fingerprints** — matches distinctive markers of known families: RedLine, LummaC2, StealC, Vidar, Raccoon, Agent Tesla, FormBook, XLoader, AsyncRAT, Quasar, Remcos, XWorm, njRAT, and more.
- **Similarity matching** — compares the sample against a JSONL corpus (`--similarity-db`) to find near-duplicates and clustered variants.
- **CAPA-style capability rules** — maps observed primitives to higher-level capabilities (persistence, injection, credential access, etc.).
- **Malware-config extraction** — recovers embedded configuration (C2 endpoints, keys, mutexes) from recognized families.
- **Recursive payload resolution** — peels layered obfuscation (base64/hex/gzip/zlib/XOR and carving) up to `--resolve-depth` (default 3, max 6), building a `payload_tree` of decoded stages. **The sample is never executed to do this — decoding is pure byte transformation.**
- **Carving** — locates embedded files by signature and reports each by offset and hash only (`--max-carves`, default 80). Nothing from the sample is written to disk.
- **Offline threat-intel enrichment** — cross-references IOCs against a local JSONL intel store (`--intel-db`); no network calls.

## MITRE ATT&CK Mapping

Findings and capability matches are annotated with MITRE ATT&CK **tactic** and **technique** identifiers (e.g. `T1059.001` for PowerShell, `T1071.001` for web-protocol C2, `T1573.002` for asymmetric encrypted channels). These annotations flow into the terminal report, the JSON `findings[]`, the generated Sigma rule, and the STIX bundle, giving every detection a standard framework reference for triage and reporting.

Related: [Output Formats](Output-Formats) · [Rules and Plugins](Rules-and-Plugins) · [Architecture](Architecture).
