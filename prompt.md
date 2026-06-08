# Implementation Prompt — FlatScan: Deepen Windows PE static analysis + add a DGA domain scorer

> Role: You are a malware-analysis + Go engineer extending **FlatScan**, a pure-Go,
> **zero-dependency**, **static-only** (never-execute) malware analysis engine at
> `/home/sudo3rs/Desktop/FlatScan`. Implement the two features below exactly, honoring the
> hard constraints. Do not add module dependencies. Do not execute samples. Keep scoring
> **Conservative** (defined below).

## Hard constraints (non-negotiable)
- **Zero dependencies**: stdlib only (`debug/pe`, `crypto/x509`, `crypto/sha256`, raw byte parsing). `go.mod` must stay dependency-free.
- **Static only**: never run the sample. Parse bytes/metadata.
- **Conservative scoring**: new posture signals are mostly `Info` (score 0) or `Low` (score ≤ 6) and must **never tip a verdict on their own** — legacy-but-benign binaries also lack mitigations. The existing research-artifact score cap in `falsepositive.go` must keep applying.
- Match surrounding code style. New struct fields are additive and `omitempty` (no breaking JSON changes).

## Verified facts (already checked against the live tree — do not re-litigate)
- `debug/pe` exposes `DllCharacteristics uint16` on **both** `OptionalHeader32` and `OptionalHeader64`.
- Exported consts exist: `pe.IMAGE_DIRECTORY_ENTRY_SECURITY` (=4, already used at formats.go:145-154) and `pe.IMAGE_DIRECTORY_ENTRY_TLS` (=9). **Use these consts, not magic numbers.**
- `analyzePE(result, cfg)` is defined at `formats.go:100` and called once from `AnalyzeFormats` at `formats.go:77`, where `data []byte` is already in scope.
- The `OptionalHeader32/64` type switch is at `formats.go:140-155`.
- An existing cert-parse helper `extractMSIXSignatureCertificates` is at `formats.go:481` and already documents that PKCS#7/CMS blobs do not parse via `x509.ParseCertificates` directly.
- Pipeline (`ScanFile`, `scanner.go`): `AnalyzeFormats` at line 160; `parallelRun` (carving + similarity) at 170; second `ApplyIOCTriage` at 196; `ClassifyMalwareFamiliesWithCorpus` at 197; `AssessResearchArtifact` at 214; `FinalizeRisk` at 215.
- `BuildSimilarityInfo` is at `similarity.go:11` and reads `result.PE`.
- Domain extraction + TLD list: `ioc.go:13` (`domainRe`), `ioc.go:328` (`normalizeDomain`).
- Renderer PE blocks: `report.go:518`, `pdf.go:431` (+ PE import-hash kv at `pdf.go:52`), `html.go:592`; similarity blocks: `report.go:359`, `pdf.go:622`, `web_ui.go:558` (JSON-driven JS).
- `data` may be **truncated** to `cfg.MaxAnalyzeBytes` (`scanner.go:94-109`, `result.TruncatedAnalysis`). Account for this in cert extraction (see correction C3).

---

## Grounding in established methods & research
Anchor each piece to a canonical, citable method/spec — not ad-hoc heuristics — so output is
interoperable with existing tooling and defensible in a report.

**PE Header Intelligence**
- Flag bit values → **Microsoft PE/COFF specification** (`DllCharacteristics`, `FileHeader.Characteristics`, `IMAGE_TLS_DIRECTORY`) — authoritative source for the constants.
- "Missing mitigations" check set + naming → align with the established binary-hardening checkers **winchecksec** (Trail of Bits), **BinSkim** (Microsoft), **PESecurity** (NetSPI): ASLR (DYNAMIC_BASE + reloc table present), DEP/NX (NX_COMPAT), CFG (GUARD_CF), High-Entropy ASLR (HIGH_ENTROPY_VA), Force Integrity, SafeSEH (no NO_SEH + a SEH table), Authenticode signed. (GS/stack-cookies are not statically determinable from the header → mark N/A, don't guess.) Matching these names makes output familiar to anyone who has run those tools.
- Rich header de-XOR → **Daniel Pistelli, "The Undocumented Microsoft Rich Header"**; emit the same value as **VirusTotal's `rich_pe_header_hash`** so the hash is cross-tool comparable.
- Authenticode → **Microsoft "Windows Authenticode Portable Executable Signature Format"** (`WIN_CERTIFICATE` wrapping a PKCS#7/CMS SignedData).
- imphash already implemented (`formats.go:611`) follows the **Mandiant/FireEye import-hash** method — keep + reference it.
- Entropy thresholds in `entropy.go` (7.2 / 7.7) follow **Lyda & Hamrock (2007), "Using Entropy Analysis to Find Encrypted and Packed Malware"** — reuse, don't reinvent.
- TLS-callback-as-anti-analysis is a documented technique (**Sikorski & Honig, _Practical Malware Analysis_**).

**DGA-likeness scorer** — use the published **non-ML lexical** method set (per-domain, context-free pure functions — exactly FlatScan's constraint):
- Feature set → **FANCI (Schüppen et al., USENIX Security 2018)**: length, vowel/consonant ratio, max consecutive consonants/digits, digit ratio, % unique characters, n-gram stats.
- Randomness → Shannon entropy of the label, **reusing existing `ShannonEntropy([]byte(label))` (`entropy.go:5`)** — no new entropy code.
- Distributional distance → **Yadav et al. (IMC 2010), "Detecting Algorithmically Generated Malicious Domain Names"**: KL-divergence / Jaccard between the label's bigram distribution and a benign reference table.
- Linguistic plausibility → **Phoenix (Schiavoni et al., DIMVA 2014)**: n-gram normality score.
- Tune/cite against **DGArchive (Plohmann et al., USENIX Security 2016)**. **Dictionary-free this increment**: no embedded wordlist; Phoenix's meaningful-word ratio is deferred.

**Deferred to a later increment** (decided out of scope here): **telfhash** (Trend Micro, 2020 — ELF analog of imphash) and **TLSH** (Oliver et al., 2013 — locality-sensitive fuzzy hash).

---

## Feature 1 — PE Header Intelligence

### 1a. `types.go` — add fields (all `omitempty`)
To `PEInfo`:
```go
DllCharacteristics   uint16   `json:"dll_characteristics,omitempty"`
SecurityFeatures     []string `json:"security_features,omitempty"`     // enabled: ASLR, DEP, CFG, HighEntropyVA, ForceIntegrity, AppContainer, TerminalServerAware
MissingMitigations   []string `json:"missing_mitigations,omitempty"`   // e.g. ["ASLR","DEP","CFG"]
ImageCharacteristics []string `json:"image_characteristics,omitempty"` // RELOCS_STRIPPED, EXECUTABLE_IMAGE, DLL, LARGE_ADDRESS_AWARE
HasTLSCallbacks      bool     `json:"has_tls_callbacks,omitempty"`
TLSCallbackCount     int      `json:"tls_callback_count,omitempty"`
RichHeaderHash       string   `json:"rich_header_hash,omitempty"`
Signed               bool     `json:"signed,omitempty"`
SignatureStatus      string   `json:"signature_status,omitempty"`
SelfSigned           bool     `json:"self_signed,omitempty"`
CertificateSubjects  []string `json:"certificate_subjects,omitempty"`
CertificateIssuers   []string `json:"certificate_issuers,omitempty"`
EntryPointSection    string   `json:"entry_point_section,omitempty"`
EntryPointAnomaly    string   `json:"entry_point_anomaly,omitempty"`
```
To `SimilarityInfo`: `RichHeaderHash string `json:"rich_header_hash,omitempty"``

### 1b. `formats.go` + new `pe_intel.go`
- Change signature to `analyzePE(result *ScanResult, cfg Config, data []byte)`; update the caller at formats.go:77 (pass `data`).
- In the `OptionalHeader32/64` switch (140-155): record `header.DllCharacteristics`, the FileHeader characteristics (`file.FileHeader.Characteristics`), and the SECURITY data-dir entry (`header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]` — `.VirtualAddress` is a **file offset** for Authenticode, `.Size` is the blob length).
- New file `pe_intel.go` with pure, unit-testable helpers:
  - `decodeDllCharacteristics(v uint16) (enabled, missing []string)` — local flag consts (debug/pe does **not** export them):
    `HIGH_ENTROPY_VA 0x0020, DYNAMIC_BASE 0x0040, FORCE_INTEGRITY 0x0080, NX_COMPAT 0x0100, NO_ISOLATION 0x0200, NO_SEH 0x0400, NO_BIND 0x0800, APPCONTAINER 0x1000, WDM_DRIVER 0x2000, GUARD_CF 0x4000, TERMINAL_SERVER_AWARE 0x8000`.
    `enabled` = friendly names of set bits (ASLR=DYNAMIC_BASE, DEP=NX_COMPAT, CFG=GUARD_CF, plus HighEntropyVA/ForceIntegrity/AppContainer/TerminalServerAware). `missing` = which of {ASLR, DEP, CFG} are absent.
  - `decodeImageCharacteristics(v uint16) []string` — `RELOCS_STRIPPED 0x0001, EXECUTABLE_IMAGE 0x0002, LARGE_ADDRESS_AWARE 0x0020, DLL 0x2000`.
  - `computeRichHeaderHash(data []byte) string` — guard `len(data) >= 0x40`; read `e_lfanew` (LE uint32 at `data[0x3C:0x40]`); within `data[0x80:e_lfanew]` find the `Rich` marker; take the 4-byte XOR key following it; walk backward XOR-ing dwords until the `DanS` marker (`0x536E6144`, the LE read of bytes `D a n S`); SHA-256 the de-XORed comp-id array; return `""` if any step fails (non-MSVC/forged → attribution-only, no finding).
  - `parseTLSCallbacks(file *pe.File, optHdr, data) (count int)` — if `DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_TLS].Size > 0`: resolve the TLS directory RVA → file offset via `file.Sections` (RVA within `[VirtualAddress, VirtualAddress+VirtualSize)` → `Offset + (rva - VirtualAddress)`), read `AddressOfCallBacks` (an **ImageBase-relative VA** → subtract `ImageBase` to get an RVA → file offset), then count consecutive non-null pointer entries. **Conservative fallback**: if the directory is present but the structure can't be resolved (or `data` is truncated past the offset), return `1` (presence). Return `0` only when the TLS data dir is empty.
  - **(C4)** Shared `parseDERCertificates(blob []byte) (subjects, issuers []string, selfSigned bool, ok bool)` — first try `x509.ParseCertificates(blob)`; if that yields nothing (the common PKCS#7/CMS case), **scan the DER for embedded certificates**: walk TLVs looking for `0x30 0x82 <hi> <lo>` sequences and attempt `x509.ParseCertificate` on each candidate slice; collect those that parse. `selfSigned` = any cert with `Subject.String() == Issuer.String()`. Refactor `extractMSIXSignatureCertificates` (formats.go:481) to call this shared helper.
  - `extractPECertificates(file io.ReaderAt, secOffset, secSize int64) (subjects, issuers []string, status string, selfSigned bool)` — **(C3)** read the cert table **from the file** at `secOffset` (use the `*os.File`/`ReaderAt` from `pe.Open`, or `os.ReadAt`) because the in-memory `data` may be truncated and the cert blob lives at end-of-file. Bounds-guard `secSize` (cap at a few MB). Skip the 8-byte WIN_CERTIFICATE header (`dwLength`,`wRevision`,`wCertificateType`) and pass `bCertificate` to `parseDERCertificates`. Always set `status` (e.g. `"signature present; N certificate(s) recovered"` or `"PKCS#7/CMS signature present; signer not recovered without CMS parser"`).

### 1c. `similarity.go`
In `BuildSimilarityInfo` (line 11), when `result.PE != nil` set `info.RichHeaderHash = result.PE.RichHeaderHash` (mirror `importSimilarityHash`'s `result.PE` access). Adds Rich hash to the structural-similarity surface for batch/case clustering.

### 1d. Findings emitted from `analyzePE` (Conservative; category `"PE Posture"`)
| Condition | Severity | Score | MITRE | Notes |
|---|---|---|---|---|
| ASLR **and** DEP both missing | Low | 3 | — (no tag) | evidence lists `MissingMitigations` |
| only some mitigations missing | Info | 0 | — | informational |
| TLS callbacks present | Low | 4 | Execution / Hijack Execution Flow (T1574) | "runs before main / anti-debug" |
| entry point in a **writable** section | Low | 6 | Defense Evasion / Obfuscated Files or Information (T1027) | packer/injection tell |
| entry point outside all sections | Low | 4 | Defense Evasion / Obfuscated Files or Information (T1027) | |
| unsigned EXE | Info | 0 | — | most benign software is unsigned too |
| self-signed certificate | Low | 3 | — | |
| Rich header | (none) | — | — | similarity-only, no finding |

Use the existing `AddFindingDetailed(result, sev, category, title, evidence, score, offset, tactic, technique, recommendation)`.

---

## Feature 2 — DGA-likeness scorer

### 2a. `types.go`
New type + `ScanResult` field:
```go
type DGADomain struct {
    Domain  string   `json:"domain"`
    Score   float64  `json:"score"`
    Reasons []string `json:"reasons,omitempty"`
}
// in ScanResult:
DGADomains []DGADomain `json:"dga_domains,omitempty"`
```

### 2b. New `dga.go` (dictionary-free; grounded in FANCI / Yadav / Phoenix)
- `dgaScore(domain string) (score float64, reasons []string)` — pure function on the **registrable label** (strip the TLD using the same suffix set as `ioc.go`'s `domainRe`). **Dictionary-free** feature set (no embedded wordlist; meaningful-word ratio deferred):
  - **Shannon entropy** of the label — reuse `ShannonEntropy([]byte(label))` (`entropy.go:5`); high → random.
  - **FANCI lexical features**: label length, vowel ratio, consonant ratio, max consecutive consonants, digit ratio, % unique characters.
  - **n-gram normality** (Phoenix): mean log-probability of the label's bigrams under a **small embedded benign-bigram frequency table (~couple KB)** — low → DGA-like.
  - **distributional distance** (Yadav): KL-divergence (and/or Jaccard) of the label's bigram distribution vs that benign table.
  - Combine into a normalized `[0,1]` score via thresholds derived from those works; return the features that fired as `Reasons`. No deps, no I/O.
- `AnalyzeDGADomains(result *ScanResult)` — iterate `result.IOCs.Domains` (already triaged/allowlisted). For each over a tuned threshold, append a `DGADomain`. For high scorers add a finding via `AddFindingDetailed`: **Low** by default; **Medium** only for a very-high score on an unusual TLD (`.xyz/.top/.club/.tk/.pw/.cc` etc.). Tactic `Command and Control`, Technique `Dynamic Resolution: Domain Generation Algorithms (T1568.002)`.

### 2c. `scanner.go` wiring
Insert one line **after** `ClassifyMalwareFamiliesWithCorpus` (line 197) and **before** `AssessResearchArtifact` (214) / `FinalizeRisk` (215), so the research-artifact cap still applies to any DGA score:
```go
AnalyzeDGADomains(&result)
```
(PE intel needs no new wiring — it rides inside `AnalyzeFormats`, already sequenced before similarity at scanner.go:160.)

---

## Renderers — surface the new fields (follow the existing PE/similarity blocks)
- `report.go`: PE block at 518 → Security features / Missing mitigations / Image characteristics / TLS callbacks / Signature(status, signed, self-signed) + subjects/issuers / Entry-point line. Similarity block at 359 → Rich header hash. New "Algorithmically-generated domains" subsection from `result.DGADomains`.
- `pdf.go`: PE block at 431 (+ kv near 52) and similarity at 622 — mirror the above.
- `html.go`: PE block at 592 — mirror.
- `web_ui.go`: JSON-driven JS — add `kvRow`s in the PE render block and `sim.rich_header_hash` near 558; other new JSON fields flow through automatically.

---

## Tests — `scanner_test.go` (or new `pe_intel_test.go` / `dga_test.go`)
- `decodeDllCharacteristics`: known bitmasks → expected enabled/missing sets (e.g. `0x4140` ⇒ ASLR+CFG enabled, DEP missing).
- `decodeImageCharacteristics`: flag decoding.
- `computeRichHeaderHash`: deterministic stable hash on a hand-built synthetic DOS-stub fixture containing a `DanS … Rich` block; `""` when absent or `len(data) < 0x40`.
- `parseDERCertificates`: feed a known DER cert → subjects/issuers recovered, `selfSigned` correct; feed garbage → `ok=false`.
- `dgaScore`: benign (`google.com`, `microsoft.com`, `github.io`) score low; DGA-style (`kq3v9zlx7w2p.com`, `asdkfjqweoiru.net`) score high — assert ordering and that the threshold separates them.
- Finding gating: a `PEInfo` with **both** ASLR+DEP missing ⇒ exactly one `Low` "PE Posture" finding; only-some-missing ⇒ `Info` (score 0). Confirms Conservative behavior.

---

## Verification
1. `cd "/home/sudo3rs/Desktop/FlatScan/source go" && go build -o ../flatscan .` — clean build, zero deps (`go.mod`, in `source go/`, unchanged).
2. `go test ./...` — new tests pass; existing suite stays green (no regressions).
3. `go vet ./...` and `go test -race ./...` — PE intel writes only inside `analyzePE`; DGA writes after the `parallelRun` group → no new races.
4. Real PE smoke test:
   `./flatscan -f <some.exe> -m deep --report-mode Full --json - --no-progress --no-splash --no-color | jq '.pe.security_features, .pe.missing_mitigations, .pe.rich_header_hash, .pe.signature_status, .pe.has_tls_callbacks'`
   Cross-check against `pestudio`/known values where possible.
5. A Microsoft-signed system binary: confirm it gains **no** score from posture signals (Conservative) and shows `signed: true` with a real subject (or a clear "signer not recovered" status, never a crash).
6. A sample carrying a DGA-style C2 domain: confirm the `T1568.002` finding + `dga_domains` entry appear; confirm common domains do **not** false-positive.
7. `--pdf` / `--html`: eyeball the new PE Posture + Rich-hash + DGA sections.

## Out of scope (deliberate — later increment; see `Docs/research-gap-analysis-2026-06-07.md`)
Sandbox/dynamic-report (CAPE/Cuckoo) importer, canonical MITRE Mobile IDs on Android findings,
nearest-family-prototype scorer, byteplot/entropy image, CAPEC tags, **telfhash (ELF imphash analog)
and TLSH fuzzy hashing** (both deferred this increment). No ML/LLM/IR-lifting (conflicts with the
zero-dependency static-only design).
