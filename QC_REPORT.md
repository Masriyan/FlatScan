# FlatScan QA/QC Report

> **Historical record — not current status.** This is a cumulative audit log covering releases
> 0.3.0 through 0.7.0. Its figures (39 source files, 11,867 LOC, 12 tests) were accurate for the
> versions audited and are retained as a point-in-time record. For current numbers see the
> verification table in [README.md](README.md) and the Unreleased section of
> [changelog.md](changelog.md): as of 2026-08-13 the tree is 93 source files, ~22.9k non-test LOC,
> 176 tests, 50.3% coverage, and 0 `golangci-lint` issues.

**Last Updated**: 2026-06-07
**Current Version**: 0.7.0
**Scope**: Cumulative audit log — all releases from 0.3.0 through 0.7.0, including the 2026-06-07 malware-sample precision sweep

---

## Cumulative Status

| Release | Date | Build | Tests | Race | Vet | Open Issues |
|---------|------|-------|-------|------|-----|-------------|
| 0.3.0 | 2026-04-28 | ✅ | ✅ 12/12 | ✅ | ✅ | All fixed (see §7) |
| 0.4.0 | 2026-05-xx | ✅ | ✅ | ✅ | ✅ | None |
| 0.5.0 | 2026-05-26 | ✅ | ✅ | ✅ | ✅ | None |
| 0.6.0 | 2026-06-06 | ✅ | ⚠️ 1 pre-existing fail | ✅ (race fixed) | ✅ | Scanner data race **fixed** (0.6-PRE-1); `TestRenderHTMLReport` drift still open (see §v0.6.0) |
| 0.7.0 | 2026-06-07 | ✅ | ✅ 23/23 | ✅ | ✅ | All prior issues **resolved** |

---

## v0.3.0 Audit (2026-04-28)

**Scope**: 39 Go source files, 11,867 LOC

### Executive Summary

FlatScan is in **good overall shape** with 12 tests passing, clean race detection, and clean `go vet`. However, the audit found **3 bugs**, **4 code quality issues**, and **3 enhancement recommendations**.

| Category | 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low |
|----------|-------------|---------|-----------|--------|
| **Bugs** | 1 | 1 | 1 | 0 |
| **Code Quality** | 0 | 0 | 2 | 2 |
| **Recommendations** | 0 | 0 | 1 | 2 |

### 1. Build & Test Results ✅

| Check | Result |
|-------|--------|
| `go build` | ✅ Clean |
| `go vet` | ✅ No warnings |
| `go test -v` | ✅ 12/12 pass (0.010s) |
| `go test -race` | ✅ No data races (1.042s) |
| `gofmt` | ✅ No formatting issues |

### 2. Bugs Found

#### BUG-1: 🔴 JSON stdout (`--json -`) emits text report before JSON (CRITICAL)

**File**: `main.go:138-155`

**Problem**: When `--json -` is used without `--report`, the text report is printed to stdout first (line 146), then the JSON (line 155). This makes the JSON output unparseable — piping to `jq` fails:

```bash
./flatscan -f sample.bin --json - | jq  # FAILS: "Expecting value"
```

**Root Cause**: Line 145 `else { fmt.Print(report) }` runs unconditionally before the JSON check at line 149.

**Fix**: Suppress text stdout output when `--json -` is active.

**Impact**: JSON scripting pipeline completely broken.

---

#### BUG-2: 🟠 Version constant still says `0.2.0` (HIGH)

**File**: `main.go:14`

**Problem**: `const defaultVersion = "0.2.0"` — should be `"0.3.0"` after the architecture release.

**Impact**: All output (reports, JSON, STIX, PDF, help text) shows wrong version. Misleading for analysts.

---

#### BUG-3: 🟡 Logger `WithPrefix` shares `entries` slice (MEDIUM)

**File**: `logger.go:47-54`

**Problem**: `WithPrefix()` copies the slice header but not the backing array. If the parent and child loggers both append, they can corrupt each other's entries. Currently `WithPrefix` is not called in the codebase, so this is latent.

**Fix**: Use a `*[]LogEntry` pointer or always copy entries.

---

### 3. Code Quality Issues

#### CQ-1: 🟡 Logger double-locks mutex in `log()` method

**File**: `logger.go:125-133`

**Problem**: The `log()` method acquires the mutex at line 125 to append to entries, releases it, then acquires it again at line 130 to write to output. Between the two locks, another goroutine could interleave. This should be a single critical section.

---

#### CQ-2: 🟡 STIX verdictResult maps 10-54 as "benign" (INCORRECT)

**File**: `stix.go:160-167`

**Problem**: Scores 10-54 are mapped as `"benign"` in the STIX verdict, but FlatScan's own scoring calls 10-29 "Low suspicion" and 30-54 "Suspicious". A score of 45 should not produce a STIX result of "benign".

---

#### CQ-3: 🟢 Cache silently drops errors on write

**File**: `cache.go:86`

**Problem**: `_ = os.WriteFile(path, data, 0o644)` — if the cache write fails (disk full, permission denied), the error is silently ignored. Acceptable for a cache but should at least log.

---

#### CQ-4: 🟢 Watch mode: SHA256 slice access without bounds check

**File**: `watch.go:141`

**Problem**: `result.Hashes.SHA256[:16]` — if SHA256 is empty (e.g., read error), this panics with index out of range. Should guard against empty hash.

---

### 4. Enhancement Recommendations

#### REC-1: 🟡 Test coverage is minimal (12 tests for 11,867 LOC)

**Current coverage**: ~2.6% of source lines. Key untested areas: Watch mode, Batch mode, Plugin system, Cache module, STIX export, Logger, Parallel pipeline, mmap path.

#### REC-2: 🟢 Missing `--watch` validation error message is unclear

When running `./flatscan --watch` without `--dir`, the error doesn't tell the user that `--watch` requires `--dir`.

#### REC-3: 🟢 Interactive mode doesn't mention STIX in output profile options

---

### 5. Security Audit

| Check | Result |
|-------|--------|
| **No sample execution** | ✅ Verified — static analysis only |
| **Panic recovery** | ✅ `recover()` in `main.go` and `interactive.go` |
| **No network calls** | ✅ No outbound network in default mode |
| **Path traversal** | ✅ Carving reports offsets only, no disk extraction |
| **Memory limits** | ✅ `MaxAnalyzeBytes` cap (256MB default) |
| **Archive bomb protection** | ✅ `MaxArchiveFiles` (500), `MaxCarves` (80) |
| **Input sanitization** | ✅ STIX patterns escaped via `escapeSTIXPattern()` |
| **Thread safety** | ✅ Race detector clean, `findingsMu` on append |
| **Cache injection** | ✅ SHA256-keyed paths, no user-controlled filenames |

---

### 6. Performance Audit

| Component | Status | Notes |
|-----------|--------|-------|
| **Corpus caching** | ✅ Optimal | Single build shared across 5 consumers |
| **Incremental entropy** | ✅ Optimal | O(step) sliding window |
| **Zero-alloc strings** | ✅ Optimal | Byte-slice indexing |
| **Parallel pipeline** | ✅ Optimal | 4 concurrent goroutines, race-clean |
| **mmap** | ✅ Works | Linux only, transparent fallback |
| **XOR buffer** | ✅ Optimal | Single reused buffer |
| **Plugin registry** | ✅ OK | Linear scan, few plugins |
| **Cache I/O** | ⚠️ Acceptable | Per-entry JSON files, could use single DB for scale |
| **Batch scan** | ⚠️ Sequential | Not yet parallelized (addressed in 0.5.0) |

---

### 7. Fix Priority — v0.3.0

| ID | Severity | Issue | Status |
|----|----------|-------|--------|
| BUG-1 | 🔴 Critical | JSON stdout broken | ✅ **Fixed** — suppress text when `--json -` active |
| BUG-2 | 🟠 High | Version 0.2.0 | ✅ **Fixed** — updated to `0.3.0` |
| CQ-2 | 🟡 Medium | STIX benign mapping | ✅ **Fixed** — 30-79 now maps to `suspicious` |
| CQ-1 | 🟡 Medium | Logger double-lock | ✅ **Fixed** — single lock/unlock block |
| BUG-3 | 🟡 Medium | WithPrefix slice share | ✅ **Fixed** — independent entry list |
| CQ-4 | 🟢 Low | Watch SHA256 bounds | ✅ **Fixed** — bounds check added |
| CQ-3 | 🟢 Low | Cache error logging | Deferred (acceptable for cache) |
| REC-1 | 🟡 Medium | Test coverage | Ongoing |
| REC-2 | 🟢 Low | Watch error message | Deferred |
| REC-3 | 🟢 Low | Interactive STIX mention | Deferred |

---

## v0.4.0 QA (2026-05-xx)

**New in 0.4.0**: Shell completion (bash/zsh/fish), grouped help with examples, post-scan contextual hints, dark analyst HTML report with SVG risk gauge, PDF badge improvements, batch Size column, ANSI color helpers refactor.

### Build & Test Results

| Check | Result |
|-------|--------|
| `go build` | ✅ Clean |
| `go vet` | ✅ No warnings |
| `go test -v` | ✅ Pass |
| `go test -race` | ✅ No data races |
| `gofmt` | ✅ No formatting issues |

### New Files Audited

| File | Purpose | Notes |
|------|---------|-------|
| `completion.go` | bash/zsh/fish completion scripts | No dynamic evaluation, static strings only |
| `hints.go` | Post-scan contextual tips | Reads `ScanResult` only, no side effects |
| `color.go` | ANSI color helpers, dark HTML theme | Correctly gates on `colorEnabled()` |

### Feature Verification

| Feature | Result |
|---------|--------|
| Shell completion output (bash) | ✅ Valid bash completion script |
| Shell completion output (zsh) | ✅ Valid zsh `_arguments` spec |
| Shell completion output (fish) | ✅ Valid fish `complete` commands |
| HTML dark theme renders | ✅ Dark background, correct SVG gauge |
| Hints suppressed when `--json -` active | ✅ Gate correct |
| Hints suppressed in non-interactive mode | ✅ Gate correct |
| PDF badge CISO layout | ✅ Badge aligned, no overlap |
| Batch Size column | ✅ `formatBytes` renders correctly |

### Issues Found

None. 0.4.0 is clean.

---

## v0.5.0 QA (2026-05-26)

**New in 0.5.0**: API behavioral chain detection (`chains.go`), packer/protector fingerprinting (`packer.go`), extended IOC types (Ethereum/Monero/Bitcoin wallets, mutex names, named pipes), wiper family detection, cryptominer family detection, entropy FP mitigation for compressed formats, `ScoreBreakdown` per-category scoring, `--ci`/`--ci-threshold` CI/CD mode, `--output-format csv|jsonl`, `--batch-json`, `--watch-alert-only`, parallel batch worker pool, HTML global search bar.

### Build & Test Results

| Check | Result |
|-------|--------|
| `go build` | ✅ Clean |
| `go vet` | ✅ No warnings |
| `go test -v` | ✅ Pass |
| `go test -race` | ✅ No data races |
| `gofmt` | ✅ No formatting issues |

### New Files Audited

| File | Purpose | Security Notes |
|------|---------|---------------|
| `chains.go` | API behavioral chain detection | Read-only over `ScanResult.Functions`; no external I/O |
| `packer.go` | Packer/protector fingerprinting | Reads PE section names and overlay bytes only; defines local `min()` which shadows Go 1.21 builtin (harmless) |

### Feature Verification

| Feature | Test | Result |
|---------|------|--------|
| CI mode exit code — malicious | `./flatscan -f mercuristealer --ci --no-splash; echo $?` | ✅ exit 20 |
| CI mode exit code — clean | `./flatscan -f /etc/hostname --ci --no-splash; echo $?` | ✅ exit 0 |
| CI mode one-liner stderr | Output contains `FLATSCAN: MALICIOUS score=100` | ✅ |
| Semantic exit codes (non-CI) | score ≥ 80 → exit 20; score < 30 → exit 0 | ✅ |
| Parallel batch (NumCPU workers) | 5-file batch, CPU usage ~148% | ✅ |
| Batch JSON summary | `--batch-json /tmp/batch.json` writes valid JSON | ✅ |
| JSONL output | `--output-format jsonl` writes one JSON object per file to stdout | ✅ |
| CSV output | `--output-format csv` writes `file,score,verdict,findings,iocs,sha256` | ✅ |
| Hints suppressed with non-text format | `--output-format jsonl` suppresses hints | ✅ |
| Wiper detection | Input with shadow copy strings → `[High] Wiper` finding | ✅ |
| Cryptominer detection | Input with `stratum+tcp`, `xmrig` → `[High] Cryptominer` finding | ✅ |
| Entropy FP mitigation | `.zip` file no longer generates global entropy finding | ✅ |
| Score breakdown in terminal report | Header shows `Score breakdown: [Category:N ...]` | ✅ |
| Score breakdown in JSON | `score_breakdown` field present in JSON output | ✅ |
| Ethereum wallet IOC extraction | `0x<40-hex>` strings extracted to `iocs.crypto_wallets` | ✅ |
| Mutex IOC extraction | `Global\<name>` strings extracted to `iocs.mutexes` | ✅ |
| Named pipe IOC extraction | `\\.\pipe\<name>` strings extracted to `iocs.named_pipes` | ✅ |
| HTML global search | `globalSearch()` filters `.finding-card` and `.ioc-row` elements | ✅ |
| HTML new IOC tabs | Mutexes / Named Pipes / Crypto Wallets tabs render | ✅ |
| Packer detection (UPX) | Section names `UPX0`/`UPX1` → `[High] Packing: UPX` finding | ✅ |
| `--watch-alert-only` | Clean files skipped silently; rolling status line updated | ✅ |

### Issues Found

| ID | Severity | Issue | Status |
|----|----------|-------|--------|
| 0.5-NON-1 | Info | `min()` in `packer.go` shadows Go 1.21 builtin | Not an issue — compiles and runs correctly; no action needed |
| 0.5-NON-2 | Info | API chains do not fire on .NET PE samples | Expected — .NET PE hides native import tables; chains require explicit API imports |

No blocking issues. 0.5.0 is clean.

### Performance Audit — v0.5.0

| Component | Status | Notes |
|-----------|--------|-------|
| **Corpus caching** | ✅ Optimal | Single build shared across all consumers |
| **Incremental entropy** | ✅ Optimal | O(step) sliding window unchanged |
| **Parallel pipeline** | ✅ Optimal | Race-clean |
| **Batch scan** | ✅ Optimal | Worker pool = `runtime.NumCPU()`; semaphore limits goroutine burst |
| **Chain detection** | ✅ Optimal | O(chains × families) — small fixed set, negligible overhead |
| **Packer detection** | ✅ Optimal | O(sections × signatures) — PE-only, no overhead for ELF/APK |
| **IOC regex** | ✅ Acceptable | 5 new compiled regexes added; all pre-compiled at package init |
| **mmap** | ✅ Works | Linux only, transparent fallback |
| **Cache I/O** | ⚠️ Acceptable | Per-entry JSON files; no version key (stale results possible after upgrade) — tracked for 0.6.0 |

### Security Audit — v0.5.0

| Check | Result |
|-------|--------|
| **No sample execution** | ✅ Verified — static analysis only |
| **Panic recovery** | ✅ Unchanged from 0.3.0 |
| **No network calls** | ✅ No outbound network |
| **New file writes** | ✅ `--batch-json` writes only to user-specified path with `0o644` permissions |
| **JSONL/CSV stdout** | ✅ No secrets or credentials emitted beyond what JSON already exposes |
| **Worker pool goroutines** | ✅ Race-clean; bounded by semaphore; results written under mutex |
| **New IOC regex** | ✅ All pre-compiled; no user-controlled regex patterns |

---

## v0.6.0 QA (2026-06-06)

**New in 0.6.0**: self-contained local web GUI (`--web`, `--web-port`). Two new files — `web.go` (HTTP server, async scan jobs, four API endpoints) and `web_ui.go` (embedded single-page UI as a Go string constant). Zero new external dependencies. `main.go` gained two `Config` fields, two flags, a dispatch branch, a `--web` carve-out in the no-target check, and a `WEB` help section. Version bumped 0.5.0 → 0.6.0.

### Build & Test Results

| Check | Result |
|-------|--------|
| `go build` | ✅ Clean |
| `go vet` | ✅ No warnings |
| `gofmt` | ✅ `web.go` / `web_ui.go` clean |
| `node --check` (embedded JS) | ✅ Valid ES2020; no stray `</script>`; tags balanced |
| `go test` | ⚠️ Pass **except** `TestRenderHTMLReport` (pre-existing, see Issues) |
| `go build -race` (full scan) | ✅ Race-clean after the 0.6-PRE-1 fix (CLI + web; multiple file types) |

### New Files Audited

| File | Purpose | Security Notes |
|------|---------|---------------|
| `web.go` | `--web` HTTP server, scan-job map, upload/result/download handlers, on-the-fly report-pack zip | Binds `127.0.0.1` only; no auth (by design, warned at startup); all `jobs` access guarded by `sync.RWMutex`; per-job `os.MkdirTemp` isolation; 30-min reaper; `safeFileName` strips traversal/control/quote chars; 256 MB `MaxBytesReader` cap; multipart spill cleaned via `RemoveAll`; per-scan `recover()`; `nosniff` on every response; no CORS |
| `web_ui.go` | Embedded single-page UI (`webUIHTML` raw-string constant) | Static asset only; all dynamic values HTML-escaped client-side; no external CDN/fonts/npm; no backticks (JS uses string concatenation) |

### Feature Verification

| Feature | Test | Result |
|---------|------|--------|
| Startup banner | 3 lines incl. no-auth warning + listening URL | ✅ |
| `GET /` | Serves embedded HTML, `Content-Type: text/html`, `nosniff` | ✅ |
| `POST /api/scan` | Returns `202 {"job_id":...}` | ✅ |
| Poll lifecycle | `202 scanning` → `200 done` with full `ScanResult` + `available_downloads` | ✅ |
| Rich result | ELF binary deep scan → score 100, 38 findings, 53 functions, `pe:null` | ✅ |
| Downloads | All 7 formats (`json·txt·iocs·yar·yml·stix·pack`) stream with correct `Content-Type`/`Content-Disposition` | ✅ |
| Report-pack zip | `pack` format returns a valid zip of the full pack | ✅ |
| Error paths | no file → 400; wrong method → 405; bad job/format → 404; all JSON | ✅ |
| Path traversal | `../../../etc/evil..passwd` → stored as `evilpasswd` inside temp dir | ✅ |
| Header injection | filename with `"` → well-formed `Content-Disposition` | ✅ |
| Concurrency | 5–8 simultaneous scans + downloads all succeed | ✅ |
| `web.go` race safety | race detector clean for `web.go` under concurrent read/write hammering | ✅ |

### Issues Found

| ID | Severity | Issue | Status |
|----|----------|-------|--------|
| 0.6-WEB-1 | 🟡 Medium | `safeFileName` did not strip quotes/control chars → `Content-Disposition` header-injection risk | ✅ Fixed — now strips control chars, `"`, `/`, leading dots |
| 0.6-WEB-2 | 🟢 Low | Multipart spill temp files were not cleaned up | ✅ Fixed — `defer r.MultipartForm.RemoveAll()` in `handleScan` |
| 0.6-PRE-1 | 🔴 High | **Pre-existing data race** in core scanner: `parallelRun` ran `AnalyzeFormats`, `ExtractCryptoAndConfigWithCorpus`, and `BuildSimilarityInfo` concurrently on shared `*ScanResult` state. `BuildSimilarityInfo` also copied the whole `*result` (`importSimilarityHash(*result)`/`sectionSimilarityHash(*result)`), reading every field while others wrote `PE`/`ELF`/`MachO`/`ConfigArtifacts`/`Plugins`. Fired on a full scan via **both CLI and web** (the v0.5.0 race check missed it — the test suite did not exercise the racy path). **Not introduced by the web GUI.** | ✅ **Fixed** — pipeline reordered to respect data deps (formats → `carve ∥ similarity` → crypto/config); similarity hashers take `*ScanResult` (no whole-struct copy); concurrent `Plugins` appends routed through guarded `appendPlugin`. Verified race-clean (`go test -race`, multi-type `go build -race` scans) + new `TestScanFileParallelPipelineRaceFree`. |
| 0.6-PRE-2 | 🟢 Low | `TestRenderHTMLReport` expects `"FlatScan Malware Analysis Report"`, which only `pdf.go` emits; `html.go` uses a different title. Test/code drift, pre-existing. | Open — tracked for 0.7.0 |

### Security Audit — v0.6.0

| Check | Result |
|-------|--------|
| **No sample execution** | ✅ Web mode runs the same static engine; no execution |
| **No outbound network** | ✅ Loopback HTTP only; no external calls |
| **Bind scope** | ✅ `127.0.0.1` only (not `0.0.0.0`) |
| **Authentication** | ⚠️ None by design — documented and warned; localhost-only |
| **Writes stay in temp dir** | ✅ Per-job `os.MkdirTemp`; HTML/PDF/case writes disabled in web mode |
| **Filename safety** | ✅ Traversal, control chars, and quotes stripped |
| **Upload cap** | ✅ 256 MB via `MaxBytesReader`; spill files removed |
| **Concurrency safety (web)** | ✅ `jobs` map fully guarded by `RWMutex`; race-clean |

---

## v0.7.0 QA (2026-06-07)

**New in 0.7.0**: PE Header Intelligence (`pe_intel.go` — DllCharacteristics/exploit-mitigation posture, Rich-header hash, TLS callbacks, Authenticode signer, entry-point sanity), DGA domain scorer (`dga.go` — lexical model, Shannon entropy, n-gram normality, bigram distance), .NET managed-code detection (`dotnet.go` — reflective loading, P/Invoke injection, obfuscator fingerprints), detection-artifact false-positive guard (`falsepositive.go` — multi-archetype catalog recognition, score capping), PDF Unicode rendering fix, HTML & PDF downloads in web mode, archive payload finding aggregation. Version bumped 0.6.0 → 0.7.0. Four new source files, two new test files. All prior open issues resolved.

### Build & Test Results

| Check | Result |
|-------|--------|
| `go build` | ✅ Clean |
| `go vet` | ✅ No warnings |
| `gofmt` | ✅ All new files clean |
| `go test` | ✅ **23/23 pass** (including previously-failing `TestRenderHTMLReport`) |
| `go test -race` | ✅ Race-clean (pipeline reorder from 0.6.0 verified; new parallel stages safe) |

### New Files Audited

| File | Purpose | Security Notes |
|------|---------|----------------|
| `pe_intel.go` | PE Header Intelligence: DllCharacteristics decoder, Rich-header XOR decode, TLS callback detection, Authenticode certificate recovery, entry-point sanity check | Read-only byte parsing; `recoverAuthenticodeCerts` is truncation-safe (checks `data` length before slicing); no new allocations in hot path |
| `pe_intel_test.go` | Unit tests for `decodeDllCharacteristics`, Rich-header hash, TLS detection, entry-point anomaly | Test-only |
| `dga.go` | DGA domain scorer: Shannon entropy, FANCI features, Phoenix n-gram normality, Yadav bigram distance | Pure function on extracted domains; no regex DoS risk; conservative scoring (Medium only for very-high score on abused TLD) |
| `dga_test.go` | Unit tests for DGA scorer | Test-only |
| `dotnet.go` | .NET managed-code detection: reflective loading, P/Invoke injection, obfuscator fingerprints | Substring matching on existing string corpus; gated to `result.PE.IsManaged`; requires evidence combinations (no single-string trigger) |
| `falsepositive.go` | Detection-artifact recognizer: multi-archetype catalog detection, score capping to Low tier | Read-only analysis of existing findings; caps score but preserves raw findings/breakdown; `benign_context` field for transparency |

### Feature Verification

| Feature | Test | Result |
|---------|------|--------|
| PE mitigation posture | Scan PE with known ASLR+DEP flags | ✅ `security_features` and `missing_mitigations` populated correctly |
| Rich-header hash | Scan PE with Rich header | ✅ Hash matches expected value; added to `SimilarityInfo` |
| TLS callbacks | Scan PE with TLS directory | ✅ `has_tls_callbacks` and `tls_callback_count` detected |
| Authenticode signer | Scan signed PE | ✅ `certificate_subjects`, `certificate_issuers`, `signed`, `signature_status` populated |
| Entry-point sanity | Scan packed PE with EP in writable section | ✅ `entry_point_anomaly` fires, finding generated |
| DGA domain scoring | Domains extracted from C2 sample | ✅ Algorithmic domains scored High; legitimate domains pass |
| .NET reflective loader | Packed .NET dropper sample | ✅ Score 75→97 via precise Loader finding |
| .NET obfuscator detection | ConfuserEx-protected sample | ✅ Obfuscator fingerprint detected |
| False-positive guard | FlatScan's own ELF binary | ✅ Score 100→20 with `benign_context` annotation |
| Archive payload rollup | APK with 13+ embedded executables | ✅ Findings capped at 6+1 rollup (13→7), verdict unchanged |
| PDF Unicode fix | Report with em-dashes, curly quotes | ✅ Renders legible ASCII equivalents instead of `?` |
| HTML/PDF web downloads | `--web` mode download tab | ✅ `html` and `pdf` formats available in `available_downloads` |
| TestRenderHTMLReport | `go test -run TestRenderHTMLReport` | ✅ Pass — title updated to `FlatScan Malware Analysis Report — <file>` |

### Issues Resolved from 0.6.0

| ID | Severity | Issue | Resolution |
|----|----------|-------|------------|
| 0.6-PRE-2 | 🟢 Low | `TestRenderHTMLReport` title drift | ✅ Fixed — `<title>` is now `FlatScan Malware Analysis Report — <file>`, test updated to match |
| REC-4 | 🟡 Medium | .NET recall gap — managed PEs scored low | ✅ Fixed — `dotnet.go` adds .NET-specific behavioral detection |
| REC-5 | 🟢 Low | Archive payload finding noise | ✅ Fixed — `maxArchivePayloadFindings` rollup in `formats.go` |

### Security Audit — v0.7.0

| Check | Result |
|-------|--------|
| **No sample execution** | ✅ All new modules are read-only byte parsers |
| **No outbound network** | ✅ No new network activity |
| **No new dependencies** | ✅ `go.mod` unchanged; all new code uses stdlib only |
| **Conservative scoring** | ✅ PE mitigations are Info/Low; DGA is Medium only for very-high scores on abused TLDs; .NET requires evidence combinations |
| **Truncation safety** | ✅ `recoverAuthenticodeCerts` checks `data` length before slicing (handles `TruncatedAnalysis`) |
| **False-positive guard** | ✅ Preserves raw findings and score breakdown; only caps final score; `benign_context` field for audit trail |
| **Race safety** | ✅ New fields written in sequential pipeline stages; no new concurrent access patterns |

---

## Open Items (tracked for 0.8.0)

| ID | Severity | Description |
|----|----------|-------------|
| 0.6-PRE-2 | ✅ Fixed in 0.7.0 | `TestRenderHTMLReport` drift — `<title>` now `FlatScan Malware Analysis Report — <file>`, test updated |
| CQ-3 | 🟢 Low | Cache silently drops write errors — add debug log |
| REC-1 | 🟡 Medium | Test coverage remains low (~2.6%) — add unit tests for cache, STIX, chains, packer, and the web handlers |
| CACHE-VER | 🟢 Low | Cache has no version key — stale results possible after upgrades |
| REC-2 | 🟢 Low | `--watch` without `--dir` gives a generic error message |
| REC-3 | 🟢 Low | Interactive mode doesn't mention STIX in output profile list |
| REC-4 | ✅ Fixed in 0.7.0 | **.NET recall gap** — addressed by `dotnet.go` (`AnalyzeDotNet`); see Precision Sweep follow-ups |
| REC-5 | ✅ Fixed in 0.7.0 | Archive payload-finding noise — addressed by `maxArchivePayloadFindings` rollup in `formats.go` |

---

## Precision Sweep (2026-06-07)

**Scope**: 6 real samples scanned in `--mode deep --carve` — Android loader APK, two stealers (one .NET), a packed .NET dropper, an x64 banker DLL, plus FlatScan's own ELF as a benign control.

### Key finding: false positive on detection/analysis artifacts 🔴 → ✅ Fixed

FlatScan's detection is substring-based over the file's string corpus. Any file that *contains* malware indicators as data — an AV signature set, a YARA/Sigma rule pack, a sandbox, a threat-intel feed, an analysis tool (**FlatScan's own binary**), or an incident report — matched every signature and scored 100/"Likely malicious".

**Fix** (`falsepositive.go` + `FinalizeRisk`): `AssessResearchArtifact` recognizes the catalog signature — headline strings for many *mutually-exclusive* archetypes present at once (ransomware + cryptominer + wiper + credential-dump + Discord-stealer + webshell). Trigger: ≥4 disjoint archetypes, or ≥3 plus security-tooling/MITRE markers. On trigger it annotates the verdict, records a `benign_context` block, and caps the score at the "Low suspicion" tier (20). Raw findings/breakdown preserved.

### Before / after

| Sample | Type | Before | After | Note |
|--------|------|--------|-------|------|
| `flatscan` (control) | ELF | **100 Likely malicious** | **20 Low suspicion (artifact)** | ✅ FP corrected — 5 archetypes, 8 tool markers |
| APK loader | APK | 100 Likely malicious | 100 Likely malicious | ✅ unchanged TP |
| stealer | PE .NET | 100 Likely malicious | 100 Likely malicious | ✅ unchanged TP |
| unknown | PE x64 | 100 Likely malicious | 100 Likely malicious | ✅ unchanged TP |
| packed .NET | PE .NET | 75 High suspicion | **97 Likely malicious** | ✅ recall fix — `.NET` reflective-loader detection (REC-4) |
| banker | PE x64 DLL | 34 Suspicious | 34 Suspicious | ✅ unchanged |

Zero true-positive regression; the control was corrected and the .NET loader was promoted from a vague "packed" verdict to a precise loader detection. Regression tests added: `TestResearchArtifactCapsScore`, `TestFocusedSampleNotFlaggedAsArtifact`, `TestDotNetReflectiveLoaderDetected`, `TestDotNetGuardsNonManagedAndBenign`, `TestArchivePayloadFindingsAggregated`.

### Follow-up fixes (same sweep)

- **REC-4 — .NET recall (`dotnet.go`)**: managed PEs have no native import table, so native signatures/chains rarely fired. `AnalyzeDotNet` adds .NET-specific detection (reflective in-memory loading, managed P/Invoke injection, obfuscator fingerprints), gated to managed binaries and requiring evidence combinations to avoid false positives on ordinary .NET apps. Lifted the packed .NET loader 75 → 97.
- **REC-5 — archive finding noise (`formats.go`)**: "Executable payload inside archive" findings are now capped at `maxArchivePayloadFindings` (6) with a single rollup for the rest. The malicious APK's container findings dropped 13 → 7 with no verdict change.

### Boundary checks (other artifacts in the sample set)

| Input | Score | Flagged as artifact? | Assessment |
|-------|-------|----------------------|------------|
| `embargo.yar` (single-family YARA rule) | 14 | No (1 archetype) | ✅ correct — not a multi-archetype catalog |
| prior `banker.report.json` | 17 | No | ✅ low, fine |
| `embargo-ransom.html` (ransom note) | 66 | No (1 archetype) | Defensible — genuinely contains ransomware content |
