# FlatScan QA/QC Report

**Last Updated**: 2026-05-26
**Current Version**: 0.5.0
**Scope**: Cumulative audit log — all releases from 0.3.0 through 0.5.0

---

## Cumulative Status

| Release | Date | Build | Tests | Race | Vet | Open Issues |
|---------|------|-------|-------|------|-----|-------------|
| 0.3.0 | 2026-04-28 | ✅ | ✅ 12/12 | ✅ | ✅ | All fixed (see §7) |
| 0.4.0 | 2026-05-xx | ✅ | ✅ | ✅ | ✅ | None |
| 0.5.0 | 2026-05-26 | ✅ | ✅ | ✅ | ✅ | None |

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

## Open Items (tracked for 0.6.0)

| ID | Severity | Description |
|----|----------|-------------|
| CQ-3 | 🟢 Low | Cache silently drops write errors — add debug log |
| REC-1 | 🟡 Medium | Test coverage remains low (~2.6%) — add unit tests for cache, STIX, chains, packer |
| CACHE-VER | 🟢 Low | Cache has no version key — stale results possible after upgrades |
| REC-2 | 🟢 Low | `--watch` without `--dir` gives a generic error message |
| REC-3 | 🟢 Low | Interactive mode doesn't mention STIX in output profile list |
