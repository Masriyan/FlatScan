# FlatScan QA/QC Report

**Date**: 2026-04-28  
**Version**: 0.3.0  
**Scope**: Full codebase audit — 39 Go source files, 11,867 LOC

---

## Executive Summary

FlatScan is in **good overall shape** with 12 tests passing, clean race detection, and clean `go vet`. However, the audit found **3 bugs**, **4 code quality issues**, and **3 enhancement recommendations**.

| Category | 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low |
|----------|-------------|---------|-----------|--------|
| **Bugs** | 1 | 1 | 1 | 0 |
| **Code Quality** | 0 | 0 | 2 | 2 |
| **Recommendations** | 0 | 0 | 1 | 2 |

---

## 1. Build & Test Results ✅

| Check | Result |
|-------|--------|
| `go build` | ✅ Clean |
| `go vet` | ✅ No warnings |
| `go test -v` | ✅ 12/12 pass (0.010s) |
| `go test -race` | ✅ No data races (1.042s) |
| `gofmt` | ✅ No formatting issues |

---

## 2. Bugs Found

### BUG-1: 🔴 JSON stdout (`--json -`) emits text report before JSON (CRITICAL)

**File**: [main.go:138-155](file:///home/sudo3rs/Documents/PrivateTools/FlatScan/main.go#L138-L155)

**Problem**: When `--json -` is used without `--report`, the text report is printed to stdout first (line 146), then the JSON (line 155). This makes the JSON output unparseable — piping to `jq` fails:

```bash
./flatscan -f sample.bin --json - | jq  # FAILS: "Expecting value"
```

**Root Cause**: Line 145 `else { fmt.Print(report) }` runs unconditionally before the JSON check at line 149.

**Fix**: Suppress text stdout output when `--json -` is active.

**Impact**: JSON scripting pipeline completely broken.

---

### BUG-2: 🟠 Version constant still says `0.2.0` (HIGH)

**File**: [main.go:14](file:///home/sudo3rs/Documents/PrivateTools/FlatScan/main.go#L14)

**Problem**: `const defaultVersion = "0.2.0"` — should be `"0.3.0"` after the architecture release.

**Impact**: All output (reports, JSON, STIX, PDF, help text) shows wrong version. Misleading for analysts.

---

### BUG-3: 🟡 Logger `WithPrefix` shares `entries` slice (MEDIUM)

**File**: [logger.go:47-54](file:///home/sudo3rs/Documents/PrivateTools/FlatScan/logger.go#L47-L54)

**Problem**: `WithPrefix()` copies the slice header but not the backing array. If the parent and child loggers both append, they can corrupt each other's entries. Currently `WithPrefix` is not called in the codebase, so this is latent.

**Fix**: Use a `*[]LogEntry` pointer or always copy entries.

---

## 3. Code Quality Issues

### CQ-1: 🟡 Logger double-locks mutex in `log()` method

**File**: [logger.go:125-133](file:///home/sudo3rs/Documents/PrivateTools/FlatScan/logger.go#L125-L133)

**Problem**: The `log()` method acquires the mutex at line 125 to append to entries, releases it, then acquires it again at line 130 to write to output. Between the two locks, another goroutine could interleave. This should be a single critical section.

```go
l.mu.Lock()
l.entries = append(l.entries, entry)  // lock 1
l.mu.Unlock()

if l.out != nil {
    l.mu.Lock()                        // lock 2 — gap between!
    fmt.Fprintf(l.out, ...)
    l.mu.Unlock()
}
```

---

### CQ-2: 🟡 STIX verdictResult maps 10-54 as "benign" (INCORRECT)

**File**: [stix.go:160-167](file:///home/sudo3rs/Documents/PrivateTools/FlatScan/stix.go#L160-L167)

**Problem**: Scores 10-54 are mapped as `"benign"` in the STIX verdict, but FlatScan's own scoring calls 10-29 "Low suspicion" and 30-54 "Suspicious". A score of 45 should not produce a STIX result of "benign".

**Fix**: Map scores to STIX result values correctly.

---

### CQ-3: 🟢 Cache silently drops errors on write

**File**: [cache.go:86](file:///home/sudo3rs/Documents/PrivateTools/FlatScan/cache.go#L86)

**Problem**: `_ = os.WriteFile(path, data, 0o644)` — if the cache write fails (disk full, permission denied), the error is silently ignored. This is acceptable for a cache but should at least log.

---

### CQ-4: 🟢 Watch mode: SHA256 slice access without bounds check

**File**: [watch.go:141](file:///home/sudo3rs/Documents/PrivateTools/FlatScan/watch.go#L141)

**Problem**: `result.Hashes.SHA256[:16]` — if SHA256 is empty (e.g., read error), this panics with index out of range. Should guard against empty hash.

---

## 4. Enhancement Recommendations

### REC-1: 🟡 Test coverage is minimal (12 tests for 11,867 LOC)

**Current coverage**: ~2.6% of source lines have dedicated tests. Key untested areas:
- Watch mode
- Batch mode
- Plugin system
- Cache module
- STIX export
- Logger
- Parallel pipeline
- mmap path

**Recommendation**: Add at least unit tests for cache Get/Put, STIX bundle structure, plugin ShouldRun/Run, and logger thread safety.

---

### REC-2: 🟢 Missing `--watch` validation error message is unclear

When running `./flatscan --watch` without `--dir`, the error is `"missing required -f/--file path or --dir path"` — it doesn't tell the user that `--watch` requires `--dir`.

---

### REC-3: 🟢 `--report-pack` should mention STIX in help text

The help text for `--report-pack` already includes STIX, but the interactive mode doesn't mention STIX in the output profile options.

---

## 5. Security Audit

| Check | Result |
|-------|--------|
| **No sample execution** | ✅ Verified — static analysis only |
| **Panic recovery** | ✅ `recover()` in main.go:107 and interactive.go:288 |
| **No network calls** | ✅ No outbound network in default mode |
| **Path traversal** | ✅ Carving reports offsets only, no disk extraction |
| **Memory limits** | ✅ `MaxAnalyzeBytes` cap (256MB default) |
| **Archive bomb protection** | ✅ `MaxArchiveFiles` (500), `MaxCarves` (80) |
| **Input sanitization** | ✅ STIX patterns escaped via `escapeSTIXPattern()` |
| **Thread safety** | ✅ Race detector clean, `findingsMu` on append |
| **Cache injection** | ✅ SHA256-keyed paths, no user-controlled filenames |

---

## 6. Performance Audit

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

---

## 7. Fix Priority

| ID | Severity | Issue | Status |
|----|----------|-------|--------|
| BUG-1 | 🔴 Critical | JSON stdout broken | ✅ **Fixed** — suppress text when `--json -` active |
| BUG-2 | 🟠 High | Version 0.2.0 | ✅ **Fixed** — updated to `0.3.0` |
| CQ-2 | 🟡 Medium | STIX benign mapping | ✅ **Fixed** — 30-79 now maps to `suspicious` |
| CQ-1 | 🟡 Medium | Logger double-lock | ✅ **Fixed** — single lock/unlock block |
| BUG-3 | 🟡 Medium | WithPrefix slice share | ✅ **Fixed** — independent entry list |
| CQ-4 | 🟢 Low | Watch SHA256 bounds | ✅ **Fixed** — bounds check added |
| CQ-3 | 🟢 Low | Cache error logging | Deferred (acceptable for cache) |
| REC-1 | 🟡 Medium | Test coverage | Separate PR |
| REC-2 | 🟢 Low | Watch error message | Deferred |
| REC-3 | 🟢 Low | Interactive STIX mention | Deferred |
