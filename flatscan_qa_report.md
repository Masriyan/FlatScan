# FlatScan QA / Hardening Report

**Date:** 2026-08-10
**Version audited:** 0.10.0
**Scope:** Full codebase audit — 61 Go source files, ~21,600 LOC, plus CLI UX and web UI/UX.

> This report supersedes the earlier `flatscan_qa_report.md` (v0.3.0, 39 files). It records
> a full re-audit of the current codebase and every fix applied in this pass. Every fix below
> was verified against real build/test/run output, not just code inspection.

---

## 1. Build & Test Baseline

| Check | Before | After |
|-------|--------|-------|
| `go build ./...` | clean | clean |
| `go vet ./...` | clean | clean |
| `gofmt -l .` | **14 files unformatted** | clean |
| `go test ./...` | 89 tests pass | pass (+ new regression tests) |
| `go test -race ./...` | clean | clean |
| Coverage | 42.0% | 42%+ (new CLI tests added) |

Go toolchain: 1.26.x (module targets go 1.25). Sole third-party dependency: `golang.org/x/arch`.

---

## 2. Bugs Found & Fixed

### 🔴 High severity

| ID | File | Problem | Fix |
|----|------|---------|-----|
| B1 | `batch.go` / `main.go` | Batch mode printed the **full per-file report to stdout** and the summary to stderr, so `flatscan --dir x > out.txt` captured concatenated per-file reports and *not* the summary. | Added a `Quiet` config flag; batch/watch set it to suppress per-file reports. The summary now goes to **stdout** (redirectable); per-file progress stays on stderr. |
| B2 | `batch.go` / `watch.go` | Color detection called `colorEnabled()` (which stats **stdout**) while every byte was written to **stderr** — colors leaked into redirected stderr and were wrongly suppressed when stderr was a TTY. | Both now use `stderrColorEnabled()`, which stats the stream actually written to. |
| B3 | `main.go` | Batch mode **ignored risk entirely** and always exited `0`; CI mode could **never return exit 20** (malicious). | Batch now returns the worst-file code (20/10/0); CI emits both 20 (>=80) and 10 (>=threshold). |
| B4 | `interactive.go` / `main.go` | Typing `--version` or `--completion` inside the interactive shell called `os.Exit` deep in `parseFlags`, **killing the whole shell process**. | `parseFlags` now returns sentinel errors (`errVersionRequested` / `errCompletionRequested`); `main()` exits cleanly, the shell catches them and keeps running. |
| B5 | `interactive.go` | Ctrl-D at the interactive menu returned an error → `"interactive mode failed: EOF"`, exit 1. | EOF at the menu is now a clean quit (exit 0), matching the shell. |

### 🟠 Medium severity

| ID | File | Problem | Fix |
|----|------|---------|-----|
| B6 | `main.go` | `--output-format csv` / `jsonl` **double-wrote stdout** when combined with `--json -`, producing unparseable mixed output (the `json` case already guarded against this; csv/jsonl did not). | Applied the same `JSONPath != "-"` guard to the csv and jsonl cases. |
| B7 | `main.go` | `--web-port` and `--watch-interval` were unvalidated: `--web-port 99999` was accepted and failed later with a raw socket error; `--watch-interval 0` was silently rewritten. | Both are now bounds-checked at parse time (port 1–65535, interval ≥ 1) **before** the web/interactive early-return. |
| B8 | `main.go` | Mode conflicts were silently resolved by flag order: `--web -f`, `--watch -f`, `--ci --interactive` discarded one flag without warning. | These combinations are now rejected with a clear message and exit 2. |
| B9 | `batch.go` | `truncStr` / `padRight` / `padLeft` sliced by **byte** (`s[:n]`), so a multibyte (UTF-8) filename could split mid-codepoint or panic. | Rewritten to be rune-aware (`[]rune`), safe on Cyrillic/emoji/CJK filenames. |
| B10 | `interactive.go` | A single typo in the guided wizard (`promptChoice` / `promptYesNo`) unwound the whole wizard, discarding every prior answer. | Both now re-prompt on invalid input instead of aborting. |

### 🟡 Low / consistency

| ID | Problem | Fix |
|----|---------|-----|
| B11 | 14 files failed `gofmt`. | All formatted. |
| B12 | Batch/watch error prints lacked the `error:` prefix used elsewhere. | Prefixed for consistency. |
| B13 | `--ci-threshold` semantics were unclear outside CI. | Documented; CI exit logic now honors it precisely. |

---

## 3. CLI UX Improvements

- **`--help` / `-h` now writes to STDOUT** (was stderr), so `flatscan --help | less` works. Help shown *as part of an error* still goes to stderr.
- **Did-you-mean suggestions**: an unknown flag now prints a single actionable line with the nearest known flag (Levenshtein) instead of dumping full help twice. Example: `--carv` → `did you mean --carve ?`.
- **New `-q` / `--quiet`**: suppresses report body, tips, splash, and progress while keeping the verdict — ideal for scripting and batch.
- **Shell completions synced**: added 10 flags that were missing from one or more of bash/zsh/fish (`--quiet`, `--ci`, `--ci-threshold`, `--output-format`, `--batch-json`, `--similarity-db`, `--intel-db`, `--watch-alert-only`, `--web`, `--web-port`) and `--resolve-depth` to fish. All three scripts validated.
- **Help completeness**: added a `LIMITS` section documenting the five previously-undocumented tuning flags (`--min-string`, `--max-analyze-bytes`, `--max-archive-files`, `--max-carves`, `--splash-seconds`), plus `--quiet` and `-h/--help`.

---

## 4. Web UI / Server Hardening

| Area | Before | After |
|------|--------|-------|
| HTTP timeouts | none (slowloris exposure) | `ReadHeaderTimeout` 10s, `ReadTimeout` 5m, `WriteTimeout` 10m, `IdleTimeout` 2m, `MaxHeaderBytes` 1MiB |
| Security headers | `X-Content-Type-Options` only | + strict `Content-Security-Policy`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` |
| Bind address | `127.0.0.1` (already correct) | unchanged, documented |
| Upload cap | 256MB `MaxBytesReader` (already correct) | unchanged |
| Filename safety | `safeFileName` strips traversal/control chars (already correct) | unchanged, verified |
| XSS | JS `esc()` on all attacker-controlled values (already correct) | verified end-to-end with an `<img onerror>` filename |

### Web UI accessibility & responsive (web_ui.go)

- Added ARIA roles to the div-based controls: `role="tablist"`/`tab`, `radiogroup`/`radio` (modes), `switch` (options), `list` (history), with `aria-selected`/`aria-checked` kept in sync by the JS handlers.
- Added **keyboard activation** (Enter/Space) and visible `:focus-visible` outlines for every custom control, plus an `sr-only` hint for the drop zone.
- Added a **responsive `@media (max-width:720px)`** layout that stacks the sidebar, reflows the stat grid, and makes tables horizontally scrollable on mobile.

All web changes verified against a live server (headers via `curl -D-`, end-to-end upload → scan → result → downloads).

---

## 5. Security Audit (unchanged — verified still holding)

| Check | Result |
|-------|--------|
| No sample execution | ✅ Static analysis only; carving reports offsets/hashes, never extracts to disk |
| No network calls (default mode) | ✅ |
| Panic recovery | ✅ `recover()` in scan path and per-request web goroutine |
| Memory / archive-bomb caps | ✅ `MaxAnalyzeBytes`, `MaxArchiveFiles`, `MaxCarves`, payload work budgets |
| Parser bounds safety | ✅ Audited PE/LNK/APK/PDF/carve/payload paths — all length-checked before slicing |
| STIX / report escaping | ✅ `html.EscapeString` in HTML report; STIX pattern escaping intact |

---

## 6. Regression Tests Added

`cli_fixes_test.go` covers: flag-conflict rejection (web+file, watch+file, ci+interactive, bad port/interval), valid combinations still parse, `--quiet`/`-q`, `suggestFlag` did-you-mean behavior, `levenshtein`, and rune-safe `truncStr`/`padRight`/`padLeft`.

---

## 7. Verification Summary

Every fix in this report was confirmed against real output:

- `go build`, `go vet`, `gofmt -l`, `go test`, `go test -race` — all clean.
- CLI: interactive EOF quit, shell `--version` no longer exits, mode-conflict rejection, port/interval validation, did-you-mean, `--help` to stdout, clean JSON stdout, batch summary-to-stdout with risk-based exit code — all exercised on the built binary.
- Web: security headers present, a11y markup rendered, end-to-end scan + all download formats working — verified on a live local server.
