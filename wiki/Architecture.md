# Architecture

FlatScan is a single, statically-linked Go binary organized around a linear-yet-parallel analysis pipeline. This page describes that pipeline, the source layout, the concurrency model, and its performance characteristics.

## High-Level Pipeline

```
input file
   │
   ▼
[ read / mmap ]         memory-map on Linux, portable read fallback elsewhere
   │
   ▼
[ hashing ]            MD5 / SHA-1 / SHA-256 / SHA-512
   │
   ▼
[ format detection ]  PE / ELF / Mach-O / APK / DEX / PDF / Office / archive / script / .lnk
   │
   ▼
[ parallel analysis passes ]
   ├─ string extraction        ├─ entropy (incremental)
   ├─ PE/ELF/Mach-O intel      ├─ disassembly (x86/x64)
   ├─ hashdb import resolution ├─ IOC extract + triage + classify
   ├─ DGA scoring              ├─ family fingerprints
   ├─ capability rules         ├─ malware-config extraction
   ├─ similarity matching      ├─ custom rules / plugins
   ├─ recursive payload resolve (payload_tree)
   └─ carving (offset/hash only)
   │
   ▼
[ scoring & correlation ]   per-category breakdown → multi-evidence correlation → risk_score + verdict
   │
   ▼
[ reporting ]           terminal / JSON / CSV / JSONL / PDF / HTML / YARA / Sigma / STIX / IOC / report-pack
```

## Source Organization (93 source files, ~22.9k non-test LOC)

The Go source under `source go/` is organized by concern. Representative files:

- **Entry & orchestration** — `main.go`, `scanner.go`, `types.go`, `platform.go`.
- **Run modes** — `batch.go`, `watch.go`, `interactive.go`, `expert.go` (shell), `web.go`, `web_ui.go`.
- **I/O & hashing** — `mmap_linux.go`, `mmap_other.go`, `cache.go`.
- **Format parsers** — `formats.go`, `pe_intel.go`, `dotnet.go`, `apk.go`, `pdf.go`, `pdf_document.go`, `lnk.go`, `script.go`.
- **Code analysis** — `disasm.go`, `hashdb.go`, `packer.go`, `entropy.go`, `numeric.go` (saturating conversions for attacker-controlled header fields).
- **Strings & decoding** — `strings_extract.go`, `decode.go`, `deobfuscate.go`, `masquerade.go`, `payload_resolve.go`, `carve.go`, `chains.go`.
- **IOCs & intel** — `ioc.go`, `ioc_classify.go`, `ioc_triage.go`, `dga.go`, `intel.go`.
- **Detection content** — `rules.go`, `plugin.go`, `signatures.go`, `capability.go`, `family.go`, `family_fingerprints.go`, `config_extract.go`, `config_family.go`, `correlation.go`, `falsepositive.go`, `similarity.go`, `similarity_match.go`, `behavior.go`.
- **Reporting & exports** — `report.go`, `html.go`, `pdf.go`, `yara.go`, `sigma.go`, `stix.go`, `case_report_pack.go`, `hints.go`.
- **UX & infra** — `color.go`, `progress.go`, `splash.go`, `logger.go`, `completion.go`, `parallel.go`, `external_tools.go`.

## Concurrency Model

- **Parallel batch worker pool.** In batch/watch mode files are scanned concurrently across a worker pool (`parallel.go`, `batch.go`), keeping throughput high on directories of artifacts. The aggregate exit code is the worst file's code.
- **Parallel per-scan passes.** Within a single scan, independent analysis passes run concurrently and their findings are merged before scoring.
- **Per-stage panic isolation.** The analysis stages parse attacker-controlled bytes, so an out-of-range index is a realistic outcome rather than a theoretical one. A panic on a goroutine cannot be recovered by the caller, so each stage recovers locally and the failure is re-raised on the calling goroutine, where it becomes an error for that one file. One malformed sample therefore costs one result, not the whole batch. Findings dedup through a per-result index under `findingsMu`, so concurrent stages cannot record duplicates or race.
- **Per-scan work budgets.** Each scan operates under bounded budgets — byte caps (`--max-analyze-bytes`), archive-member caps (`--max-archive-files`), carve caps (`--max-carves`), and decode/resolve depth limits — so no single file (including an archive bomb) can exhaust the host.

## Zero-Dependency Philosophy

FlatScan uses **only the Go standard library**. `go.mod` requires no modules and there is no `go.sum`, so nothing is downloaded to build it — `GOPROXY=off go build` succeeds on a clean checkout. The one piece of third-party code is `internal/x86asm`, an unmodified vendored copy of `golang.org/x/arch/x86/x86asm` (BSD-3-Clause, The Go Authors) used for x86/x64 disassembly; it lives in the tree, is attributed in `internal/x86asm/LICENSE`, and is documented in `internal/x86asm/README.md`.

There is no CGo and **no network access in default mode**. This keeps the binary portable, auditable, reproducible, and safe to build and run in an air-gapped lab — the supply chain is exactly what is checked into this repository.

## Performance Characteristics

- **Corpus caching** — repeated corpus/DB lookups (similarity, intel) are cached to avoid rework across a batch.
- **Incremental entropy** — entropy is computed in a streaming/windowed fashion rather than by repeatedly rescanning buffers.
- **Memory-mapped reads** — large files are mmap'd (Linux) so analysis touches pages on demand instead of buffering the whole file.
- **Bounded resource caps** — the work budgets above cap CPU/memory per scan, giving predictable performance even on hostile inputs.

Related: [Detection Engine](Detection-Engine) · [CLI Reference](CLI-Reference#limits) · [Installation](Installation).
