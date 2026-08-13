# Installation

FlatScan is a single, statically-linked Go binary. There is no installer and no runtime dependency — you build it once and copy the resulting `flatscan` executable wherever you need it.

## Prerequisites

- **Go 1.25.0 or newer** (the module declares `go 1.25.0`).
- A checkout of the FlatScan repository. The Go source lives under `source go/` — **note the space in the directory name; always quote it.**
- **No third-party dependencies to fetch.** `go.mod` requires nothing and there is no `go.sum`, so `go build` works offline and air-gapped. Everything is the Go standard library plus `internal/x86asm`, a vendored unmodified copy of `golang.org/x/arch/x86/x86asm` (BSD-3-Clause) that ships in the tree.

Verify your toolchain:

```bash
go version   # expect go1.25.0 or newer
```

## Building from Source

From the repository root:

```bash
cd 'source go'
go build -ldflags "-X main.version=0.10.2" -o ../flatscan .
```

This produces a `flatscan` binary in the repository root. The `-ldflags "-X main.version=0.10.2"` injects the version string reported by `--version`.

## Verifying the Build

```bash
../flatscan --version      # prints the version stamped at build time
../flatscan --help         # prints the full grouped flag reference
```

A healthy build prints `0.10.2` for `--version` and exits `0`. Run a smoke scan against a known-clean file:

```bash
../flatscan -f /bin/ls
echo "exit code: $?"       # expect 0 (clean)
```

## Cross-Compilation

Go cross-compiles without a C toolchain. Set `GOOS`/`GOARCH` before `go build`:

```bash
cd 'source go'
GOOS=linux   GOARCH=amd64 go build -ldflags "-X main.version=0.10.2" -o ../dist/flatscan-linux-amd64 .
GOOS=linux   GOARCH=arm64 go build -ldflags "-X main.version=0.10.2" -o ../dist/flatscan-linux-arm64 .
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.version=0.10.2" -o ../dist/flatscan-windows-amd64.exe .
GOOS=windows GOARCH=arm64 go build -ldflags "-X main.version=0.10.2" -o ../dist/flatscan-windows-arm64.exe .
GOOS=darwin  GOARCH=amd64 go build -ldflags "-X main.version=0.10.2" -o ../dist/flatscan-darwin-amd64 .
GOOS=darwin  GOARCH=arm64 go build -ldflags "-X main.version=0.10.2" -o ../dist/flatscan-darwin-arm64 .
```

### Target Matrix

| GOOS | GOARCH | Output |
|------|--------|--------|
| linux | amd64 | `flatscan-linux-amd64` |
| linux | arm64 | `flatscan-linux-arm64` |
| windows | amd64 | `flatscan-windows-amd64.exe` |
| windows | arm64 | `flatscan-windows-arm64.exe` |
| darwin | amd64 | `flatscan-darwin-amd64` |
| darwin | arm64 | `flatscan-darwin-arm64` |

Memory-mapped reads use a native path on Linux and a portable fallback elsewhere, so all targets are fully supported.

## Installing Shell Completions

FlatScan can emit a completion script for your shell with `--completion`:

```bash
# bash
flatscan --completion bash | sudo tee /etc/bash_completion.d/flatscan > /dev/null

# zsh (ensure the target dir is on your $fpath)
flatscan --completion zsh > ~/.zsh/completions/_flatscan

# fish
flatscan --completion fish > ~/.config/fish/completions/flatscan.fish
```

Reload your shell (or `source` the file) and tab-completion for flags and modes becomes available.

## Safe Isolated Analysis Environment

FlatScan is built to ingest live malware. Even though it never executes samples and makes no network calls in default mode, treat every sample as hostile and follow lab hygiene:

1. **Run inside a disposable VM or container** dedicated to analysis. Snapshot it clean beforehand.
2. **Cut network egress** for the analysis host (host-only networking or no NIC). FlatScan does not need the network.
3. **Keep samples in a locked-down directory** with restrictive permissions; never double-click or open them with their native handler.
4. **Copy only the report artifacts out** — the JSON/PDF/HTML/report-pack — not the sample itself.
5. **Respect the resource caps** (`--max-analyze-bytes`, `--max-archive-files`, `--max-carves`) so an archive bomb or a giant file cannot exhaust the host. Defaults are safe; see [CLI Reference](CLI-Reference#limits).

Related: [Quick Start](Quick-Start) · [CLI Reference](CLI-Reference) · [Troubleshooting](Troubleshooting).
