# Troubleshooting

Common issues and how to resolve them.

## Build Errors

**`go: go.mod requires go >= 1.25.0`** — your Go toolchain is too old. Install Go 1.25.0+ and re-run `go version`. See [Installation](Installation#prerequisites).

**`no such file or directory` when building** — remember the source directory has a space in its name. Quote it: `cd 'source go'`, not `cd source go`.

**`cannot find module golang.org/x/arch`** — you are on a pre-vendoring checkout. Current versions have no external dependencies: `go.mod` requires nothing, the disassembler ships in-tree at `internal/x86asm`, and `GOPROXY=off go build` succeeds. Pull the latest source, or delete a stale `go.sum` if one is present.

## "Unknown Flag" and Did-You-Mean

If you mistype a flag, FlatScan reports a usage error (exit code `2`) and suggests the closest valid flag. Check the exact spelling and grouping in the [CLI Reference](CLI-Reference). Note that some combinations are rejected on purpose (see below), which also produce exit `2`.

## Exit Codes Surprising CI

The exit code encodes the verdict, so a "failing" pipeline may simply mean a detection:

- `0` clean, `10` suspicious, `20` malicious, `1` runtime error, `2` usage error.
- **Batch mode** returns the worst file's code.
- **CI mode** uses `--ci-threshold` (default 55) for the suspicious boundary and emits both `10` and `20`.

If CI fails unexpectedly, read the `FLATSCAN:` stderr line and the score before assuming a bug. See [CI/CD Integration](CI-CD-Integration#exit-code-contract-for-gating).

### Rejected Flag Combinations (exit 2)

- `--web` with `-f`/`--file` or `--dir`
- `--watch` with `-f`/`--file`
- `--ci` with `--interactive`/`-i` or `--shell`
- out-of-range `--web-port` or `--watch-interval`

## Colors Leaking / NO_COLOR

If ANSI escape codes leak into logs, redirected files, or a dumb terminal, disable color:

```bash
./flatscan -f sample.bin --no-color
# or, environment-wide:
NO_COLOR=1 ./flatscan -f sample.bin
```

Use `--no-progress` to also suppress the progress indicator, and `--no-splash` (or `--splash-seconds 0`) to skip the splash screen in non-interactive contexts. `-q`/`--quiet` collapses output to just the verdict.

## Web Port Conflicts

`--web` binds `127.0.0.1:5000` by default. If the port is already in use, pick another:

```bash
./flatscan --web --web-port 8080
```

An out-of-range port is rejected (exit `2`). The server only ever binds loopback — see [Web UI](Web-UI#security-model-localhost-only-no-auth).

## Large Files and Timeouts

Analysis is bounded by design. If a very large file appears truncated in the report, it hit `--max-analyze-bytes` (default 256 MiB) — raise it deliberately if you must. Archives that stop early hit `--max-archive-files` (default 500), and carving stops at `--max-carves` (default 80). These caps protect the host from archive bombs and runaway inputs; raise them only in a controlled lab. Deep obfuscation that isn't fully unwrapped may need a higher `--resolve-depth` (max 6) or `--decode-depth` (max 5).

## How `--debug` Helps

Add `--debug` to emit verbose diagnostics (captured as `debug_log` in JSON). Use it to see which analysis passes ran, why a rule did or did not match, how the payload resolver descended, and where time was spent — the fastest way to understand an unexpected verdict before filing an issue.

Related: [CLI Reference](CLI-Reference) · [FAQ](FAQ) · [Installation](Installation).
