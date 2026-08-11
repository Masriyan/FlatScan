# CLI Reference

This is the exhaustive flag reference for FlatScan v0.10.0, grouped exactly as in `flatscan --help`. Each flag lists its type, default, and a one-line description.

## SCAN TARGET

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-f`, `--file <path>` | path | — | Scan a single file. |
| `--dir <path>` | path | — | Scan a directory (batch mode; add `--watch` to monitor continuously). |
| `-m`, `--mode <quick\|standard\|deep>` | enum | `quick` | Analysis depth. |

## OUTPUT

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--report <path>` | path | — | Write the terminal-style text report to a file. |
| `--json <path>` | path | — | Write JSON; use `-` to stream JSON to stdout. |
| `--pdf <path>` | path | — | Write a management-oriented PDF report. |
| `--html <path>` | path | — | Write an analyst-oriented HTML report. |
| `--report-pack <dir>` | dir | — | Write a zipped bundle of all report artifacts into a directory. |
| `--extract-ioc <path>` | path | — | Export a flat text list of extracted IOCs. |
| `--yara <path>` | path | — | Generate a YARA rule derived from the sample. |
| `--sigma <path>` | path | — | Generate a Sigma rule derived from the sample. |
| `--stix <path>` | path | — | Write a STIX 2.1 bundle of indicators. |
| `--report-mode <Full\|Summary\|minimal>` | enum | `summary` | Verbosity of the terminal/text report. |
| `--output-format <text\|json\|csv\|jsonl>` | enum | `text` | Primary stdout format. |

## ADVANCED

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--carve` | bool | off | Carve embedded artifacts (reports offset/hash only; nothing extracted to disk). |
| `--decode-depth <n>` | int (0–5) | `2` | How many decode layers to peel for obfuscated strings. |
| `--resolve-depth <n>` | int (0–6, 0=off) | `3` | Recursion depth for the payload resolver / `payload_tree`. |
| `--rules <paths>` | paths | — | Load one or more custom `.rule` packs (comma/space separated). |
| `--plugins <paths>` | paths | — | Load one or more plugin `.rule` packs. |
| `--external-tools` | bool | off | Enable optional external tool integrations (opt-in). |
| `--ioc-allowlist <path>` | path | — | Suppress IOCs matching an allowlist file. |
| `--similarity-db <path>` | path | — | JSONL corpus used for similarity matching. |
| `--intel-db <path>` | path | — | JSONL offline threat-intel store used for enrichment. |

## LIMITS

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--min-string <n>` | int (min 3) | `5` | Minimum string length to extract. |
| `--max-analyze-bytes <n>` | bytes | `256MiB` | Cap on bytes analyzed per file. |
| `--max-archive-files <n>` | int | `500` | Cap on archive members processed (archive-bomb guard). |
| `--max-carves <n>` | int (1–1000) | `80` | Cap on carved artifacts reported. |
| `--splash-seconds <n>` | int (0–120) | `20` | Splash screen duration (0 disables). |

## CI/CD

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--ci` | bool | off | CI mode: machine-readable stderr line + gating exit codes. |
| `--ci-threshold <n>` | int | `55` | Score at/above which CI treats a file as suspicious (exit 10). |

## WEB

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--web` | bool | off | Launch the local web GUI. |
| `--web-port <n>` | int | `5000` | Port for the web GUI (binds `127.0.0.1` only, no auth). |

## WATCH / CASE

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--batch-json <path>` | path | — | Write aggregated batch results as JSON. |
| `--watch` | bool | off | Continuously monitor `--dir` for new/changed files. |
| `--watch-alert-only` | bool | off | In watch mode, only surface suspicious/malicious hits. |
| `--watch-interval <n>` | int | `3` | Polling interval (seconds) for watch mode. |
| `--case <id>` | string | — | Attach results to a case identifier. |
| `--case-db <path>` | path | — | Case database file for persisting case records. |

## FLAGS

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-q`, `--quiet` | bool | off | Suppress report/tips/progress; keep the verdict line. |
| `--no-color` | bool | off | Disable ANSI color output. |
| `--no-progress` | bool | off | Disable the progress indicator. |
| `--no-splash` | bool | off | Skip the splash screen. |
| `--debug` | bool | off | Emit verbose debug diagnostics (`debug_log`). |
| `--completion <bash\|zsh\|fish>` | enum | — | Print a shell completion script and exit. |
| `-h`, `--help` | bool | — | Print the grouped help and exit. |
| `--version` | bool | — | Print the version and exit. |

## Exit-Code Matrix

| Exit code | Meaning | When it is returned |
|-----------|---------|---------------------|
| `0` | Clean | Score below the suspicious threshold. |
| `10` | Suspicious | Single-file score `>= 30`, or in CI mode score `>= --ci-threshold`. |
| `20` | Malicious | Score `>= 80`. |
| `1` | Runtime error | An error occurred during analysis. |
| `2` | Usage / flag error | Invalid, missing, or mutually-exclusive flags. |

Notes:

- **Batch mode** returns the **worst file's** code (`20`, else `10`, else `0`).
- **CI mode** emits both `20` (malicious) and `10` (suspicious at/above `--ci-threshold`), so a pipeline can gate on either. See [CI/CD Integration](CI-CD-Integration).

## Mutually-Exclusive Flag Combinations (Rejected with Exit 2)

The following combinations are invalid and cause a usage error (exit code `2`) rather than silently doing the wrong thing:

- `--web` together with `-f`/`--file` or `--dir` — the web GUI is its own input surface; you cannot also pass a scan target on the CLI.
- `--watch` together with `-f`/`--file` — watch mode monitors a directory (`--dir`), not a single file.
- `--ci` together with `--interactive`/`-i` or `--shell` — CI mode is non-interactive by definition.
- `--web-port` out of the valid port range — rejected.
- `--watch-interval` out of range — rejected.

Related: [Output Formats](Output-Formats) · [CI/CD Integration](CI-CD-Integration) · [Troubleshooting](Troubleshooting).
