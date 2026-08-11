# Rules and Plugins

FlatScan supports user-supplied detection content in a simple, line-oriented `.rule` pack format. The same format powers both `--rules` and `--plugins` packs. Example packs ship under `rules/` and `plugins/` in the repository.

## Loading Packs

```bash
./flatscan -f sample.bin --rules rules/network-c2.rule,rules/credential-theft.rule
./flatscan -f sample.bin --plugins plugins/android-risk.rule
```

Both flags accept one or more paths (comma/space separated). `--rules` and `--plugins` use the identical syntax; the split is organizational.

## Pack File Format

A pack is a plain-text file. The first meaningful line names the pack; rules follow, separated by blank lines. Each rule is a set of `key: value` lines. A new rule begins at each `id:`.

```
pack: FlatScan starter rules

id: starter.native.injection
name: Native process injection API cluster
severity: High
category: Custom Rule
score: 16
strings_all: WriteProcessMemory, CreateRemoteThread
strings_any: VirtualAllocEx, VirtualAlloc, NtCreateThreadEx
tactic: Defense Evasion
technique: Process Injection
recommendation: Trace process creation and memory-write telemetry around first execution time.
```

### Recognized Keys

| Key | Purpose |
|-----|---------|
| `pack` | Pack display name (once, at top). |
| `id` | Unique rule identifier; also starts a new rule. |
| `name` (alias `title`) | Human-readable rule name. |
| `severity` | e.g. `Critical`, `High`, `Medium`. |
| `category` | Grouping category shown in the report. |
| `score` | Integer weight contributed when the rule matches. |
| `tactic` | MITRE ATT&CK tactic. |
| `technique` | MITRE ATT&CK technique (optionally with a `T####` id). |
| `recommendation` | Analyst guidance emitted with the finding. |
| `file_types` | Restrict the rule to matching detected file types (e.g. `APK package, DEX bytecode`). |
| `strings_any` | Match if **any** listed substring is present (comma-separated). |
| `strings_all` | Match only if **all** listed substrings are present. |
| `regex_any` | Match if any listed regex matches (compiled case-insensitively). |
| `functions_any` | Match against resolved/imported function names. |
| `domains_any` | Match against extracted domains. |
| `urls_any` | Match against extracted URLs. |
| `sha256_any` | Match against the file/artifact SHA-256. |
| `min_entropy` | Match only if file entropy is at least this value. |
| `max_entropy` | Match only if file entropy is at most this value. |

Unknown keys produce a load warning but do not abort loading. A pack with zero valid rules fails to load.

### Matching Semantics

- `file_types` acts as a precondition — if set and the detected type does not match, the rule is skipped.
- `strings_all` requires every term; `strings_any`/`regex_any`/`domains_any`/`urls_any` require at least one.
- All string matching is case-insensitive; `regex_any` patterns are compiled with `(?i)`.
- On a match, the rule's `score` is added and a finding is emitted with its `severity`, `category`, `tactic`, `technique`, `recommendation`, and the matched evidence (e.g. `regex_any=<match>`).

Example packs to study: `rules/starter.rule`, `rules/network-c2.rule`, `rules/credential-theft.rule`, `rules/reconnaissance.rule`, `rules/persistence-evasion.rule`, and `plugins/android-risk.rule`.

## IOC Allowlist (`--ioc-allowlist <path>`)

A file of known-good indicators. IOCs matching the allowlist are suppressed from the results with a recorded reason, and the suppression is logged (`suppressed_count`, `suppression_reason`, `suppression_log`). Use it to silence your own infrastructure and known-benign values so they do not inflate the IOC set or the score.

## Similarity DB (`--similarity-db <path>`)

A JSONL store (one JSON object per line) describing previously-seen samples. FlatScan compares the current sample against this corpus to surface near-duplicates and variant clusters (`similarity` in the JSON output). Build it up over time from your own analyzed samples for local, offline variant tracking.

## Intel DB (`--intel-db <path>`)

A JSONL offline threat-intel store. Extracted IOCs are cross-referenced against it to enrich findings (`enrichment[]`) — all locally, with **no network calls**. Use it to fold your own indicator feeds into FlatScan's output without any online lookup.

Related: [Detection Engine](Detection-Engine) · [Output Formats](Output-Formats) · [CLI Reference](CLI-Reference#advanced).
