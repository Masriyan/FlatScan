# CI/CD Integration

FlatScan is designed to gate builds and release pipelines on the presence of malicious or suspicious artifacts, entirely offline.

## `--ci` and `--ci-threshold`

Add `--ci` to switch FlatScan into CI mode. In CI mode:

- FlatScan emits a **machine-readable stderr line** (see below).
- Exit codes are tuned for gating: it emits both `20` (malicious) and `10` (suspicious at or above the threshold).
- The suspicious threshold is set with `--ci-threshold <n>` (default `55`), instead of the `30` used in interactive single-file mode.

```bash
./flatscan -f build/artifact.exe --ci --ci-threshold 55
```

## The `FLATSCAN:` Machine-Readable Stderr Line

In CI mode FlatScan prints a single, parseable line to **stderr**:

```
FLATSCAN: <LABEL> score=<n> file=<name> findings=<n> sha256=<hash>
```

where `<LABEL>` is `MALICIOUS`, `SUSPICIOUS`, or the clean label. Parse this line to record the score, finding count, and hash in your pipeline logs or artifact metadata.

## Exit-Code Contract for Gating

| Exit code | Meaning | Typical gate action |
|-----------|---------|---------------------|
| `0` | Clean | Continue the pipeline. |
| `10` | Suspicious (score `>= --ci-threshold`) | Warn, or fail depending on policy. |
| `20` | Malicious (score `>= 80`) | Fail the build. |
| `1` | Runtime error | Fail (investigate). |
| `2` | Usage/flag error | Fail (fix invocation). |

`--ci` cannot be combined with `--interactive`/`-i` or `--shell` (usage error, exit 2), since CI mode is non-interactive. See [CLI Reference](CLI-Reference#exit-code-matrix).

## Batch-Scanning a Directory of Artifacts

Scan every artifact and capture aggregated JSON:

```bash
./flatscan --dir ./dist --ci --batch-json results.json
```

In batch mode the process exit code is the **worst file's** code (`20` if any file is malicious, else `10` if any is suspicious, else `0`), so a single check gates the whole artifact set. `--batch-json` writes the full per-file results for later inspection.

## GitHub Actions Example

```yaml
name: malware-scan
on: [push, pull_request]
jobs:
  flatscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'
      - name: Build FlatScan
        run: |
          cd 'source go'
          go build -ldflags "-X main.version=0.10.2" -o ../flatscan .
      - name: Scan build artifacts
        run: ./flatscan --dir ./dist --ci --ci-threshold 55 --batch-json flatscan-results.json
      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: flatscan-results
          path: flatscan-results.json
```

The job fails automatically when FlatScan exits `20` (or `10`, per your threshold), because a non-zero exit fails the step.

## GitLab CI Example

```yaml
flatscan:
  image: golang:1.25
  script:
    - cd 'source go' && go build -ldflags "-X main.version=0.10.2" -o ../flatscan . && cd ..
    - ./flatscan --dir ./dist --ci --ci-threshold 55 --batch-json flatscan-results.json
  artifacts:
    when: always
    paths:
      - flatscan-results.json
```

A non-zero exit from `flatscan` fails the job, gating the pipeline on the scan result.

Related: [CLI Reference](CLI-Reference) · [Output Formats](Output-Formats) · [Troubleshooting](Troubleshooting#exit-codes-surprising-ci).
