# Contributing

Repository: https://github.com/Masriyan/FlatScan

Thanks for improving FlatScan. This project is a malware-analysis tool, so contributions should prioritize correctness, safety, and clear reporting over flashy output.

## Contribution Priorities

High-value contributions include:

- Better static signatures with clear evidence and low false-positive risk.
- Better parser coverage for PE, ELF, Mach-O, APK, Office, and archive formats.
- Improved malware profile enrichment.
- Better MITRE-style TTP mapping.
- More useful PDF report sections.
- Hunting exports such as YARA and Sigma.
- Tests for scanner behavior and report output.
- Documentation that helps analysts understand assumptions and limitations.

## Development Setup

```bash
git clone https://github.com/Masriyan/FlatScan
cd FlatScan
go test ./...
go build -o flatscan .
```

If the Go cache is restricted:

```bash
GOCACHE=/tmp/flatscan-go-build go test ./...
GOCACHE=/tmp/flatscan-go-build go build -o flatscan .
```

## Code Style

- Use Go standard library where practical.
- Keep the CLI dependency-light.
- Run `gofmt` on modified Go files.
- Prefer clear data structures over ad hoc string-only logic.
- Add comments only where logic is non-obvious.
- Keep static analysis safe; do not execute target samples.
- Do not add network calls by default. Any enrichment feature that uses a network must be explicit and optional.

## Testing

Before submitting:

```bash
gofmt -w *.go
GOCACHE=/tmp/flatscan-go-build go test ./...
GOCACHE=/tmp/flatscan-go-build go build -o flatscan .
```

Useful smoke test:

```bash
./flatscan -m quick -f README.md --report-mode minimal --no-progress
```

Full output smoke test:

```bash
./flatscan -m deep -f README.md \
  --report-mode Full \
  --report reports/readme.full.txt \
  --json reports/readme.json \
  --pdf reports/readme.pdf \
  --yara reports/readme.yar \
  --extract-ioc reports/readme.iocs.txt \
  --no-progress
```

## Adding New Findings

When adding a new detection:

1. Add clear evidence.
2. Choose severity conservatively.
3. Add a category that matches existing reporting.
4. Add MITRE-style tactic/technique only when the evidence supports it.
5. Add a practical recommendation.
6. Avoid duplicate findings.
7. Add or update tests when possible.

Good finding evidence:

- Specific API/function names.
- Specific URL/domain/registry/path artifacts.
- Specific PE section names or entropy values.
- Specific decoded string content.
- Specific archive entry names.

Weak finding evidence:

- Generic words such as `encrypt` alone.
- Benign API names without context.
- A single domain that may be documentation or telemetry.
- High entropy alone in a compressed document.

## Adding Report Features

FlatScan supports text, JSON, PDF, IOC, and YARA outputs.

When adding fields:

- Add them to `types.go`.
- Populate them during scan/profile enrichment.
- Render them in relevant output formats.
- Keep JSON stable and explicit.
- Keep PDF readable for both executives and analysts.

## Handling Malware Samples

Do not commit live malware samples to normal source-control history unless the repository is explicitly designed and access-controlled for malware storage.

Recommended sample handling:

- Use password-protected archives.
- Store samples outside the source tree when possible.
- Use clear warning labels.
- Avoid accidental execution paths.
- Do not include live credentials, tokens, or private victim data in reports.

## Commit Guidance

Good commit scopes:

- `scanner: add Discord webhook exfiltration detection`
- `pdf: improve MITRE matrix wrapping`
- `yara: add generated rule export`
- `docs: expand usage guide`
- `tests: cover IOC extraction`

Keep unrelated formatting or generated report changes out of code commits when possible.

## Pull Requests

A useful pull request should include:

- What changed.
- Why it matters.
- How it was tested.
- Any false-positive or safety tradeoffs.
- Screenshots or extracted text if changing PDF layout.

Open issues and pull requests at:

https://github.com/Masriyan/FlatScan
