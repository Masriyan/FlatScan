# Contributing

Repository: [https://github.com/Masriyan/FlatScan](https://github.com/Masriyan/FlatScan)

---

Thanks for improving FlatScan. This is a malware analysis tool, so contributions should prioritize **correctness, safety, and clear reporting** over feature quantity or visual polish.

---

## Contribution Priorities

High-value contributions:

| Area | Examples |
|---|---|
| **Static signatures** | New behavioral detections with clear evidence and low false-positive risk |
| **Parser coverage** | PE, ELF, Mach-O, APK, Office, archive format improvements |
| **Malware profile enrichment** | Better classification logic, confidence scoring, capability labeling |
| **MITRE TTP mapping** | More precise tactic/technique mapping with cleaner evidence chains |
| **Hunting exports** | YARA quality improvements, Sigma rule support |
| **PDF report sections** | New sections, layout improvements, better analyst content |
| **Tests** | Coverage for scanner behavior, IOC extraction, report output, edge cases |
| **Documentation** | Analyst-focused explanations of assumptions and limitations |

Lower-priority contributions:

- Visual or aesthetic changes without functional improvement
- New dependencies without strong justification
- Network-enabled features without explicit opt-in design
- Signatures with high false-positive risk or weak evidence

---

## Development Setup

```bash
git clone https://github.com/Masriyan/FlatScan
cd FlatScan
go test ./...
go build -o flatscan .
```

With a restricted build cache:

```bash
GOCACHE=/tmp/flatscan-go-build go test ./...
GOCACHE=/tmp/flatscan-go-build go build -o flatscan .
```

Verify the build:

```bash
./flatscan --version
./flatscan -m quick -f README.md --report-mode minimal --no-progress
```

---

## Code Style

- **Standard library first.** Use Go's standard library where practical. Keep the dependency footprint minimal.
- **No network calls by default.** Any feature that uses a network must be explicitly opt-in and clearly documented.
- **Static analysis must stay static.** Never execute or partially execute a target file, even in test code.
- **Clear data structures over string logic.** Prefer typed structs and named constants over ad hoc string parsing.
- **`gofmt` on all Go files** before committing.
- **Comments only where non-obvious.** Don't comment what the code already says. Do comment signature logic, scoring formulas, and format-specific parser quirks.
- **No live malware in source control.** Never commit actual malware samples or real incident artifacts.

---

## Testing

Before submitting any change, run the full test and build chain:

```bash
gofmt -w *.go
GOCACHE=/tmp/flatscan-go-build go test ./...
GOCACHE=/tmp/flatscan-go-build go build -o flatscan .
```

### Smoke Tests

Quick sanity check:

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

Check that all output files were created and are non-empty:

```bash
ls -lh reports/readme.*
```

### Testing With Real Samples

When testing with actual malware samples:
- Use an isolated malware-analysis VM (see [security.md](security.md))
- Use password-protected archives for sample storage and transfer
- Test in `deep` mode with all outputs enabled
- Check that findings match expected behaviors for the sample family

---

## Adding New Findings

When adding a new detection:

1. **Add clear, specific evidence.** Avoid generic terms.
2. **Choose severity conservatively.** Over-classification reduces analyst trust.
3. **Assign a category** that matches existing report groupings.
4. **Map MITRE tactics/techniques only when the evidence supports it.** Don't speculate.
5. **Add a practical, actionable recommendation.**
6. **Avoid duplicating existing findings.** Check existing signatures before adding.
7. **Add or update tests.**

### Evidence Quality

Strong evidence (use these):

| Type | Example |
|---|---|
| Specific API/function names | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` |
| Specific URL/domain/registry artifacts | `discord.com/api/webhooks/`, `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| Specific PE section names or entropy values | `.text` section entropy > 7.2, `.UPX0` section name |
| Decoded string content | base64-decoded URL or PowerShell command |
| Specific archive entry names | `autorun.inf`, `payload.exe` in archive root |

Weak evidence (avoid or combine with stronger evidence):

| Type | Why It's Weak |
|---|---|
| Generic words like `encrypt` alone | Common in legitimate software |
| Benign API names without context | `CreateFile`, `ReadFile` appear in almost everything |
| A single domain without other indicators | May be documentation or telemetry |
| High entropy alone in a compressed document | DOCX/XLSX/JAR files are compressed by design |

### Severity Guide

| Severity | Criteria |
|---|---|
| **Critical** | Confirmed high-confidence malicious capability (e.g., process injection chain complete) |
| **High** | Strong evidence of malicious intent (e.g., ransomware extension list + file enumeration) |
| **Medium** | Notable indicator requiring correlation (e.g., sandbox-awareness strings alone) |
| **Low** | Weak signal that adds context (e.g., high entropy in an otherwise clean file) |
| **Informational** | Non-malicious context useful to the analyst (e.g., .NET runtime detected) |

---

## Adding Report Features

FlatScan supports five output formats: text, JSON, PDF, IOC, and YARA.

When adding new fields or sections:

1. **Define types in `types.go`** — keep structs explicit and named
2. **Populate during scan or profile enrichment** — `scanner.go` or `expert.go`
3. **Render in all relevant output formats** — text (`report.go`), JSON (struct tag), PDF (`pdf.go`), YARA (`yara.go`)
4. **Keep JSON stable** — don't rename or remove existing fields; add only
5. **Keep PDF readable** — test layout at various content lengths; long IOC lists and strings need wrapping and pagination

---

## Handling Malware Samples in Development

**Do not commit live malware samples** to source control history.

- Use password-protected archives for any sample shared with contributors
- Store samples outside the source tree
- Label archives and directories clearly (`MALWARE_DO_NOT_EXECUTE`)
- Do not include live credentials, tokens, or private victim data in any committed file
- Strip sensitive data from test fixtures before committing

If a test requires a malicious-looking pattern, create a synthetic fixture file with benign content that mimics the pattern structurally.

---

## Commit Message Convention

Keep commits focused and descriptive. Prefix with the relevant component:

```
scanner: add Discord webhook exfiltration detection
signatures: add browser credential theft API chain
expert: improve ransomware confidence scoring
pdf: fix MITRE matrix table wrapping on long technique names
yara: include decoded artifact strings in hunting rule output
report: add cryptography section to Full mode
docs: expand usage guide with automation examples
tests: add IOC extraction coverage for IPv6
fix: handle malformed PE optional header without panic
```

Keep formatting changes, generated file updates, and functional changes in separate commits where possible.

---

## Pull Request Checklist

A useful PR includes:

- **What changed** — which component, which behavior
- **Why it matters** — analyst impact, detection value, false-positive tradeoffs
- **How it was tested** — test samples (described, not attached), smoke test output, unit test additions
- **Safety considerations** — does this add network calls? execute anything? change output format stability?
- **Screenshots or extracted text** if changing PDF layout

Open PRs and issues at:

[https://github.com/Masriyan/FlatScan](https://github.com/Masriyan/FlatScan)

---

## Areas Actively Wanted

If you're looking for a place to start:

- **Sigma rule export** — similar to the YARA export but targeting SIEM rules
- **ELF parser depth** — expanded section and symbol analysis
- **Mach-O parser depth** — expanded load command and code signature inspection
- **Office macro heuristics** — deeper VBA string extraction from OLE/OOXML
- **PDF malware heuristics** — JavaScript, embedded streams, /Launch actions
- **Additional MITRE coverage** — map more behavioral signatures to specific ATT&CK sub-techniques
- **Integration tests** — synthetic test fixtures covering each file format and finding type
- **CI workflow** — GitHub Actions configuration for automated build and test on push
