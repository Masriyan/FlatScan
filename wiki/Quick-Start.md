# Quick Start

This page walks you through your first scan, how to read the result, the run modes, and a set of copy-paste commands. It assumes you have already built the `flatscan` binary (see [Installation](Installation)).

## Your First Scan

```bash
./flatscan -f suspicious.exe
```

FlatScan reads the file (memory-mapped when possible), hashes it, detects its format, runs its analysis passes, scores the evidence, and prints a terminal report ending in a verdict line. It **never executes the sample**.

## Reading the Verdict and Risk Score

Every scan produces an integer **risk score (0–100)** and a **verdict** derived from it. The score is a weighted sum of correlated findings across categories (see [Detection Engine](Detection-Engine)). The single-file verdict thresholds are:

| Score | Verdict | Exit code |
|-------|---------|-----------|
| `>= 80` | Malicious | `20` |
| `>= 30` | Suspicious | `10` |
| `< 30` | Clean | `0` |

Findings are listed with a severity, category, MITRE tactic/technique, evidence, and a recommendation. Higher-confidence findings backed by multiple pieces of evidence carry `confidence` and `evidence_count`. In CI mode the suspicious threshold is configurable with `--ci-threshold` (default 55) instead of 30.

## The Five Scan Modes

| Mode | How to invoke | Purpose |
|------|---------------|---------|
| **Single-file** | `-f <path>` | Analyze one file. |
| **Batch** | `--dir <path>` | Recursively scan a directory; exit code is the worst file's code. |
| **Watch** | `--dir <path> --watch` | Continuously monitor a directory and scan new/changed files. |
| **Interactive wizard** | `--interactive` / `-i` | Guided prompt-driven scan for newcomers. |
| **Manual shell** | `--shell` | An interactive command shell for iterative analysis. |

A sixth surface, the **local web GUI** (`--web`), is documented in [Web UI](Web-UI). Scan depth within any mode is set with `-m quick|standard|deep` (default `quick`).

## Example Commands

```bash
# 1. Single-file, default (quick) scan
./flatscan -f sample.bin

# 2. Deep scan of a single file with a saved text report
./flatscan -f sample.bin -m deep --report report.txt

# 3. Batch-scan a directory of artifacts (exit code = worst file)
./flatscan --dir ./samples -m standard

# 4. Emit JSON to stdout and pipe into jq
./flatscan -f sample.bin --json - | jq '.risk_score, .verdict'

# 5. Produce a zipped report-pack (JSON + PDF + HTML + IOCs + YARA/Sigma)
./flatscan -f sample.bin --report-pack ./out

# 6. Generate a YARA rule and a Sigma rule from the sample
./flatscan -f sample.bin --yara sample.yar --sigma sample.sigma.yml

# 7. Export a STIX 2.1 bundle and a flat IOC list
./flatscan -f sample.bin --stix sample.stix.json --extract-ioc iocs.txt

# 8. Launch the local web GUI on the default port (127.0.0.1:5000)
./flatscan --web
```

## Where to Go Next

- Full flag list and exit codes: [CLI Reference](CLI-Reference)
- Every output type explained: [Output Formats](Output-Formats)
- How the score is computed: [Detection Engine](Detection-Engine)
- Gating a pipeline on the verdict: [CI/CD Integration](CI-CD-Integration)
