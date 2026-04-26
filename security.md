# Security Policy

Repository: [https://github.com/Masriyan/FlatScan](https://github.com/Masriyan/FlatScan)

---

FlatScan is a malware analysis utility. Security handling matters both for the tool itself and for the samples analyzed with it.

---

## Threat Model

FlatScan's primary threat surface is the **malicious input file**. The tool reads and parses untrusted bytes from adversary-controlled samples. Relevant risks:

| Threat | Severity | Mitigation |
|---|---|---|
| Crafted file triggers parser bug → crash | Medium | Use an isolated VM; run inside a container |
| Crafted file causes resource exhaustion (memory, CPU) | Medium | `--max-analyze-bytes` and `--max-archive-files` limits apply |
| Generated report contains live C2 URLs | Low | Treat all reports as sensitive; do not click embedded links |
| Report output written to unsafe path | Low | Review `--report`, `--json`, `--pdf`, `--yara` paths before running |
| Sample accidentally executed | Critical | FlatScan is static-only; accidental exec would be a critical bug — report it |
| Sensitive strings extracted into shared reports | Medium | Review reports before sharing; redact tokens and victim-specific data |

---

## Scope of Security Reports

Security issues in scope:

- Bugs that cause unsafe or incorrect sample handling
- Parser crashes or panics on malformed or adversarially crafted files
- Resource exhaustion (CPU, memory, disk) from crafted inputs
- Incorrect output paths or unsafe file writes
- Report generation bugs that expose unintended data
- Any behavior that executes a target sample (critical — report immediately)
- Vulnerabilities introduced by future dependency additions

Out of scope (as intended behavior):

- False negatives — FlatScan missing a malicious sample
- False positives — FlatScan flagging benign content
- Low-scoring results on packed or obfuscated samples (static analysis limitation)

---

## Reporting a Security Issue

Open an issue or contact the maintainer through the repository:

[https://github.com/Masriyan/FlatScan](https://github.com/Masriyan/FlatScan)

When reporting:
- Provide a minimal reproducer (a small crafted file, not a live malware sample)
- Describe the expected vs. actual behavior
- Include the OS, Go version, and FlatScan version
- **Do not post live malware, private tokens, credentials, victim data, or exploit payloads publicly**

---

## Safe Malware Handling

### Analyst VM Checklist

| Step | Detail |
|---|---|
| Use an isolated VM | No production access; air-gapped preferred |
| Take a snapshot before analysis | Roll back cleanly after each sample |
| Disable shared clipboard | Prevents accidental paste of malicious strings to host |
| Disable shared folders unless required | Limits escape risk from crafted file paths |
| Do not run samples on production hosts | Even static analysis should stay in the lab |
| Keep samples in a dedicated directory | Separate from tools, reports, and code |
| Do not open samples in GUI tools | GUI apps may execute embedded content or macros |
| Use password-protected archives for transfer | Prevents accidental execution during file transfer (`password: infected` is standard) |
| Keep reports and samples separated | Incident artifacts should be stored and handled differently from live malware |

### Recommended Directory Structure

```
/malware-lab/
├── samples/          # Live malware — password-protected archives
│   └── 2024-q4/
├── reports/          # FlatScan outputs — treat as sensitive artifacts
│   └── <sha256>/
├── tools/            # FlatScan binary and other analysis tools
└── quarantine/       # Extracted samples during active analysis
```

---

## Static Analysis Limitations and Disclaimers

FlatScan does not execute target samples. It reads bytes and parses metadata. This reduces risk but does not eliminate it.

Specific limitations:

- **File parsers can have bugs.** Malformed PE, ZIP, or ELF structures may trigger unexpected behavior.
- **Malformed inputs can exhaust resources.** Zip bombs, oversized headers, and recursive structures can cause high memory or CPU usage. FlatScan applies limits, but edge cases exist.
- **Static analysis can miss behavior.** Environment-gated, staged, packed, or dynamically generated code will not appear in a static scan.
- **A clean-looking report is not a clean verdict.** A score of 0–9 means no strong static indicators, not that the file is benign.

Use FlatScan as one component in a broader workflow:

```
FlatScan (static) → Sandbox (behavioral) → RE (deep dive) → EDR/NDR telemetry → Threat intel
```

---

## Output Security

Generated reports are sensitive incident artifacts and must be handled accordingly.

Reports may contain:

| Content | Risk if Exposed |
|---|---|
| C2 URLs | Operational details about active threat infrastructure |
| Webhook tokens | Active exfiltration endpoint credentials |
| API paths and keys | Potentially active credentials |
| Registry keys | Specific persistence mechanisms |
| Internal file paths | Victim environment details |
| Extracted strings with secrets | Embedded credentials or configuration |
| Hashes and metadata | Sample fingerprints useful to adversaries tracking detection |

**Before sharing a report:**
- Review for embedded tokens and credentials
- Review for victim-specific data (hostnames, usernames, internal paths)
- Redact or replace sensitive fields as appropriate
- Apply TLP/sharing labels appropriate for your organization

---

## YARA Rule Safety

FlatScan generates YARA rules with `--yara`. These rules are hunting starting points, not production-ready signatures.

Before deploying generated YARA rules:

1. Review the rule logic and string selections manually
2. Test against known-good corpora to measure false positive rate
3. Test against known-malicious samples to confirm detection
4. Validate with your YARA engine (syntax and performance)
5. Apply appropriate scope limits (do not deploy broad rules to endpoint blocking without testing)

Generated rules may contain:
- Sensitive URLs or C2 strings
- Paths or registry keys that are environment-specific
- Strings that are too broad or too narrow for production use

---

## PDF Report Safety

PDF reports are generated locally by FlatScan's internal PDF writer. No external PDF libraries or cloud services are used.

- **Do not click embedded links** in PDF reports on production systems. Reports may contain live C2 URLs.
- Store PDF reports as sensitive artifacts alongside other incident documentation.
- Apply access controls appropriate to the sensitivity of the case.

---

## Network Behavior

Current FlatScan analysis is fully local and static. **It does not contact external services by default.**

If future enrichment features are added (e.g., VirusTotal lookups, threat intel enrichment), they will be:
- Explicitly opt-in — disabled by default
- Clearly documented in the changelog and usage guide
- Safe for sensitive incident data (no automatic sample submission)
- Configurable or disableable for offline and air-gapped environments

---

## Dependency Policy

FlatScan currently uses the Go standard library only. No third-party Go modules are used or required.

If dependencies are added in the future:
- Prefer well-maintained, narrowly scoped libraries
- Pin to specific versions; vendor if possible
- Document the dependency and the reason it was added
- Pay extra attention to parser and archive-handling libraries, which are the highest-risk surface area

---

## Responsible Use

FlatScan is built for:
- Defensive malware analysis
- Incident response and triage
- Threat hunting
- Security research and education

**Do not use FlatScan to:**
- Improve malware evasion or packing techniques
- Assist in developing or deploying malware
- Conduct unauthorized analysis of systems or files you do not own or have explicit permission to analyze
- Bypass detection mechanisms on systems you do not control

Misuse of this tool may violate applicable laws and organizational policies.
