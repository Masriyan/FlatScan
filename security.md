# Security Policy

Repository: https://github.com/Masriyan/FlatScan

FlatScan is a malware-analysis utility. Security handling matters both for the tool and for the samples analyzed with it.

## Supported Scope

Security reports may include:

- Bugs that could cause unsafe sample handling.
- Parser crashes or panics on malformed files.
- Resource exhaustion from crafted samples.
- Incorrect output paths or unsafe file writes.
- Report-generation bugs that expose unintended data.
- Dangerous behavior such as accidental sample execution.
- Vulnerabilities introduced by future dependencies.

FlatScan is intended to perform static analysis only. Any behavior that executes a target sample is considered a serious security issue.

## Reporting Security Issues

Report issues through:

https://github.com/Masriyan/FlatScan

If the issue includes sensitive details, do not post live malware, private tokens, credentials, victim data, or exploit payloads publicly. Provide a minimal reproducer when possible.

## Safe Malware Handling

Recommended analyst workflow:

- Use an isolated VM.
- Keep the VM snapshotted.
- Disable shared clipboard and shared folders unless required.
- Do not run samples on production hosts.
- Keep samples in a dedicated directory.
- Avoid opening samples with GUI tools that may execute active content.
- Store live samples in password-protected archives when sharing.
- Keep generated reports and raw samples separated.

## Static Analysis Disclaimer

FlatScan does not execute target samples. It reads bytes and parses metadata. However:

- File parsers can still have bugs.
- Malformed inputs can trigger high memory or CPU usage.
- Static analysis can miss malicious behavior.
- A clean-looking report is not proof that a file is benign.

Use FlatScan as one component in a broader workflow that may include sandboxing, reverse engineering, endpoint telemetry, network telemetry, and threat intelligence.

## Output Security

Generated reports may contain:

- Malware C2 URLs.
- Webhook tokens.
- API paths.
- Registry keys.
- Internal paths.
- Extracted strings with secrets.
- Hashes and metadata.

Handle reports as sensitive incident artifacts. Do not publish reports without reviewing them for exposed tokens or victim-specific data.

## YARA Rule Safety

FlatScan can generate YARA rules with `--yara`.

Generated YARA rules:

- Are intended for hunting and triage.
- Should be reviewed before production deployment.
- May include sensitive strings or URLs.
- May be too broad or too narrow depending on the sample.

Validate rules with your YARA engine and test against known-good corpora before using them for blocking decisions.

## PDF Report Safety

PDF reports are generated locally by FlatScan. They may include suspicious URLs or strings. Do not click links from malware reports on production systems.

## Network Behavior

Current FlatScan analysis is local and static. It does not query external services by default.

If future enrichment features are added, they should be:

- Explicitly enabled by the user.
- Clearly documented.
- Safe for sensitive incident data.
- Easy to disable in offline environments.

## Dependency Policy

The project currently avoids third-party Go dependencies. If dependencies are added later:

- Prefer well-maintained libraries.
- Pin versions.
- Document why the dependency is needed.
- Review parser and archive-handling libraries carefully.

## Responsible Use

FlatScan is intended for defensive malware analysis, incident response, threat hunting, and education. Do not use it to improve malware deployment, evasion, or unauthorized activity.
