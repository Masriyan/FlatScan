# Web UI

FlatScan ships a small local web GUI for analysts who prefer a browser to the CLI. It is deliberately minimal and hardened for local use only.

## Launching

```bash
./flatscan --web                 # binds 127.0.0.1:5000
./flatscan --web --web-port 8080 # choose a different local port
```

Open `http://127.0.0.1:<port>/` in a browser on the same host. Upload a file and FlatScan runs the same static analysis pipeline as the CLI and renders the result.

> `--web` cannot be combined with `-f`/`--file` or `--dir` — the browser is the input surface. Passing both is a usage error (exit code 2). An out-of-range `--web-port` is also rejected. See [CLI Reference](CLI-Reference#mutually-exclusive-flag-combinations-rejected-with-exit-2).

## Security Model: Localhost-Only, No Auth

- The server **binds `127.0.0.1` only** — it is not reachable from other hosts on the network by design.
- There is **no authentication**. This is safe *because* it is bound to loopback and expected to be used by the local operator only.
- **Do not expose it to a network.** Do not port-forward it, do not put it behind a reverse proxy on a public interface, and do not bind it to `0.0.0.0`. If multiple people need access, run separate local instances inside their own isolated environments.

## Upload Limits

Uploads are capped at **256 MB** to bound memory and protect the analysis host. Oversized uploads are rejected. The same resource caps that apply to the CLI (archive-member and carve caps) apply to web scans.

## Result Tabs

After a scan the result view organizes output into tabs, typically covering:

- **Overview / Verdict** — risk score, verdict, and headline classification.
- **Findings** — the full finding list with severity, MITRE tactic/technique, and evidence.
- **IOCs** — extracted and classified indicators.
- **File / PE intelligence** — format details and PE posture.
- **Payload tree** — recursively resolved obfuscation layers.

## Downloading Outputs

The result page lets you download the generated artifacts (e.g. JSON, and the other report formats) so you can archive them or feed them into other tooling — the same artifacts described in [Output Formats](Output-Formats).

## Hardening

The web server is built to safely serve results derived from live malware:

- **Strict Content-Security-Policy (CSP)** to constrain what the page can load/execute.
- **`X-Frame-Options`** to prevent click-jacking / framing.
- **HTTP read/write timeouts** so slow or malicious clients cannot tie up the server.
- **Filename sanitization** on uploads so attacker-controlled names cannot cause path traversal or injection.
- **XSS-safe rendering** — all attacker-controlled data (strings, IOCs, filenames) is escaped before it reaches the DOM.
- **256 MB upload cap** to bound resource use.

Related: [Quick Start](Quick-Start) · [CLI Reference](CLI-Reference) · [Troubleshooting](Troubleshooting#web-port-conflicts).
