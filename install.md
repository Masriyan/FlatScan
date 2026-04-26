# Installation

Repository: [https://github.com/Masriyan/FlatScan](https://github.com/Masriyan/FlatScan)

---

## Requirements

| Requirement | Details |
|---|---|
| **Go** | 1.22 or newer |
| **OS** | Linux, macOS, or Windows |
| **Shell** | Any terminal with a working Go toolchain |
| **YARA CLI** | Optional — for validating generated `.yar` rules externally |

FlatScan uses the Go standard library only. No third-party Go modules are required. No internet access is needed at build time after cloning.

---

## Clone

```bash
git clone https://github.com/Masriyan/FlatScan
cd FlatScan
```

If the source is already on disk:

```bash
cd /path/to/FlatScan
```

---

## Build

```bash
go build -o flatscan .
```

If the default Go build cache is restricted (common in sandboxed or shared lab environments):

```bash
GOCACHE=/tmp/flatscan-go-build go build -o flatscan .
```

---

## Verify

Run the test suite:

```bash
go test ./...
```

With a restricted cache:

```bash
GOCACHE=/tmp/flatscan-go-build go test ./...
```

Check the binary:

```bash
./flatscan --version
./flatscan --help
```

Expected version output:

```
FlatScan 0.1.0
```

Smoke test against a benign file to confirm output is working:

```bash
./flatscan -m quick -f README.md --report-mode minimal --no-progress
```

---

## Install Into PATH (Optional)

**Linux / macOS:**

```bash
sudo install -m 0755 flatscan /usr/local/bin/flatscan
flatscan --help
```

**Windows (PowerShell, run as Administrator):**

```powershell
Copy-Item .\flatscan.exe C:\Windows\System32\flatscan.exe
flatscan --help
```

If you prefer not to install globally, run from the project directory:

```bash
./flatscan --help
```

---

## Cross-Compilation

FlatScan compiles cleanly for all major platforms from any host.

| Target | Command |
|---|---|
| Linux x86-64 | `GOOS=linux GOARCH=amd64 go build -o flatscan-linux-amd64 .` |
| Linux ARM64 | `GOOS=linux GOARCH=arm64 go build -o flatscan-linux-arm64 .` |
| Windows x86-64 | `GOOS=windows GOARCH=amd64 go build -o flatscan.exe .` |
| macOS Intel | `GOOS=darwin GOARCH=amd64 go build -o flatscan-darwin-amd64 .` |
| macOS Apple Silicon | `GOOS=darwin GOARCH=arm64 go build -o flatscan-darwin-arm64 .` |

Useful when building from a CI runner or deploying to a different lab machine architecture.

---

## Project File Layout

```
FlatScan/
├── main.go             # CLI entry point, flag parsing, orchestration
├── scanner.go          # Core analysis pipeline
├── signatures.go       # Behavioral and malware-family signature rules
├── expert.go           # Malware profile enrichment and MITRE TTP mapping
├── pdf.go              # PDF report renderer
├── yara.go             # YARA rule generator
├── report.go           # Text and JSON report renderer
├── README.md
├── install.md
├── usage.md
├── security.md
├── contributing.md
└── changelog.md
```

Generated outputs are typically placed under:

```
reports/
├── sample.full.txt
├── sample.iocs.txt
├── sample.report.json
├── sample.ciso.pdf
└── sample.yar
```

Keep the `reports/` directory separate from the source tree and outside of version control when it contains real malware artifacts.

---

## Docker / Container Setup (Recommended for Shared Labs)

If your lab policy requires process isolation, FlatScan can run inside a minimal container.

Example `Dockerfile`:

```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY . .
RUN go build -o flatscan .

FROM alpine:latest
RUN adduser -D analyst
WORKDIR /home/analyst
COPY --from=builder /build/flatscan .
USER analyst
ENTRYPOINT ["./flatscan"]
```

Build and run:

```bash
docker build -t flatscan:latest .
docker run --rm \
  -v /path/to/samples:/samples:ro \
  -v /path/to/reports:/reports \
  flatscan:latest \
  -m deep -f /samples/sample.exe \
  --report-mode Full \
  --json /reports/sample.json \
  --pdf /reports/sample.pdf \
  --no-progress
```

Mounting samples read-only (`ro`) prevents accidental writes into the sample directory.

---

## Safe Lab Setup

| Recommendation | Reason |
|---|---|
| Use an isolated VM with snapshots | Roll back cleanly after handling live samples |
| Disable shared clipboard | Prevents accidental paste of malicious strings |
| Disable shared folders unless required | Limits lateral movement risk from crafted samples |
| No direct access to production networks | C2 connections cannot reach the internet |
| Dedicated sample storage directory | Keeps live malware clearly separated |
| Password-protected archives for sample transfer | Prevents accidental execution during file transfer |
| Separate output directory for reports | Avoids mixing incident artifacts with source code |

FlatScan does not execute the target file. Parser bugs are still possible on malformed or adversarially crafted inputs. Always work in a disposable environment.

---

## Troubleshooting

**`go: command not found`**
Install Go from [https://golang.org/dl/](https://golang.org/dl/) and ensure `$GOPATH/bin` and the Go install directory are on your `PATH`.

**`permission denied` when running `./flatscan`**
Mark the binary executable:
```bash
chmod +x flatscan
```

**Build cache errors in restricted environments**
Use a writable temp directory:
```bash
GOCACHE=/tmp/flatscan-go-build go build -o flatscan .
```

**`go test` failures**
Run tests individually to isolate the failure:
```bash
go test -v -run TestIOCExtraction ./...
```

**Large memory usage on huge samples**
FlatScan limits in-memory analysis via `--max-analyze-bytes` (default 256 MB). The full file is still hashed. Adjust if needed:
```bash
./flatscan -m deep -f huge-sample.bin --max-analyze-bytes 134217728
```
