# Installation

Repository: https://github.com/Masriyan/FlatScan

This document explains how to install, build, and verify FlatScan.

## Requirements

- Go 1.22 or newer.
- Linux, macOS, or Windows with a working Go toolchain.
- A terminal/shell.
- Optional: YARA CLI if you want to validate generated `.yar` rules externally.

FlatScan currently uses the Go standard library only. It does not require third-party Go modules.

## Clone

```bash
git clone https://github.com/Masriyan/FlatScan
cd FlatScan
```

If you already have the source directory, enter it:

```bash
cd /path/to/FlatScan
```

## Build

```bash
go build -o flatscan .
```

Restricted environments may block the default Go build cache. In that case:

```bash
GOCACHE=/tmp/flatscan-go-build go build -o flatscan .
```

## Verify

Run tests:

```bash
GOCACHE=/tmp/flatscan-go-build go test ./...
```

Check the binary:

```bash
./flatscan --version
./flatscan --help
```

Expected version output format:

```text
FlatScan 0.1.0
```

## Optional Install Into PATH

Linux/macOS:

```bash
sudo install -m 0755 flatscan /usr/local/bin/flatscan
```

Then run:

```bash
flatscan --help
```

If you do not want to install globally, run it from the project directory:

```bash
./flatscan --help
```

## Build For Another Platform

Examples:

```bash
GOOS=linux GOARCH=amd64 go build -o flatscan-linux-amd64 .
GOOS=windows GOARCH=amd64 go build -o flatscan.exe .
GOOS=darwin GOARCH=arm64 go build -o flatscan-darwin-arm64 .
```

## Directory Layout

Typical project files:

```text
.
├── main.go
├── scanner.go
├── signatures.go
├── expert.go
├── pdf.go
├── yara.go
├── report.go
├── README.md
├── install.md
├── usage.md
├── security.md
├── contributing.md
└── changelog.md
```

Generated outputs are commonly placed under:

```text
reports/
```

## Safe Lab Setup

Recommended malware-analysis environment:

- Isolated VM with snapshots.
- No shared clipboard or shared folders unless required.
- No direct access to production networks.
- Dedicated sample storage directory.
- Password-protected archives for sample transfer.
- Separate output directory for reports.

FlatScan does not execute the target file, but sample handling still requires care.
