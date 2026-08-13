# internal/x86asm — vendored x86 instruction decoder

This package is an **unmodified copy** of `golang.org/x/arch/x86/x86asm` at
**v0.28.0**, redistributed under its original BSD-3-Clause licence
(`LICENSE`, Copyright 2015 The Go Authors).

## Why it is vendored rather than required

FlatScan analyses live malware, frequently on air-gapped or otherwise isolated
hosts. Vendoring the decoder means `go.mod` requires nothing, there is no
`go.sum`, and `go build` needs no module download and no network access — the
tree is self-contained. It also means the supply chain for a tool that handles
hostile input is exactly what is checked into this repository, which is a
property worth having for this class of software.

`disasm.go` is the only consumer. It uses `Decode`, the `Inst`/`Arg` types, and
about fifteen opcode and register constants.

## Do not edit these files

They are held to upstream's standards, not FlatScan's, and are excluded from
`golangci-lint` in `.golangci.yml` for that reason. Keeping them byte-identical
is what allows a re-sync to stay a plain copy instead of becoming a merge. Any
local fix belongs upstream first.

## Re-syncing with upstream

```bash
VERSION=v0.28.0   # bump as needed
go mod download -x golang.org/x/arch@$VERSION
M=$(go env GOMODCACHE)/golang.org/x/arch@$VERSION
cp $M/x86/x86asm/{avx,avx_tables,decode,inst,intel,gnu,plan9x,tables}.go internal/x86asm/
cp $M/LICENSE internal/x86asm/LICENSE
chmod +w internal/x86asm/*
```

The package declaration is already `package x86asm` and the import path is
rewritten only at the call site (`disasm.go`), so no edits to the copied files
are required. Verify with the full block afterwards:

```bash
go build ./... && go vet ./... && go test -race ./... && golangci-lint run ./...
```

Upstream: https://pkg.go.dev/golang.org/x/arch/x86/x86asm
