package main

import (
	"debug/elf"
	"encoding/binary"
	"math"
	"testing"
)

// codeWindow derives a [start,end) slice range from ELF/PE header fields that
// are entirely attacker-controlled, using unsigned arithmetic that gosec flags
// as overflow-prone (G115 at disasm.go:92/96/270/295/300). AnalyzeCode then
// slices data[codeStart:codeEnd], and a slice expression panics whenever the
// range is out of bounds or inverted.
//
// These tests pin the two distinct defenses that make those conversions safe,
// so a future change cannot quietly remove either:
//
//  1. Go's debug/elf rejects the arithmetic-wrapping headers outright — a
//     section whose offset or size does not fit in an int64 fails at
//     elf.NewFile, before FlatScan sees it. The first three cases below are
//     rejected there.
//  2. AnalyzeCode's own `codeStart < 0 || codeStart >= len(data)` guard catches
//     what the stdlib accepts. The "offset past end of file" case IS accepted by
//     debug/elf and does reach FlatScan; deleting that guard makes the suite
//     fail with "slice bounds out of range [4294967040:4096]".
//
// The second case is the one that matters: it is the only fixture here that
// exercises FlatScan's own bounds logic, and it is why the guard must stay.

// buildELF64 assembles a minimal but structurally valid 64-bit little-endian
// ELF whose single section carries caller-chosen Addr/Offset/Size fields, so a
// test can drive codeWindow's arithmetic directly.
func buildELF64(t *testing.T, entry, secAddr, secOffset, secSize uint64, totalLen int) []byte {
	t.Helper()

	const (
		ehSize     = 64
		shEntSize  = 64
		shNum      = 2 // index 0 is the mandatory SHT_NULL entry
		shOff      = ehSize
		sectionEnd = shOff + shEntSize*shNum
	)
	if totalLen < sectionEnd {
		totalLen = sectionEnd
	}
	buf := make([]byte, totalLen)

	// ELF identification.
	copy(buf[0:4], []byte{0x7F, 'E', 'L', 'F'})
	buf[4] = byte(elf.ELFCLASS64)
	buf[5] = byte(elf.ELFDATA2LSB)
	buf[6] = byte(elf.EV_CURRENT)
	buf[7] = byte(elf.ELFOSABI_NONE)

	le := binary.LittleEndian
	le.PutUint16(buf[16:], uint16(elf.ET_EXEC))
	le.PutUint16(buf[18:], uint16(elf.EM_X86_64))
	le.PutUint32(buf[20:], uint32(elf.EV_CURRENT))
	le.PutUint64(buf[24:], entry)  // e_entry
	le.PutUint64(buf[32:], 0)      // e_phoff (no program headers)
	le.PutUint64(buf[40:], shOff)  // e_shoff
	le.PutUint16(buf[52:], ehSize) // e_ehsize
	le.PutUint16(buf[58:], shEntSize)
	le.PutUint16(buf[60:], shNum)
	le.PutUint16(buf[62:], 0) // e_shstrndx -> the SHT_NULL entry

	// Section header 1: executable, carrying the hostile Addr/Offset/Size.
	sh := buf[shOff+shEntSize:]
	le.PutUint32(sh[0:], 0)                        // sh_name
	le.PutUint32(sh[4:], uint32(elf.SHT_PROGBITS)) // sh_type
	le.PutUint64(sh[8:], uint64(elf.SHF_EXECINSTR|elf.SHF_ALLOC))
	le.PutUint64(sh[16:], secAddr)   // sh_addr
	le.PutUint64(sh[24:], secOffset) // sh_offset
	le.PutUint64(sh[32:], secSize)   // sh_size

	return buf
}

// TestAnalyzeCodeELFSectionOverflowDoesNotPanic is the regression test for the
// wrap. sh_offset is near the top of the uint64 range and sh_size pushes it
// over, so Offset+Size wraps to a small value while the computed start stays
// large — producing end < start.
func TestAnalyzeCodeELFSectionOverflowDoesNotPanic(t *testing.T) {
	const dataLen = 4096

	cases := []struct {
		name                      string
		entry, addr, offset, size uint64
	}{
		{
			name:   "offset+size wraps past uint64 max",
			entry:  0x1000,
			addr:   0x1000,
			offset: 0xFFFFFFFFFFFFFF00,
			size:   0x200,
		},
		{
			name:   "size alone is uint64 max",
			entry:  0x1000,
			addr:   0x1000,
			offset: 0x40,
			size:   0xFFFFFFFFFFFFFFFF,
		},
		{
			name:   "entry far beyond addr yields a huge start",
			entry:  0xFFFFFFFFFFFFFF00,
			addr:   0x0,
			offset: 0x40,
			size:   0xFFFFFFFFFFFFFFFF,
		},
		{
			name:   "offset past end of file with plausible size",
			entry:  0x1000,
			addr:   0x1000,
			offset: 0xFFFFFF00,
			size:   0x100,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := buildELF64(t, tc.entry, tc.addr, tc.offset, tc.size, dataLen)

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("AnalyzeCode panicked on crafted ELF section header: %v", r)
				}
			}()

			result := &ScanResult{FileType: "ELF binary"}
			t.Cleanup(func() { releaseFindingIndex(result) })
			AnalyzeCode(result, Config{Mode: "standard"}, data)
		})
	}
}

// TestAnalyzeCodeRejectsInvertedWindow exercises the defense-in-depth guard on
// the range itself.
//
// Honest scope: no ELF/PE was found that actually drives codeWindow to return
// end < start — this fixture is rejected earlier (mode 0, because a zero-sized
// section cannot contain the entry point). The test therefore documents the
// invariant and keeps the path exercised; it is not a reproduction of a live
// crash, and deleting the guard in disasm.go does not make it fail.
func TestAnalyzeCodeRejectsInvertedWindow(t *testing.T) {
	data := buildELF64(t, 0x1000, 0x1000, 0x800, 0, 4096)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("AnalyzeCode panicked on an inverted code window: %v", r)
		}
	}()

	result := &ScanResult{FileType: "ELF binary"}
	t.Cleanup(func() { releaseFindingIndex(result) })
	AnalyzeCode(result, Config{Mode: "standard"}, data)
}

// TestSaturatingConversions pins the helpers that keep parser arithmetic from
// wrapping. Wrapping is the dangerous failure: it turns an absurd 64-bit field
// into a small plausible number (or a negative offset) that passes later
// bounds checks.
func TestSaturatingConversions(t *testing.T) {
	t.Run("saturateU32", func(t *testing.T) {
		tests := []struct {
			in   uint64
			want uint32
		}{
			{0, 0},
			{1234, 1234},
			{math.MaxUint32, math.MaxUint32},
			{math.MaxUint32 + 1, math.MaxUint32},
			{0x1_0000_0100, math.MaxUint32}, // would truncate to 0x100
			{math.MaxUint64, math.MaxUint32},
		}
		for _, tt := range tests {
			if got := saturateU32(tt.in); got != tt.want {
				t.Fatalf("saturateU32(0x%X) = 0x%X, want 0x%X", tt.in, got, tt.want)
			}
		}
	})

	t.Run("saturateI64", func(t *testing.T) {
		tests := []struct {
			in   uint64
			want int64
		}{
			{0, 0},
			{1234, 1234},
			{math.MaxInt64, math.MaxInt64},
			{math.MaxInt64 + 1, math.MaxInt64},
			{math.MaxUint64, math.MaxInt64}, // would wrap to -1
		}
		for _, tt := range tests {
			got := saturateI64(tt.in)
			if got != tt.want {
				t.Fatalf("saturateI64(0x%X) = %d, want %d", tt.in, got, tt.want)
			}
			if got < 0 {
				t.Fatalf("saturateI64(0x%X) returned a negative offset (%d)", tt.in, got)
			}
		}
	})
}

// TestCodeWindowNeverReturnsInvertedRange asserts the invariant directly rather
// than only observing that nothing panicked: whenever codeWindow reports a
// usable window, start must be within the buffer and end must not precede it.
func TestCodeWindowNeverReturnsInvertedRange(t *testing.T) {
	cases := []struct {
		name                      string
		entry, addr, offset, size uint64
	}{
		{"wrapping offset", 0x1000, 0x1000, 0xFFFFFFFFFFFFFF00, 0x200},
		{"max size", 0x1000, 0x1000, 0x40, 0xFFFFFFFFFFFFFFFF},
		{"huge entry", 0xFFFFFFFFFFFFFF00, 0x0, 0x40, 0xFFFFFFFFFFFFFFFF},
		{"sane values", 0x1000, 0x1000, 0x40, 0x100},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := buildELF64(t, tc.entry, tc.addr, tc.offset, tc.size, 4096)
			mode, start, end, _ := codeWindow("ELF binary", data)
			if mode == 0 {
				return // window rejected outright, which is a valid outcome
			}
			if start < 0 || start >= int64(len(data)) {
				t.Fatalf("codeWindow returned start=%d outside buffer of %d bytes", start, len(data))
			}
			if end < start {
				t.Fatalf("codeWindow returned an inverted range [%d:%d]; slicing this panics", start, end)
			}
		})
	}
}
