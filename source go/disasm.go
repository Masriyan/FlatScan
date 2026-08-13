package main

import (
	"bytes"
	"debug/elf"
	"debug/pe"
	"fmt"

	"golang.org/x/arch/x86/x86asm"
)

// Instruction-level (disassembly) analysis.
//
// FlatScan's behavioral detection is substring matching over an extracted-string
// corpus, which has a structural ceiling: it can only see techniques that leave
// cleartext behind. The highest-value evasions defeat exactly that — APIs are
// resolved by hash (no "VirtualAlloc" string exists), imports are resolved at
// runtime, and code is packed/encrypted. This pass disassembles the code at the
// entry point and detects those techniques at the instruction level.
//
// Scope: x86/x64 PE and ELF (the dominant native-malware targets), gated to
// standard/deep modes. Pure Go (golang.org/x/arch) — no cgo. It is defensive
// about adversarial bytes: a decode error advances one byte and never panics.

const (
	maxDisasmBytesStandard = 64 * 1024
	maxDisasmBytesDeep     = 256 * 1024
	maxDisasmInsns         = 80000
	vmwareBackdoorMagic    = 0x564D5868 // "VMXh" — VMware backdoor I/O magic
)

// AnalyzeCode runs the disassembly pass and records findings + a CodeInfo.
func AnalyzeCode(result *ScanResult, cfg Config, data []byte) {
	if result == nil || cfg.Mode == "quick" {
		return
	}
	mode, codeStart, codeEnd, arch := codeWindow(result.FileType, data)
	if mode == 0 || codeStart < 0 || codeStart >= int64(len(data)) {
		return // unsupported architecture or unmappable entry point
	}

	limit := int64(maxDisasmBytesStandard)
	if cfg.Mode == "deep" {
		limit = maxDisasmBytesDeep
	}
	if codeEnd <= 0 || codeEnd > int64(len(data)) {
		codeEnd = int64(len(data))
	}
	if codeEnd > codeStart+limit {
		codeEnd = codeStart + limit
	}
	// Defense in depth, not a fix for a known-reachable case: codeStart and
	// codeEnd are derived from separate header fields, and `data[start:end]`
	// panics if end ever precedes start. No crafted ELF/PE was found that
	// reaches this state today — debug/elf rejects the wrapping headers first —
	// so this is a cheap invariant guarding future changes to codeWindow rather
	// than a live vulnerability.
	if codeEnd <= codeStart {
		return
	}

	scanCode(result, mode, arch, data[codeStart:codeEnd], codeStart)
}

// scanCode disassembles a code buffer, records findings and a CodeInfo, and
// resolves hashed imports. Split out from AnalyzeCode so it can be unit-tested
// with hand-assembled byte sequences (no full PE/ELF fixture required).
func scanCode(result *ScanResult, mode int, arch string, code []byte, baseOffset int64) {
	info := &CodeInfo{Arch: arch, EntryOffset: baseOffset}

	var (
		rorRol13     bool
		pebAccess    bool
		getpc        bool
		vmwareMagic  bool
		cpuidHyper   bool
		redPill      bool
		rdtscCount   int
		lastEAXImm   int64 = -1
		prevCallRel0 bool
		immediates   = make(map[uint32]struct{})
	)

	off := 0
	for off < len(code) && info.InstructionsDecoded < maxDisasmInsns {
		inst, err := x86asm.Decode(code[off:], mode)
		if err != nil || inst.Len == 0 {
			info.DecodeErrors++
			off++
			prevCallRel0 = false
			continue
		}
		info.InstructionsDecoded++
		if len(info.EntryDisasm) < 16 {
			info.EntryDisasm = append(info.EntryDisasm, inst.String())
		}

		// Collect immediates for hash-database resolution (Task 2).
		for _, arg := range inst.Args {
			if imm, ok := arg.(x86asm.Imm); ok {
				// Taking the low 32 bits of the immediate is the point: API
				// hashes are 32-bit, and a sign-extended 64-bit immediate must
				// be folded back down to match the hash tables.
				v := uint32(uint64(int64(imm))) //nolint:gosec // G115: deliberate low-32-bit extraction for hash matching
				if v > 0xFFFF {                 // hashes are 32-bit and large; skip small constants
					immediates[v] = struct{}{}
				}
				// Same deliberate 32-bit fold as above: the backdoor magic is a
				// 32-bit constant, so compare only the low word.
				if uint64(int64(imm))&0xFFFFFFFF == vmwareBackdoorMagic { //nolint:gosec // G115: deliberate low-32-bit mask for constant comparison
					vmwareMagic = true
				}
			}
		}

		// PEB access via segment override. Only the PEB offsets (fs:[0x30] on
		// x86, gs:[0x60] on x64) — the TEB self-reference offsets (fs:[0x18],
		// gs:[0x30]) are read by ordinary CRT startup and would false-positive.
		for _, arg := range inst.Args {
			if m, ok := arg.(x86asm.Mem); ok {
				if mode == 32 && m.Segment == x86asm.FS && m.Disp == 0x30 {
					pebAccess = true
				}
				if mode == 64 && m.Segment == x86asm.GS && m.Disp == 0x60 {
					pebAccess = true
				}
			}
		}

		isGetpcCallThisInst := false
		switch inst.Op {
		case x86asm.ROR, x86asm.ROL:
			if imm, ok := inst.Args[1].(x86asm.Imm); ok && int64(imm) == 13 {
				rorRol13 = true
			}
		case x86asm.CPUID:
			if lastEAXImm >= 0x40000000 && lastEAXImm <= 0x4FFFFFFF {
				cpuidHyper = true
			}
		case x86asm.RDTSC:
			rdtscCount++
		case x86asm.SIDT, x86asm.SGDT, x86asm.SLDT, x86asm.STR:
			redPill = true
		case x86asm.MOV:
			if reg, ok := inst.Args[0].(x86asm.Reg); ok && (reg == x86asm.EAX || reg == x86asm.RAX) {
				if imm, ok := inst.Args[1].(x86asm.Imm); ok {
					lastEAXImm = int64(imm)
				} else {
					lastEAXImm = -1
				}
			}
		case x86asm.CALL:
			if isIndirectTarget(inst.Args[0]) {
				info.IndirectCalls++
			} else if rel, ok := inst.Args[0].(x86asm.Rel); ok && int32(rel) == 0 {
				isGetpcCallThisInst = true // call $+5 (target = next instruction)
			}
		case x86asm.JMP:
			if isIndirectTarget(inst.Args[0]) {
				info.IndirectJumps++
			}
		case x86asm.POP:
			if prevCallRel0 {
				getpc = true // call $+5 ; pop reg  => GetPC idiom
			}
		}
		prevCallRel0 = isGetpcCallThisInst
		off += inst.Len
	}

	// --- findings ---
	addTechnique := func(name string) { info.Techniques = append(info.Techniques, name) }

	if rorRol13 {
		addTechnique("API hashing (ROR13)")
		AddFindingDetailed(result, "High", "Behavior",
			"API-hashing routine",
			"the code rotates a value by 13 in a loop (the canonical ROR13 import-hashing idiom) — APIs are resolved by hash, not by name",
			24, info.EntryOffset,
			"Defense Evasion", "Obfuscated Files or Information (T1027)",
			"Resolve the hashes (FlatScan matches a hash database) to recover the real import list; treat as a loader/shellcode stage.")
	}
	if pebAccess {
		addTechnique("PEB access")
		// PEB access alone is a Medium tell (some CRTs touch the PEB); combined
		// with ROR13 import hashing it is the manual-resolution loader signature.
		if rorRol13 {
			AddFindingDetailed(result, "High", "Behavior",
				"Manual API resolution (PEB walk + hashing)",
				"the code reads the PEB (fs:[0x30]/gs:[0x60]) and hashes names — it manually maps modules and resolves exports to evade the import table",
				24, info.EntryOffset,
				"Defense Evasion", "Reflective Code Loading (T1620)",
				"Classic loader/shellcode pattern; recover the resolved imports and the manually-mapped payload.")
		} else {
			AddFindingDetailed(result, "Medium", "Behavior",
				"Direct PEB access",
				"the code reads the Process Environment Block via a segment override (fs:[0x30]/gs:[0x60]) — used by loaders/shellcode for manual module resolution",
				12, info.EntryOffset,
				"Execution", "Native API (T1106)",
				"Inspect the surrounding code for module-list traversal (Ldr / InMemoryOrderModuleList) and export resolution.")
		}
	}
	if getpc {
		addTechnique("GetPC stub")
		AddFindingDetailed(result, "Medium", "Behavior",
			"Position-independent code (GetPC) stub",
			"a call $+5 / pop idiom is present — the code resolves its own address, a hallmark of position-independent shellcode",
			16, info.EntryOffset,
			"Execution", "Native API (T1106)",
			"Carve and analyze the position-independent payload; PIC stubs usually precede a decoder or loader.")
	}
	if vmwareMagic {
		addTechnique("VMware backdoor")
		AddFindingDetailed(result, "High", "Evasion",
			"VMware backdoor detection",
			"the VMware backdoor I/O magic (0x564D5868 \"VMXh\") is used as an immediate — an instruction-level virtual-machine check",
			20, info.EntryOffset,
			"Defense Evasion", "Virtualization/Sandbox Evasion (T1497)",
			"Re-run dynamic analysis with hardened sandbox artifacts; the sample alters behavior under VMware.")
	}
	if cpuidHyper {
		addTechnique("hypervisor CPUID check")
		AddFindingDetailed(result, "Medium", "Evasion",
			"Hypervisor presence check (CPUID)",
			"CPUID is issued with a hypervisor leaf (0x40000000-0x4FFFFFFF) — an instruction-level sandbox/VM check",
			12, info.EntryOffset,
			"Defense Evasion", "Virtualization/Sandbox Evasion (T1497)",
			"Treat as anti-analysis; vary hypervisor CPUID responses in the sandbox.")
	}
	if redPill {
		addTechnique("descriptor-table check")
		AddFindingDetailed(result, "Medium", "Evasion",
			"Descriptor-table VM check (Red Pill)",
			"SIDT/SGDT/SLDT/STR is used to read a descriptor-table register — the classic Red Pill virtualization check",
			10, info.EntryOffset,
			"Defense Evasion", "Virtualization/Sandbox Evasion (T1497)",
			"Anti-VM tell; corroborate with other sandbox-evasion behavior.")
	}
	if rdtscCount >= 4 {
		addTechnique("RDTSC timing")
		AddFindingDetailed(result, "Low", "Evasion",
			"RDTSC timing checks",
			fmt.Sprintf("%d RDTSC instructions — likely timing-based sandbox/debugger detection", rdtscCount),
			6, info.EntryOffset,
			"Defense Evasion", "Time Based Evasion (T1497.003)",
			"Timing checks can stall execution under instrumentation; consider time-acceleration in the sandbox.")
	}

	result.Code = info

	// Task 2: resolve hashed imports from the collected immediates.
	resolveHashedAPIs(result, info, immediates)
}

// codeWindow returns the x86 decode mode (32 or 64), the file offset of the
// entry point, the end-of-code file offset, and an architecture label. mode 0
// means "unsupported" (non-x86 arch or unmappable entry).
func codeWindow(fileType string, data []byte) (mode int, codeStart, codeEnd int64, arch string) {
	switch fileType {
	case "PE executable":
		pf, err := pe.NewFile(bytes.NewReader(data))
		if err != nil {
			return 0, -1, 0, ""
		}
		defer pf.Close() //nolint:errcheck // read-only handle: Close discards nothing
		var entryRVA uint64
		switch oh := pf.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			entryRVA = uint64(oh.AddressOfEntryPoint)
			mode, arch = 32, "x86"
		case *pe.OptionalHeader64:
			entryRVA = uint64(oh.AddressOfEntryPoint)
			mode, arch = 64, "x86-64"
		default:
			return 0, -1, 0, ""
		}
		for _, s := range pf.Sections {
			vsize := uint64(s.VirtualSize)
			if vsize == 0 {
				vsize = uint64(s.Size)
			}
			if entryRVA >= uint64(s.VirtualAddress) && entryRVA < uint64(s.VirtualAddress)+vsize {
				// Saturate rather than wrap: a negative start would survive the
				// caller's "start < len(data)" test and panic the slice, while a
				// saturated one is rejected cleanly.
				start := entryRVA - uint64(s.VirtualAddress) + uint64(s.Offset)
				return mode, saturateI64(start), saturateI64(uint64(s.Offset) + uint64(s.Size)), arch
			}
		}
		return 0, -1, 0, ""

	case "ELF binary":
		ef, err := elf.NewFile(bytes.NewReader(data))
		if err != nil {
			return 0, -1, 0, ""
		}
		defer ef.Close() //nolint:errcheck // read-only handle: Close discards nothing
		switch ef.Machine {
		case elf.EM_386:
			mode, arch = 32, "x86"
		case elf.EM_X86_64:
			mode, arch = 64, "x86-64"
		default:
			return 0, -1, 0, ""
		}
		entry := ef.Entry
		for _, s := range ef.Sections {
			if s.Type == elf.SHT_NOBITS || s.Flags&elf.SHF_EXECINSTR == 0 {
				continue
			}
			if entry >= s.Addr && entry < s.Addr+s.Size {
				return mode, saturateI64(entry - s.Addr + s.Offset), saturateI64(s.Offset + s.Size), arch
			}
		}
		for _, p := range ef.Progs {
			if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && entry >= p.Vaddr && entry < p.Vaddr+p.Filesz {
				return mode, saturateI64(entry - p.Vaddr + p.Off), saturateI64(p.Off + p.Filesz), arch
			}
		}
		return 0, -1, 0, ""
	}
	return 0, -1, 0, ""
}

// isIndirectTarget reports whether a CALL/JMP target is indirect (register or
// memory) rather than a direct relative displacement.
func isIndirectTarget(arg x86asm.Arg) bool {
	switch arg.(type) {
	case x86asm.Reg, x86asm.Mem:
		return true
	}
	return false
}
