package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
)

// PE OptionalHeader.DllCharacteristics flags. debug/pe does not export these,
// so they are defined here per the Microsoft PE/COFF specification.
const (
	dllCharHighEntropyVA       = 0x0020
	dllCharDynamicBase         = 0x0040 // ASLR
	dllCharForceIntegrity      = 0x0080
	dllCharNXCompat            = 0x0100 // DEP
	dllCharNoSEH               = 0x0400
	dllCharAppContainer        = 0x1000
	dllCharGuardCF             = 0x4000 // Control Flow Guard
	dllCharTerminalServerAware = 0x8000
)

// PE FileHeader.Characteristics flags (PE/COFF spec).
const (
	imageFileRelocsStripped    = 0x0001
	imageFileExecutableImage   = 0x0002
	imageFileLargeAddressAware = 0x0020
	imageFileDLL               = 0x2000
)

// decodeDllCharacteristics returns the human-readable exploit mitigations that
// are enabled, plus which of the modern baseline {ASLR, DEP, CFG} are absent.
// Naming follows the winchecksec / BinSkim / PESecurity convention.
func decodeDllCharacteristics(v uint16) (enabled, missing []string) {
	if v&dllCharDynamicBase != 0 {
		enabled = append(enabled, "ASLR")
	} else {
		missing = append(missing, "ASLR")
	}
	if v&dllCharNXCompat != 0 {
		enabled = append(enabled, "DEP")
	} else {
		missing = append(missing, "DEP")
	}
	if v&dllCharGuardCF != 0 {
		enabled = append(enabled, "CFG")
	} else {
		missing = append(missing, "CFG")
	}
	if v&dllCharHighEntropyVA != 0 {
		enabled = append(enabled, "HighEntropyVA")
	}
	if v&dllCharForceIntegrity != 0 {
		enabled = append(enabled, "ForceIntegrity")
	}
	if v&dllCharNoSEH != 0 {
		enabled = append(enabled, "NoSEH")
	}
	if v&dllCharAppContainer != 0 {
		enabled = append(enabled, "AppContainer")
	}
	if v&dllCharTerminalServerAware != 0 {
		enabled = append(enabled, "TerminalServerAware")
	}
	return enabled, missing
}

// decodeImageCharacteristics decodes the FileHeader.Characteristics bitmask.
func decodeImageCharacteristics(v uint16) []string {
	var out []string
	if v&imageFileRelocsStripped != 0 {
		out = append(out, "RELOCS_STRIPPED")
	}
	if v&imageFileExecutableImage != 0 {
		out = append(out, "EXECUTABLE_IMAGE")
	}
	if v&imageFileLargeAddressAware != 0 {
		out = append(out, "LARGE_ADDRESS_AWARE")
	}
	if v&imageFileDLL != 0 {
		out = append(out, "DLL")
	}
	return out
}

// computeRichHeaderHash extracts the MSVC "Rich" header from the DOS stub,
// XOR-decodes the comp-id array (DanS..Rich), and returns its SHA-256. Returns
// "" when the Rich header is absent (non-MSVC, stripped, or forged). Algorithm
// per Daniel Pistelli's reverse engineering of the undocumented Rich header.
func computeRichHeaderHash(data []byte) string {
	if len(data) < 0x40 {
		return ""
	}
	elfanew := int(binary.LittleEndian.Uint32(data[0x3C:0x40]))
	if elfanew <= 0 || elfanew > len(data) {
		elfanew = len(data)
	}
	region := data[:elfanew]
	richIdx := bytes.LastIndex(region, []byte("Rich"))
	if richIdx < 0 || richIdx+8 > len(region) {
		return ""
	}
	key := binary.LittleEndian.Uint32(region[richIdx+4 : richIdx+8])
	const danS = 0x536E6144 // "DanS" little-endian
	dansIdx := -1
	for off := richIdx - 4; off >= 0; off -= 4 {
		if binary.LittleEndian.Uint32(region[off:off+4])^key == danS {
			dansIdx = off
			break
		}
	}
	if dansIdx < 0 {
		return ""
	}
	clear := make([]byte, richIdx-dansIdx)
	for i := 0; i < len(clear); i += 4 {
		v := binary.LittleEndian.Uint32(region[dansIdx+i:dansIdx+i+4]) ^ key
		binary.LittleEndian.PutUint32(clear[i:i+4], v)
	}
	sum := sha256.Sum256(clear)
	return hex.EncodeToString(sum[:])
}

// rvaToOffset maps a relative virtual address to a file offset using the PE
// section table. Returns false when the RVA falls outside every section.
func rvaToOffset(file *pe.File, rva uint32) (int, bool) {
	for _, s := range file.Sections {
		size := s.VirtualSize
		if size == 0 {
			size = s.Size
		}
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+size {
			return int(s.Offset + (rva - s.VirtualAddress)), true
		}
	}
	return 0, false
}

// peSectionForRVA returns the name of the section containing the RVA and whether
// that section is writable. found is false when the RVA is outside all sections.
func peSectionForRVA(file *pe.File, rva uint32) (name string, writable, found bool) {
	for _, s := range file.Sections {
		size := s.VirtualSize
		if size == 0 {
			size = s.Size
		}
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+size {
			return s.Name, s.Characteristics&pe.IMAGE_SCN_MEM_WRITE != 0, true
		}
	}
	return "", false, false
}

// parseTLSCallbacks counts the TLS callback routines registered in the PE. These
// execute before the entry point and are a classic anti-debug / early-execution
// technique. Conservative: when the TLS directory is present but its structure
// cannot be resolved (e.g. truncated data), it returns 1 (presence). Returns 0
// when there is no TLS directory or no callbacks are registered.
func parseTLSCallbacks(file *pe.File, data []byte) int {
	var dirRVA, dirSize uint32
	var imageBase uint64
	is64 := false
	switch h := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(h.DataDirectory) <= pe.IMAGE_DIRECTORY_ENTRY_TLS {
			return 0
		}
		dirRVA = h.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress
		dirSize = h.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_TLS].Size
		imageBase = uint64(h.ImageBase)
	case *pe.OptionalHeader64:
		if len(h.DataDirectory) <= pe.IMAGE_DIRECTORY_ENTRY_TLS {
			return 0
		}
		dirRVA = h.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress
		dirSize = h.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_TLS].Size
		imageBase = h.ImageBase
		is64 = true
	default:
		return 0
	}
	if dirSize == 0 || dirRVA == 0 {
		return 0
	}
	dirOff, ok := rvaToOffset(file, dirRVA)
	if !ok {
		return 1
	}
	ptr := 4
	if is64 {
		ptr = 8
	}
	// IMAGE_TLS_DIRECTORY: AddressOfCallBacks is the 4th pointer-sized field.
	cbField := dirOff + 3*ptr
	if cbField+ptr > len(data) {
		return 1
	}
	cbVA := readPtr(data[cbField:], is64)
	if cbVA == 0 || cbVA <= imageBase {
		return 0
	}
	// AddressOfCallBacks is a full 64-bit VA on PE32+, so the RVA is a 64-bit
	// difference. Truncating it to uint32 would fold an out-of-image address
	// down into a small RVA that resolves to a valid — but entirely wrong —
	// file offset, and cbOff is then used to index data. Reject anything that
	// does not fit a real 32-bit RVA instead of wrapping it into range.
	cbRVA := cbVA - imageBase
	if cbRVA > math.MaxUint32 {
		return 1
	}
	cbOff, ok := rvaToOffset(file, uint32(cbRVA))
	if !ok {
		return 1
	}
	n := 0
	// The bounds test is the loop condition: cbOff advances by ptr each pass and
	// indexes attacker-controlled data, so it must be re-checked every iteration.
	for cbOff+ptr <= len(data) {
		if readPtr(data[cbOff:], is64) == 0 {
			break
		}
		n++
		cbOff += ptr
		if n > 64 { // sanity cap against malformed arrays
			break
		}
	}
	return n
}

func readPtr(b []byte, is64 bool) uint64 {
	if is64 {
		return binary.LittleEndian.Uint64(b[:8])
	}
	return uint64(binary.LittleEndian.Uint32(b[:4]))
}

// parseDERCertificates extracts X.509 certificates from a DER blob. It first
// tries a direct parse; if that yields nothing — the common case for an
// Authenticode WIN_CERTIFICATE, which wraps a PKCS#7/CMS SignedData rather than
// bare certificates — it scans for embedded certificate TLVs (SEQUENCE,
// 0x30 0x82 <len16>) and parses each. Avoids needing a full CMS parser.
func parseDERCertificates(blob []byte) ([]*x509.Certificate, bool) {
	if certs, err := x509.ParseCertificates(blob); err == nil && len(certs) > 0 {
		return certs, true
	}
	var out []*x509.Certificate
	for i := 0; i+4 < len(blob); i++ {
		if blob[i] != 0x30 || blob[i+1] != 0x82 {
			continue
		}
		length := int(blob[i+2])<<8 | int(blob[i+3])
		end := i + 4 + length
		if end > len(blob) {
			continue
		}
		if cert, err := x509.ParseCertificate(blob[i:end]); err == nil {
			out = append(out, cert)
			i = end - 1 // skip past the certificate we just consumed
		}
	}
	return out, len(out) > 0
}

const maxCertBlobBytes = 8 * 1024 * 1024

// extractPECertificates reads the Authenticode WIN_CERTIFICATE blob directly
// from the file at the SECURITY directory offset (the in-memory sample may be
// truncated and the blob lives at end-of-file), then recovers signer subjects
// and issuers. selfSigned is reported only for a lone subject==issuer cert (a
// real Authenticode chain contains a self-signed root, which is normal).
func extractPECertificates(r io.ReaderAt, secOffset, secSize int64) (subjects, issuers []string, status string, selfSigned bool) {
	if r == nil || secOffset <= 0 || secSize <= 8 {
		return nil, nil, "", false
	}
	if secSize > maxCertBlobBytes {
		secSize = maxCertBlobBytes
	}
	buf := make([]byte, secSize)
	n, err := r.ReadAt(buf, secOffset)
	if n <= 8 {
		if err != nil {
			return nil, nil, "signature directory present; certificate blob unreadable", false
		}
		return nil, nil, "signature directory present; truncated", false
	}
	buf = buf[:n]
	// WIN_CERTIFICATE: dwLength(4) wRevision(2) wCertificateType(2) bCertificate[].
	certs, ok := parseDERCertificates(buf[8:])
	if !ok {
		return nil, nil, "PKCS#7/CMS signature present; signer not recovered without CMS parser", false
	}
	for _, c := range certs {
		subjects = appendUnique(subjects, c.Subject.String())
		issuers = appendUnique(issuers, c.Issuer.String())
	}
	if len(certs) == 1 && certs[0].Subject.String() == certs[0].Issuer.String() {
		selfSigned = true
	}
	return subjects, issuers, fmt.Sprintf("signature present; %d certificate(s) recovered", len(certs)), selfSigned
}
