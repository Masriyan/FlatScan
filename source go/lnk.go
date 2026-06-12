package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

// Windows shortcut (.lnk) analysis.
//
// FlatScan previously had no LNK parser, so malicious shortcuts fell through to
// "unknown binary" and their entire payload — the embedded command line — was
// never structurally extracted. Malicious LNKs are a top initial-access vector:
// they point at a LOLBin (powershell.exe, cmd.exe, mshta.exe...) and carry a
// download/execute cradle in the CommandLineArguments block, frequently with a
// reversed-string or encoded URL. The live sample launched powershell.exe with
// a reversed-URL DownloadFile cradle and scored only 22 before this analyzer.
//
// This is a focused parser of the MS-SHLLINK ShellLinkHeader + StringData
// blocks (enough to recover the target and arguments); it does not aim to be a
// complete LNK implementation.

// lnkCLSID is the LinkCLSID that follows the 0x4C header size in every shell
// link: {00021401-0000-0000-C000-000000000046} in little-endian byte order.
var lnkCLSID = []byte{
	0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
}

// LinkFlags bits we care about (MS-SHLLINK 2.1.1).
const (
	lnkHasLinkTargetIDList = 1 << 0
	lnkHasLinkInfo         = 1 << 1
	lnkHasName             = 1 << 2
	lnkHasRelativePath     = 1 << 3
	lnkHasWorkingDir       = 1 << 4
	lnkHasArguments        = 1 << 5
	lnkHasIconLocation     = 1 << 6
	lnkIsUnicode           = 1 << 7
)

// lolbinTargets are interpreter / living-off-the-land binaries whose presence
// as a shortcut target is a strong malicious signal.
var lolbinTargets = []string{
	"powershell.exe", "powershell", "pwsh.exe", "cmd.exe", "wscript.exe",
	"cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "msbuild.exe",
	"installutil.exe", "certutil.exe", "bitsadmin.exe", "conhost.exe",
	"forfiles.exe", "wmic.exe", "msiexec.exe", "explorer.exe",
}

func looksLNK(data []byte) bool {
	if len(data) < 0x4C {
		return false
	}
	if binary.LittleEndian.Uint32(data[:4]) != 0x4C {
		return false
	}
	return bytes.Equal(data[4:20], lnkCLSID)
}

func analyzeLNK(result *ScanResult, cfg Config, data []byte) error {
	if !looksLNK(data) {
		return nil
	}
	flags := binary.LittleEndian.Uint32(data[20:24])
	unicode := flags&lnkIsUnicode != 0

	pos := 0x4C // end of fixed ShellLinkHeader

	// Skip LinkTargetIDList: a 2-byte size prefix followed by the ID list.
	if flags&lnkHasLinkTargetIDList != 0 {
		if pos+2 > len(data) {
			return nil
		}
		idListSize := int(binary.LittleEndian.Uint16(data[pos : pos+2]))
		pos += 2 + idListSize
	}
	// Skip LinkInfo: a 4-byte total-size prefix.
	if flags&lnkHasLinkInfo != 0 {
		if pos+4 > len(data) {
			return nil
		}
		linkInfoSize := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
		pos += linkInfoSize
	}

	var name, relativePath, workingDir, arguments, iconLocation string
	readBlock := func() string {
		s, next, ok := readLNKStringData(data, pos, unicode)
		if !ok {
			pos = len(data) + 1 // force remaining reads to no-op
			return ""
		}
		pos = next
		return s
	}
	if flags&lnkHasName != 0 {
		name = readBlock()
	}
	if flags&lnkHasRelativePath != 0 {
		relativePath = readBlock()
	}
	if flags&lnkHasWorkingDir != 0 {
		workingDir = readBlock()
	}
	if flags&lnkHasArguments != 0 {
		arguments = readBlock()
	}
	if flags&lnkHasIconLocation != 0 {
		iconLocation = readBlock()
	}

	target := strings.ToLower(relativePath + " " + name)
	combinedCmd := strings.TrimSpace(relativePath + " " + arguments)

	// Target points at an interpreter / LOLBin.
	if hitTarget := firstLOLBin(target); hitTarget != "" {
		AddFindingDetailed(result, "High", "Execution",
			"Shortcut launches a command interpreter",
			"the .lnk target resolves to "+hitTarget+" (RelativePath: "+strings.TrimSpace(relativePath)+")",
			22, 0,
			"Execution", "User Execution: Malicious File (T1204.002)",
			"A shortcut whose target is a script interpreter/LOLBin is almost never benign; review the full command line and any downloaded payload.")
	}

	// An oversized LNK indicates an appended/embedded payload (LNKs are tiny).
	if len(data) > 8*1024 {
		AddFindingDetailed(result, "Medium", "Packing",
			"Unusually large shortcut file",
			"the .lnk is larger than expected for a shortcut, suggesting an appended or embedded payload",
			10, 0,
			"Defense Evasion", "Obfuscated Files or Information (T1027)",
			"Carve the shortcut for an appended executable/script payload.")
	}

	// Run the embedded command line through the shared script behavioral engine
	// (download cradle, defense evasion, obfuscation, reversed-URL recovery).
	if strings.TrimSpace(arguments) != "" || combinedCmd != "" {
		scanScriptContent(result, cfg, combinedCmd+"\n"+arguments, "LNK command line")
	}

	if strings.Contains(iconLocation, "%") || strings.Contains(strings.ToLower(workingDir), "temp") {
		AddFinding(result, "Low", "Execution", "Shortcut uses environment-variable paths",
			"working directory or icon path uses environment variables: "+previewString(workingDir+" "+iconLocation, 120), 4, 0)
	}

	return nil
}

// readLNKStringData reads a StringData block: a 2-byte CountCharacters prefix
// followed by the string (UTF-16LE when unicode, else ANSI). Returns the string,
// the position just past it, and ok=false on a malformed/out-of-range block.
func readLNKStringData(data []byte, pos int, unicode bool) (string, int, bool) {
	if pos < 0 || pos+2 > len(data) {
		return "", pos, false
	}
	count := int(binary.LittleEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if unicode {
		byteLen := count * 2
		if pos+byteLen > len(data) {
			return "", pos, false
		}
		u16 := make([]uint16, count)
		for i := 0; i < count; i++ {
			u16[i] = binary.LittleEndian.Uint16(data[pos+i*2 : pos+i*2+2])
		}
		return string(utf16.Decode(u16)), pos + byteLen, true
	}
	if pos+count > len(data) {
		return "", pos, false
	}
	return string(data[pos : pos+count]), pos + count, true
}

func firstLOLBin(haystack string) string {
	for _, bin := range lolbinTargets {
		if strings.Contains(haystack, bin) {
			return bin
		}
	}
	return ""
}
