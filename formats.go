package main

import (
	"archive/zip"
	"crypto/md5"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func DetectFileType(data []byte, path string) string {
	lowerName := strings.ToLower(filepath.Base(path))
	switch {
	case len(data) >= 2 && data[0] == 'M' && data[1] == 'Z':
		return "PE executable"
	case len(data) >= 4 && string(data[:4]) == "\x7fELF":
		return "ELF binary"
	case hasMagic(data, []byte{0xfe, 0xed, 0xfa, 0xce}) || hasMagic(data, []byte{0xfe, 0xed, 0xfa, 0xcf}) ||
		hasMagic(data, []byte{0xce, 0xfa, 0xed, 0xfe}) || hasMagic(data, []byte{0xcf, 0xfa, 0xed, 0xfe}) ||
		hasMagic(data, []byte{0xca, 0xfe, 0xba, 0xbe}):
		if strings.HasSuffix(lowerName, ".class") {
			return "Java class"
		}
		return "Mach-O binary"
	case len(data) >= 5 && string(data[:5]) == "%PDF-":
		return "PDF document"
	case hasMagic(data, []byte{'P', 'K', 0x03, 0x04}) || hasMagic(data, []byte{'P', 'K', 0x05, 0x06}) || hasMagic(data, []byte{'P', 'K', 0x07, 0x08}):
		switch {
		case strings.HasSuffix(lowerName, ".apk"):
			return "APK package"
		case strings.HasSuffix(lowerName, ".jar"):
			return "JAR package"
		case strings.HasSuffix(lowerName, ".docx") || strings.HasSuffix(lowerName, ".xlsx") || strings.HasSuffix(lowerName, ".pptx") ||
			strings.HasSuffix(lowerName, ".docm") || strings.HasSuffix(lowerName, ".xlsm") || strings.HasSuffix(lowerName, ".pptm"):
			return "Office Open XML document"
		default:
			return "ZIP container"
		}
	case hasMagic(data, []byte{'R', 'a', 'r', '!', 0x1a, 0x07}):
		return "RAR archive"
	case hasMagic(data, []byte{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c}):
		return "7-Zip archive"
	case hasMagic(data, []byte{0x1f, 0x8b}):
		return "Gzip compressed data"
	case hasMagic(data, []byte{'B', 'Z', 'h'}):
		return "Bzip2 compressed data"
	case hasMagic(data, []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}):
		return "XZ compressed data"
	case len(data) >= 8 && string(data[:4]) == "dex\n" && data[7] == 0x00:
		return "DEX bytecode"
	case hasMagic(data, []byte{0xca, 0xfe, 0xba, 0xbe}):
		return "Java class"
	case len(data) >= 2 && data[0] == '#' && data[1] == '!':
		return "script/text"
	case looksText(data):
		return "text"
	default:
		return "unknown binary"
	}
}

func AnalyzeFormats(result *ScanResult, cfg Config, data []byte, debugf debugLogger) error {
	switch result.FileType {
	case "PE executable":
		return analyzePE(result, cfg)
	case "ELF binary":
		return analyzeELF(result, cfg)
	case "Mach-O binary":
		return analyzeMachO(result, cfg)
	case "ZIP container", "APK package", "JAR package", "Office Open XML document":
		return analyzeZIP(result, cfg, debugf)
	default:
		if strings.Contains(result.FileType, "compressed") || strings.Contains(result.FileType, "archive") {
			AddFinding(result, "Info", "Container", "Compressed or archived content", result.FileType+" detected; only ZIP-family containers are recursively inspected", 0, 0)
		}
	}
	return nil
}

func analyzePE(result *ScanResult, cfg Config) error {
	file, err := pe.Open(result.Target)
	if err != nil {
		return err
	}
	defer file.Close()

	info := &PEInfo{
		Machine:   peMachine(file.FileHeader.Machine),
		Timestamp: time.Unix(int64(file.FileHeader.TimeDateStamp), 0).UTC().Format(time.RFC3339),
	}

	if imports, err := file.ImportedSymbols(); err == nil {
		sort.Strings(imports)
		info.Imports = limitStrings(imports, importLimitForMode(cfg.Mode))
		info.ImportHash = importHash(imports)
		for _, imported := range imports {
			lower := strings.ToLower(imported)
			if strings.Contains(lower, "_corexemain") || strings.Contains(lower, "mscoree.dll") {
				info.ManagedRuntime = true
			}
			for _, api := range apiPatterns {
				if strings.Contains(lower, api.Needle) {
					result.Functions = append(result.Functions, FunctionHit{
						Name:     api.Name,
						Family:   api.Family,
						Severity: api.Severity,
						Source:   "pe imports",
					})
				}
			}
		}
		if info.ManagedRuntime {
			AddFindingDetailed(result, "Info", "PE", "Managed .NET executable", "PE imports _CorExeMain from mscoree.dll", 0, 0, "Discovery", "Software Discovery (T1518)", "Review .NET strings, resources, and configuration artifacts; managed malware often stores behavior in metadata and resources.")
		}
		if len(imports) <= 3 && result.Entropy >= 6.8 {
			AddFinding(result, "Medium", "Packing", "Sparse PE imports with elevated entropy", fmt.Sprintf("%d imports and entropy %.2f", len(imports), result.Entropy), 12, 0)
		}
	}

	switch header := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		info.Subsystem = peSubsystem(header.Subsystem)
		info.ImageBase = fmt.Sprintf("0x%x", header.ImageBase)
		info.EntryPoint = fmt.Sprintf("0x%x", header.AddressOfEntryPoint)
		if len(header.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_SECURITY {
			info.HasCertificate = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].Size > 0
		}
	case *pe.OptionalHeader64:
		info.Subsystem = peSubsystem(header.Subsystem)
		info.ImageBase = fmt.Sprintf("0x%x", header.ImageBase)
		info.EntryPoint = fmt.Sprintf("0x%x", header.AddressOfEntryPoint)
		if len(header.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_SECURITY {
			info.HasCertificate = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].Size > 0
		}
	}

	var maxRawEnd int64
	for _, section := range file.Sections {
		sectionData, _ := section.Data()
		sectionInfo := SectionInfo{
			Name:       section.Name,
			Virtual:    section.VirtualAddress,
			RawOffset:  section.Offset,
			RawSize:    section.Size,
			Entropy:    ShannonEntropy(sectionData),
			Executable: section.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE != 0,
			Writable:   section.Characteristics&pe.IMAGE_SCN_MEM_WRITE != 0,
		}
		info.Sections = append(info.Sections, sectionInfo)
		rawEnd := int64(section.Offset) + int64(section.Size)
		if rawEnd > maxRawEnd {
			maxRawEnd = rawEnd
		}

		lowerName := strings.ToLower(section.Name)
		if hasAny(lowerName, "upx", "aspack", "vmp", "themida", "mpress") {
			info.SuspiciousSections = append(info.SuspiciousSections, section.Name)
			AddFinding(result, "Medium", "Packing", "Suspicious PE section name", section.Name, 12, 0)
		}
		if sectionInfo.Executable && sectionInfo.Writable {
			AddFinding(result, "Medium", "PE", "Writable and executable PE section", section.Name, 10, int64(section.Offset))
		}
		if sectionInfo.Entropy >= 7.20 && sectionInfo.RawSize > 4096 {
			AddFinding(result, "Medium", "Packing", "High-entropy PE section", fmt.Sprintf("%s entropy %.2f", section.Name, sectionInfo.Entropy), 10, int64(section.Offset))
			if info.ManagedRuntime && strings.EqualFold(section.Name, ".rsrc") {
				AddFindingDetailed(result, "Medium", "Packing", "High-entropy .NET resource section", fmt.Sprintf("%s entropy %.2f", section.Name, sectionInfo.Entropy), 14, int64(section.Offset), "Defense Evasion", "Obfuscated Files or Information (T1027)", "Inspect .NET resources for embedded payloads, compressed configuration, or encrypted strings.")
			}
		}
	}

	if result.Size > maxRawEnd && maxRawEnd > 0 {
		info.OverlayOffset = maxRawEnd
		info.OverlaySize = result.Size - maxRawEnd
		if info.OverlaySize > 1024*1024 || info.OverlaySize > result.Size/5 {
			AddFinding(result, "Medium", "PE", "Large PE overlay", fmt.Sprintf("overlay size %d bytes", info.OverlaySize), 10, maxRawEnd)
		}
	}

	result.PE = info
	return nil
}

func analyzeELF(result *ScanResult, cfg Config) error {
	file, err := elf.Open(result.Target)
	if err != nil {
		return err
	}
	defer file.Close()

	info := &ELFInfo{
		Class:   file.Class.String(),
		Machine: file.Machine.String(),
		Type:    file.Type.String(),
	}
	if imports, err := file.ImportedSymbols(); err == nil {
		names := make([]string, 0, len(imports))
		for _, imported := range imports {
			names = append(names, imported.Name)
		}
		sort.Strings(names)
		info.Imports = limitStrings(names, importLimitForMode(cfg.Mode))
	}
	for _, section := range file.Sections {
		if section.Size == 0 {
			continue
		}
		data, _ := section.Data()
		info.Sections = append(info.Sections, SectionInfo{
			Name:       section.Name,
			Virtual:    uint32(section.Addr),
			RawOffset:  uint32(section.Offset),
			RawSize:    uint32(section.Size),
			Entropy:    ShannonEntropy(data),
			Executable: section.Flags&elf.SHF_EXECINSTR != 0,
			Writable:   section.Flags&elf.SHF_WRITE != 0,
		})
		if section.Flags&elf.SHF_EXECINSTR != 0 && section.Flags&elf.SHF_WRITE != 0 {
			AddFinding(result, "Medium", "ELF", "Writable and executable ELF section", section.Name, 10, int64(section.Offset))
		}
	}
	result.ELF = info
	return nil
}

func analyzeMachO(result *ScanResult, cfg Config) error {
	file, err := macho.Open(result.Target)
	if err != nil {
		return err
	}
	defer file.Close()

	info := &MachOInfo{
		CPU:  file.Cpu.String(),
		Type: file.Type.String(),
	}
	if imports, err := file.ImportedSymbols(); err == nil {
		sort.Strings(imports)
		info.Imports = limitStrings(imports, importLimitForMode(cfg.Mode))
	}
	for _, section := range file.Sections {
		data, _ := section.Data()
		info.Sections = append(info.Sections, SectionInfo{
			Name:      section.Name,
			Virtual:   uint32(section.Addr),
			RawOffset: section.Offset,
			RawSize:   uint32(section.Size),
			Entropy:   ShannonEntropy(data),
		})
	}
	result.MachO = info
	return nil
}

func analyzeZIP(result *ScanResult, cfg Config, debugf debugLogger) error {
	reader, err := zip.OpenReader(result.Target)
	if err != nil {
		return err
	}
	defer reader.Close()

	entryLimit := cfg.MaxArchiveFiles
	for index, file := range reader.File {
		if index >= entryLimit {
			AddFinding(result, "Info", "Container", "Archive entry inspection capped", fmt.Sprintf("only first %d entries inspected", entryLimit), 0, 0)
			break
		}
		reason := archiveEntryReason(file)
		entry := ArchiveEntry{
			Name:           file.Name,
			Size:           file.UncompressedSize64,
			CompressedSize: file.CompressedSize64,
		}
		if reason != "" {
			entry.SuspiciousReason = reason
			AddFinding(result, "Medium", "Container", "Suspicious archive entry", file.Name+": "+reason, 10, 0)
		}
		result.ArchiveEntries = append(result.ArchiveEntries, entry)

		if file.CompressedSize64 > 0 && file.UncompressedSize64 > 10*1024*1024 && file.UncompressedSize64/file.CompressedSize64 > 100 {
			AddFinding(result, "High", "Container", "Archive bomb heuristic", fmt.Sprintf("%s expands from %d to %d bytes", file.Name, file.CompressedSize64, file.UncompressedSize64), 20, 0)
		}

		if cfg.Mode == "quick" || file.FileInfo().IsDir() || file.UncompressedSize64 == 0 || file.UncompressedSize64 > 2*1024*1024 {
			continue
		}
		handle, err := file.Open()
		if err != nil {
			debugf("archive entry open failed for %s: %v", file.Name, err)
			continue
		}
		content, err := io.ReadAll(io.LimitReader(handle, 2*1024*1024))
		handle.Close()
		if err != nil {
			debugf("archive entry read failed for %s: %v", file.Name, err)
			continue
		}
		entryType := DetectFileType(content, file.Name)
		if entryType == "PE executable" || entryType == "ELF binary" || entryType == "Mach-O binary" || entryType == "DEX bytecode" {
			AddFinding(result, "High", "Container", "Executable payload inside archive", file.Name+" detected as "+entryType, 20, 0)
		}
		entryStrings, _, _ := ExtractStrings(content, cfg.MinStringLen, 5000)
		MergeIOCSet(&result.IOCs, ExtractIOCsFromStrings(entryStrings))
		for _, sample := range suspiciousStringSamples(entryStrings, 5) {
			result.SuspiciousStrings = appendUnique(result.SuspiciousStrings, "archive:"+file.Name+": "+sample)
		}
	}
	return nil
}

func archiveEntryReason(file *zip.File) string {
	name := strings.ReplaceAll(file.Name, "\\", "/")
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(name, "../") || strings.HasPrefix(name, "/"):
		return "path traversal capable name"
	case strings.Contains(lower, "vbaproject.bin"):
		return "Office macro project"
	case strings.HasSuffix(lower, ".exe") || strings.HasSuffix(lower, ".dll") || strings.HasSuffix(lower, ".scr") ||
		strings.HasSuffix(lower, ".ps1") || strings.HasSuffix(lower, ".vbs") || strings.HasSuffix(lower, ".jse") ||
		strings.HasSuffix(lower, ".hta") || strings.HasSuffix(lower, ".bat") || strings.HasSuffix(lower, ".cmd") ||
		strings.HasSuffix(lower, ".sh"):
		return "executable or script extension"
	case strings.HasSuffix(lower, ".dex") || lower == "classes.dex" || lower == "androidmanifest.xml":
		return "Android executable/package metadata"
	case strings.Contains(lower, "autoopen") || strings.Contains(lower, "document_open"):
		return "Office auto-execution macro name"
	default:
		return ""
	}
}

func importHash(imports []string) string {
	normalized := make([]string, 0, len(imports))
	for _, imported := range imports {
		item := strings.ToLower(strings.TrimSpace(imported))
		if item != "" {
			normalized = append(normalized, item)
		}
	}
	sort.Strings(normalized)
	sum := md5.Sum([]byte(strings.Join(normalized, ",")))
	return hex.EncodeToString(sum[:])
}

func importLimitForMode(mode string) int {
	switch mode {
	case "quick":
		return 200
	case "standard":
		return 1000
	default:
		return 5000
	}
}

func limitStrings(values []string, limit int) []string {
	if len(values) <= limit {
		return values
	}
	out := make([]string, limit)
	copy(out, values[:limit])
	return out
}

func peMachine(machine uint16) string {
	switch machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		return "i386"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "amd64"
	case pe.IMAGE_FILE_MACHINE_ARM:
		return "arm"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	default:
		return fmt.Sprintf("0x%x", machine)
	}
}

func peSubsystem(subsystem uint16) string {
	switch subsystem {
	case pe.IMAGE_SUBSYSTEM_WINDOWS_GUI:
		return "windows-gui"
	case pe.IMAGE_SUBSYSTEM_WINDOWS_CUI:
		return "windows-console"
	case pe.IMAGE_SUBSYSTEM_NATIVE:
		return "native"
	case pe.IMAGE_SUBSYSTEM_EFI_APPLICATION:
		return "efi-application"
	default:
		return fmt.Sprintf("0x%x", subsystem)
	}
}

func hasMagic(data []byte, magic []byte) bool {
	if len(data) < len(magic) {
		return false
	}
	for i, b := range magic {
		if data[i] != b {
			return false
		}
	}
	return true
}

func looksText(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	check := len(data)
	if check > 4096 {
		check = 4096
	}
	printable := 0
	for _, b := range data[:check] {
		if b == '\n' || b == '\r' || b == '\t' || (b >= 0x20 && b <= 0x7e) {
			printable++
		}
	}
	return float64(printable)/float64(check) >= 0.90
}
