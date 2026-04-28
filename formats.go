package main

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"crypto/x509"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
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
	case looksJavaClass(data):
		return "Java class"
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
	case "DEX bytecode":
		return analyzeStandaloneDEX(result, cfg, data, debugf)
	case "APK package":
		if err := analyzeAPK(result, cfg, debugf); err != nil {
			AddFindingDetailed(result, "Low", "Android", "APK parser warning", err.Error(), 2, 0, "Discovery", "Application Discovery", "Open the APK with dedicated Android tooling if the ZIP parser succeeds but APK metadata is incomplete.")
			debugf("apk parser error: %v", err)
		}
		return analyzeZIP(result, cfg, debugf)
	case "ZIP container", "JAR package", "Office Open XML document":
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

	detectMSIXPackage(result, reader.File, debugf)

	entryLimit := cfg.MaxArchiveFiles
	for index, file := range reader.File {
		if index >= entryLimit {
			AddFinding(result, "Info", "Container", "Archive entry inspection capped", fmt.Sprintf("only first %d entries inspected", entryLimit), 0, 0)
			break
		}
		reason := archiveEntryReason(file, result.FileType)
		dataOffset, _ := file.DataOffset()
		entry := ArchiveEntry{
			Name:             file.Name,
			Size:             file.UncompressedSize64,
			CompressedSize:   file.CompressedSize64,
			CompressionRatio: compressionRatio(file.CompressedSize64, file.UncompressedSize64),
			Offset:           dataOffset,
		}
		if reason != "" {
			entry.SuspiciousReason = reason
			AddFindingDetailed(result, "Medium", "Container", "Suspicious archive entry", file.Name+": "+reason, 10, 0, "Defense Evasion", "Obfuscated Files or Information (T1027)", "Inspect suspicious archive entries and embedded scripts or executables in an isolated malware lab.")
		}
		result.ArchiveEntries = append(result.ArchiveEntries, entry)
		entryIndex := len(result.ArchiveEntries) - 1
		if reason := obfuscatedArchiveNameReason(file.Name); reason != "" {
			AddFindingDetailed(result, "High", "Container", "Obfuscated identical-name executable directory", file.Name+": "+reason, 18, dataOffset, "Defense Evasion", "Masquerading (T1036.005)", "Use the random directory and embedded payload hashes as primary hunting pivots; this pattern is associated with Magniber-style MSIX delivery.")
		}

		if file.CompressedSize64 > 0 && file.UncompressedSize64 > 10*1024*1024 && file.UncompressedSize64/file.CompressedSize64 > 100 {
			AddFindingDetailed(result, "High", "Container", "Archive bomb heuristic", fmt.Sprintf("%s expands from %d to %d bytes", file.Name, file.CompressedSize64, file.UncompressedSize64), 20, 0, "Defense Evasion", "Obfuscated Files or Information (T1027)", "Handle the archive in a constrained lab and avoid automatic extraction on production systems.")
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
		contentSHA := sha256.Sum256(content)
		entry.Type = entryType
		entry.SHA256 = hex.EncodeToString(contentSHA[:])
		entry.Entropy = ShannonEntropy(content)
		result.ArchiveEntries[entryIndex] = entry
		if entryType == "PE executable" || entryType == "ELF binary" || entryType == "Mach-O binary" || (entryType == "DEX bytecode" && result.FileType != "APK package") {
			AddFindingDetailed(result, "High", "Container", "Executable payload inside archive", file.Name+" detected as "+entryType, 20, 0, "Defense Evasion", "Obfuscated Files or Information (T1027)", "Reverse engineer embedded executable payloads and hunt for the container hash plus embedded payload hashes.")
		}
		if entryType == "PE executable" && archivePEPayloadName(file.Name) {
			promoteArchivePEHash(result, file, entry, dataOffset)
			if entry.CompressionRatio > 0.35 && entry.Entropy > 7.5 {
				AddFindingDetailed(result, "Medium", "Packing", "Possibly encrypted PE payload inside archive", fmt.Sprintf("%s ratio=%.3f entropy=%.2f", file.Name, entry.CompressionRatio, entry.Entropy), 12, dataOffset, "Defense Evasion", "Obfuscated Files or Information (T1027)", "Prioritize unpacking or emulation of the embedded PE payload; high entropy and poor compression suggest encrypted or packed content.")
			}
		}
		entryStrings, _, _ := ExtractStrings(content, cfg.MinStringLen, 5000)
		MergeIOCSet(&result.IOCs, ExtractIOCsFromStrings(entryStrings))
		for _, sample := range suspiciousStringSamples(entryStrings, 5) {
			result.SuspiciousStrings = appendUnique(result.SuspiciousStrings, "archive:"+file.Name+": "+sample)
		}
	}
	return nil
}

var obfuscatedArchivePENameRe = regexp.MustCompile(`^([a-z]{5,8})/([a-z]{5,8})\.(exe|dll)$`)

func detectMSIXPackage(result *ScanResult, files []*zip.File, debugf debugLogger) {
	if result == nil {
		return
	}
	entries := map[string]*zip.File{}
	for _, file := range files {
		entries[normalizeArchivePath(file.Name)] = file
	}
	required := []string{"appxmanifest.xml", "appxsignature.p7x", "appxblockmap.xml", "[content_types].xml"}
	for _, name := range required {
		if entries[name] == nil {
			return
		}
	}

	result.FileType = "MSIX/AppX package"
	result.MIMEHint = "application/vnd.ms-appx"
	AddFindingDetailed(result, "Info", "Container", "MSIX/AppX package detected", "Archive contains AppxManifest.xml, AppxSignature.p7x, AppxBlockMap.xml, and [Content_Types].xml", 0, 0, "Discovery", "Software Discovery (T1518)", "Treat MSIX/AppX files as executable delivery containers and inspect the manifest, signature, and embedded payload hashes together.")

	info := &MSIXInfo{}
	if manifestFile := entries["appxmanifest.xml"]; manifestFile != nil {
		if manifestData, _, err := readZipEntryLimited(manifestFile, 2*1024*1024); err != nil {
			debugf("msix manifest read failed: %v", err)
			AddFinding(result, "Low", "MSIX", "MSIX manifest read failed", err.Error(), 2, 0)
		} else if parsed, err := parseMSIXManifest(manifestData); err != nil {
			debugf("msix manifest parse failed: %v", err)
			AddFinding(result, "Low", "MSIX", "MSIX manifest parse failed", err.Error(), 2, 0)
		} else {
			info = parsed
		}
	}
	info.PublisherTrusted = trustedMSIXPublisher(info.IdentityPublisher)
	info.UndeclaredExecutables = msixUndeclaredExecutables(files, info.DeclaredExecutables)
	if info.IdentityPublisher == "" || !info.PublisherTrusted {
		AddFindingDetailed(result, "Medium", "MSIX", "Unknown or untrusted MSIX publisher", nonEmpty(info.IdentityPublisher, "publisher missing from AppxManifest.xml"), 10, 0, "Defense Evasion", "Masquerading (T1036.005)", "Validate the package signing chain and publisher against approved enterprise software sources before trusting the package.")
	}
	if containsStringFold(info.Capabilities, "runFullTrust") {
		AddFindingDetailed(result, "High", "MSIX", "Full-trust execution requested", "AppxManifest capability includes runFullTrust", 22, 0, "Privilege Escalation", "Abuse Elevation Control Mechanism (T1548)", "Treat full-trust MSIX packages as native executable delivery artifacts and review payload behavior before deployment.")
	}
	if len(info.UndeclaredExecutables) > 0 {
		info.Finding = "Executables not declared in AppxManifest - hidden payload pattern"
		AddFindingDetailed(result, "High", "MSIX", "Hidden executable payloads not declared in manifest", strings.Join(info.UndeclaredExecutables, ", "), 22, 0, "Defense Evasion", "Masquerading (T1036.005)", "Use undeclared payload names and hashes for hunting; compare manifest-declared entry points against actual executable content.")
	}

	if sigFile := entries["appxsignature.p7x"]; sigFile != nil {
		info.SignatureSize = sigFile.UncompressedSize64
		if sigData, _, err := readZipEntryLimited(sigFile, 4*1024*1024); err != nil {
			info.SignatureParseStatus = "signature read failed: " + err.Error()
			debugf("msix signature read failed: %v", err)
		} else {
			sum := sha256.Sum256(sigData)
			info.SignatureSHA256 = hex.EncodeToString(sum[:])
			extractMSIXSignatureCertificates(info, sigData)
		}
	}
	result.MSIX = info
	debugf("msix package metadata extracted: identity=%q publisher=%q undeclared=%d", info.IdentityName, info.IdentityPublisher, len(info.UndeclaredExecutables))
}

func parseMSIXManifest(data []byte) (*MSIXInfo, error) {
	type xmlIdentity struct {
		Name      string `xml:"Name,attr"`
		Publisher string `xml:"Publisher,attr"`
		Version   string `xml:"Version,attr"`
	}
	type xmlApplication struct {
		ID         string `xml:"Id,attr"`
		Executable string `xml:"Executable,attr"`
	}
	type xmlApplications struct {
		Applications []xmlApplication `xml:"Application"`
	}
	type xmlCapability struct {
		Name string `xml:"Name,attr"`
	}
	type xmlCapabilities struct {
		Capabilities           []xmlCapability `xml:"Capability"`
		DeviceCapabilities     []xmlCapability `xml:"DeviceCapability"`
		RestrictedCapabilities []xmlCapability `xml:"RestrictedCapability"`
	}
	type xmlPackage struct {
		Identity     xmlIdentity     `xml:"Identity"`
		Applications xmlApplications `xml:"Applications"`
		Capabilities xmlCapabilities `xml:"Capabilities"`
	}

	var manifest xmlPackage
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = false
	if err := decoder.Decode(&manifest); err != nil {
		return nil, err
	}
	info := &MSIXInfo{
		IdentityName:      manifest.Identity.Name,
		IdentityPublisher: manifest.Identity.Publisher,
		IdentityVersion:   manifest.Identity.Version,
	}
	for _, app := range manifest.Applications.Applications {
		if app.Executable != "" {
			info.DeclaredExecutables = appendUnique(info.DeclaredExecutables, normalizeArchivePath(app.Executable))
		}
	}
	for _, cap := range append(append(manifest.Capabilities.Capabilities, manifest.Capabilities.DeviceCapabilities...), manifest.Capabilities.RestrictedCapabilities...) {
		if cap.Name != "" {
			info.Capabilities = appendUnique(info.Capabilities, cap.Name)
		}
	}
	info.DeclaredExecutables = uniqueSorted(info.DeclaredExecutables)
	info.Capabilities = uniqueSorted(info.Capabilities)
	return info, nil
}

func extractMSIXSignatureCertificates(info *MSIXInfo, data []byte) {
	if info == nil {
		return
	}
	certs, err := x509.ParseCertificates(data)
	if err != nil || len(certs) == 0 {
		info.SignatureParseStatus = "PKCS#7/CMS signature present; direct X.509 parse unavailable without CMS parser"
		return
	}
	info.SignatureParseStatus = fmt.Sprintf("%d certificate(s) parsed from signature data", len(certs))
	for _, cert := range certs {
		info.CertificateSubjects = appendUnique(info.CertificateSubjects, cert.Subject.String())
		info.CertificateIssuers = appendUnique(info.CertificateIssuers, cert.Issuer.String())
		if cert.SerialNumber != nil {
			info.CertificateSerials = appendUnique(info.CertificateSerials, cert.SerialNumber.Text(16))
		}
	}
}

func msixUndeclaredExecutables(files []*zip.File, declared []string) []string {
	declaredSet := map[string]struct{}{}
	for _, value := range declared {
		declaredSet[normalizeArchivePath(value)] = struct{}{}
	}
	var out []string
	for _, file := range files {
		name := normalizeArchivePath(file.Name)
		if !archivePEPayloadName(name) {
			continue
		}
		if _, ok := declaredSet[name]; ok {
			continue
		}
		out = appendUnique(out, name)
	}
	return uniqueSorted(out)
}

func trustedMSIXPublisher(publisher string) bool {
	lower := strings.ToLower(publisher)
	return strings.Contains(lower, "cn=microsoft corporation") || strings.Contains(lower, "o=microsoft corporation")
}

func containsStringFold(values []string, needle string) bool {
	for _, value := range values {
		if strings.EqualFold(value, needle) {
			return true
		}
	}
	return false
}

func promoteArchivePEHash(result *ScanResult, file *zip.File, entry ArchiveEntry, dataOffset int64) {
	tier := pePayloadTier(entry.CompressionRatio, entry.Entropy)
	addPEHashIOC(&result.IOCs, PEHashIOC{
		Path:             normalizeArchivePath(file.Name),
		SHA256:           entry.SHA256,
		Size:             entry.Size,
		CompressedSize:   entry.CompressedSize,
		CompressionRatio: entry.CompressionRatio,
		Entropy:          entry.Entropy,
		CarvedOffset:     fmt.Sprintf("0x%x", dataOffset),
		Tier:             tier,
		Note:             "Decompressed embedded PE payload - execution hash",
	})
}

func pePayloadTier(compressionRatio, entropy float64) string {
	switch {
	case compressionRatio < 0.5 && entropy > 7.5:
		return "HIGH"
	case compressionRatio >= 0.5 && entropy > 7.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func compressionRatio(compressed, uncompressed uint64) float64 {
	if compressed == 0 || uncompressed == 0 {
		return 0
	}
	return float64(compressed) / float64(uncompressed)
}

func archivePEPayloadName(name string) bool {
	lower := strings.ToLower(normalizeArchivePath(name))
	return strings.HasSuffix(lower, ".exe") || strings.HasSuffix(lower, ".dll")
}

func obfuscatedArchiveNameReason(name string) string {
	normalized := strings.ToLower(normalizeArchivePath(name))
	match := obfuscatedArchivePENameRe.FindStringSubmatch(normalized)
	if len(match) != 4 {
		return ""
	}
	if match[1] != match[2] {
		return ""
	}
	return "random lowercase directory and executable stem match; Magniber-style package naming convention"
}

func normalizeArchivePath(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = strings.TrimPrefix(name, "./")
	return strings.ToLower(strings.TrimSpace(name))
}

func archiveEntryReason(file *zip.File, containerType string) string {
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
	case (strings.HasSuffix(lower, ".dex") || lower == "classes.dex" || lower == "androidmanifest.xml") && containerType != "APK package":
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

func looksJavaClass(data []byte) bool {
	if len(data) < 8 || !hasMagic(data, []byte{0xca, 0xfe, 0xba, 0xbe}) {
		return false
	}
	major := uint16(data[6])<<8 | uint16(data[7])
	return major >= 45 && major <= 70
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
