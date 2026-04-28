package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

func BuildSimilarityInfo(result *ScanResult, data []byte, stringsFound []ExtractedString) {
	if result == nil {
		return
	}
	info := SimilarityInfo{
		FlatHash:           flatFuzzyHash(data),
		ByteHistogramHash:  byteHistogramHash(data),
		StringSetHash:      stringSetHash(stringsFound),
		ImportHash:         importSimilarityHash(*result),
		SectionHash:        sectionSimilarityHash(*result),
		DEXStringHash:      dexStringSimilarityHash(result.DEXFiles),
		ArchiveContentHash: archiveContentHash(result.ArchiveEntries),
	}
	result.Similarity = info
	result.Plugins = append(result.Plugins, PluginResult{Name: "similarity", Version: version, Status: "complete", Summary: "computed FlatHash and structural similarity hashes"})
}

func byteHistogramHash(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	var buckets [16]int
	for _, b := range data {
		buckets[int(b)/16]++
	}
	parts := make([]string, 0, len(buckets))
	for _, count := range buckets {
		parts = append(parts, fmt.Sprintf("%x", count*255/len(data)))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, ":")))
	return hex.EncodeToString(sum[:])
}

func flatFuzzyHash(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	chunk := 4096
	if len(data) > 4*1024*1024 {
		chunk = 16384
	}
	var parts []string
	for offset := 0; offset < len(data); offset += chunk {
		end := offset + chunk
		if end > len(data) {
			end = len(data)
		}
		sum := sha256.Sum256(data[offset:end])
		parts = append(parts, hex.EncodeToString(sum[:])[:8])
		if len(parts) >= 256 {
			break
		}
	}
	return fmt.Sprintf("FLS1:%d:%s", chunk, strings.Join(parts, ""))
}

func stringSetHash(stringsFound []ExtractedString) string {
	if len(stringsFound) == 0 {
		return ""
	}
	seen := map[string]struct{}{}
	for _, item := range stringsFound {
		value := strings.ToLower(strings.TrimSpace(item.Value))
		if len(value) < 5 || len(value) > 180 {
			continue
		}
		seen[value] = struct{}{}
		if len(seen) >= 20000 {
			break
		}
	}
	values := make([]string, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	sort.Strings(values)
	sum := sha256.Sum256([]byte(strings.Join(values, "\n")))
	return hex.EncodeToString(sum[:])
}

func importSimilarityHash(result ScanResult) string {
	var imports []string
	if result.PE != nil {
		imports = append(imports, result.PE.Imports...)
	}
	if result.ELF != nil {
		imports = append(imports, result.ELF.Imports...)
	}
	if result.MachO != nil {
		imports = append(imports, result.MachO.Imports...)
	}
	if len(imports) == 0 {
		return ""
	}
	for i := range imports {
		imports[i] = strings.ToLower(strings.TrimSpace(imports[i]))
	}
	sort.Strings(imports)
	sum := sha256.Sum256([]byte(strings.Join(imports, "\n")))
	return hex.EncodeToString(sum[:])
}

func sectionSimilarityHash(result ScanResult) string {
	var sections []SectionInfo
	if result.PE != nil {
		sections = append(sections, result.PE.Sections...)
	}
	if result.ELF != nil {
		sections = append(sections, result.ELF.Sections...)
	}
	if result.MachO != nil {
		sections = append(sections, result.MachO.Sections...)
	}
	if len(sections) == 0 {
		return ""
	}
	var parts []string
	for _, section := range sections {
		parts = append(parts, fmt.Sprintf("%s:%d:%.1f:%v:%v", strings.ToLower(section.Name), section.RawSize/1024, section.Entropy, section.Executable, section.Writable))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:])
}

func dexStringSimilarityHash(values []DEXInfo) string {
	if len(values) == 0 {
		return ""
	}
	var parts []string
	for _, dex := range values {
		for _, sample := range dex.SuspiciousStrings {
			parts = append(parts, strings.ToLower(sample))
		}
		for _, hit := range dex.APIHits {
			parts = append(parts, hit.Category+":"+hit.Indicator)
		}
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:])
}

func archiveContentHash(entries []ArchiveEntry) string {
	if len(entries) == 0 {
		return ""
	}
	parts := make([]string, 0, len(entries))
	for _, entry := range entries {
		parts = append(parts, fmt.Sprintf("%s:%d:%d", strings.ToLower(entry.Name), entry.Size, entry.CompressedSize))
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:])
}
