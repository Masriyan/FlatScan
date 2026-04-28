package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
)

type carveMagic struct {
	Type   string
	Magic  []byte
	Reason string
}

var carveMagics = []carveMagic{
	{"PE executable", []byte{'M', 'Z'}, "embedded Windows executable magic"},
	{"ELF binary", []byte{0x7f, 'E', 'L', 'F'}, "embedded ELF magic"},
	{"ZIP container", []byte{'P', 'K', 0x03, 0x04}, "embedded ZIP-family container magic"},
	{"DEX bytecode", []byte{'d', 'e', 'x', '\n'}, "embedded Android DEX magic"},
	{"PDF document", []byte{'%', 'P', 'D', 'F', '-'}, "embedded PDF magic"},
	{"Gzip compressed data", []byte{0x1f, 0x8b}, "embedded gzip stream magic"},
	{"7-Zip archive", []byte{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c}, "embedded 7-Zip archive magic"},
	{"RAR archive", []byte{'R', 'a', 'r', '!', 0x1a, 0x07}, "embedded RAR archive magic"},
}

func AnalyzeCarvedArtifacts(result *ScanResult, data []byte, cfg Config, debugf debugLogger) {
	if !cfg.EnableCarving {
		return
	}
	if len(data) == 0 {
		return
	}
	artifacts := carveArtifacts(data, cfg.MaxCarves)
	for _, artifact := range artifacts {
		if artifact.Offset == 0 && artifact.Type == result.FileType {
			continue
		}
		result.CarvedArtifacts = append(result.CarvedArtifacts, artifact)
	}
	if len(result.CarvedArtifacts) == 0 {
		result.Plugins = append(result.Plugins, PluginResult{Name: "safe-carver", Version: version, Status: "complete", Summary: "no embedded artifacts found"})
		return
	}
	execCount := 0
	for _, artifact := range result.CarvedArtifacts {
		switch artifact.Type {
		case "PE executable", "ELF binary", "DEX bytecode":
			execCount++
		}
	}
	if execCount > 0 {
		AddFindingDetailed(result, "Medium", "Carving", "Embedded executable artifacts found", fmt.Sprintf("%d executable-like artifacts found by safe carving", execCount), 12, 0, "Defense Evasion", "Obfuscated Files or Information", "Review carved artifact hashes and offsets; extract only inside an isolated malware lab if deeper analysis is required.")
	}
	if len(result.CarvedArtifacts) >= cfg.MaxCarves {
		AddFinding(result, "Info", "Carving", "Carving result cap reached", fmt.Sprintf("%d artifacts reported", cfg.MaxCarves), 0, 0)
	}
	result.Plugins = append(result.Plugins, PluginResult{
		Name:     "safe-carver",
		Version:  version,
		Status:   "complete",
		Summary:  fmt.Sprintf("%d embedded artifacts reported", len(result.CarvedArtifacts)),
		Findings: execCount,
	})
	debugf("safe carving found %d artifacts", len(result.CarvedArtifacts))
}

func PromoteCarvedPayloadIOCs(result *ScanResult) {
	if result == nil || len(result.CarvedArtifacts) == 0 {
		return
	}
	entries := map[string]ArchiveEntry{}
	for _, entry := range result.ArchiveEntries {
		entries[normalizeArchivePath(entry.Name)] = entry
	}
	for _, artifact := range result.CarvedArtifacts {
		if artifact.Type != "ZIP container" && artifact.Type != "PE executable" {
			continue
		}
		path := normalizeArchivePath(artifact.Preview)
		if !archivePEPayloadName(path) {
			continue
		}
		entry := entries[path]
		size := uint64(artifact.Length)
		compressedSize := uint64(artifact.Length)
		ratio := 0.0
		if entry.Name != "" {
			size = entry.Size
			compressedSize = entry.CompressedSize
			ratio = entry.CompressionRatio
		}
		addPEHashIOC(&result.IOCs, PEHashIOC{
			Path:             path,
			SHA256:           artifact.SHA256,
			Size:             size,
			CompressedSize:   compressedSize,
			CompressionRatio: ratio,
			Entropy:          artifact.Entropy,
			CarvedOffset:     fmt.Sprintf("0x%x", artifact.Offset),
			Tier:             pePayloadTier(ratio, artifact.Entropy),
			Note:             "Carved embedded payload record - primary hunting pivot",
		})
	}
}

func carveArtifacts(data []byte, limit int) []CarvedArtifact {
	type candidate struct {
		offset int
		magic  carveMagic
	}
	var candidates []candidate
	seen := map[int]struct{}{}
	for _, magic := range carveMagics {
		start := 0
		for start < len(data) {
			index := bytes.Index(data[start:], magic.Magic)
			if index < 0 {
				break
			}
			offset := start + index
			start = offset + 1
			if offset == 0 {
				continue
			}
			if !validCarveAt(data, offset, magic.Type) {
				continue
			}
			if _, ok := seen[offset]; ok {
				continue
			}
			seen[offset] = struct{}{}
			candidates = append(candidates, candidate{offset: offset, magic: magic})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].offset < candidates[j].offset
	})
	if limit > 0 && len(candidates) > limit {
		candidates = candidates[:limit]
	}
	out := make([]CarvedArtifact, 0, len(candidates))
	for i, item := range candidates {
		end := len(data)
		if i+1 < len(candidates) && candidates[i+1].offset > item.offset {
			end = candidates[i+1].offset
		}
		if end-item.offset > 2*1024*1024 {
			end = item.offset + 2*1024*1024
		}
		if end <= item.offset {
			continue
		}
		chunk := data[item.offset:end]
		sum := sha256.Sum256(chunk)
		stringsFound, _, _ := ExtractStrings(chunk, 5, 8)
		preview := ""
		if len(stringsFound) > 0 {
			preview = previewString(stringsFound[0].Value, 120)
		}
		out = append(out, CarvedArtifact{
			Type:      item.magic.Type,
			Offset:    int64(item.offset),
			Length:    len(chunk),
			SHA256:    hex.EncodeToString(sum[:]),
			Entropy:   ShannonEntropy(chunk),
			Reason:    item.magic.Reason,
			Preview:   preview,
			Contained: true,
		})
	}
	return out
}

func validCarveAt(data []byte, offset int, fileType string) bool {
	switch fileType {
	case "PE executable":
		if offset+0x40 >= len(data) {
			return false
		}
		peOff := int(data[offset+0x3c]) | int(data[offset+0x3d])<<8 | int(data[offset+0x3e])<<16 | int(data[offset+0x3f])<<24
		return peOff > 0 && offset+peOff+4 <= len(data) && string(data[offset+peOff:offset+peOff+4]) == "PE\x00\x00"
	case "DEX bytecode":
		return offset+8 <= len(data) && data[offset+7] == 0
	default:
		return true
	}
}
