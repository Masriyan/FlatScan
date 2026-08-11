package main

import (
	"bytes"
	"strings"
)

type PackerSignature struct {
	Name            string
	Severity        string
	Score           int
	SectionNames    []string // any of these section names triggers
	EntryPointBytes []byte   // optional entry-point byte prefix
	OverlayMarker   []byte   // optional overlay magic bytes
}

var packerSignatures = []PackerSignature{
	{
		Name:          "UPX packer",
		Severity:      "High",
		Score:         20,
		SectionNames:  []string{"upx0", "upx1", "upx!"},
		OverlayMarker: []byte("UPX!"),
	},
	{
		Name:         "Themida/WinLicense protector",
		Severity:     "High",
		Score:        22,
		SectionNames: []string{"themida", "winlicense", ".winlicence"},
	},
	{
		Name:         "VMProtect protector",
		Severity:     "High",
		Score:        22,
		SectionNames: []string{".vmp0", ".vmp1", ".vmp2"},
	},
	{
		Name:         "MPRESS packer",
		Severity:     "Medium",
		Score:        15,
		SectionNames: []string{".mpress1", ".mpress2"},
	},
	{
		Name:         "ASPack packer",
		Severity:     "Medium",
		Score:        15,
		SectionNames: []string{".aspack", ".adata"},
	},
	{
		Name:         "Enigma Protector",
		Severity:     "High",
		Score:        20,
		SectionNames: []string{".enigma1", ".enigma2"},
	},
	{
		Name:         "PELock protector",
		Severity:     "Medium",
		Score:        15,
		SectionNames: []string{".pelock"},
	},
}

func DetectPackers(result *ScanResult, data []byte) {
	if result.PE == nil {
		return
	}

	// Index section names for O(1) lookup
	sectionNames := make(map[string]bool, len(result.PE.Sections))
	for _, sec := range result.PE.Sections {
		sectionNames[strings.ToLower(strings.TrimRight(sec.Name, "\x00"))] = true
	}

	for _, sig := range packerSignatures {
		triggered := false

		// Check section name matches
		for _, name := range sig.SectionNames {
			if sectionNames[strings.ToLower(name)] {
				triggered = true
				break
			}
		}

		// Check overlay marker in last 8 bytes of file or overlay region
		if !triggered && len(sig.OverlayMarker) > 0 && len(data) >= len(sig.OverlayMarker) {
			if bytes.Contains(data[len(data)-min(4096, len(data)):], sig.OverlayMarker) {
				triggered = true
			}
			if !triggered && bytes.HasPrefix(data, sig.OverlayMarker) {
				triggered = true
			}
		}

		if triggered {
			AddFindingDetailed(result, sig.Severity, "Packing", sig.Name+" detected",
				"packer/protector signature matched in PE section names or overlay",
				sig.Score, 0,
				"Defense Evasion", "Obfuscated Files or Information (T1027)",
				"Unpack or dump the process from memory before static analysis. Use automated unpacking if available.")
		}
	}

	// Generic packer heuristic: single code section + very high entropy + no named imports
	if len(result.PE.Sections) <= 2 && result.Entropy >= 7.0 && len(result.PE.Imports) == 0 {
		AddFinding(result, "Medium", "Packing", "Generic packer heuristic",
			"single/minimal PE sections with high entropy and no resolved imports",
			15, 0)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
