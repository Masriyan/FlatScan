package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AnalysisPlugin defines the interface for FlatScan analysis plugins.
// Plugins receive the scan result and file data, then return findings
// and metadata to merge into the final result.
//
// Built-in plugins implement this interface and are registered at init
// time. External plugins can be loaded from JSON manifests with the
// same structure.
type AnalysisPlugin interface {
	// Name returns the human-readable name of the plugin.
	Name() string
	// Version returns the plugin version string.
	Version() string
	// ShouldRun determines if this plugin is relevant for the given scan.
	ShouldRun(result *ScanResult, cfg Config) bool
	// Run executes the plugin analysis and mutates the result.
	Run(result *ScanResult, data []byte, extracted []ExtractedString, corpus string, cfg Config, debugf debugLogger)
}

// pluginRegistry holds all registered analysis plugins.
var pluginRegistry []AnalysisPlugin

// RegisterPlugin adds a plugin to the global registry.
func RegisterPlugin(p AnalysisPlugin) {
	pluginRegistry = append(pluginRegistry, p)
}

// RunRegisteredPlugins executes all registered plugins that are
// applicable to the current scan.
func RunRegisteredPlugins(result *ScanResult, data []byte, extracted []ExtractedString, corpus string, cfg Config, debugf debugLogger) {
	for _, plugin := range pluginRegistry {
		if !plugin.ShouldRun(result, cfg) {
			debugf("plugin %s: skipped (not applicable)", plugin.Name())
			continue
		}
		start := time.Now()
		plugin.Run(result, data, extracted, corpus, cfg, debugf)
		elapsed := time.Since(start)
		debugf("plugin %s: completed in %s", plugin.Name(), elapsed)
		result.Plugins = append(result.Plugins, PluginResult{
			Name:    plugin.Name(),
			Version: plugin.Version(),
			Status:  "complete",
			Summary: fmt.Sprintf("ran in %s", elapsed.Round(time.Millisecond)),
		})
	}
}

// --- Built-in plugins ---

// HighEntropyBlobPlugin detects large contiguous high-entropy regions
// that may indicate encrypted or packed payloads.
type HighEntropyBlobPlugin struct{}

func (p *HighEntropyBlobPlugin) Name() string    { return "high-entropy-blob-detector" }
func (p *HighEntropyBlobPlugin) Version() string { return version }
func (p *HighEntropyBlobPlugin) ShouldRun(result *ScanResult, cfg Config) bool {
	return cfg.Mode != "quick" && result.Size > 1024
}
func (p *HighEntropyBlobPlugin) Run(result *ScanResult, data []byte, _ []ExtractedString, _ string, _ Config, debugf debugLogger) {
	// Find the single largest contiguous high-entropy region
	windowSize := 4096
	if len(data) < windowSize {
		return
	}
	var maxEntropy float64
	var maxOffset int
	for offset := 0; offset+windowSize <= len(data); offset += windowSize {
		e := ShannonEntropy(data[offset : offset+windowSize])
		if e > maxEntropy {
			maxEntropy = e
			maxOffset = offset
		}
	}
	if maxEntropy >= 7.90 {
		AddFindingDetailed(result, "Medium", "Packing", "Large high-entropy blob detected",
			fmt.Sprintf("4KB block at offset 0x%x has entropy %.2f/8.00 — likely encrypted or compressed payload", maxOffset, maxEntropy),
			8, int64(maxOffset),
			"Defense Evasion", "Obfuscated Files or Information (T1027)",
			"Investigate whether the high-entropy region contains an encrypted payload or packed executable stage.")
		debugf("high-entropy blob: offset=0x%x entropy=%.2f", maxOffset, maxEntropy)
	}
}

// SuspiciousImportPlugin flags combinations of imported functions that
// strongly indicate malicious intent.
type SuspiciousImportPlugin struct{}

func (p *SuspiciousImportPlugin) Name() string    { return "suspicious-import-combinator" }
func (p *SuspiciousImportPlugin) Version() string { return version }
func (p *SuspiciousImportPlugin) ShouldRun(result *ScanResult, cfg Config) bool {
	return result.PE != nil && len(result.PE.Imports) > 0
}
func (p *SuspiciousImportPlugin) Run(result *ScanResult, _ []byte, _ []ExtractedString, _ string, _ Config, debugf debugLogger) {
	imports := strings.ToLower(strings.Join(result.PE.Imports, "\n"))

	// Detect process hollowing pattern
	if strings.Contains(imports, "ntunmapviewofsection") &&
		strings.Contains(imports, "writeprocessmemory") &&
		strings.Contains(imports, "resumethread") {
		AddFindingDetailed(result, "Critical", "Behavior", "Process hollowing API chain",
			"NtUnmapViewOfSection + WriteProcessMemory + ResumeThread imports present",
			30, 0,
			"Defense Evasion", "Process Injection: Process Hollowing (T1055.012)",
			"Analyze with dynamic sandbox to confirm hollowing behavior; inspect child process spawns.")
		debugf("suspicious-import: process hollowing chain detected")
	}

	// Detect reflective DLL injection
	if strings.Contains(imports, "virtualalloc") &&
		strings.Contains(imports, "rtlmovememory") &&
		strings.Contains(imports, "createthread") {
		AddFinding(result, "High", "Behavior", "Reflective loading API chain",
			"VirtualAlloc + RtlMoveMemory + CreateThread imports suggest reflective DLL injection",
			20, 0)
		debugf("suspicious-import: reflective loading chain detected")
	}
}

// --- JSON Plugin Manifest Support ---

// JSONPluginManifest describes a plugin defined via JSON configuration.
type JSONPluginManifest struct {
	PluginName    string   `json:"name"`
	PluginVersion string   `json:"version"`
	Description   string   `json:"description"`
	Modes         []string `json:"modes,omitempty"`
	FileTypes     []string `json:"file_types,omitempty"`
	StringChecks  []struct {
		Contains   string `json:"contains"`
		Severity   string `json:"severity"`
		Category   string `json:"category"`
		Title      string `json:"title"`
		Evidence   string `json:"evidence,omitempty"`
		Score      int    `json:"score"`
		Tactic     string `json:"tactic,omitempty"`
		Technique  string `json:"technique,omitempty"`
	} `json:"string_checks,omitempty"`
}

// LoadJSONPlugin reads a JSON plugin manifest and returns an AnalysisPlugin.
func LoadJSONPlugin(path string) (AnalysisPlugin, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var manifest JSONPluginManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("invalid plugin manifest %s: %w", path, err)
	}
	if manifest.PluginName == "" {
		manifest.PluginName = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	if manifest.PluginVersion == "" {
		manifest.PluginVersion = "1.0"
	}
	return &jsonPlugin{manifest: manifest, path: path}, nil
}

type jsonPlugin struct {
	manifest JSONPluginManifest
	path     string
}

func (p *jsonPlugin) Name() string    { return p.manifest.PluginName }
func (p *jsonPlugin) Version() string { return p.manifest.PluginVersion }

func (p *jsonPlugin) ShouldRun(result *ScanResult, cfg Config) bool {
	if len(p.manifest.Modes) > 0 {
		found := false
		for _, m := range p.manifest.Modes {
			if strings.EqualFold(m, cfg.Mode) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(p.manifest.FileTypes) > 0 {
		found := false
		for _, ft := range p.manifest.FileTypes {
			if strings.EqualFold(ft, result.FileType) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (p *jsonPlugin) Run(result *ScanResult, _ []byte, _ []ExtractedString, corpus string, _ Config, debugf debugLogger) {
	for _, check := range p.manifest.StringChecks {
		needle := strings.ToLower(check.Contains)
		if strings.Contains(corpus, needle) {
			AddFindingDetailed(result, check.Severity, check.Category, check.Title,
				nonEmpty(check.Evidence, "matched: "+check.Contains),
				check.Score, 0, check.Tactic, check.Technique, "")
			debugf("json-plugin %s: matched %q", p.manifest.PluginName, check.Contains)
		}
	}
}

// init registers the built-in plugins.
func init() {
	RegisterPlugin(&HighEntropyBlobPlugin{})
	RegisterPlugin(&SuspiciousImportPlugin{})
}
