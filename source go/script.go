package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

// Script / interpreted-payload analysis.
//
// Before this analyzer FlatScan classified a .ps1 as generic "text" and only
// fired the catch-all "Encoded data decoded successfully" finding (score 4),
// badly under-scoring real droppers. The live sample sweep (2026-06) decoded a
// multi-layer PowerShell payload (base64 -> separator-delimited hex) that
// disabled Microsoft Defender and stripped the Windows Security UI.
//
// analyzeScript routes script-like files here; scanScriptContent is the shared
// behavioral engine, also reused by the LNK analyzer for embedded command
// lines. It deobfuscates nested encoding layers and scores interpreter abuse,
// defense-evasion, download cradles, and obfuscation — matching on the decoded
// content, not just the literal bytes.

// scriptTypeByExt maps a script file extension to a human-readable type. Empty
// string means "not a recognized script extension".
func scriptTypeByExt(lowerName string) string {
	switch {
	case strings.HasSuffix(lowerName, ".ps1") || strings.HasSuffix(lowerName, ".psm1") || strings.HasSuffix(lowerName, ".psd1"):
		return "PowerShell script"
	case strings.HasSuffix(lowerName, ".bat") || strings.HasSuffix(lowerName, ".cmd"):
		return "Batch script"
	case strings.HasSuffix(lowerName, ".vbs") || strings.HasSuffix(lowerName, ".vbe"):
		return "VBScript"
	case strings.HasSuffix(lowerName, ".js") || strings.HasSuffix(lowerName, ".jse"):
		return "JScript"
	case strings.HasSuffix(lowerName, ".wsf"):
		return "Windows Script File"
	case strings.HasSuffix(lowerName, ".hta"):
		return "HTA application"
	case strings.HasSuffix(lowerName, ".sh"):
		return "Shell script"
	}
	return ""
}

// isScriptType reports whether a detected file type should be routed through the
// script behavioral engine.
func isScriptType(fileType string) bool {
	switch fileType {
	case "PowerShell script", "Batch script", "VBScript", "JScript",
		"Windows Script File", "HTA application", "Shell script", "script/text", "text",
		"HTML application", "HTML document":
		return true
	}
	return false
}

func analyzeScript(result *ScanResult, cfg Config, data []byte) error {
	scanScriptContent(result, cfg, scriptText(data), "script body")
	return nil
}

// scriptText returns the script body as UTF-8, transparently decoding UTF-16
// (LE/BE, with or without BOM) so token matching and deobfuscation work on
// scripts saved in UTF-16 (a common PowerShell/JScript dropper encoding).
func scriptText(data []byte) string {
	if !looksUTF16Text(data) {
		return string(data)
	}
	bigEndian := false
	if len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF {
		bigEndian = true
		data = data[2:]
	} else if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		data = data[2:]
	} else {
		// No BOM: infer endianness from which phase has the NUL bytes.
		odd := 0
		n := len(data)
		if n > 512 {
			n = 512
		}
		for i := 0; i+1 < n; i += 2 {
			if data[i] == 0x00 {
				odd++
			}
		}
		bigEndian = odd*2 > n/2 // NULs in the low byte => big-endian
	}
	u16 := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		if bigEndian {
			u16 = append(u16, uint16(data[i])<<8|uint16(data[i+1]))
		} else {
			u16 = append(u16, uint16(data[i+1])<<8|uint16(data[i]))
		}
	}
	return string(utf16.Decode(u16))
}

// scanScriptContent deobfuscates and scores an interpreted payload. content is
// the raw script/command text; source describes its origin (e.g. "script body"
// or "LNK command line") and is used in finding evidence.
func scanScriptContent(result *ScanResult, cfg Config, content, source string) {
	if result == nil || strings.TrimSpace(content) == "" {
		return
	}

	depth := cfg.MaxDecodeDepth
	if depth < 3 {
		depth = 3 // scripts chain several layers; ensure we follow them
	}
	layers := decodeAllLayers(content, depth)

	// Recover IOCs hidden by encoding or whole-string reversal (a common
	// PowerShell trick) and merge them so downstream reporting and the
	// downloader heuristics see the real C2.
	reversed := reverseString(content)
	MergeIOCSet(&result.IOCs, ExtractIOCs(reversed))
	for _, layer := range layers {
		MergeIOCSet(&result.IOCs, ExtractIOCs(layer))
		MergeIOCSet(&result.IOCs, ExtractIOCs(reverseString(layer)))
	}

	// Replay fragment-at-a-time string building over the raw body and every
	// decoded layer. Droppers assemble "adodb.stream" or an XMLHTTP call from
	// dozens of one- and two-character appends, so the token never appears in
	// the file and every check below would otherwise miss it.
	split := resolveSplitLiterals(content)
	for _, layer := range layers {
		layerSplit := resolveSplitLiterals(layer)
		split.Values = append(split.Values, layerSplit.Values...)
		split.Assignments += layerSplit.Assignments
		split.Lines += layerSplit.Lines
	}
	for _, value := range split.Values {
		MergeIOCSet(&result.IOCs, ExtractIOCs(value))
	}

	// combined: lower-cased raw + reversed + every decoded layer + every
	// reconstructed literal, so behavioral matching sees through the
	// obfuscation.
	var b strings.Builder
	b.WriteString(strings.ToLower(content))
	b.WriteByte('\n')
	b.WriteString(strings.ToLower(reversed))
	b.WriteByte('\n')
	for _, layer := range layers {
		b.WriteString(strings.ToLower(layer))
		b.WriteByte('\n')
	}
	for _, value := range split.Values {
		b.WriteString(strings.ToLower(value))
		b.WriteByte('\n')
	}
	combined := b.String()

	psContext := result.FileType == "PowerShell script" ||
		hasAny(combined, "powershell", "invoke-expression", "-encodedcommand", "frombase64string",
			"get-appxpackage", "set-mppreference", "[system.convert]", "new-object system.net")

	// --- Defense evasion: Microsoft Defender / AMSI tampering ---
	if hasAny(combined, "set-mppreference", "add-mppreference", "disablerealtimemonitoring",
		"disablebehaviormonitoring", "disableioavprotection", "disableantispyware", "-exclusionpath", "-exclusionextension") {
		AddFindingDetailed(result, "High", "Evasion",
			"Microsoft Defender tampering",
			"script disables or adds exclusions to Microsoft Defender (Set/Add-MpPreference) in "+source,
			28, 0,
			"Defense Evasion", "Impair Defenses: Disable or Modify Tools (T1562.001)",
			"Treat the host as having had real-time protection disabled; review Defender event logs around execution time and re-enable protection.")
	}
	if hasAny(combined, "amsiinitfailed", "amsiutils", "amsiscanbuffer", "amsicontext", "etweventwrite") {
		AddFindingDetailed(result, "High", "Evasion",
			"AMSI/ETW bypass indicator",
			"script references AMSI/ETW internals used to blind in-memory scanning in "+source,
			26, 0,
			"Defense Evasion", "Impair Defenses (T1562)",
			"Assume script-block/AMSI logging was tampered with; rely on process and network telemetry for this execution.")
	}
	if hasAny(combined, "sechealthui", "remove-appxprovisionedpackage", "set-nonremovableapppolicy") &&
		hasAny(combined, "defender", "sechealthui", "windowssecurity", "appx") {
		AddFindingDetailed(result, "Medium", "Evasion",
			"Windows Security component removal",
			"script provisions away the Windows Security UI / Defender AppX package in "+source,
			14, 0,
			"Defense Evasion", "Impair Defenses (T1562.001)",
			"Verify the Windows Security app and Defender packages are intact on affected hosts.")
	}

	// --- Download-and-execute cradle ---
	hasDownload := hasAny(combined, "downloadstring", "downloadfile", "downloaddata", "invoke-webrequest",
		"net.webclient", "system.net.webclient", "start-bitstransfer", "wget ", " curl ",
		"certutil -urlcache", "certutil.exe -urlcache", "bitsadmin", "xmlhttp", "msxml2.serverxmlhttp",
		// WSH/VBScript cradle: XMLHTTP fetches the payload and ADODB.Stream
		// writes it to disk via SaveToFile.
		"adodb.stream", "winhttp.winhttprequest", "urldownloadtofile", ".savetofile")
	hasExec := hasAny(combined, "invoke-expression", " iex ", "iex(", "iex ", ".invoke(", "start-process",
		"saps ", "createobject(\"wscript.shell\")", ".run", "shellexecute", "cmd /c", "cmd.exe /c",
		// "cript.shell" rather than "wscript.shell": split-literal builders
		// routinely leave the "WS" prefix in a different variable, so the
		// reconstructed value starts mid-token.
		"cript.shell", "shell.application")
	switch {
	case hasDownload && hasExec:
		AddFindingDetailed(result, "High", "Network",
			"Remote download-and-execute cradle",
			"script downloads a remote payload and executes it (download API + IEX/Start-Process) in "+source,
			30, 0,
			"Command and Control", "Ingress Tool Transfer (T1105)",
			"Block and hunt for the extracted URLs/domains; the staged second-stage payload should be retrieved and analyzed.")
	case hasDownload:
		AddFindingDetailed(result, "Medium", "Network",
			"Remote file download",
			"script references a remote file download API in "+source,
			14, 0,
			"Command and Control", "Ingress Tool Transfer (T1105)",
			"Review the destination URLs and whether downloaded content is executed.")
	}

	// --- Stealthy execution flags ---
	if hasAny(combined, "-w hidden", "-windowstyle hidden", "-executionpolicy bypass", "-ep bypass",
		"-exec bypass", "-noprofile", "-nop ", "-noni", "-noninteractive", "-enc ", "-encodedcommand") {
		AddFindingDetailed(result, "Medium", "Execution",
			"Stealthy/bypassing interpreter flags",
			"script invokes an interpreter with hidden-window, execution-policy-bypass, or encoded-command flags in "+source,
			12, 0,
			"Execution", "Command and Scripting Interpreter: PowerShell (T1059.001)",
			"Correlate with process-creation telemetry for hidden PowerShell/cmd children.")
	}

	// --- Obfuscation ---
	maxB64 := 0
	for _, candidate := range base64CandidateRe.FindAllString(content, -1) {
		if len(candidate) > maxB64 {
			maxB64 = len(candidate)
		}
	}
	if psContext && (maxB64 >= 200 || len(layers) >= 2) {
		AddFindingDetailed(result, "High", "Obfuscation",
			"Heavily obfuscated script content",
			fmt.Sprintf("nested encoding layers decoded (%d) and/or large encoded literal (%d chars) in %s", len(layers), maxB64, source),
			22, 0,
			"Defense Evasion", "Obfuscated Files or Information (T1027)",
			"Use the decoded layers below as the true payload for triage and IOC extraction.")
	}
	if hasAny(combined, "-join", "[char]", "[char[]]", "fromcharcode", "[convert]::tochar", "[system.text.encoding]") &&
		hasAny(content, "'", "\"", "+") {
		AddFindingDetailed(result, "Medium", "Obfuscation",
			"Character-code string reconstruction",
			"script rebuilds commands from character codes / -join concatenation in "+source,
			14, 0,
			"Defense Evasion", "Obfuscated Files or Information (T1027)",
			"De-obfuscate the reconstructed string to reveal the underlying command.")
	}
	// Fragment-at-a-time string building. Scored on the technique rather than
	// on what was recovered: a script that assembles hundreds of literals a
	// character at a time is hiding its tokens by construction, and that holds
	// even when reconstruction cannot resolve them into a recognizable API
	// name. Benign code concatenates strings, but not at this density — the
	// thresholds require both a large absolute count and a large share of all
	// lines so that ordinary string-building code does not qualify.
	if split.Assignments >= 40 && split.Density() >= 5 {
		severity, score := "Medium", 16
		if split.Assignments >= 200 {
			severity, score = "High", 26
		}
		AddFindingDetailed(result, severity, "Obfuscation",
			"Split-literal string obfuscation",
			fmt.Sprintf("%d append assignments across %d lines (%d%%) rebuild strings a fragment at a time in %s; %d values reconstructed",
				split.Assignments, split.Lines, split.Density(), source, len(split.Values)),
			score, 0,
			"Defense Evasion", "Obfuscated Files or Information (T1027.010)",
			"The reconstructed strings hold the real API names and C2 URLs; hunt on those rather than on literals in the file.")
	}
	if hasAny(combined, "[array]::reverse", ".length..0", "[-1..-", "$_.length..0") {
		AddFindingDetailed(result, "Medium", "Obfuscation",
			"Reversed-string obfuscation",
			"script reverses a string to hide a URL or command in "+source,
			12, 0,
			"Defense Evasion", "Obfuscated Files or Information (T1027)",
			"Reverse the literal to recover the hidden value (FlatScan extracts reversed IOCs automatically).")
	}

	// --- Persistence ---
	if hasAny(combined, "schtasks /create", "register-scheduledtask", "new-scheduledtask") {
		AddFindingDetailed(result, "Medium", "Persistence",
			"Scheduled task creation",
			"script creates a scheduled task in "+source,
			14, 0,
			"Persistence", "Scheduled Task/Job (T1053.005)",
			"Audit scheduled tasks created on affected hosts.")
	}
	if hasAny(combined, "currentversion\\run", "new-itemproperty", "set-itemproperty") &&
		hasAny(combined, "\\run", "startup") {
		AddFindingDetailed(result, "Medium", "Persistence",
			"Registry Run-key persistence",
			"script writes a Run key / startup entry in "+source,
			14, 0,
			"Persistence", "Registry Run Keys / Startup Folder (T1547.001)",
			"Inspect Run keys and startup folders on affected hosts.")
	}

	// Record decoded layers as artifacts so the report shows the true payload.
	for _, layer := range layers {
		preview := previewString(layer, 240)
		exists := false
		for _, existing := range result.DecodedArtifacts {
			if existing.Preview == preview {
				exists = true
				break
			}
		}
		if !exists {
			result.DecodedArtifacts = append(result.DecodedArtifacts, DecodedArtifact{
				Encoding: "script-layer",
				Source:   source,
				Preview:  preview,
				IOCs:     ExtractIOCs(layer),
			})
		}
	}
}

// scriptHint returns a script type if path/content look script-like even when
// the binary sniff fell through to "text"/"unknown".
func scriptHint(data []byte, path string) string {
	return scriptTypeByExt(strings.ToLower(filepath.Base(path)))
}
