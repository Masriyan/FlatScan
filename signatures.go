package main

import (
	"fmt"
	"strings"
)

type apiPattern struct {
	Needle   string
	Name     string
	Family   string
	Severity string
}

var apiPatterns = []apiPattern{
	{"virtualalloc", "VirtualAlloc", "memory allocation", "Medium"},
	{"virtualallocex", "VirtualAllocEx", "process injection", "High"},
	{"writeprocessmemory", "WriteProcessMemory", "process injection", "High"},
	{"createremotethread", "CreateRemoteThread", "process injection", "High"},
	{"ntcreatethreadex", "NtCreateThreadEx", "process injection", "High"},
	{"queueuserapc", "QueueUserAPC", "process injection", "Medium"},
	{"setwindowshookex", "SetWindowsHookEx", "process injection", "Medium"},
	{"openprocess", "OpenProcess", "process access", "Medium"},
	{"readprocessmemory", "ReadProcessMemory", "process access", "Medium"},
	{"ntqueryinformationprocess", "NtQueryInformationProcess", "anti-analysis", "Medium"},
	{"isdebuggerpresent", "IsDebuggerPresent", "anti-debugging", "Medium"},
	{"checkremotedebuggerpresent", "CheckRemoteDebuggerPresent", "anti-debugging", "Medium"},
	{"loadlibrary", "LoadLibrary", "dynamic loading", "Low"},
	{"getprocaddress", "GetProcAddress", "dynamic loading", "Low"},
	{"urldownloadtofile", "URLDownloadToFile", "downloader", "High"},
	{"internetopen", "InternetOpen", "network", "Medium"},
	{"internetreadfile", "InternetReadFile", "network", "Medium"},
	{"winhttpopen", "WinHttpOpen", "network", "Medium"},
	{"winhttpreaddata", "WinHttpReadData", "network", "Medium"},
	{"wsastartup", "WSAStartup", "network", "Low"},
	{"cryptdecrypt", "CryptDecrypt", "cryptography", "Medium"},
	{"cryptencrypt", "CryptEncrypt", "cryptography", "Medium"},
	{"bcryptdecrypt", "BCryptDecrypt", "cryptography", "Medium"},
	{"createservice", "CreateService", "persistence", "High"},
	{"regsetvalue", "RegSetValue", "persistence", "Medium"},
	{"shellexecute", "ShellExecute", "execution", "Medium"},
	{"createprocess", "CreateProcess", "execution", "Medium"},
	{"ptrace", "ptrace", "linux anti-debug/process access", "Medium"},
	{"mprotect", "mprotect", "linux memory permission", "Medium"},
	{"dlopen", "dlopen", "dynamic loading", "Low"},
	{"dlsym", "dlsym", "dynamic loading", "Low"},
	{"execve", "execve", "execution", "Medium"},
	{"system(", "system", "execution", "Medium"},
}

func AnalyzePatterns(result *ScanResult, stringsFound []ExtractedString, cfg Config) {
	corpus := buildCorpus(stringsFound, result.DecodedArtifacts, 32*1024*1024)

	for _, api := range apiPatterns {
		if strings.Contains(corpus, api.Needle) {
			result.Functions = append(result.Functions, FunctionHit{
				Name:     api.Name,
				Family:   api.Family,
				Severity: api.Severity,
				Source:   "strings/imports",
			})
		}
	}

	if hasAll(corpus, "writeprocessmemory") && hasAny(corpus, "createremotethread", "ntcreatethreadex", "queueuserapc") && hasAny(corpus, "virtualallocex", "virtualalloc") {
		AddFinding(result, "High", "Behavior", "Process injection API chain", "memory allocation, process write, and remote execution APIs are present", 24, 0)
	}
	if hasAll(corpus, "loadlibrary", "getprocaddress") && hasAny(corpus, "virtualalloc", "virtualprotect", "ntprotectvirtualmemory") {
		AddFinding(result, "Medium", "Behavior", "Dynamic API resolution with executable memory", "LoadLibrary/GetProcAddress and memory permission APIs are present", 12, 0)
	}
	if hasAny(corpus, "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "outputdebugstring") {
		AddFinding(result, "Medium", "Evasion", "Anti-debugging reference", "debugger detection strings or APIs are present", 10, 0)
	}
	if hasAny(corpus, "vmware", "vboxservice", "virtualbox", "qemu", "xenservice", "wireshark", "procmon", "processhacker", "x64dbg", "ollydbg") {
		AddFindingDetailed(result, "Medium", "Evasion", "Sandbox or analyst tool awareness", "virtualization, debugger, or analyst tool strings are present", 11, 0, "Defense Evasion", "Virtualization/Sandbox Evasion (T1497)", "Run the sample in an isolated lab with VM artifact controls varied, and correlate with dynamic anti-analysis behavior.")
	}
	if hasAny(corpus, "ven_vmware", "vmware tools", "vbox_", "virtualbox") && hasAny(corpus, "hardware\\acpi", "currentcontrolset\\enum", "software\\vmware") {
		AddFindingDetailed(result, "High", "Evasion", "Explicit VM fingerprinting registry checks", "VMware or VirtualBox registry/device identifiers are embedded", 20, 0, "Defense Evasion", "Virtualization/Sandbox Evasion (T1497)", "Treat VM-check strings as an anti-analysis signal; repeat dynamic analysis with hardened sandbox artifacts.")
	}
	if hasAny(corpus, "amsi", "amsiscanbuffer", "etweventwrite", "disableantispyware", "add-mppreference", "set-mppreference") {
		AddFindingDetailed(result, "High", "Evasion", "Security tooling bypass indicator", "AMSI, ETW, or Microsoft Defender bypass strings are present", 20, 0, "Defense Evasion", "Impair Defenses (T1562)", "Review endpoint telemetry for security tool tampering around first execution time.")
	}
	if hasAny(corpus, "urldownloadtofile", "winhttpopen", "internetopen", "downloadstring", "webclient") && (len(result.IOCs.URLs) > 0 || len(result.IOCs.Domains) > 0 || len(result.IOCs.IPv4) > 0) {
		AddFindingDetailed(result, "High", "Network", "Downloader behavior indicators", "network download APIs and network IOCs are present", 22, 0, "Command and Control", "Application Layer Protocol (T1071)", "Block and hunt for extracted network indicators in proxy, DNS, and EDR telemetry.")
	}
	if len(result.IOCs.URLs) > 0 && hasAny(corpus, "user-agent", "bot", "gate.php", "/api/", "telegram", "discord.com/api/webhooks") {
		AddFindingDetailed(result, "Medium", "Network", "Command-and-control style network strings", "URLs appear alongside bot, API, webhook, or user-agent strings", 12, 0, "Command and Control", "Web Service (T1102)", "Review HTTP telemetry for the listed URLs and any adjacent API/webhook traffic.")
	}
	if webhook := firstMatchingURL(result.IOCs.URLs, "discord.com/api/webhooks", "discordapp.com/api/webhooks"); webhook != "" {
		AddFindingDetailed(result, "High", "Exfiltration", "Discord webhook exfiltration endpoint", webhook, 28, 0, "Exfiltration", "Exfiltration Over Web Service (T1567)", "Revoke the webhook, preserve it as an IOC, and search proxy/EDR telemetry for POST traffic to the endpoint.")
	}
	if hasAny(corpus, "discordapp.com/api/v8/users/@me", "discord.com/api/v", "cdn.discordapp.com/avatars") && hasAny(corpus, "token", "authorization", "webhook", "avatar") {
		AddFindingDetailed(result, "High", "Credential Access", "Discord account/API access indicators", "Discord user API/avatar/webhook strings are embedded", 18, 0, "Credential Access", "Credentials from Web Browsers (T1555.003)", "Reset exposed Discord tokens and hunt for unauthorized API calls from affected hosts.")
	}
	if hasAny(corpus, "hkey_current_user\\software\\microsoft\\windows\\currentversion\\run", "hklm\\software\\microsoft\\windows\\currentversion\\run", "software\\microsoft\\windows\\currentversion\\run", "createservice", "schtasks", "\\startup\\") {
		AddFindingDetailed(result, "High", "Persistence", "Windows persistence indicator", "Run keys, service creation, scheduled task, or startup folder strings are present", 20, 0, "Persistence", "Registry Run Keys / Startup Folder (T1547.001)", "Inspect Run keys, services, scheduled tasks, and startup directories on systems where this file executed.")
	}
	if hasAny(corpus, "/etc/cron", "crontab", "/etc/systemd/system", "authorized_keys", "ld_preload", ".bashrc", ".profile") {
		AddFinding(result, "Medium", "Persistence", "Linux persistence indicator", "cron, systemd, SSH, preload, or shell profile paths are present", 12, 0)
	}
	if hasAny(corpus, "powershell") && hasAny(corpus, "-enc", "-encodedcommand", "frombase64string", "downloadstring", "invoke-expression", " iex ") {
		AddFinding(result, "High", "Script", "Suspicious PowerShell execution", "PowerShell appears with encoded command or download/execution terms", 22, 0)
	}
	if hasAny(corpus, "wscript.shell", "activexobject", "mshta", "rundll32", "regsvr32", "javascript:eval", "fromcharcode", "unescape(") {
		AddFinding(result, "Medium", "Script", "Suspicious script execution or obfuscation", "script host, LOLBin, eval, or character-code obfuscation strings are present", 13, 0)
	}
	if hasAny(corpus, "your files have been encrypted", "decrypt your files", "recover your files", "bitcoin", "monero", ".onion") && hasAny(corpus, "encrypt", "decrypt", "ransom", ".locked", ".encrypted") {
		AddFinding(result, "High", "Ransomware", "Ransomware-style strings", "encryption, payment, recovery, or onion-service terms are present", 24, 0)
	}
	if hasAny(corpus, "lsass", "sekurlsa", "logonpasswords", "samlib.dll", "ntds.dit", "dpapi", "browsercookies", "wallet.dat") {
		AddFindingDetailed(result, "High", "Credential Access", "Credential or wallet theft indicator", "credential store, LSASS, DPAPI, browser, or wallet strings are present", 22, 0, "Credential Access", "OS Credential Dumping (T1003)", "Collect host triage for credential access artifacts and rotate credentials exposed on affected endpoints.")
	}
	if hasAny(corpus, "\"encrypted_key\"", "encrypted_key", "decryptwithkey", "unable to decrypt") && hasAny(corpus, "bcryptdecrypt", "cryptunprotectdata", "dpapi", "decrypt") {
		AddFindingDetailed(result, "High", "Credential Access", "Chromium credential decryption workflow", "encrypted_key and Windows crypto/decrypt routines are referenced", 26, 0, "Credential Access", "Credentials from Web Browsers (T1555.003)", "Assume browser secrets may be targeted; rotate passwords/tokens and inspect browser Login Data, Cookies, and Local State access telemetry.")
	}
	if hasAny(corpus, "upx0", "upx1", "upx!", ".aspack", "themida", "vmprotect", "enigma protector", "mpress") {
		AddFinding(result, "Medium", "Packing", "Known packer or protector marker", "UPX, ASPack, Themida, VMProtect, Enigma, or MPRESS marker present", 13, 0)
	}
	if result.Entropy >= 7.70 {
		AddFinding(result, "High", "Packing", "Very high file entropy", fmt.Sprintf("overall entropy %.2f/8.00", result.Entropy), 18, 0)
	} else if result.Entropy >= 7.20 {
		AddFinding(result, "Medium", "Packing", "High file entropy", fmt.Sprintf("overall entropy %.2f/8.00", result.Entropy), 10, 0)
	}
	if len(result.HighEntropyRegions) >= 3 {
		AddFinding(result, "Medium", "Packing", "Multiple high-entropy regions", fmt.Sprintf("%d high-entropy regions found", len(result.HighEntropyRegions)), 10, 0)
	}
	if len(result.DecodedArtifacts) > 0 {
		AddFinding(result, "Low", "Obfuscation", "Encoded data decoded successfully", fmt.Sprintf("%d base64/hex/URL encoded artifacts decoded", len(result.DecodedArtifacts)), 4, 0)
	}
	if len(result.IOCs.SHA256)+len(result.IOCs.SHA1)+len(result.IOCs.MD5) >= 5 {
		AddFinding(result, "Low", "IOC", "Embedded hash-like indicators", "multiple MD5/SHA1/SHA256-looking values were extracted", 3, 0)
	}
	if IOCCount(result.IOCs) >= 10 {
		AddFinding(result, "Low", "IOC", "High IOC density", fmt.Sprintf("%d total IOCs extracted", IOCCount(result.IOCs)), 4, 0)
	}

	result.SuspiciousStrings = suspiciousStringSamples(stringsFound, 60)
}

func firstMatchingURL(urls []string, needles ...string) string {
	for _, value := range urls {
		lower := strings.ToLower(value)
		for _, needle := range needles {
			if strings.Contains(lower, strings.ToLower(needle)) {
				return value
			}
		}
	}
	return ""
}

func buildCorpus(stringsFound []ExtractedString, decoded []DecodedArtifact, maxBytes int) string {
	var builder strings.Builder
	for _, item := range stringsFound {
		if builder.Len()+len(item.Value)+1 > maxBytes {
			break
		}
		builder.WriteString(strings.ToLower(item.Value))
		builder.WriteByte('\n')
	}
	for _, item := range decoded {
		if builder.Len()+len(item.Preview)+1 > maxBytes {
			break
		}
		builder.WriteString(strings.ToLower(item.Preview))
		builder.WriteByte('\n')
	}
	return builder.String()
}

func suspiciousStringSamples(stringsFound []ExtractedString, limit int) []string {
	keywords := []string{
		"powershell", "cmd.exe", "rundll32", "regsvr32", "mshta", "wscript",
		"virtualalloc", "writeprocessmemory", "createremotethread", "isdebuggerpresent",
		"downloadstring", "urldownloadtofile", "winhttp", "internetopen",
		"hkey_current_user", "hkey_local_machine", "\\currentversion\\run",
		"bitcoin", "monero", ".onion", "decrypt", "encrypt", "ransom",
		"lsass", "sekurlsa", "mimikatz", "wallet.dat", "discord.com/api/webhooks",
		"amsi", "etw", "defender", "vbox", "vmware", "x64dbg", "ollydbg",
	}
	var out []string
	seen := make(map[string]struct{})
	for _, item := range stringsFound {
		lower := strings.ToLower(item.Value)
		if !hasAny(lower, keywords...) {
			continue
		}
		preview := previewString(item.Value, 180)
		if _, ok := seen[preview]; ok {
			continue
		}
		seen[preview] = struct{}{}
		out = append(out, preview)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func hasAll(text string, needles ...string) bool {
	for _, needle := range needles {
		if !strings.Contains(text, strings.ToLower(needle)) {
			return false
		}
	}
	return true
}

func hasAny(text string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(text, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}
