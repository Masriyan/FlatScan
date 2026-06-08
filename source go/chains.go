package main

import "strings"

type APIChain struct {
	ID               string
	Name             string
	Severity         string
	Score            int
	Tactic           string
	Technique        string
	Recommendation   string
	RequiredFamilies []string
}

var apiChains = []APIChain{
	{
		ID:               "chain-dll-injection",
		Name:             "Classic DLL injection chain",
		Severity:         "Critical",
		Score:            40,
		Tactic:           "Defense Evasion",
		Technique:        "Process Injection (T1055)",
		Recommendation:   "Correlate process injection artifacts in EDR telemetry; capture memory from injected processes.",
		RequiredFamilies: []string{"process injection", "memory allocation", "network"},
	},
	{
		ID:               "chain-process-hollowing",
		Name:             "Process hollowing chain",
		Severity:         "Critical",
		Score:            38,
		Tactic:           "Defense Evasion",
		Technique:        "Process Hollowing (T1055.012)",
		Recommendation:   "Look for CreateProcess+SUSPENDED followed by WriteProcessMemory and ResumeThread in EDR logs.",
		RequiredFamilies: []string{"process injection", "execution", "process access"},
	},
	{
		ID:               "chain-keylogger-exfil",
		Name:             "Keylogger with exfiltration",
		Severity:         "High",
		Score:            30,
		Tactic:           "Collection",
		Technique:        "Input Capture (T1056)",
		Recommendation:   "Block outbound connections to extracted network IOCs and rotate credentials on affected hosts.",
		RequiredFamilies: []string{"process injection", "network"},
	},
	{
		ID:               "chain-cred-webhook",
		Name:             "Credential theft + webhook exfiltration",
		Severity:         "High",
		Score:            28,
		Tactic:           "Credential Access",
		Technique:        "Credentials from Web Browsers (T1555.003)",
		Recommendation:   "Revoke captured credentials and block webhook endpoints found in IOCs.",
		RequiredFamilies: []string{"process access", "network"},
	},
	{
		ID:               "chain-persist-evade",
		Name:             "Persistence with evasion",
		Severity:         "High",
		Score:            25,
		Tactic:           "Persistence",
		Technique:        "Boot or Logon Autostart Execution (T1547)",
		Recommendation:   "Inspect startup locations, run keys, and services for malicious entries.",
		RequiredFamilies: []string{"persistence", "anti-debugging"},
	},
	{
		ID:               "chain-crypto-wipe",
		Name:             "Ransomware: encrypt + inhibit recovery",
		Severity:         "Critical",
		Score:            45,
		Tactic:           "Impact",
		Technique:        "Data Encrypted for Impact (T1486)",
		Recommendation:   "Isolate the host immediately, preserve memory, and initiate incident response.",
		RequiredFamilies: []string{"cryptography", "wiper"},
	},
	{
		ID:               "chain-namedpipe-inject",
		Name:             "Named pipe C2 with code injection",
		Severity:         "High",
		Score:            30,
		Tactic:           "Command and Control",
		Technique:        "Non-Application Layer Protocol (T1095)",
		Recommendation:   "Hunt for named pipe creation events matching extracted pipe names in EDR telemetry.",
		RequiredFamilies: []string{"named pipe C2", "process injection"},
	},
}

func DetectAPIChains(result *ScanResult) {
	presentFamilies := make(map[string]bool)
	for _, fn := range result.Functions {
		presentFamilies[strings.ToLower(fn.Family)] = true
	}
	// Also check Wiper findings to cover the wiper family marker
	for _, f := range result.Findings {
		if f.Category == "Wiper" {
			presentFamilies["wiper"] = true
		}
		if f.Category == "Cryptominer" {
			presentFamilies["cryptominer"] = true
		}
	}

	for _, chain := range apiChains {
		if chainFires(presentFamilies, chain.RequiredFamilies) {
			AddFindingDetailed(result, chain.Severity, "Chain", chain.Name, "behavioral API chain: "+strings.Join(chain.RequiredFamilies, " + "), chain.Score, 0, chain.Tactic, chain.Technique, chain.Recommendation)
		}
	}
}

func chainFires(present map[string]bool, required []string) bool {
	for _, family := range required {
		if !present[strings.ToLower(family)] {
			return false
		}
	}
	return true
}
