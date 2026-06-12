package main

import (
	"fmt"
	"strings"
)

// CAPA-style capability rule engine (improvementprompt-v3 Task 5).
//
// Substring rules see only cleartext. This engine matches declarative rules over
// a richer feature set — strings, imports (INCLUDING hashdb-resolved API names
// from the disassembly pass), disassembly techniques, and IOC categories — and
// maps the result to ATT&CK. The headline win: capabilities like process
// injection are detected even when the binary resolves its APIs by hash, because
// the feature set includes the names recovered by hashdb.go. Rules are
// declarative (a list of AllOf conditions across feature spaces), so the set is
// extensible without new Go code.

// featureSpace identifies which extracted feature a condition matches against.
type featureSpace int

const (
	featString    featureSpace = iota // lowercase string corpus
	featAPI                           // imports / functions / hashdb-resolved names
	featTechnique                     // disassembly techniques (result.Code)
	featIOCCat                        // IOC categories present
)

type capCondition struct {
	Space featureSpace
	AnyOf []string
}

type capabilityRule struct {
	Name      string
	Category  string
	Severity  string
	Tactic    string
	Technique string
	Recommend string
	AllOf     []capCondition
	Score     int
}

// features is the evaluated feature view of a scan result.
type features struct {
	strings    string
	apis       map[string]bool
	techniques map[string]bool
	iocCats    map[string]bool
}

func (f features) matches(c capCondition) (string, bool) {
	switch c.Space {
	case featString:
		for _, t := range c.AnyOf {
			if strings.Contains(f.strings, strings.ToLower(t)) {
				return t, true
			}
		}
	case featAPI:
		for _, t := range c.AnyOf {
			lt := strings.ToLower(t)
			if f.apis[lt] {
				return t, true
			}
			// Fall back to the corpus: imports often appear there too.
			if strings.Contains(f.strings, lt) {
				return t, true
			}
		}
	case featTechnique:
		for _, t := range c.AnyOf {
			if f.techniques[strings.ToLower(t)] {
				return t, true
			}
		}
	case featIOCCat:
		for _, t := range c.AnyOf {
			if f.iocCats[t] {
				return t, true
			}
		}
	}
	return "", false
}

// capabilityRules is the built-in starter pack. Each requires ALL of its
// conditions, so a single feature never fires a capability on its own.
var capabilityRules = []capabilityRule{
	{
		Name: "Process injection", Category: "Behavior", Severity: "High",
		Tactic: "Defense Evasion", Technique: "Process Injection (T1055)",
		Recommend: "Confirm the target process and injected buffer; resolved-by-hash injection APIs are recovered into this feature set.",
		Score:     24,
		AllOf: []capCondition{
			{featAPI, []string{"writeprocessmemory", "ntwritevirtualmemory", "ntwritevirtualmemory"}},
			{featAPI, []string{"createremotethread", "ntcreatethreadex", "queueuserapc", "setthreadcontext", "rtlcreateuserthread"}},
			{featAPI, []string{"virtualallocex", "ntallocatevirtualmemory", "ntmapviewofsection"}},
		},
	},
	{
		Name: "Browser credential theft", Category: "Credential Access", Severity: "High",
		Tactic: "Credential Access", Technique: "Credentials from Web Browsers (T1555.003)",
		Recommend: "Rotate browser-stored secrets; inspect Login Data / Local State access.",
		Score:     22,
		AllOf: []capCondition{
			{featString, []string{"encrypted_key", "login data", "local state", "web data"}},
			{featAPI, []string{"cryptunprotectdata", "bcryptdecrypt"}},
		},
	},
	{
		Name: "Disable security tooling", Category: "Evasion", Severity: "High",
		Tactic: "Defense Evasion", Technique: "Impair Defenses (T1562.001)",
		Recommend: "Verify Defender/EDR state on hosts where this executed.",
		Score:     22,
		AllOf: []capCondition{
			{featString, []string{"set-mppreference", "disablerealtimemonitoring", "sc stop windefend", "net stop", "add-mppreference -exclusionpath"}},
			{featString, []string{"defender", "windefend", "amsi", "antivirus", "antispyware"}},
		},
	},
	{
		Name: "Scheduled-task persistence", Category: "Persistence", Severity: "Medium",
		Tactic: "Persistence", Technique: "Scheduled Task/Job (T1053.005)",
		Recommend: "Audit scheduled tasks created on affected hosts.",
		Score:     14,
		AllOf: []capCondition{
			{featString, []string{"schtasks /create", "schtasks  /create", "register-scheduledtask", "taskschd.dll", "itaskservice"}},
		},
	},
	{
		Name: "Self-deletion / anti-forensics", Category: "Evasion", Severity: "Medium",
		Tactic: "Defense Evasion", Technique: "Indicator Removal: File Deletion (T1070.004)",
		Recommend: "A self-deleting stub indicates intent to evade triage; recover the dropped artifacts.",
		Score:     12,
		AllOf: []capCondition{
			{featString, []string{"cmd /c del", "cmd.exe /c del", "ping 127.0.0.1 -n", "choice /c y /n /d y /t", "/c timeout"}},
		},
	},
	{
		Name: "Clipboard cryptocurrency hijacking", Category: "Impact", Severity: "High",
		Tactic: "Impact", Technique: "Transmitted Data Manipulation (T1565.002)",
		Recommend: "Clipboard monitoring + a wallet address is the crypto-clipper pattern; warn affected users.",
		Score:     20,
		AllOf: []capCondition{
			{featAPI, []string{"getclipboarddata", "setclipboarddata", "openclipboard", "addclipboardformatlistener"}},
			{featIOCCat, []string{"suspicious-infra"}}, // crypto-wallet IOCs classify as suspicious-infra
		},
	},
}

// RunCapabilityRules evaluates the built-in capability rules and records
// correlated findings (with evidence count + confidence) for matches.
func RunCapabilityRules(result *ScanResult, corpus string) {
	if result == nil {
		return
	}
	f := buildFeatures(result, corpus)
	for _, rule := range capabilityRules {
		var evidence []string
		ok := true
		for _, cond := range rule.AllOf {
			if hit, matched := f.matches(cond); matched {
				evidence = append(evidence, hit)
			} else {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		confidence := clampInt(58+len(rule.AllOf)*10, 0, 96)
		AddCorrelatedFinding(result, rule.Severity, rule.Category,
			"Capability: "+rule.Name,
			fmt.Sprintf("capability rule matched on %s", strings.Join(evidence, " + ")),
			rule.Score, 0, rule.Tactic, rule.Technique, rule.Recommend,
			len(rule.AllOf), confidence)
	}
}

func buildFeatures(result *ScanResult, corpus string) features {
	f := features{
		strings:    corpus,
		apis:       map[string]bool{},
		techniques: map[string]bool{},
		iocCats:    map[string]bool{},
	}
	addAPI := func(names []string) {
		for _, n := range names {
			f.apis[strings.ToLower(strings.TrimSpace(n))] = true
		}
	}
	if result.PE != nil {
		addAPI(result.PE.Imports)
	}
	if result.ELF != nil {
		addAPI(result.ELF.Imports)
	}
	if result.MachO != nil {
		addAPI(result.MachO.Imports)
	}
	for _, fn := range result.Functions {
		f.apis[strings.ToLower(fn.Name)] = true
	}
	if result.Code != nil {
		addAPI(result.Code.ResolvedHashedAPIs) // hashdb-recovered imports
		for _, t := range result.Code.Techniques {
			f.techniques[strings.ToLower(t)] = true
		}
	}
	for _, c := range result.IOCs.Classified {
		f.iocCats[c.Category] = true
	}
	return f
}
