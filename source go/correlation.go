package main

import (
	"fmt"
	"strings"
)

// Correlation engine (improvementprompt-v3 Task 2).
//
// Several legacy signatures fire a serious, high-severity finding from a single
// generic string — e.g. any one of {lsass, sekurlsa, sam, …} => "Credential
// Access / High". That inflates confidence and pollutes ATT&CK mapping. This
// engine models a capability as an *evidence cluster*: several token GROUPS,
// where matching one token in a group counts as one independent evidence point.
// A capability only fires when enough distinct groups co-occur, and its
// confidence + score scale with the number of corroborating groups. A lone
// generic string therefore never produces a high-confidence serious finding.

type clusterGroup struct {
	Label  string
	Tokens []string
}

type evidenceCluster struct {
	Name      string
	Category  string
	Severity  string
	Tactic    string
	Technique string
	Recommend string
	Groups    []clusterGroup
	MinGroups int // distinct groups that must match before the cluster fires
	BaseScore int // score at MinGroups; +scoreStep per additional group
	ScoreStep int
}

// correlationClusters are the multi-evidence capabilities. Each requires at
// least MinGroups distinct evidence groups, so no single repeated token fires.
var correlationClusters = []evidenceCluster{
	{
		Name:      "OS credential dumping",
		Category:  "Credential Access",
		Severity:  "High",
		Tactic:    "Credential Access",
		Technique: "OS Credential Dumping (T1003)",
		Recommend: "Collect host triage for LSASS/SAM access and rotate credentials exposed on affected endpoints.",
		Groups: []clusterGroup{
			{"credential store", []string{"lsass", "ntds.dit", "\\sam", "hklm\\sam", "security hive", "sam database"}},
			{"dump mechanism", []string{"minidumpwritedump", "sekurlsa", "logonpasswords", "lsadump", "comsvcs.dll", "procdump", "dbghelp.dll"}},
			{"process access", []string{"openprocess", "readprocessmemory", "ntreadvirtualmemory", "ntopenprocess"}},
		},
		MinGroups: 2,
		BaseScore: 20,
		ScoreStep: 6,
	},
	{
		Name:      "Browser credential theft",
		Category:  "Credential Access",
		Severity:  "High",
		Tactic:    "Credential Access",
		Technique: "Credentials from Web Browsers (T1555.003)",
		Recommend: "Assume browser secrets are targeted; rotate passwords/tokens and inspect Login Data / Cookies / Local State access.",
		Groups: []clusterGroup{
			{"browser store", []string{"login data", "cookies.sqlite", "\\user data\\", "web data", "moz_logins"}},
			{"master key", []string{"local state", "encrypted_key", "os_crypt"}},
			{"decryptor", []string{"cryptunprotectdata", "bcryptdecrypt", "dpapi", "aes-gcm", "aes_256_gcm"}},
		},
		MinGroups: 2,
		BaseScore: 22,
		ScoreStep: 6,
	},
	{
		Name:      "Keylogging + collection",
		Category:  "Collection",
		Severity:  "Medium",
		Tactic:    "Collection",
		Technique: "Input Capture: Keylogging (T1056.001)",
		Recommend: "Correlate keystroke-capture APIs with the exfiltration channel to confirm an info-stealer.",
		Groups: []clusterGroup{
			{"keystroke", []string{"getasynckeystate", "setwindowshookex", "getkeyboardstate", "getrawinputdata"}},
			{"window context", []string{"getforegroundwindow", "getwindowtext", "getkeyboardlayout"}},
			{"buffer/log", []string{"keylog", "[backspace]", "[enter]", "logfile", "clipboard"}},
		},
		MinGroups: 2,
		BaseScore: 14,
		ScoreStep: 5,
	},
}

// RunCorrelationClusters evaluates every cluster against the shared lowercase
// corpus and records correlated findings (with evidence count + confidence).
func RunCorrelationClusters(result *ScanResult, corpus string) {
	if result == nil || corpus == "" {
		return
	}
	for _, cluster := range correlationClusters {
		matched, labels := cluster.evaluate(corpus)
		if matched < cluster.MinGroups {
			continue
		}
		extra := matched - cluster.MinGroups
		score := cluster.BaseScore + extra*cluster.ScoreStep
		confidence := clampInt(48+matched*14, 0, 96)
		evidence := fmt.Sprintf("%d corroborating evidence groups present (%s)", matched, strings.Join(labels, ", "))
		AddCorrelatedFinding(result, cluster.Severity, cluster.Category, cluster.Name, evidence,
			score, 0, cluster.Tactic, cluster.Technique, cluster.Recommend, matched, confidence)
	}
}

// evaluate returns the number of distinct groups that matched and their labels.
func (c evidenceCluster) evaluate(corpus string) (int, []string) {
	var labels []string
	for _, g := range c.Groups {
		if hasAny(corpus, g.Tokens...) {
			labels = append(labels, g.Label)
		}
	}
	return len(labels), labels
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
