package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// FlatScan's detection is substring-based over the file's string corpus. That
// makes it vulnerable to a classic precision failure: any file that *contains*
// malware indicator strings as data — an AV signature set, a YARA/Sigma rule
// pack, a sandbox, a threat-intel feed, a malware-analysis tool (FlatScan's own
// binary included), or an incident report — lights up every signature and lands
// at "Likely malicious". AssessResearchArtifact recognizes that situation so the
// matches can be treated as references rather than behavior.
//
// The discriminator is breadth: a real specimen is focused, but a catalog is
// not. Each entry below is a headline phrase from a normally mutually-exclusive
// malware archetype. One sample being simultaneously ransomware, a cryptominer,
// a wiper, a credential dumper, a Discord stealer, and a PHP webshell is
// implausible; a signature database describing all of them is routine.
var archetypeHeadlines = map[string][]string{
	"ransomware":      {"your files have been encrypted", "recover your files", "decrypt your files"},
	"cryptominer":     {"stratum+tcp", "stratum+ssl", "xmrig", "cryptonight", "randomx", "donate.v2.xmrig"},
	"wiper":           {"vssadmin delete", "wmic shadowcopy delete", "bcdedit /set", "recoveryenabled no"},
	"credential-dump": {"sekurlsa", "logonpasswords", "mimikatz", "ntds.dit"},
	"discord-stealer": {"discord.com/api/webhooks", "discordapp.com/api/webhooks"},
	"webshell":        {"eval($_post", "eval($_get", "c99shell", "r57shell", "shell_exec($_", "passthru($_"},
}

// securityToolMarkers is vocabulary typical of security tooling, rule packs,
// threat-intel feeds, and analysis reports — not of live malware payloads.
var securityToolMarkers = []string{
	"att&ck", "mitre", "virustotal", "yara rule", "sigma rule",
	"malware analysis", "indicator of compromise", "false positive",
	"detection rule", "threat intel", "incident response",
}

var mitreTechniqueRe = regexp.MustCompile(`\bt1\d{3}\b`)

// researchArtifactScoreCap keeps a recognized detection artifact at the "Low
// suspicion" tier: flagged for an analyst's eye, but not reported as malicious.
const researchArtifactScoreCap = 20

// AssessResearchArtifact populates result.BenignContext when the file looks like
// a detection/analysis artifact rather than a live sample. It must run after the
// signature, chain, and family stages (it reads their output) and before
// FinalizeRisk, which applies the score cap recorded here.
func AssessResearchArtifact(result *ScanResult, corpus string) {
	if result == nil || corpus == "" {
		return
	}

	archetypes := make([]string, 0, len(archetypeHeadlines))
	for name, phrases := range archetypeHeadlines {
		if hasAny(corpus, phrases...) {
			archetypes = append(archetypes, name)
		}
	}
	sort.Strings(archetypes)

	markers := make([]string, 0, len(securityToolMarkers))
	for _, m := range securityToolMarkers {
		if strings.Contains(corpus, m) {
			markers = append(markers, m)
		}
	}

	mitreRefs := len(uniqueSorted(mitreTechniqueRe.FindAllString(corpus, -1)))
	strongToolSignal := len(markers) >= 2 || mitreRefs >= 8

	// Real focused malware sits at 0-1 archetypes. Require a broad, implausible
	// spread (>=4), or a slightly narrower spread (>=3) backed by explicit
	// security-tool / threat-intel vocabulary, before overriding the verdict.
	likely := len(archetypes) >= 4 || (len(archetypes) >= 3 && strongToolSignal)
	if !likely {
		return
	}

	reason := fmt.Sprintf("carries headline indicators for %d unrelated malware archetypes (%s)",
		len(archetypes), strings.Join(archetypes, ", "))
	if len(markers) > 0 {
		reason += fmt.Sprintf(" plus %d security-tooling markers", len(markers))
	}
	if mitreRefs >= 8 {
		reason += fmt.Sprintf(" and %d MITRE technique references", mitreRefs)
	}
	reason += " — consistent with a signature set, rule pack, sandbox, analysis tool, or report rather than a live specimen"

	result.BenignContext = &BenignContext{
		Reason:        reason,
		Archetypes:    archetypes,
		ToolMarkers:   markers,
		MITRETechRefs: mitreRefs,
		ScoreCap:      researchArtifactScoreCap,
	}

	AddFindingDetailed(result, "Info", "Context",
		"Likely security tool, signature set, or analysis artifact",
		reason, 0, 0,
		"", "",
		"Confirm provenance: indicator matches here are most likely catalogued references, not behavior. Treat the risk score as capped and review the listed evidence manually before acting.")
}
