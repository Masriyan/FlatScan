package main

import (
	"fmt"
	"sort"
)

func ClassifyMalwareFamilies(result *ScanResult, stringsFound []ExtractedString) {
	if result == nil {
		return
	}
	corpus := buildCorpus(stringsFound, result.DecodedArtifacts, defaultMaxCorpusBytes)
	ClassifyMalwareFamiliesWithCorpus(result, stringsFound, corpus)
}

// ClassifyMalwareFamiliesWithCorpus uses a pre-built corpus string.
func ClassifyMalwareFamiliesWithCorpus(result *ScanResult, stringsFound []ExtractedString, corpus string) {
	if result == nil {
		return
	}
	var matches []FamilyMatch
	add := func(family, category, confidence string, score int, evidence ...string) {
		for _, existing := range matches {
			if existing.Family == family {
				return
			}
		}
		matches = append(matches, FamilyMatch{
			Family:     family,
			Category:   category,
			Confidence: confidence,
			Score:      score,
			Evidence:   uniqueSorted(evidence),
		})
	}

	if hasFinding(result.Findings, "Ransomware") || hasAny(corpus, "your files have been encrypted", "decrypt your files", ".locked", ".encrypted", "ransom note") {
		add("Generic ransomware", "ransomware", "High", 90, "ransomware strings or findings")
	}
	if hasFinding(result.Findings, "Credential Access") && (hasFinding(result.Findings, "Exfiltration") || len(result.IOCs.URLs) > 0) {
		add("Information stealer", "stealer", "High", 88, "credential access and exfiltration/network indicators")
	}
	if hasAny(corpus, "encrypted_key", "login data", "cookies", "chromium", "cryptunprotectdata") && !isAndroidPackage(*result) {
		add("Browser credential stealer", "stealer", "High", 86, "browser secret and crypto markers")
	}
	if firstMatchingURL(result.IOCs.URLs, "discord.com/api/webhooks", "discordapp.com/api/webhooks") != "" || hasAny(corpus, "discordapp.com/api/v8/users/@me") {
		add("Discord token/webhook stealer", "stealer", "High", 84, "Discord webhook or API indicators")
	}
	if hasFinding(result.Findings, "Network") && (hasAny(corpus, "urldownloadtofile", "downloadstring", "winhttpopen") || len(result.CarvedArtifacts) > 0) {
		add("Downloader or loader", "loader", "Medium-High", 72, "download APIs or embedded payloads")
	}
	if hasFindingTitle(result.Findings, "Process injection API chain") || hasAny(corpus, "createremotethread", "writeprocessmemory", "virtualallocex") {
		add("Injection-capable loader", "loader", "Medium-High", 70, "process injection API cluster")
	}
	if hasAny(corpus, "keylogger", "getasynckeystate", "screenshot", "reverse shell", "remote desktop", "vnc") {
		add("Remote access trojan", "rat", "Medium", 62, "remote-control, keylogging, or screenshot strings")
	}
	if isAndroidPackage(*result) {
		if hasFindingTitle(result.Findings, "Android SMS collection or sending capability") {
			add("Android SMS trojan", "android", "High", 82, "SMS permission/API cluster")
		}
		if hasFindingTitle(result.Findings, "Android accessibility service capability") || hasFindingTitle(result.Findings, "Android overlay capability") {
			add("Android banker/riskware", "android", "Medium-High", 74, "accessibility or overlay capability")
		}
		if hasAndroidDEXHit(*result, "dynamic-code") || len(result.CarvedArtifacts) > 0 {
			add("Android loader/riskware", "android", "Medium", 60, "dynamic code loading or embedded payload indicators")
		}
	}
	if hasAny(corpus, "<?php", "passthru(", "shell_exec(", "eval($_", "move_uploaded_file") {
		add("PHP webshell or offensive web toolkit", "webshell", "Medium", 58, "PHP upload, eval, or shell execution strings")
	}
	if score, evidence := magniberScore(result); score >= 60 {
		confidence := "Medium"
		if score >= 80 {
			confidence = "High"
		}
		add("Magniber ransomware", "ransomware", confidence, score, evidence...)
	}
	if len(result.CarvedArtifacts) > 0 {
		add("Packed or bundled payload", "dropper", "Medium", 55, fmt.Sprintf("%d carved artifacts", len(result.CarvedArtifacts)))
	}

	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Score == matches[j].Score {
			return matches[i].Family < matches[j].Family
		}
		return matches[i].Score > matches[j].Score
	})
	result.FamilyMatches = matches
	if len(matches) > 0 {
		result.Plugins = append(result.Plugins, PluginResult{Name: "family-classifier", Version: version, Status: "complete", Summary: fmt.Sprintf("%d family hypotheses", len(matches)), Findings: len(matches)})
		top := matches[0]
		AddFinding(result, "Info", "Classifier", "Malware family hypothesis", top.Family+" ("+top.Confidence+")", 0, 0)
	}
}

func magniberScore(result *ScanResult) (int, []string) {
	if result == nil {
		return 0, nil
	}
	score := 0
	var evidence []string
	if result.FileType == "MSIX/AppX package" || result.MSIX != nil {
		score += 25
		evidence = append(evidence, "MSIX/AppX delivery container")
	}
	if len(result.IOCs.PEHashes) > 0 || hasFindingTitle(result.Findings, "Executable payload inside archive") {
		score += 20
		evidence = append(evidence, "embedded PE payload")
	}
	randomName := false
	nameStemMatch := false
	nearMaxEntropy := false
	smallPE := false
	for _, entry := range result.ArchiveEntries {
		if obfuscatedArchiveNameReason(entry.Name) != "" {
			randomName = true
			nameStemMatch = true
		}
		if entry.Type == "PE executable" || archivePEPayloadName(entry.Name) {
			if entry.Entropy >= 7.8 {
				nearMaxEntropy = true
			}
			if entry.Size > 0 && entry.Size < 10*1024 {
				smallPE = true
			}
		}
	}
	for _, peHash := range result.IOCs.PEHashes {
		if peHash.Entropy >= 7.8 {
			nearMaxEntropy = true
		}
		if peHash.Size > 0 && peHash.Size < 10*1024 {
			smallPE = true
		}
	}
	if randomName {
		score += 20
		evidence = append(evidence, "random lowercase payload directory pattern")
	}
	if nameStemMatch {
		score += 15
		evidence = append(evidence, "directory name matches executable stem")
	}
	if nearMaxEntropy {
		score += 10
		evidence = append(evidence, "near-maximum entropy embedded payload")
	}
	if smallPE {
		score += 10
		evidence = append(evidence, "small embedded PE loader/stager size")
	}
	if score > 100 {
		score = 100
	}
	return score, uniqueSorted(evidence)
}
