package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var techniqueIDRe = regexp.MustCompile(`\((T[0-9]{4}(?:\.[0-9]{3})?)\)`)

func EnrichAnalysisProfile(result *ScanResult, stringsFound []ExtractedString) {
	if result == nil {
		return
	}
	corpus := buildCorpus(stringsFound, result.DecodedArtifacts, defaultMaxCorpusBytes)
	EnrichAnalysisProfileWithCorpus(result, stringsFound, corpus)
}

// EnrichAnalysisProfileWithCorpus uses a pre-built corpus string.
func EnrichAnalysisProfileWithCorpus(result *ScanResult, stringsFound []ExtractedString, corpus string) {
	if result == nil {
		return
	}
	profile := AnalysisProfile{
		Classification:      reportClassification(*result),
		Confidence:          confidenceLabel(result.RiskScore),
		ConfidenceScore:     confidenceScore(*result),
		TTPs:                buildTTPEntries(result.Findings),
		CryptoIndicators:    buildCryptoIndicators(*result, corpus),
		RecommendedActions:  findingRecommendations(result.Findings),
		BusinessImpact:      businessImpact(*result, corpus),
		KeyCapabilities:     keyCapabilities(*result, corpus),
		ExecutiveAssessment: executiveAssessment(*result),
	}
	profile.MalwareType = malwareType(profile, *result, corpus)
	result.Profile = profile
}

func buildTTPEntries(findings []Finding) []TTPEntry {
	seen := map[string]struct{}{}
	var out []TTPEntry
	for _, finding := range findings {
		if finding.Tactic == "" && finding.Technique == "" {
			continue
		}
		id := ""
		if match := techniqueIDRe.FindStringSubmatch(finding.Technique); len(match) == 2 {
			id = match[1]
		}
		key := finding.Tactic + "|" + finding.Technique + "|" + finding.Title
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, TTPEntry{
			Tactic:     finding.Tactic,
			Technique:  finding.Technique,
			ID:         id,
			Severity:   finding.Severity,
			Confidence: findingConfidence(finding),
			Evidence:   finding.Evidence,
			Finding:    finding.Title,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Tactic == out[j].Tactic {
			return out[i].Technique < out[j].Technique
		}
		return out[i].Tactic < out[j].Tactic
	})
	return out
}

func buildCryptoIndicators(result ScanResult, corpus string) []CryptoIndicator {
	var indicators []CryptoIndicator
	add := func(primitive, source, purpose, confidence, evidence string) {
		key := primitive + "|" + source + "|" + purpose
		for _, existing := range indicators {
			if existing.Primitive+"|"+existing.Source+"|"+existing.Purpose == key {
				return
			}
		}
		indicators = append(indicators, CryptoIndicator{
			Primitive:  primitive,
			Source:     source,
			Purpose:    purpose,
			Confidence: confidence,
			Evidence:   evidence,
		})
	}

	if hasAny(corpus, "bcryptdecrypt", "bcryptencrypt") {
		add("Windows CNG BCrypt", "strings/API references", "Browser credential or payload decryption/encryption", "High", "BCryptDecrypt/BCryptEncrypt strings")
	}
	if hasAny(corpus, "cryptdecrypt", "cryptencrypt", "cryptunprotectdata") {
		add("Windows CryptoAPI/DPAPI", "strings/API references", "Protected secret handling or decryption", "Medium", "CryptDecrypt/CryptEncrypt/CryptUnprotectData strings")
	}
	if hasAny(corpus, "encrypted_key", "\"encrypted_key\"", "decryptwithkey") {
		add("Chromium encrypted_key workflow", "application strings", "Extract and decrypt Chromium Local State browser secret material", "High", "encrypted_key/DecryptWithKey strings")
	}
	if hasAny(corpus, "aes", "rijndael", "gcm", "authentication tag", "iv", "nonce") {
		add("Symmetric crypto markers", "application strings", "Possible AES-GCM or authenticated decryption logic", "Medium", "AES/GCM/tag/IV/nonce style strings")
	}
	if hasAny(corpus, "frombase64string", "convert.frombase64string") || len(result.DecodedArtifacts) > 0 {
		add("Encoding/obfuscation layer", "decoded strings", "Static obfuscation or configuration wrapping", "Medium", fmt.Sprintf("%d decoded artifacts", len(result.DecodedArtifacts)))
	}

	for _, fn := range result.Functions {
		if strings.Contains(strings.ToLower(fn.Family), "cryptography") {
			add(fn.Name, fn.Source, "Cryptographic operation reference", fn.Severity, fn.Family)
		}
		if strings.Contains(strings.ToLower(fn.Family), "android crypto") {
			add(fn.Name, fn.Source, "Android/Java cryptography reference", fn.Severity, fn.Family)
		}
	}
	for _, dex := range result.DEXFiles {
		for _, hit := range dex.APIHits {
			if hit.Category == "crypto" {
				add(hit.Indicator, "DEX strings: "+dex.Name, "Android/Java cryptography reference", hit.Severity, "Static DEX API/string indicator")
			}
		}
	}

	sort.SliceStable(indicators, func(i, j int) bool {
		if indicators[i].Confidence == indicators[j].Confidence {
			return indicators[i].Primitive < indicators[j].Primitive
		}
		return severityRank(indicators[i].Confidence) > severityRank(indicators[j].Confidence)
	})
	return indicators
}

func businessImpact(result ScanResult, corpus string) []string {
	var impact []string
	if isAndroidPackage(result) {
		impact = append(impact, "Potentially risky Android application; validate requested permissions, embedded payloads, and network destinations before installation or distribution.")
		if result.APK != nil {
			dangerous := androidPermissionsByMinimumRisk(result.APK.Permissions, "Medium")
			if len(dangerous) > 0 {
				impact = append(impact, fmt.Sprintf("Android permission exposure includes %d dangerous or special permissions across categories such as %s.", len(dangerous), strings.Join(firstAndroidPermissionCategories(dangerous, 4), ", ")))
			}
			if unguarded := exportedComponentsWithoutPermission(result.APK); len(unguarded) > 0 {
				impact = append(impact, fmt.Sprintf("%d exported Android components appear unguarded and may expand IPC, deep-link, or intent attack surface.", len(unguarded)))
			}
		}
	}
	if hasFindingTitle(result.Findings, "Executable payload inside archive") {
		impact = append(impact, "Archive/container includes executable payloads; treat it as a potential dropper or packaged malware delivery artifact until the embedded binaries are reverse engineered.")
	}
	if len(result.CarvedArtifacts) > 0 {
		impact = append(impact, "Embedded artifact carving found additional payload-like content by offset and hash; preserve the original container and analyze carved hashes in an isolated lab.")
	}
	if hasFinding(result.Findings, "Credential Access") || (!isAndroidPackage(result) && hasAny(corpus, "encrypted_key", "discordapp.com/api/v8/users/@me")) {
		impact = append(impact, "Credential and session-token exposure risk, including browser-stored secrets and Discord account/API tokens.")
	}
	if hasFinding(result.Findings, "Exfiltration") || firstMatchingURL(result.IOCs.URLs, "discord.com/api/webhooks") != "" {
		impact = append(impact, "Potential data exfiltration over a trusted cloud/web service, which may bypass simple domain allow-list assumptions.")
	}
	if hasFindingTitle(result.Findings, "Windows persistence indicator") {
		impact = append(impact, "Potential host persistence through Windows startup mechanisms, increasing dwell-time risk.")
	} else if hasFindingTitle(result.Findings, "Linux persistence indicator") {
		impact = append(impact, "Potential Unix/Linux persistence indicators; validate whether paths are application resources or operational scripts.")
	}
	if hasFinding(result.Findings, "Evasion") {
		impact = append(impact, "Anti-analysis behavior may reduce sandbox fidelity and delay detection.")
	}
	if len(impact) == 0 {
		impact = append(impact, "No specific business-impact statement was inferred from the current static findings.")
	}
	return uniqueSorted(impact)
}

func keyCapabilities(result ScanResult, corpus string) []string {
	var caps []string
	if isAndroidPackage(result) {
		caps = append(caps, "Android application package")
		if result.APK != nil {
			if len(androidPermissionsByMinimumRisk(result.APK.Permissions, "Medium")) > 0 {
				caps = append(caps, "Dangerous Android permission access")
			}
			if len(exportedComponentsWithoutPermission(result.APK)) > 0 {
				caps = append(caps, "Unguarded exported Android components")
			}
			if len(result.APK.NativeLibraries) > 0 {
				caps = append(caps, "Packaged Android native code")
			}
			if len(result.APK.EmbeddedPayloads) > 0 {
				caps = append(caps, "Embedded secondary Android payloads")
			}
		}
	}
	if hasAndroidDEXHit(result, "sms") {
		caps = append(caps, "Android SMS access")
	}
	if hasFindingTitle(result.Findings, "Android accessibility service capability") {
		caps = append(caps, "Android accessibility service behavior")
	}
	if hasFindingTitle(result.Findings, "Android device administrator capability") {
		caps = append(caps, "Android device administrator behavior")
	}
	if hasAndroidDEXHit(result, "dynamic-code") {
		caps = append(caps, "Android dynamic code loading")
	}
	if hasAndroidDEXHit(result, "runtime-exec") {
		caps = append(caps, "Android runtime command execution")
	}
	if hasFinding(result.Findings, "Credential Access") {
		caps = append(caps, "Credential and token collection")
	}
	if hasFinding(result.Findings, "Exfiltration") {
		caps = append(caps, "Webhook-based exfiltration")
	}
	if hasFindingTitle(result.Findings, "Windows persistence indicator") {
		caps = append(caps, "Windows startup persistence")
	} else if hasFindingTitle(result.Findings, "Linux persistence indicator") {
		caps = append(caps, "Unix/Linux persistence artifact references")
	}
	if hasFinding(result.Findings, "Evasion") {
		caps = append(caps, "Sandbox and VM awareness")
	}
	if len(result.Profile.CryptoIndicators) > 0 || (!isAndroidPackage(result) && hasAny(corpus, "decrypt", "encrypted_key", "bcryptdecrypt")) {
		caps = append(caps, "Cryptographic secret handling")
	}
	if result.PE != nil && result.PE.ManagedRuntime {
		caps = append(caps, ".NET managed payload")
	}
	if len(result.CarvedArtifacts) > 0 {
		caps = append(caps, "Embedded artifact carrier")
	}
	if len(result.ConfigArtifacts) > 0 {
		caps = append(caps, "Static configuration artifacts")
	}
	return uniqueSorted(caps)
}

func malwareType(profile AnalysisProfile, result ScanResult, corpus string) []string {
	var types []string
	for _, family := range result.FamilyMatches {
		if family.Confidence == "High" || family.Confidence == "Medium-High" {
			types = append(types, family.Family)
		}
	}
	if hasFinding(result.Findings, "Credential Access") && hasFinding(result.Findings, "Exfiltration") {
		types = append(types, "Information stealer")
	}
	if hasAny(corpus, "discord.com/api/webhooks", "discordapp.com/api/v8/users/@me") {
		types = append(types, "Discord token/webhook stealer")
	}
	if !isAndroidPackage(result) && (hasAny(corpus, "encrypted_key", "login data", "cookies", "chromium", "chrome") || hasFindingTitle(result.Findings, "Chromium credential decryption workflow")) {
		types = append(types, "Browser credential stealer")
	}
	if hasFindingTitle(result.Findings, "Windows persistence indicator") {
		types = append(types, "Persistent Windows malware")
	}
	if isAndroidPackage(result) && result.RiskScore >= 55 {
		types = append(types, "Android high-risk application")
		types = append(types, "Suspicious Android application")
	}
	if isAndroidPackage(result) && hasAndroidDEXHit(result, "sms") {
		types = append(types, "Android SMS-risk application")
	}
	if isAndroidPackage(result) && (hasFindingTitle(result.Findings, "Android accessibility service capability") || hasFindingTitle(result.Findings, "Android overlay capability")) {
		types = append(types, "Android overlay/accessibility-risk application")
	}
	if isAndroidPackage(result) && hasFindingTitle(result.Findings, "Dynamic DEX or class loading references") {
		types = append(types, "Android dynamic-code-loading application")
	}
	if len(types) == 0 && isArchiveLike(result) && result.RiskScore >= 55 {
		types = append(types, "Suspicious archive/dropper")
	}
	if len(types) == 0 && result.RiskScore >= 55 {
		types = append(types, "Suspicious executable")
	}
	return uniqueSorted(types)
}

func executiveAssessment(result ScanResult) string {
	if result.RiskScore >= 80 && (hasFinding(result.Findings, "Credential Access") || hasFinding(result.Findings, "Exfiltration")) {
		return "The sample should be treated as malware with likely credential-theft and exfiltration capability. From a management perspective, the priority is containment, token and password rotation, IOC blocking, and confirmation of host exposure."
	}
	if isAndroidPackage(result) && result.RiskScore >= 55 {
		return "The APK contains suspicious static indicators. Prioritize Android permission review, embedded payload inspection, network-destination validation, and dynamic analysis in an isolated Android lab before making a final disposition."
	}
	if isAndroidPackage(result) && result.APK != nil && len(exportedComponentsWithoutPermission(result.APK)) > 0 {
		return "The APK did not reach a high malware score, but it exposes Android-specific review points. Management should require manifest permission validation, exported-component review, and controlled Android lab testing before deployment."
	}
	return executiveNarrative(result)
}

func confidenceScore(result ScanResult) int {
	score := result.RiskScore
	if mappedTTPCount(result.Findings) >= 4 {
		score += 8
	}
	if IOCCount(result.IOCs) >= 10 {
		score += 4
	}
	if result.PE != nil && result.PE.ManagedRuntime {
		score += 3
	}
	if score > 100 {
		score = 100
	}
	return score
}

func mappedTTPCount(findings []Finding) int {
	count := 0
	for _, finding := range findings {
		if finding.Tactic != "" || finding.Technique != "" {
			count++
		}
	}
	return count
}

func confidenceLabel(score int) string {
	switch {
	case score >= 80:
		return "High"
	case score >= 55:
		return "Medium-High"
	case score >= 30:
		return "Medium"
	case score >= 10:
		return "Low-Medium"
	default:
		return "Low"
	}
}

func findingConfidence(finding Finding) string {
	switch finding.Severity {
	case "Critical", "High":
		return "High"
	case "Medium":
		return "Medium"
	case "Low":
		return "Low"
	default:
		return "Info"
	}
}

func hasFinding(findings []Finding, category string) bool {
	for _, finding := range findings {
		if strings.EqualFold(finding.Category, category) {
			return true
		}
	}
	return false
}

func hasFindingTitle(findings []Finding, title string) bool {
	for _, finding := range findings {
		if strings.EqualFold(finding.Title, title) {
			return true
		}
	}
	return false
}

func firstAndroidPermissionCategories(values []AndroidPermission, limit int) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, permission := range values {
		category := permission.Category
		if category == "" {
			category = permission.Protection
		}
		if category == "" {
			continue
		}
		if _, ok := seen[category]; ok {
			continue
		}
		seen[category] = struct{}{}
		out = append(out, category)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	if len(out) == 0 {
		return []string{"unspecified"}
	}
	return out
}
