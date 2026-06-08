package main

import (
	"fmt"
	"math"
	"strings"
)

// dgaThreshold is the minimum likelihood score for a domain to be reported as
// DGA-suspicious. Tuned conservatively to avoid flagging ordinary domains.
const dgaThreshold = 0.55

// dgaKnownTLDs mirrors the TLD set recognized by ioc.go's domainRe so the
// scorer evaluates the registrable label rather than the suffix.
var dgaKnownTLDs = map[string]bool{
	"com": true, "net": true, "org": true, "io": true, "co": true, "ru": true,
	"cn": true, "xyz": true, "top": true, "biz": true, "info": true, "online": true,
	"site": true, "club": true, "me": true, "dev": true, "app": true, "gov": true,
	"edu": true, "mil": true, "uk": true, "de": true, "jp": true, "kr": true,
	"br": true, "in": true, "ir": true, "tr": true, "id": true, "vn": true,
	"pl": true, "fr": true, "it": true, "es": true, "nl": true, "se": true,
	"no": true, "fi": true, "ua": true, "su": true, "pw": true, "cc": true,
	"tk": true, "local": true,
}

// dgaUnusualTLDs are suffixes disproportionately abused by DGA/C2 campaigns;
// a very-high lexical score on one of these is escalated to Medium.
var dgaUnusualTLDs = map[string]bool{
	"xyz": true, "top": true, "club": true, "tk": true, "pw": true, "cc": true,
	"online": true, "site": true, "su": true,
}

// commonBigrams is a compact set of high-frequency English bigrams used as a
// benign reference for the n-gram normality signal (Phoenix-style). A low share
// of common bigrams indicates an unpronounceable, likely generated label.
var commonBigrams = map[string]bool{
	"th": true, "he": true, "in": true, "er": true, "an": true, "re": true,
	"on": true, "at": true, "en": true, "nd": true, "ti": true, "es": true,
	"or": true, "te": true, "of": true, "ed": true, "is": true, "it": true,
	"al": true, "ar": true, "st": true, "to": true, "nt": true, "ng": true,
	"se": true, "ha": true, "as": true, "ou": true, "io": true, "le": true,
	"ve": true, "co": true, "me": true, "de": true, "hi": true, "ri": true,
	"ro": true, "ic": true, "ne": true, "ea": true, "ra": true, "ce": true,
	"li": true, "ch": true, "ll": true, "be": true, "ma": true, "si": true,
	"om": true, "ur": true, "ca": true, "el": true, "ta": true, "la": true,
	"ns": true, "di": true, "fo": true, "ho": true, "pe": true, "ec": true,
	"pr": true, "us": true, "ut": true, "ad": true, "ai": true, "no": true,
	"ss": true, "et": true, "em": true, "il": true, "so": true, "un": true,
	"ac": true, "ot": true, "ol": true, "ge": true, "lo": true, "tr": true,
	"da": true, "mo": true, "ie": true, "po": true, "do": true, "wi": true,
}

// dgaScore returns a 0..1 likelihood that the domain is algorithmically
// generated, plus the lexical signals that fired. Dictionary-free: grounded in
// FANCI lexical features, Shannon entropy, and a Phoenix-style n-gram normality
// score over a benign-bigram reference. Pure function — no I/O.
func dgaScore(domain string) (float64, []string) {
	label := registrableLabel(domain)
	if len(label) < 7 {
		return 0, nil
	}

	var reasons []string
	score := 0.0

	// 1. Shannon entropy of the label (reuse the engine's helper).
	ent := ShannonEntropy([]byte(label))
	switch {
	case ent >= 3.7:
		score += 0.30
		reasons = append(reasons, fmt.Sprintf("high label entropy %.2f", ent))
	case ent >= 3.3:
		score += 0.15
	}

	// 2. FANCI-style lexical ratios.
	var vowels, digits, consec, maxConsec int
	unique := map[rune]bool{}
	for _, r := range label {
		unique[r] = true
		switch {
		case r >= '0' && r <= '9':
			digits++
			consec = 0
		case isVowel(r):
			vowels++
			consec = 0
		case r >= 'a' && r <= 'z':
			consec++
			if consec > maxConsec {
				maxConsec = consec
			}
		default:
			consec = 0
		}
	}
	n := float64(len([]rune(label)))
	vowelRatio := float64(vowels) / n
	digitRatio := float64(digits) / n
	uniqueRatio := float64(len(unique)) / n

	if vowelRatio < 0.26 {
		score += 0.20
		reasons = append(reasons, fmt.Sprintf("low vowel ratio %.2f", vowelRatio))
	}
	if digitRatio > 0.25 {
		score += 0.20
		reasons = append(reasons, fmt.Sprintf("high digit ratio %.2f", digitRatio))
	}
	if maxConsec >= 5 {
		score += 0.20
		reasons = append(reasons, fmt.Sprintf("%d consecutive consonants", maxConsec))
	}
	if len(label) >= 16 && uniqueRatio > 0.72 {
		score += 0.10
		reasons = append(reasons, "long high-uniqueness label")
	}

	// 3. n-gram normality (Phoenix): share of bigrams that are common English.
	if normal, ok := bigramNormality(label); ok {
		switch {
		case normal < 0.20:
			score += 0.25
			reasons = append(reasons, fmt.Sprintf("low n-gram normality %.2f", normal))
		case normal < 0.35:
			score += 0.10
		}
	}

	if score > 1 {
		score = 1
	}
	return score, reasons
}

func isVowel(r rune) bool {
	switch r {
	case 'a', 'e', 'i', 'o', 'u', 'y':
		return true
	}
	return false
}

// bigramNormality returns the fraction of a label's bigrams that appear in the
// common-English-bigram reference set. ok is false for labels too short to have
// a bigram.
func bigramNormality(label string) (float64, bool) {
	if len(label) < 2 {
		return 0, false
	}
	total, hits := 0, 0
	for i := 0; i+1 < len(label); i++ {
		total++
		if commonBigrams[label[i:i+2]] {
			hits++
		}
	}
	if total == 0 {
		return 0, false
	}
	return float64(hits) / float64(total), true
}

// registrableLabel strips the recognized TLD and returns the label immediately
// to its left (the second-level / registrable label) for lexical analysis.
func registrableLabel(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(domain, ".")))
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return domain
	}
	i := len(parts) - 1
	if dgaKnownTLDs[parts[i]] {
		i--
	}
	if i >= 0 {
		return parts[i]
	}
	return domain
}

func unusualDGATLD(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(domain, ".")))
	parts := strings.Split(domain, ".")
	if len(parts) == 0 {
		return false
	}
	return dgaUnusualTLDs[parts[len(parts)-1]]
}

// AnalyzeDGADomains scores each extracted domain for DGA-likeness and records
// findings for high scorers. Runs after IOC triage so allowlisted domains are
// already removed, and before risk finalization so the research-artifact cap
// still applies. Conservative: Low by default, Medium only for a very-high
// score on a frequently-abused TLD.
func AnalyzeDGADomains(result *ScanResult) {
	if result == nil || len(result.IOCs.Domains) == 0 {
		return
	}
	for _, domain := range result.IOCs.Domains {
		score, reasons := dgaScore(domain)
		if score < dgaThreshold {
			continue
		}
		result.DGADomains = append(result.DGADomains, DGADomain{
			Domain:  domain,
			Score:   math.Round(score*100) / 100,
			Reasons: reasons,
		})
		severity, points := "Low", 4
		if score >= 0.80 && unusualDGATLD(domain) {
			severity, points = "Medium", 10
		}
		AddFindingDetailed(result, severity, "C2", "Likely algorithmically-generated domain (DGA)",
			fmt.Sprintf("%s (score %.2f: %s)", domain, score, strings.Join(reasons, "; ")), points, 0,
			"Command and Control", "Dynamic Resolution: Domain Generation Algorithms (T1568.002)",
			"Pivot on the domain's registration and resolution history; DGA domains signal resilient C2 — block and hunt for sibling domains and the generation seed.")
	}
}
