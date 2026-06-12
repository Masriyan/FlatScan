package main

import (
	"regexp"
	"strings"
)

// Malware config extractor framework (improvementprompt-v3 Task 6).
//
// config_extract.go handles generic crypto/encoding artifacts. This recovers the
// structured operator-config primitives analysts pivot on — C2, mutex, bot
// token, webhook, wallet, campaign/build IDs, version — from the corpus and the
// already-extracted IOCs, keyed to the detected family when one is identified.
// It is regex/marker-driven (not family-binary-specific), so it works without a
// per-family sample to test against while still producing a clean config view.

var (
	telegramBotRe = regexp.MustCompile(`(?i)bot\d{8,10}:[A-Za-z0-9_-]{30,40}`)
	campaignRe    = regexp.MustCompile(`(?i)(?:campaign|build|botnet|group)[_\- ]?(?:id|name|tag)?\s*[:=]\s*["']?([A-Za-z0-9._\-]{2,40})`)
	versionRe     = regexp.MustCompile(`(?i)\b(?:version|ver|build)\s*[:=]\s*["']?(v?\d+(?:\.\d+){1,3})`)
)

// ExtractMalwareConfig builds the structured config view. It runs after family
// classification and IOC extraction so it can attach the family label and reuse
// the triaged IOCs.
func ExtractMalwareConfig(result *ScanResult, corpus string) {
	if result == nil {
		return
	}
	cfg := &MalwareConfig{}

	// Family label from the top named hypothesis, if any.
	for _, fm := range result.FamilyMatches {
		if fm.Category == "stealer" || fm.Category == "rat" {
			cfg.Family = fm.Family
			break
		}
	}

	// C2: actionable network IOCs (drop benign/namespace noise via the classifier).
	for _, u := range result.IOCs.URLs {
		if actionableIOCCategory(classifyIOCValue("url", u).Category) {
			cfg.C2 = appendUnique(cfg.C2, u)
		}
	}
	for _, d := range result.IOCs.Domains {
		if actionableIOCCategory(classifyIOCValue("domain", d).Category) {
			cfg.C2 = appendUnique(cfg.C2, d)
		}
	}
	cfg.C2 = appendUnique(cfg.C2, result.IOCs.IPv4...)
	cfg.C2 = limitStrings(uniqueSorted(cfg.C2), 25)

	cfg.Mutexes = result.IOCs.Mutexes
	cfg.Wallets = result.IOCs.CryptoWallets

	// Webhooks (Discord/Telegram) from the URL set.
	for _, u := range result.IOCs.URLs {
		lu := strings.ToLower(u)
		if strings.Contains(lu, "/api/webhooks") || strings.Contains(lu, "api.telegram.org/bot") {
			cfg.Webhooks = appendUnique(cfg.Webhooks, u)
		}
	}

	// Telegram bot tokens, campaign/build IDs, version — from the corpus.
	cfg.BotTokens = uniqueSorted(telegramBotRe.FindAllString(corpus, 8))
	cfg.CampaignID = uniqueSorted(firstSubmatches(campaignRe, corpus, 8))
	versions := firstSubmatches(versionRe, corpus, 6)
	cfg.Version = uniqueSorted(versions)

	if malwareConfigEmpty(cfg) {
		return
	}
	result.MalwareConfig = cfg

	// A recovered operator config is strong, actionable intelligence.
	count := len(cfg.C2) + len(cfg.Mutexes) + len(cfg.BotTokens) + len(cfg.Webhooks) + len(cfg.Wallets) + len(cfg.CampaignID)
	if count == 0 {
		return
	}
	conf := clampInt(50+count*5, 0, 92)
	label := "extracted operator configuration"
	if cfg.Family != "" {
		label = cfg.Family + " configuration extracted"
	}
	// Informational (score 0): the recovered fields are already counted as IOCs
	// elsewhere, so this re-presentation must not inflate the risk score. It
	// gives analysts a consolidated, pivotable config view, not new evidence.
	AddCorrelatedFinding(result, "Info", "Configuration",
		"Malware configuration recovered",
		label+": "+malwareConfigSummary(cfg),
		0, 0,
		"Command and Control", "Application Layer Protocol (T1071)",
		"Block the recovered C2/webhook indicators and pivot threat-intel on the campaign/build IDs and mutexes.",
		count, conf)
}

func firstSubmatches(re *regexp.Regexp, corpus string, limit int) []string {
	var out []string
	for _, m := range re.FindAllStringSubmatch(corpus, limit*2) {
		if len(m) > 1 && strings.TrimSpace(m[1]) != "" {
			out = append(out, m[1])
		}
		if len(out) >= limit {
			break
		}
	}
	return out
}

func malwareConfigEmpty(c *MalwareConfig) bool {
	return len(c.C2) == 0 && len(c.Mutexes) == 0 && len(c.BotTokens) == 0 &&
		len(c.Webhooks) == 0 && len(c.Wallets) == 0 && len(c.CampaignID) == 0 &&
		len(c.BuildID) == 0 && len(c.Version) == 0
}

func malwareConfigSummary(c *MalwareConfig) string {
	var parts []string
	if len(c.C2) > 0 {
		parts = append(parts, itoa(len(c.C2))+" C2")
	}
	if len(c.Webhooks) > 0 {
		parts = append(parts, itoa(len(c.Webhooks))+" webhook")
	}
	if len(c.BotTokens) > 0 {
		parts = append(parts, itoa(len(c.BotTokens))+" bot-token")
	}
	if len(c.Mutexes) > 0 {
		parts = append(parts, itoa(len(c.Mutexes))+" mutex")
	}
	if len(c.Wallets) > 0 {
		parts = append(parts, itoa(len(c.Wallets))+" wallet")
	}
	if len(c.CampaignID) > 0 {
		parts = append(parts, itoa(len(c.CampaignID))+" campaign-id")
	}
	return strings.Join(parts, ", ")
}

func itoa(n int) string { return int64ToString(int64(n)) }
