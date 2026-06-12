package main

import (
	"strings"
	"testing"
)

func TestExtractMalwareConfig(t *testing.T) {
	result := &ScanResult{
		IOCs: IOCSet{
			URLs:          []string{"https://discord.com/api/webhooks/123/abc", "http://evil-c2.top/gate"},
			Domains:       []string{"evil-c2.top"},
			Mutexes:       []string{"Global\\RmcMutex_1"},
			CryptoWallets: []string{"0x1234567890abcdef1234567890abcdef12345678"},
		},
	}
	corpus := "bot1234567890:AAFakeTelegramTokenValueHere1234567 campaign_id: ALPHA-07 version=v2.3.1"
	ExtractMalwareConfig(result, corpus)

	if result.MalwareConfig == nil {
		t.Fatal("expected a recovered config")
	}
	c := result.MalwareConfig
	if len(c.Webhooks) == 0 {
		t.Errorf("expected discord webhook in config: %#v", c.Webhooks)
	}
	if len(c.BotTokens) == 0 {
		t.Errorf("expected telegram bot token: %#v", c.BotTokens)
	}
	if !containsStringFold(c.CampaignID, "ALPHA-07") {
		t.Errorf("expected campaign id ALPHA-07: %#v", c.CampaignID)
	}
	if !containsStringFold(c.Mutexes, "Global\\RmcMutex_1") {
		t.Errorf("expected mutex in config: %#v", c.Mutexes)
	}
	if !hasFindingTitle(result.Findings, "Malware configuration recovered") {
		t.Fatalf("expected config finding, got: %s", findingTitles(result))
	}
}

func TestEnrichFromIntel(t *testing.T) {
	result := &ScanResult{
		Hashes: Hashes{SHA256: "abc123"},
		IOCs:   IOCSet{Domains: []string{"known-bad.top"}},
	}
	records := []IntelRecord{
		{Indicator: "known-bad.top", Type: "domain", Family: "RedLine", Campaign: "Op-Foo", FirstSeen: "2026-01-02"},
		{Indicator: "unrelated.com", Type: "domain", Family: "Other"},
	}
	EnrichFromIntel(result, records, func(string, ...any) {})
	if len(result.Enrichment) != 1 || result.Enrichment[0].Family != "RedLine" {
		t.Fatalf("expected one RedLine enrichment, got: %#v", result.Enrichment)
	}
	if !hasFindingTitle(result.Findings, "Known threat-intel match") {
		t.Fatalf("expected intel finding, got: %s", findingTitles(result))
	}
}

func TestEnrichFromIntelHashMatch(t *testing.T) {
	result := &ScanResult{Hashes: Hashes{SHA256: "DEADBEEF"}}
	records := []IntelRecord{{Indicator: "deadbeef", Type: "sha256", Family: "Lumma"}}
	EnrichFromIntel(result, records, func(string, ...any) {})
	if len(result.Enrichment) != 1 {
		t.Fatalf("hash match (case-insensitive) expected, got: %#v", result.Enrichment)
	}
}

func TestPredictExpectedBehavior(t *testing.T) {
	result := &ScanResult{
		Findings: []Finding{
			{Title: "Capability: Process injection"},
			{Title: "Microsoft Defender tampering"},
			{Title: "Registry Run-key persistence"},
		},
		IOCs: IOCSet{URLs: []string{"https://discord.com/api/webhooks/1/2"}},
	}
	PredictExpectedBehavior(result)
	got := strings.Join(result.Profile.ExpectedBehavior, " | ")
	for _, want := range []string{"Injects code", "disable or evade endpoint defenses", "persistence", "webhook"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected behavior to mention %q, got: %s", want, got)
		}
	}
}
