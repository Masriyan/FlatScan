package main

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	bitcoinAddressRe = regexp.MustCompile(`\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b`)
	mutexLikeRe      = regexp.MustCompile(`(?i)\b(?:Global\\|Local\\)?[A-Za-z0-9_\-.]{8,64}(?:mutex|mtx|lock)[A-Za-z0-9_\-.]{0,32}\b`)
)

func ExtractCryptoAndConfig(result *ScanResult, data []byte, stringsFound []ExtractedString, cfg Config) {
	if result == nil {
		return
	}
	corpus := buildCorpus(stringsFound, result.DecodedArtifacts, defaultMaxCorpusBytes)
	ExtractCryptoAndConfigWithCorpus(result, data, stringsFound, cfg, corpus)
}

// ExtractCryptoAndConfigWithCorpus uses a pre-built corpus string.
func ExtractCryptoAndConfigWithCorpus(result *ScanResult, data []byte, stringsFound []ExtractedString, cfg Config, corpus string) {
	if result == nil {
		return
	}
	var artifacts []ConfigArtifact
	add := func(kind, source, confidence, evidence, preview string, iocs IOCSet) {
		key := kind + "|" + source + "|" + preview
		for _, existing := range artifacts {
			if existing.Type+"|"+existing.Source+"|"+existing.Preview == key {
				return
			}
		}
		artifacts = append(artifacts, ConfigArtifact{
			Type:       kind,
			Source:     source,
			Confidence: confidence,
			Evidence:   evidence,
			Preview:    previewString(preview, 220),
			IOCs:       iocs,
		})
	}

	for _, url := range result.IOCs.URLs {
		lower := strings.ToLower(url)
		if hasAny(lower, "gate.php", "/api/", "telegram", "discord.com/api/webhooks", "pastebin", "raw.githubusercontent") {
			add("c2-or-exfil-endpoint", "ioc:url", "Medium", "network endpoint resembles C2, bot API, paste, or webhook infrastructure", url, ExtractIOCs(url))
		}
	}
	for _, item := range stringsFound {
		lower := strings.ToLower(item.Value)
		switch {
		case hasAny(lower, "api_key", "apikey", "bot_token", "authorization: bearer", "x-api-key", "webhook"):
			add("credential-or-token-marker", item.Encoding, "Medium", fmt.Sprintf("secret marker at offset 0x%x", item.Offset), item.Value, ExtractIOCs(item.Value))
		case hasAny(lower, "mutex", "global\\", "local\\") && mutexLikeRe.MatchString(item.Value):
			add("mutex-candidate", item.Encoding, "Low", fmt.Sprintf("mutex-like string at offset 0x%x", item.Offset), mutexLikeRe.FindString(item.Value), IOCSet{})
		case hasAny(lower, "your files have been encrypted", "recover your files", "decrypt your files"):
			add("ransom-note-marker", item.Encoding, "High", fmt.Sprintf("ransom note marker at offset 0x%x", item.Offset), item.Value, ExtractIOCs(item.Value))
		}
	}
	for _, wallet := range bitcoinAddressRe.FindAllString(corpus, -1) {
		add("cryptocurrency-wallet", "strings", "Medium", "Bitcoin-style wallet address", wallet, IOCSet{})
	}
	for _, artifact := range result.DecodedArtifacts {
		if IOCCount(artifact.IOCs) > 0 {
			add("decoded-config", artifact.Encoding, "Medium", "decoded artifact contains IOCs", artifact.Preview, artifact.IOCs)
		}
	}
	for _, marker := range embeddedCompressionMarkers(data, 20) {
		add("embedded-compressed-blob", "raw-bytes", "Low", "compressed stream magic found in file body", marker, IOCSet{})
	}
	for _, candidate := range xorCandidates(data, cfg.Mode) {
		add("xor-config-candidate", "single-byte-xor", "Low", "single-byte XOR produced printable network/config-looking text", candidate, ExtractIOCs(candidate))
	}

	result.ConfigArtifacts = artifacts
	result.CryptoConfig = CryptoConfigSummary{
		Encodings:          encodingSummary(result.DecodedArtifacts),
		CryptoMarkers:      cryptoMarkerSummary(corpus),
		CandidateXORKeys:   xorKeySummary(result.ConfigArtifacts),
		EmbeddedCompressed: embeddedCompressionMarkers(data, 12),
		ConfigArtifacts:    len(artifacts),
	}
	if len(artifacts) > 0 {
		result.Plugins = append(result.Plugins, PluginResult{Name: "crypto-config-extractor", Version: version, Status: "complete", Summary: fmt.Sprintf("%d config artifacts", len(artifacts)), Findings: len(artifacts)})
		if len(artifacts) >= 3 {
			AddFindingDetailed(result, "Low", "Configuration", "Static configuration artifacts extracted", fmt.Sprintf("%d likely configuration or secret-handling artifacts", len(artifacts)), 4, 0, "Discovery", "Data from Local System", "Review extracted config artifacts for live C2, token, wallet, campaign, or mutex values before sharing reports.")
		}
	} else {
		result.Plugins = append(result.Plugins, PluginResult{Name: "crypto-config-extractor", Version: version, Status: "complete", Summary: "no config artifacts extracted"})
	}
}

func embeddedCompressionMarkers(data []byte, limit int) []string {
	if len(data) == 0 {
		return nil
	}
	var out []string
	add := func(offset int, kind string) {
		if offset <= 0 {
			return
		}
		out = appendUnique(out, fmt.Sprintf("%s at 0x%x", kind, offset))
	}
	for i := 1; i+2 < len(data) && len(out) < limit; i++ {
		switch {
		case data[i] == 0x1f && data[i+1] == 0x8b:
			add(i, "gzip")
		case data[i] == 0x78 && (data[i+1] == 0x01 || data[i+1] == 0x9c || data[i+1] == 0xda):
			add(i, "zlib")
		}
	}
	return out
}

func xorCandidates(data []byte, mode string) []string {
	if mode == "quick" || len(data) < 128 {
		return nil
	}
	limit := len(data)
	if limit > defaultXORScanLimit {
		limit = defaultXORScanLimit
	}
	sample := data[:limit]
	var out []string
	// Reuse a single buffer across all 255 key iterations instead of
	// allocating a fresh []byte per key (~65 MB → ~256 KB total).
	buf := make([]byte, len(sample))
	for key := 1; key < 256 && len(out) < defaultXORMaxResults; key++ {
		printable := 0
		for i, b := range sample {
			decoded := b ^ byte(key)
			buf[i] = decoded
			if decoded == '\n' || decoded == '\r' || decoded == '\t' || (decoded >= 0x20 && decoded <= 0x7e) {
				printable++
			}
		}
		if float64(printable)/float64(len(buf)) < defaultXORPrintableRatio {
			continue
		}
		text := string(buf)
		lower := strings.ToLower(text)
		if !hasAny(lower, "http://", "https://", "gate.php", "api/", "bot_token", "mutex", "encrypted") {
			continue
		}
		stringsFound, _, _ := ExtractStrings(buf, 5, 4)
		preview := fmt.Sprintf("key=0x%02x", key)
		if len(stringsFound) > 0 {
			preview += " " + stringsFound[0].Value
		}
		out = append(out, previewString(preview, 220))
	}
	return out
}

func encodingSummary(values []DecodedArtifact) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, artifact := range values {
		if _, ok := seen[artifact.Encoding]; ok {
			continue
		}
		seen[artifact.Encoding] = struct{}{}
		out = append(out, artifact.Encoding)
	}
	return uniqueSorted(out)
}

func cryptoMarkerSummary(corpus string) []string {
	var markers []string
	for _, marker := range []string{"aes", "rsa", "rc4", "chacha", "bcryptdecrypt", "cryptunprotectdata", "javax/crypto", "secretkeyspec", "pbkdf2", "nonce", "iv"} {
		if strings.Contains(corpus, marker) {
			markers = append(markers, marker)
		}
	}
	return uniqueSorted(markers)
}

func xorKeySummary(values []ConfigArtifact) []string {
	var out []string
	for _, artifact := range values {
		if artifact.Type != "xor-config-candidate" {
			continue
		}
		fields := strings.Fields(artifact.Preview)
		if len(fields) > 0 {
			out = append(out, fields[0])
		}
	}
	return uniqueSorted(out)
}
