package main

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
)

var (
	base64CandidateRe = regexp.MustCompile(`(?:[A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9_-]{16,}={0,2})`)
	hexCandidateRe    = regexp.MustCompile(`(?i)\b(?:0x)?[a-f0-9]{16,}\b`)
)

type decodeJob struct {
	Text   string
	Source string
	Depth  int
}

func DecodeSuspiciousStrings(stringsFound []ExtractedString, cfg Config) []DecodedArtifact {
	if cfg.MaxDecodeDepth == 0 {
		return nil
	}

	limit := decodeLimitForMode(cfg.Mode)
	queue := make([]decodeJob, 0, limit)
	for _, item := range stringsFound {
		if len(queue) >= limit {
			break
		}
		if looksEncoded(item.Value) {
			queue = append(queue, decodeJob{
				Text:   item.Value,
				Source: item.Encoding + " string at offset " + int64ToString(item.Offset),
				Depth:  0,
			})
		}
	}

	var artifacts []DecodedArtifact
	seen := make(map[string]struct{})
	for len(queue) > 0 && len(artifacts) < limit {
		job := queue[0]
		queue = queue[1:]
		for _, decoded := range decodeText(job.Text) {
			if !isMostlyPrintable(decoded.Value) {
				continue
			}
			preview := previewString(decoded.Value, 240)
			key := decoded.Encoding + "\x00" + preview
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			artifact := DecodedArtifact{
				Encoding: decoded.Encoding,
				Source:   job.Source,
				Preview:  preview,
				IOCs:     ExtractIOCs(decoded.Value),
			}
			artifacts = append(artifacts, artifact)
			if job.Depth+1 < cfg.MaxDecodeDepth && looksEncoded(decoded.Value) {
				queue = append(queue, decodeJob{
					Text:   decoded.Value,
					Source: "decoded " + decoded.Encoding,
					Depth:  job.Depth + 1,
				})
			}
		}
	}
	return artifacts
}

type decodedValue struct {
	Encoding string
	Value    string
}

func decodeText(text string) []decodedValue {
	var out []decodedValue
	if strings.Contains(text, "%") {
		if unescaped, err := url.QueryUnescape(text); err == nil && unescaped != text {
			out = append(out, decodedValue{Encoding: "url-percent", Value: unescaped})
		}
	}

	for _, candidate := range base64CandidateRe.FindAllString(text, -1) {
		if decoded, ok := tryBase64(candidate); ok {
			out = append(out, decodedValue{Encoding: "base64", Value: string(decoded)})
		}
	}

	for _, candidate := range hexCandidateRe.FindAllString(text, -1) {
		candidate = strings.TrimPrefix(strings.TrimPrefix(candidate, "0x"), "0X")
		if len(candidate)%2 != 0 {
			continue
		}
		if decoded, err := hex.DecodeString(candidate); err == nil {
			out = append(out, decodedValue{Encoding: "hex", Value: string(decoded)})
		}
	}
	return out
}

func tryBase64(candidate string) ([]byte, bool) {
	candidate = strings.TrimSpace(candidate)
	if len(candidate) < 16 {
		return nil, false
	}
	candidates := []string{candidate}
	if rem := len(candidate) % 4; rem != 0 {
		candidates = append(candidates, candidate+strings.Repeat("=", 4-rem))
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, value := range candidates {
		for _, encoding := range encodings {
			decoded, err := encoding.DecodeString(value)
			if err == nil && len(decoded) >= 4 {
				return decoded, true
			}
		}
	}
	return nil, false
}

func looksEncoded(value string) bool {
	if len(value) < 8 {
		return false
	}
	return strings.Contains(value, "%") ||
		base64CandidateRe.MatchString(value) ||
		hexCandidateRe.MatchString(value)
}

func isMostlyPrintable(value string) bool {
	if len(value) == 0 {
		return false
	}
	printable := 0
	total := 0
	for _, r := range value {
		total++
		if r == '\n' || r == '\r' || r == '\t' || (r >= 0x20 && r <= 0x7e) {
			printable++
		}
	}
	return total > 0 && float64(printable)/float64(total) >= 0.80
}

func decodeLimitForMode(mode string) int {
	switch mode {
	case "quick":
		return 60
	case "standard":
		return 250
	default:
		return 1000
	}
}

func int64ToString(value int64) string {
	if value == 0 {
		return "0"
	}
	negative := value < 0
	if negative {
		value = -value
	}
	var buf [20]byte
	i := len(buf)
	for value > 0 {
		i--
		buf[i] = byte('0' + value%10)
		value /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
