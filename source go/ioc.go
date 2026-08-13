package main

import (
	"net"
	"regexp"
	"sort"
	"strings"
)

var (
	urlRe       = regexp.MustCompile(`(?i)\b(?:https?|hxxps?|ftp)://[^\s"'<>]+`)
	emailRe     = regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`)
	domainRe    = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|ru|cn|xyz|top|biz|info|online|site|club|me|dev|app|gov|edu|mil|uk|de|jp|kr|br|in|ir|tr|id|vn|pl|fr|it|es|nl|se|no|fi|ua|su|pw|cc|tk|local)\b`)
	ipv4Re      = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Re      = regexp.MustCompile(`(?i)\b(?:[a-f0-9]{1,4}:){2,7}[a-f0-9]{1,4}\b`)
	md5Re       = regexp.MustCompile(`(?i)\b[a-f0-9]{32}\b`)
	sha1Re      = regexp.MustCompile(`(?i)\b[a-f0-9]{40}\b`)
	sha256Re    = regexp.MustCompile(`(?i)\b[a-f0-9]{64}\b`)
	sha512Re    = regexp.MustCompile(`(?i)\b[a-f0-9]{128}\b`)
	cveRe       = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)
	registryRe  = regexp.MustCompile(`(?i)\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\[^\s"'<>]{3,}`)
	winPathRe   = regexp.MustCompile(`(?i)\b[A-Z]:\\[^\s"'<>|]{3,}`)
	unixPathRe  = regexp.MustCompile(`\B/(?:tmp|var|etc|home|usr|bin|sbin|dev|proc|run|opt|lib|root)/[^\s"'<>]{2,}`)
	mutexRe     = regexp.MustCompile(`(?i)(?:Global|Local)\\[A-Za-z0-9_\-\.]{4,64}`)
	namedPipeRe = regexp.MustCompile(`(?i)\\\\\.\\pipe\\[^\s"'<>]{3,64}`)
	ethWalletRe = regexp.MustCompile(`\b0x[0-9a-fA-F]{40}\b`)
	xmrWalletRe = regexp.MustCompile(`\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b`)
	btcWalletRe = regexp.MustCompile(`\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b`)
)

func ExtractIOCsFromStrings(stringsFound []ExtractedString) IOCSet {
	var out IOCSet

	// Accumulate through a set that lives across the whole loop rather than
	// merging per string. MergeIOCSet dedups via appendUnique, which rebuilds a
	// map of the entire destination on every call — with one indicator per
	// extracted string that is O(n^2), and it dominated the scan: a 1.2 MB text
	// file holding 60k URLs took over 50 seconds, and 8k URLs took 9.4s where
	// 1k took 0.24s. The dedup result is identical; only the cost changes.
	fields := iocStringFields(&out)
	seen := make([]map[string]struct{}, len(fields))
	for i := range seen {
		seen[i] = make(map[string]struct{})
	}

	for _, item := range stringsFound {
		found := ExtractIOCs(item.Value)
		for _, peHash := range found.PEHashes {
			addPEHashIOC(&out, peHash)
		}
		src := iocStringFields(&found)
		for i, values := range src {
			for _, value := range *values {
				if value == "" {
					continue
				}
				if _, ok := seen[i][value]; ok {
					continue
				}
				seen[i][value] = struct{}{}
				*fields[i] = append(*fields[i], value)
			}
		}
	}

	NormalizeIOCSet(&out)
	return out
}

// iocStringFields returns pointers to every flat indicator slice in set, in a
// fixed order. Callers pair a source and destination set by index, so the order
// only has to be stable between two calls — not meaningful on its own.
func iocStringFields(set *IOCSet) []*[]string {
	return []*[]string{
		&set.URLs, &set.Domains, &set.IPv4, &set.IPv6, &set.Emails,
		&set.MD5, &set.SHA1, &set.SHA256, &set.SHA512, &set.CVEs,
		&set.RegistryKeys, &set.WindowsPaths, &set.UnixPaths,
		&set.Mutexes, &set.NamedPipes, &set.CryptoWallets,
	}
}

func ExtractIOCs(text string) IOCSet {
	var out IOCSet
	addMatches(&out.URLs, urlRe.FindAllString(text, -1), normalizeURL)
	addMatches(&out.Emails, emailRe.FindAllString(text, -1), normalizeLower)
	addMatches(&out.Domains, domainRe.FindAllString(text, -1), normalizeDomain)
	addMatches(&out.IPv4, ipv4Re.FindAllString(text, -1), normalizeIPv4)
	addMatches(&out.IPv6, ipv6Re.FindAllString(text, -1), normalizeIPv6)
	addMatches(&out.SHA512, sha512Re.FindAllString(text, -1), normalizeLower)
	addMatches(&out.SHA256, sha256Re.FindAllString(text, -1), normalizeLower)
	addMatches(&out.SHA1, sha1Re.FindAllString(text, -1), normalizeLower)
	addMatches(&out.MD5, md5Re.FindAllString(text, -1), normalizeLower)
	addMatches(&out.CVEs, cveRe.FindAllString(text, -1), strings.ToUpper)
	addMatches(&out.RegistryKeys, registryRe.FindAllString(text, -1), cleanToken)
	addMatches(&out.WindowsPaths, winPathRe.FindAllString(text, -1), cleanToken)
	addMatches(&out.UnixPaths, unixPathRe.FindAllString(text, -1), cleanToken)
	addMatches(&out.Mutexes, mutexRe.FindAllString(text, -1), cleanToken)
	addMatches(&out.NamedPipes, namedPipeRe.FindAllString(text, -1), cleanToken)
	addMatches(&out.CryptoWallets, ethWalletRe.FindAllString(text, -1), cleanToken)
	addMatches(&out.CryptoWallets, xmrWalletRe.FindAllString(text, -1), cleanToken)
	addMatches(&out.CryptoWallets, btcWalletRe.FindAllString(text, -1), cleanToken)
	// Normalization deferred to pipeline-level (ExtractIOCsFromStrings or ApplyIOCTriage)
	// to avoid redundant sort+deduplicate when called per-string or per-artifact.
	return out
}

func MergeIOCSet(dst *IOCSet, src IOCSet) {
	if dst == nil {
		return
	}
	dst.Priority = higherIOCPriority(dst.Priority, src.Priority)
	for _, peHash := range src.PEHashes {
		addPEHashIOC(dst, peHash)
	}
	dst.URLs = appendUnique(dst.URLs, src.URLs...)
	dst.Domains = appendUnique(dst.Domains, src.Domains...)
	dst.IPv4 = appendUnique(dst.IPv4, src.IPv4...)
	dst.IPv6 = appendUnique(dst.IPv6, src.IPv6...)
	dst.Emails = appendUnique(dst.Emails, src.Emails...)
	dst.MD5 = appendUnique(dst.MD5, src.MD5...)
	dst.SHA1 = appendUnique(dst.SHA1, src.SHA1...)
	dst.SHA256 = appendUnique(dst.SHA256, src.SHA256...)
	dst.SHA512 = appendUnique(dst.SHA512, src.SHA512...)
	dst.CVEs = appendUnique(dst.CVEs, src.CVEs...)
	dst.RegistryKeys = appendUnique(dst.RegistryKeys, src.RegistryKeys...)
	dst.WindowsPaths = appendUnique(dst.WindowsPaths, src.WindowsPaths...)
	dst.UnixPaths = appendUnique(dst.UnixPaths, src.UnixPaths...)
	dst.Mutexes = appendUnique(dst.Mutexes, src.Mutexes...)
	dst.NamedPipes = appendUnique(dst.NamedPipes, src.NamedPipes...)
	dst.CryptoWallets = appendUnique(dst.CryptoWallets, src.CryptoWallets...)
	dst.SuppressedCount += src.SuppressedCount
	if dst.SuppressionReason == "" {
		dst.SuppressionReason = src.SuppressionReason
	}
	dst.SuppressionLog = appendSuppressionLog(dst.SuppressionLog, src.SuppressionLog...)
	// Normalization deferred to pipeline-level (ApplyIOCTriage) to avoid
	// redundant sort+deduplicate on every merge call.
}

func NormalizeIOCSet(iocs *IOCSet) {
	if iocs == nil {
		return
	}
	iocs.Priority = strings.ToUpper(strings.TrimSpace(iocs.Priority))
	iocs.PEHashes = normalizePEHashes(iocs.PEHashes)
	iocs.URLs = uniqueSorted(iocs.URLs)
	iocs.Domains = uniqueSorted(iocs.Domains)
	iocs.IPv4 = uniqueSorted(iocs.IPv4)
	iocs.IPv6 = uniqueSorted(iocs.IPv6)
	iocs.Emails = uniqueSorted(iocs.Emails)
	iocs.MD5 = uniqueSorted(iocs.MD5)
	iocs.SHA1 = uniqueSorted(iocs.SHA1)
	iocs.SHA256 = uniqueSorted(iocs.SHA256)
	iocs.SHA512 = uniqueSorted(iocs.SHA512)
	iocs.CVEs = uniqueSorted(iocs.CVEs)
	iocs.RegistryKeys = uniqueSorted(iocs.RegistryKeys)
	iocs.WindowsPaths = uniqueSorted(iocs.WindowsPaths)
	iocs.UnixPaths = uniqueSorted(iocs.UnixPaths)
	iocs.SuppressionLog = uniqueSuppressionLog(iocs.SuppressionLog)
}

func IOCCount(iocs IOCSet) int {
	return len(iocs.PEHashes) + len(iocs.URLs) + len(iocs.Domains) + len(iocs.IPv4) + len(iocs.IPv6) +
		len(iocs.Emails) + len(iocs.MD5) + len(iocs.SHA1) + len(iocs.SHA256) +
		len(iocs.SHA512) + len(iocs.CVEs) + len(iocs.RegistryKeys) +
		len(iocs.WindowsPaths) + len(iocs.UnixPaths) +
		len(iocs.Mutexes) + len(iocs.NamedPipes) + len(iocs.CryptoWallets)
}

func addPEHashIOC(iocs *IOCSet, value PEHashIOC) {
	if iocs == nil || value.SHA256 == "" {
		return
	}
	value.Path = strings.TrimSpace(value.Path)
	value.SHA256 = strings.ToLower(strings.TrimSpace(value.SHA256))
	value.Tier = strings.ToUpper(strings.TrimSpace(value.Tier))
	if value.Tier == "" {
		value.Tier = "LOW"
	}
	if value.Path == "" {
		value.Path = "embedded-payload"
	}
	for idx, existing := range iocs.PEHashes {
		if strings.EqualFold(existing.SHA256, value.SHA256) && existing.Path == value.Path {
			if iocTierRank(value.Tier) > iocTierRank(existing.Tier) {
				iocs.PEHashes[idx].Tier = value.Tier
			}
			if iocs.PEHashes[idx].Note == "" {
				iocs.PEHashes[idx].Note = value.Note
			}
			if iocs.PEHashes[idx].Entropy == 0 {
				iocs.PEHashes[idx].Entropy = value.Entropy
			}
			if iocs.PEHashes[idx].CompressedSize == 0 {
				iocs.PEHashes[idx].CompressedSize = value.CompressedSize
			}
			if iocs.PEHashes[idx].CompressionRatio == 0 {
				iocs.PEHashes[idx].CompressionRatio = value.CompressionRatio
			}
			if iocs.PEHashes[idx].CarvedOffset == "" {
				iocs.PEHashes[idx].CarvedOffset = value.CarvedOffset
			}
			return
		}
	}
	iocs.PEHashes = append(iocs.PEHashes, value)
	iocs.Priority = higherIOCPriority(iocs.Priority, value.Tier)
}

func normalizePEHashes(values []PEHashIOC) []PEHashIOC {
	out := make([]PEHashIOC, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value.Path = strings.TrimSpace(value.Path)
		value.SHA256 = strings.ToLower(strings.TrimSpace(value.SHA256))
		value.Tier = strings.ToUpper(strings.TrimSpace(value.Tier))
		if value.SHA256 == "" {
			continue
		}
		if value.Path == "" {
			value.Path = "embedded-payload"
		}
		if value.Tier == "" {
			value.Tier = "LOW"
		}
		key := value.Path + "|" + value.SHA256
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if iocTierRank(out[i].Tier) == iocTierRank(out[j].Tier) {
			if out[i].Path == out[j].Path {
				return out[i].SHA256 < out[j].SHA256
			}
			return out[i].Path < out[j].Path
		}
		return iocTierRank(out[i].Tier) > iocTierRank(out[j].Tier)
	})
	return out
}

func higherIOCPriority(left, right string) string {
	left = strings.ToUpper(strings.TrimSpace(left))
	right = strings.ToUpper(strings.TrimSpace(right))
	if iocTierRank(right) > iocTierRank(left) {
		return right
	}
	return left
}

func iocTierRank(tier string) int {
	switch strings.ToUpper(strings.TrimSpace(tier)) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	default:
		return 0
	}
}

func appendSuppressionLog(values []IOCSuppression, additions ...IOCSuppression) []IOCSuppression {
	seen := make(map[string]struct{}, len(values)+len(additions))
	out := make([]IOCSuppression, 0, len(values)+len(additions))
	for _, value := range values {
		key := value.Type + "|" + value.Value + "|" + value.Reason
		if value.Value == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	for _, value := range additions {
		key := value.Type + "|" + value.Value + "|" + value.Reason
		if value.Value == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}

func uniqueSuppressionLog(values []IOCSuppression) []IOCSuppression {
	return appendSuppressionLog(values)
}

func addMatches(dst *[]string, matches []string, normalizer func(string) string) {
	for _, match := range matches {
		value := normalizer(match)
		if value != "" {
			*dst = appendUnique(*dst, value)
		}
	}
}

func appendUnique(values []string, additions ...string) []string {
	seen := make(map[string]struct{}, len(values)+len(additions))
	for _, value := range values {
		if value == "" {
			continue
		}
		seen[value] = struct{}{}
	}
	for _, value := range additions {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	return values
}

func uniqueSorted(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func cleanToken(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, "`'\"<>()[]{}.,;")
	value = strings.ReplaceAll(value, "[.]", ".")
	return value
}

func normalizeLower(value string) string {
	return strings.ToLower(cleanToken(value))
}

func normalizeURL(value string) string {
	value = cleanToken(value)
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "hxxp://") {
		value = "http://" + value[7:]
	} else if strings.HasPrefix(lower, "hxxps://") {
		value = "https://" + value[8:]
	}
	return value
}

func normalizeDomain(value string) string {
	value = normalizeLower(value)
	if value == "" || strings.Contains(value, "..") || strings.Contains(value, "_") {
		return ""
	}
	if ip := net.ParseIP(value); ip != nil {
		return ""
	}
	return value
}

func normalizeIPv4(value string) string {
	value = cleanToken(value)
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return ""
	}
	return value
}

func normalizeIPv6(value string) string {
	value = strings.ToLower(cleanToken(value))
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() != nil {
		return ""
	}
	return value
}
