package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

type IOCAllowlist struct {
	Domains     []string `json:"domains,omitempty"`
	URLs        []string `json:"urls,omitempty"`
	URLPrefixes []string `json:"url_prefixes,omitempty"`
	IPv4        []string `json:"ipv4,omitempty"`
}

func ApplyIOCTriage(result *ScanResult, cfg Config, debugf debugLogger) {
	if result == nil {
		return
	}
	allowlist, err := LoadIOCAllowlist(cfg.IOCAllowlistPath)
	if err != nil {
		debugf("ioc allowlist load failed: %v", err)
		AddFinding(result, "Info", "IOC", "IOC allowlist load failed", err.Error(), 0, 0)
	}
	before := IOCCount(result.IOCs)
	result.IOCs = TriageIOCSet(result.IOCs, allowlist, debugf)
	after := IOCCount(result.IOCs)
	if result.IOCs.SuppressedCount > 0 {
		result.IOCs.SuppressionReason = fmt.Sprintf("%d extracted IOC(s) matched PKI, schema, OID, or operator allowlist patterns", result.IOCs.SuppressedCount)
	}
	if before != after {
		debugf("ioc triage retained %d of %d top-level indicators", after, before)
	}
}

func TriageIOCSet(iocs IOCSet, allowlist IOCAllowlist, debugf debugLogger) IOCSet {
	NormalizeIOCSet(&iocs)
	var out IOCSet
	out.Priority = iocs.Priority
	out.PEHashes = iocs.PEHashes
	out.IPv6 = iocs.IPv6
	out.Emails = iocs.Emails
	out.MD5 = iocs.MD5
	out.SHA1 = iocs.SHA1
	out.SHA256 = iocs.SHA256
	out.SHA512 = iocs.SHA512
	out.CVEs = iocs.CVEs
	out.RegistryKeys = iocs.RegistryKeys
	out.WindowsPaths = iocs.WindowsPaths
	out.UnixPaths = iocs.UnixPaths
	out.SuppressedCount = iocs.SuppressedCount
	out.SuppressionReason = iocs.SuppressionReason
	out.SuppressionLog = iocs.SuppressionLog

	for _, value := range iocs.URLs {
		if reason := allowlist.URLReason(value); reason != "" {
			out.recordSuppression("url", value, reason, debugf)
			continue
		}
		out.URLs = appendUnique(out.URLs, value)
	}
	for _, value := range iocs.Domains {
		if reason := allowlist.DomainReason(value); reason != "" {
			out.recordSuppression("domain", value, reason, debugf)
			continue
		}
		out.Domains = appendUnique(out.Domains, value)
	}
	for _, value := range iocs.IPv4 {
		if reason := allowlist.IPv4Reason(value); reason != "" {
			out.recordSuppression("ipv4", value, reason, debugf)
			continue
		}
		out.IPv4 = appendUnique(out.IPv4, value)
	}
	NormalizeIOCSet(&out)
	return out
}

func (iocs *IOCSet) recordSuppression(kind, value, reason string, debugf debugLogger) {
	iocs.SuppressedCount++
	iocs.SuppressionLog = appendSuppressionLog(iocs.SuppressionLog, IOCSuppression{
		Type:   kind,
		Value:  value,
		Reason: reason,
	})
	debugf("suppressed %s IOC %q: %s", kind, value, reason)
}

func LoadIOCAllowlist(path string) (IOCAllowlist, error) {
	allowlist := defaultIOCAllowlist()
	if strings.TrimSpace(path) == "" {
		return allowlist, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return allowlist, err
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return allowlist, nil
	}
	var custom IOCAllowlist
	if strings.HasPrefix(trimmed, "{") {
		if err := json.Unmarshal(data, &custom); err != nil {
			return allowlist, err
		}
		allowlist.merge(custom)
		return allowlist, nil
	}
	allowlist.merge(parseLineAllowlist(trimmed))
	return allowlist, nil
}

func defaultIOCAllowlist() IOCAllowlist {
	return IOCAllowlist{
		Domains: []string{
			"*.digicert.com",
			"*.verisign.com",
			"*.globalsign.com",
			"*.comodo.com",
			"*.sectigo.com",
			"*.entrust.com",
			"*.symantec.com",
			"*.thawte.com",
			"ocsp.msocsp.com",
			"mscrl.microsoft.com",
			"schemas.microsoft.com",
			"schemas.openxmlformats.org",
			"schemas.android.com",
			"www.w3.org",
			"purl.org",
			"dublincore.org",
			"www.iana.org",
		},
		URLPrefixes: []string{
			"http://schemas.microsoft.com/appx/",
			"http://schemas.openxmlformats.org/",
			"http://www.w3.org/2001/",
			"http://crl",
			"http://ocsp",
			"https://ocsp",
			"http://schemas.microsoft.com/",
			"http://www.w3.org/",
			"http://purl.org/",
			"http://dublincore.org/",
		},
		IPv4: []string{
			"0.0.0.0",
			"1.3.6.1",
			"1.3.6.1.*",
			"2.5.4.*",
			"2.5.29.*",
			"4.0.0.0",
			"127.0.0.1",
			"255.255.255.255",
		},
	}
}

func (allowlist *IOCAllowlist) merge(other IOCAllowlist) {
	allowlist.Domains = appendUnique(allowlist.Domains, normalizeAllowlistValues(other.Domains)...)
	allowlist.URLPrefixes = appendUnique(allowlist.URLPrefixes, normalizeAllowlistValues(other.URLPrefixes)...)
	allowlist.URLPrefixes = appendUnique(allowlist.URLPrefixes, normalizeAllowlistValues(other.URLs)...)
	allowlist.IPv4 = appendUnique(allowlist.IPv4, normalizeAllowlistValues(other.IPv4)...)
}

func parseLineAllowlist(text string) IOCAllowlist {
	var out IOCAllowlist
	section := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.Trim(line, "\"'")
		if strings.HasSuffix(line, ":") && !strings.Contains(line, "://") {
			section = normalizeAllowlistKey(strings.TrimSuffix(line, ":"))
			continue
		}
		if strings.HasPrefix(line, "-") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "-"))
			line = strings.Trim(line, "\"'")
			addAllowlistValue(&out, section, line)
			continue
		}
		key, value, ok := splitAllowlistLine(line)
		if ok {
			section = normalizeAllowlistKey(key)
			addAllowlistValue(&out, section, strings.Trim(value, "\"'"))
			continue
		}
		addAllowlistValue(&out, section, line)
	}
	return out
}

func splitAllowlistLine(line string) (string, string, bool) {
	if strings.Contains(line, "://") {
		return "", "", false
	}
	for _, sep := range []string{":", "="} {
		parts := strings.SplitN(line, sep, 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		switch normalizeAllowlistKey(key) {
		case "domain", "domains", "url", "urls", "prefix", "prefixes", "url_prefix", "url_prefixes", "ipv4", "ip", "ips":
		default:
			continue
		}
		if key != "" && value != "" {
			return key, value, true
		}
	}
	return "", "", false
}

func addAllowlistValue(out *IOCAllowlist, section, value string) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return
	}
	switch normalizeAllowlistKey(section) {
	case "domain", "domains":
		out.Domains = appendUnique(out.Domains, value)
	case "url", "urls", "prefix", "prefixes", "url_prefix", "url_prefixes":
		out.URLPrefixes = appendUnique(out.URLPrefixes, value)
	case "ipv4", "ip", "ips":
		out.IPv4 = appendUnique(out.IPv4, value)
	default:
		if strings.Contains(value, "://") {
			out.URLPrefixes = appendUnique(out.URLPrefixes, value)
		} else if strings.Count(value, ".") == 3 && strings.IndexFunc(value, func(r rune) bool {
			return !((r >= '0' && r <= '9') || r == '.' || r == '*')
		}) == -1 {
			out.IPv4 = appendUnique(out.IPv4, value)
		} else {
			out.Domains = appendUnique(out.Domains, value)
		}
	}
}

func normalizeAllowlistKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	return value
}

func normalizeAllowlistValues(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func (allowlist IOCAllowlist) URLReason(value string) string {
	lower := strings.ToLower(strings.TrimSpace(value))
	for _, prefix := range allowlist.URLPrefixes {
		prefix = strings.ToLower(strings.TrimSpace(prefix))
		if prefix != "" && strings.HasPrefix(lower, prefix) {
			return "url prefix allowlist: " + prefix
		}
	}
	if parsed, err := url.Parse(lower); err == nil && parsed.Hostname() != "" {
		if reason := allowlist.DomainReason(parsed.Hostname()); reason != "" {
			return reason
		}
	}
	return ""
}

func (allowlist IOCAllowlist) DomainReason(value string) string {
	value = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(value, ".")))
	for _, pattern := range allowlist.Domains {
		pattern = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(pattern, ".")))
		if pattern == "" {
			continue
		}
		if strings.HasPrefix(pattern, "*.") {
			base := strings.TrimPrefix(pattern, "*.")
			if value == base || strings.HasSuffix(value, "."+base) {
				return "domain allowlist: " + pattern
			}
			continue
		}
		if value == pattern || strings.HasSuffix(value, "."+pattern) && strings.HasPrefix(pattern, "schemas.") {
			return "domain allowlist: " + pattern
		}
	}
	return ""
}

func (allowlist IOCAllowlist) IPv4Reason(value string) string {
	value = strings.TrimSpace(value)
	for _, pattern := range allowlist.IPv4 {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if strings.HasSuffix(pattern, ".*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(value, prefix) {
				return "ipv4 allowlist: " + pattern
			}
			continue
		}
		if value == pattern {
			return "ipv4 allowlist: " + pattern
		}
	}
	return ""
}
