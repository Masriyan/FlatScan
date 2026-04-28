package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type flatRulePack struct {
	Name  string     `json:"name"`
	Rules []flatRule `json:"rules"`
}

type flatRule struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Severity       string   `json:"severity"`
	Category       string   `json:"category"`
	Score          int      `json:"score"`
	Tactic         string   `json:"tactic"`
	Technique      string   `json:"technique"`
	Recommendation string   `json:"recommendation"`
	FileTypes      []string `json:"file_types"`
	StringsAny     []string `json:"strings_any"`
	StringsAll     []string `json:"strings_all"`
	RegexAny       []string `json:"regex_any"`
	FunctionsAny   []string `json:"functions_any"`
	DomainsAny     []string `json:"domains_any"`
	URLsAny        []string `json:"urls_any"`
	SHA256Any      []string `json:"sha256_any"`
	MinEntropy     float64  `json:"min_entropy"`
	MaxEntropy     float64  `json:"max_entropy"`
}

func ApplyRulePacks(result *ScanResult, stringsFound []ExtractedString, cfg Config, debugf debugLogger) {
	corpus := buildCorpus(stringsFound, result.DecodedArtifacts, defaultMaxCorpusBytes)
	ApplyRulePacksWithCorpus(result, stringsFound, cfg, debugf, corpus)
}

// ApplyRulePacksWithCorpus uses a pre-built corpus string.
func ApplyRulePacksWithCorpus(result *ScanResult, stringsFound []ExtractedString, cfg Config, debugf debugLogger, corpus string) {
	paths := append(splitPathList(cfg.RulePaths), splitPathList(cfg.PluginPaths)...)
	if len(paths) == 0 {
		return
	}
	result.Plugins = append(result.Plugins, PluginResult{Name: "declarative-rule-engine", Version: version, Status: "enabled", Summary: "FlatScan custom rule/plugin pack engine"})
	for _, path := range paths {
		summary := RulePackSummary{Path: path}
		pack, warnings, err := loadRulePackPath(path)
		summary.Warnings = append(summary.Warnings, warnings...)
		if err != nil {
			summary.Warnings = append(summary.Warnings, err.Error())
			result.RulePacks = append(result.RulePacks, summary)
			debugf("rule pack load failed for %s: %v", path, err)
			continue
		}
		summary.Name = pack.Name
		summary.RulesLoaded = len(pack.Rules)
		for _, rule := range pack.Rules {
			matched, evidence := matchFlatRule(rule, *result, corpus)
			if !matched {
				continue
			}
			summary.RulesFired++
			ruleID := nonEmpty(rule.ID, rule.Name)
			severity := nonEmpty(rule.Severity, "Low")
			category := nonEmpty(rule.Category, "Custom Rule")
			title := nonEmpty(rule.Name, ruleID)
			score := rule.Score
			if score == 0 {
				score = DefaultSeverityScore(severity)
			}
			AddFindingDetailed(result, severity, category, title, strings.Join(evidence, "; "), score, 0, rule.Tactic, rule.Technique, rule.Recommendation)
			result.RuleMatches = append(result.RuleMatches, RuleMatch{
				RuleID:     ruleID,
				Name:       title,
				Severity:   severity,
				Category:   category,
				Evidence:   evidence,
				Confidence: findingConfidence(Finding{Severity: severity}),
			})
		}
		result.RulePacks = append(result.RulePacks, summary)
	}
	for _, summary := range result.RulePacks {
		result.Plugins = append(result.Plugins, PluginResult{
			Name:     "rule-pack:" + nonEmpty(summary.Name, filepath.Base(summary.Path)),
			Version:  version,
			Status:   "loaded",
			Summary:  fmt.Sprintf("%d rules loaded, %d fired", summary.RulesLoaded, summary.RulesFired),
			Findings: summary.RulesFired,
			Warnings: summary.Warnings,
		})
	}
}

func loadRulePackPath(path string) (flatRulePack, []string, error) {
	var warnings []string
	stat, err := os.Stat(path)
	if err != nil {
		return flatRulePack{}, nil, err
	}
	if stat.IsDir() {
		var combined flatRulePack
		combined.Name = filepath.Base(path)
		entries, err := os.ReadDir(path)
		if err != nil {
			return combined, warnings, err
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			lower := strings.ToLower(entry.Name())
			if !(strings.HasSuffix(lower, ".json") || strings.HasSuffix(lower, ".rule") || strings.HasSuffix(lower, ".rules") || strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")) {
				continue
			}
			pack, childWarnings, err := loadRulePackFile(filepath.Join(path, entry.Name()))
			warnings = append(warnings, childWarnings...)
			if err != nil {
				warnings = append(warnings, entry.Name()+": "+err.Error())
				continue
			}
			combined.Rules = append(combined.Rules, pack.Rules...)
		}
		return combined, warnings, nil
	}
	return loadRulePackFile(path)
}

func loadRulePackFile(path string) (flatRulePack, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return flatRulePack{}, nil, err
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return flatRulePack{}, nil, fmt.Errorf("empty rule pack")
	}
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		pack, err := parseJSONRulePack([]byte(trimmed), path)
		return pack, nil, err
	}
	pack, warnings, err := parseTextRulePack(trimmed, path)
	return pack, warnings, err
}

func parseJSONRulePack(data []byte, path string) (flatRulePack, error) {
	var pack flatRulePack
	if err := json.Unmarshal(data, &pack); err == nil && len(pack.Rules) > 0 {
		if pack.Name == "" {
			pack.Name = filepath.Base(path)
		}
		return pack, nil
	}
	var rules []flatRule
	if err := json.Unmarshal(data, &rules); err == nil {
		return flatRulePack{Name: filepath.Base(path), Rules: rules}, nil
	}
	return flatRulePack{}, fmt.Errorf("invalid JSON rule pack")
}

func parseTextRulePack(text, path string) (flatRulePack, []string, error) {
	var warnings []string
	pack := flatRulePack{Name: filepath.Base(path)}
	var current flatRule
	flush := func() {
		if current.ID != "" || current.Name != "" || len(current.StringsAny)+len(current.StringsAll)+len(current.RegexAny) > 0 {
			pack.Rules = append(pack.Rules, current)
		}
		current = flatRule{}
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			warnings = append(warnings, "ignored line without key/value: "+line)
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "pack", "pack_name":
			pack.Name = value
		case "id":
			current.ID = value
		case "name", "title":
			current.Name = value
		case "severity":
			current.Severity = value
		case "category":
			current.Category = value
		case "score":
			if parsed, err := strconv.Atoi(value); err == nil {
				current.Score = parsed
			}
		case "tactic":
			current.Tactic = value
		case "technique":
			current.Technique = value
		case "recommendation":
			current.Recommendation = value
		case "file_types":
			current.FileTypes = parseRuleList(value)
		case "strings_any":
			current.StringsAny = parseRuleList(value)
		case "strings_all":
			current.StringsAll = parseRuleList(value)
		case "regex_any":
			current.RegexAny = parseRuleList(value)
		case "functions_any":
			current.FunctionsAny = parseRuleList(value)
		case "domains_any":
			current.DomainsAny = parseRuleList(value)
		case "urls_any":
			current.URLsAny = parseRuleList(value)
		case "sha256_any":
			current.SHA256Any = parseRuleList(value)
		case "min_entropy":
			current.MinEntropy, _ = strconv.ParseFloat(value, 64)
		case "max_entropy":
			current.MaxEntropy, _ = strconv.ParseFloat(value, 64)
		default:
			warnings = append(warnings, "unknown key: "+key)
		}
	}
	flush()
	if len(pack.Rules) == 0 {
		return pack, warnings, fmt.Errorf("no rules loaded")
	}
	return pack, warnings, nil
}

func matchFlatRule(rule flatRule, result ScanResult, corpus string) (bool, []string) {
	var evidence []string
	if len(rule.FileTypes) > 0 && !containsAnyFold(result.FileType, rule.FileTypes) {
		return false, nil
	}
	if rule.MinEntropy > 0 {
		if result.Entropy < rule.MinEntropy {
			return false, nil
		}
		evidence = append(evidence, fmt.Sprintf("entropy %.2f >= %.2f", result.Entropy, rule.MinEntropy))
	}
	if rule.MaxEntropy > 0 {
		if result.Entropy > rule.MaxEntropy {
			return false, nil
		}
		evidence = append(evidence, fmt.Sprintf("entropy %.2f <= %.2f", result.Entropy, rule.MaxEntropy))
	}
	if len(rule.SHA256Any) > 0 {
		if !stringInFold(result.Hashes.SHA256, rule.SHA256Any) {
			return false, nil
		}
		evidence = append(evidence, "sha256 matched")
	}
	for _, needle := range rule.StringsAll {
		if !strings.Contains(corpus, strings.ToLower(needle)) {
			return false, nil
		}
		evidence = append(evidence, "string_all="+needle)
	}
	if len(rule.StringsAny) > 0 {
		matched := firstNeedleInText(corpus, rule.StringsAny)
		if matched == "" {
			return false, nil
		}
		evidence = append(evidence, "string_any="+matched)
	}
	if len(rule.RegexAny) > 0 {
		matchedRegex := ""
		for _, pattern := range rule.RegexAny {
			re, err := regexp.Compile("(?i)" + pattern)
			if err != nil {
				continue
			}
			if re.MatchString(corpus) {
				matchedRegex = pattern
				break
			}
		}
		if matchedRegex == "" {
			return false, nil
		}
		evidence = append(evidence, "regex_any="+matchedRegex)
	}
	if len(rule.FunctionsAny) > 0 {
		if matched := firstMatchingFunction(result.Functions, rule.FunctionsAny); matched == "" {
			return false, nil
		} else {
			evidence = append(evidence, "function="+matched)
		}
	}
	if len(rule.DomainsAny) > 0 {
		if matched := firstMatchingValueFold(result.IOCs.Domains, rule.DomainsAny); matched == "" {
			return false, nil
		} else {
			evidence = append(evidence, "domain="+matched)
		}
	}
	if len(rule.URLsAny) > 0 {
		if matched := firstMatchingValueFold(result.IOCs.URLs, rule.URLsAny); matched == "" {
			return false, nil
		} else {
			evidence = append(evidence, "url="+matched)
		}
	}
	return len(evidence) > 0 || len(rule.FileTypes) > 0, evidence
}

func parseRuleList(value string) []string {
	value = strings.Trim(value, "[]")
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';'
	})
	var out []string
	for _, part := range parts {
		part = strings.Trim(strings.TrimSpace(part), `"'`)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func splitPathList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func firstNeedleInText(text string, needles []string) string {
	for _, needle := range needles {
		if strings.Contains(text, strings.ToLower(needle)) {
			return needle
		}
	}
	return ""
}

func firstMatchingFunction(functions []FunctionHit, needles []string) string {
	for _, fn := range functions {
		value := strings.ToLower(fn.Name + " " + fn.Family)
		for _, needle := range needles {
			if strings.Contains(value, strings.ToLower(needle)) {
				return fn.Name
			}
		}
	}
	return ""
}

func firstMatchingValueFold(values, needles []string) string {
	for _, value := range values {
		lower := strings.ToLower(value)
		for _, needle := range needles {
			if strings.Contains(lower, strings.ToLower(needle)) {
				return value
			}
		}
	}
	return ""
}

func stringInFold(value string, candidates []string) bool {
	for _, candidate := range candidates {
		if strings.EqualFold(value, candidate) {
			return true
		}
	}
	return false
}

func containsAnyFold(value string, needles []string) bool {
	value = strings.ToLower(value)
	for _, needle := range needles {
		if strings.Contains(value, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}
