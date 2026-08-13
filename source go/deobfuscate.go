package main

import (
	"regexp"
	"strings"
)

// Split-literal deobfuscation.
//
// Script droppers hide every meaningful token by building it one fragment at a
// time:
//
//	confronthJo = ""
//	confronthJo = confronthJo + "a"
//	confronthJo = confronthJo + "do"
//	confronthJo = confronthJo + "db"
//	confronthJo = confronthJo + "."
//	...
//
// which assembles "adodb.stream" without the literal ever appearing in the
// file. The behavioral engine matches substrings, so every check silently
// misses: a live sample (SHA256 5095c647…) split "xmlhttp", "adodb.stream",
// "wscript.shell" and its C2 URL across 804 such lines and scored 4/100 while
// VirusTotal flagged it 27/60.
//
// resolveSplitLiterals replays the assignments and hands the reconstructed
// values back to the matcher. The fragments are also evidence in their own
// right — no benign script assembles hundreds of strings a character at a time
// — so splitLiteralDensity scores the technique even when reconstruction
// cannot recover a recognizable token.

// splitLiteralAssignRe matches an append assignment: `x = x + "lit"`, `x = x &
// "lit"` (VBScript), `$x = $x + "lit"` (PowerShell). The back-reference to the
// same name is what distinguishes an append from an ordinary assignment.
var splitLiteralAssignRe = regexp.MustCompile(`^[ \t]*\$?([A-Za-z_]\w*)[ \t]*=[ \t]*\$?([A-Za-z_]\w*)[ \t]*[+&][ \t]*(.+)$`)

// splitLiteralCompoundRe matches `x += "lit"` / `x &= "lit"`.
var splitLiteralCompoundRe = regexp.MustCompile(`^[ \t]*\$?([A-Za-z_]\w*)[ \t]*[+&]=[ \t]*(.+)$`)

// splitLiteralSeedRe matches a plain assignment that starts a chain:
// `x = ""` or `x = "ht"`.
var splitLiteralSeedRe = regexp.MustCompile(`^[ \t]*\$?([A-Za-z_]\w*)[ \t]*=[ \t]*((?:"[^"]*"|'[^']*')(?:[ \t]*[+&][ \t]*(?:"[^"]*"|'[^']*'))*)[ \t]*$`)

// splitLiteralPieceRe extracts the quoted fragments from the right-hand side.
var splitLiteralPieceRe = regexp.MustCompile(`"([^"]*)"|'([^']*)'`)

const (
	// splitLiteralMaxInput caps how much text is replayed. Reconstruction is a
	// line-oriented pass over the whole body, and a multi-hundred-megabyte
	// sample must not turn it into the dominant cost of a scan.
	splitLiteralMaxInput = 4 << 20
	// splitLiteralMaxVars bounds memory against a generated file that assigns
	// millions of distinct names.
	splitLiteralMaxVars = 4096
	// splitLiteralMaxValue caps a single reconstructed string.
	splitLiteralMaxValue = 64 << 10
	// splitLiteralMinValue is the shortest reconstruction worth reporting;
	// below this the result is noise rather than a recovered token.
	splitLiteralMinValue = 6
)

// SplitLiteralResult is the outcome of replaying append assignments over a
// script body.
type SplitLiteralResult struct {
	// Values are the reconstructed strings, longest first.
	Values []string
	// Assignments is how many append assignments were replayed.
	Assignments int
	// Lines is how many lines were examined, for density.
	Lines int
}

// Density is the share of lines that are append assignments, as a percentage.
func (r SplitLiteralResult) Density() int {
	if r.Lines == 0 {
		return 0
	}
	return r.Assignments * 100 / r.Lines
}

// resolveSplitLiterals replays fragment-at-a-time string building and returns
// the reconstructed values.
//
// Only appends whose right-hand side is entirely quoted fragments are replayed.
// A right-hand side naming another variable is skipped rather than guessed at:
// emitting a partial value would feed the matcher a string the script never
// builds, and a false "adodb.stream" is worse than a missed one.
func resolveSplitLiterals(content string) SplitLiteralResult {
	if len(content) > splitLiteralMaxInput {
		content = content[:splitLiteralMaxInput]
	}

	var result SplitLiteralResult
	parts := make(map[string]*strings.Builder)
	seen := make(map[string]bool)
	var order []string

	appendTo := func(name, rhs string) bool {
		pieces := splitLiteralPieceRe.FindAllStringSubmatch(rhs, -1)
		if len(pieces) == 0 {
			return false
		}
		// The right-hand side must be nothing but quoted fragments and the
		// operators joining them; anything else means a variable is involved.
		if strings.Trim(splitLiteralPieceRe.ReplaceAllString(rhs, ""), " \t+&") != "" {
			return false
		}
		b, ok := parts[name]
		if !ok {
			if len(parts) >= splitLiteralMaxVars {
				return false
			}
			b = &strings.Builder{}
			parts[name] = b
			if !seen[name] {
				seen[name] = true
				order = append(order, name)
			}
		}
		for _, piece := range pieces {
			text := piece[1]
			if text == "" {
				text = piece[2]
			}
			if b.Len()+len(text) > splitLiteralMaxValue {
				break
			}
			b.WriteString(text)
		}
		return true
	}

	for _, line := range strings.Split(content, "\n") {
		result.Lines++
		line = strings.TrimRight(line, "\r")

		if m := splitLiteralAssignRe.FindStringSubmatch(line); m != nil && m[1] == m[2] {
			if appendTo(m[1], m[3]) {
				result.Assignments++
			}
			continue
		}
		if m := splitLiteralCompoundRe.FindStringSubmatch(line); m != nil {
			if appendTo(m[1], m[2]) {
				result.Assignments++
			}
			continue
		}
		// A plain assignment reseeds the chain: the old value is discarded.
		if m := splitLiteralSeedRe.FindStringSubmatch(line); m != nil {
			delete(parts, m[1])
			appendTo(m[1], m[2])
		}
	}

	for _, name := range order {
		if b, ok := parts[name]; ok && b.Len() >= splitLiteralMinValue {
			result.Values = append(result.Values, b.String())
		}
	}
	return result
}
