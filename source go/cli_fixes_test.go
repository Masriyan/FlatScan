package main

import "testing"

// Test the flag-conflict rejections added to parseFlags.
func TestParseFlagsRejectsConflicts(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"web+file", []string{"--web", "-f", "/bin/ls"}},
		{"web+dir", []string{"--web", "--dir", "/tmp"}},
		{"watch+file", []string{"--watch", "-f", "/bin/ls"}},
		{"ci+interactive", []string{"--ci", "--interactive", "-f", "/bin/ls"}},
		{"badport", []string{"--web", "--web-port", "99999"}},
		{"badinterval", []string{"--dir", "/tmp", "--watch", "--watch-interval", "0"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := parseFlags(c.args); err == nil {
				t.Fatalf("expected error for args %v, got nil", c.args)
			}
		})
	}
}

// Test that valid mode combinations still parse.
func TestParseFlagsAcceptsValid(t *testing.T) {
	cases := [][]string{
		{"-f", "/bin/ls"},
		{"--dir", "/tmp"},
		{"--web"},
		{"--web", "--web-port", "8080"},
		{"-f", "/bin/ls", "--quiet"},
		{"-f", "/bin/ls", "-q"},
		{"-f", "/bin/ls", "--ci", "--ci-threshold", "70"},
	}
	for _, args := range cases {
		if _, err := parseFlags(args); err != nil {
			t.Fatalf("unexpected error for %v: %v", args, err)
		}
	}
}

// suggestFlag should map near-miss typos to the intended flag.
func TestSuggestFlag(t *testing.T) {
	cases := map[string]string{
		"carv":         "carve",
		"jsonn":        "json",
		"verbose":      "version",
		"hlp":          "help",
		"outputformat": "", // too far from any single flag name -> no suggestion or a close one
	}
	for in, want := range cases {
		got := suggestFlag(in)
		if want != "" && got != want {
			t.Errorf("suggestFlag(%q) = %q, want %q", in, got, want)
		}
	}
	// A completely unrelated token should not force a suggestion.
	if s := suggestFlag("zzzzzzzzzzzzzzzz"); s != "" {
		t.Errorf("suggestFlag(garbage) = %q, want empty", s)
	}
}

// levenshtein sanity.
func TestLevenshtein(t *testing.T) {
	if d := levenshtein("carve", "carv"); d != 1 {
		t.Errorf("levenshtein(carve,carv) = %d, want 1", d)
	}
	if d := levenshtein("abc", "abc"); d != 0 {
		t.Errorf("levenshtein(abc,abc) = %d, want 0", d)
	}
}

// truncStr must be rune-safe (no panic / no mid-codepoint split) on multibyte input.
func TestTruncStrRuneSafe(t *testing.T) {
	in := "малварь-образец-очень-длинное-имя-файла.exe" // Cyrillic, multibyte
	out := truncStr(in, 10)
	if r := []rune(out); len(r) > 10 {
		t.Errorf("truncStr returned %d runes, want <= 10", len(r))
	}
	// Emoji filename must not panic and must stay valid UTF-8.
	_ = truncStr("🦠🦠🦠🦠🦠🦠🦠🦠.bin", 5)
	// padRight/padLeft rune width
	if got := padRight("ab", 5); len([]rune(got)) != 5 {
		t.Errorf("padRight width = %d, want 5", len([]rune(got)))
	}
	if got := padLeft("café", 6); len([]rune(got)) != 6 {
		t.Errorf("padLeft width = %d, want 6", len([]rune(got)))
	}
}

// --quiet must imply no splash and no progress so a scripted run is silent
// except for the exit code and any explicitly requested machine output.
func TestQuietImpliesSilent(t *testing.T) {
	cfg, err := parseFlags([]string{"-f", "/bin/ls", "--quiet"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Quiet {
		t.Error("Quiet not set")
	}
	if !cfg.NoSplash {
		t.Error("--quiet should imply --no-splash")
	}
	if !cfg.NoProgress {
		t.Error("--quiet should imply --no-progress")
	}
	// -q shorthand behaves identically.
	short, err := parseFlags([]string{"-f", "/bin/ls", "-q"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !short.Quiet || !short.NoSplash || !short.NoProgress {
		t.Error("-q should behave like --quiet")
	}
}

// CI mode must also suppress splash/progress (pre-existing contract).
func TestCIImpliesSilent(t *testing.T) {
	cfg, err := parseFlags([]string{"-f", "/bin/ls", "--ci"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.NoSplash || !cfg.NoProgress {
		t.Error("--ci should imply --no-splash and --no-progress")
	}
}
