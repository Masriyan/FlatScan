package main

import "testing"

// TestHasAnyWordBoundaries pins the whole-word semantics that keep short
// generic needles ("bot") from matching inside ordinary words ("both").
func TestHasAnyWordBoundaries(t *testing.T) {
	cases := []struct {
		name   string
		corpus string
		needle string
		want   bool
	}{
		{"standalone word", "telegram bot token\n", "bot", true},
		{"start of corpus", "bot\n", "bot", true},
		{"punctuation bounded", "http://c2.example/bot.php\n", "bot", true},
		{"inside both", "both files were compressed\n", "bot", false},
		{"inside bottom", "scroll to the bottom\n", "bot", false},
		{"inside about", "about this program\n", "bot", false},
		{"inside robot", "robots.txt\n", "bot", false},
		{"underscore is a word char", "bot_id=1\n", "bot", false},
		{"digit suffix is a word char", "bot2\n", "bot", false},
		{"absent", "nothing here\n", "bot", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasAnyWord(tc.corpus, tc.needle); got != tc.want {
				t.Fatalf("hasAnyWord(%q, %q) = %v, want %v", tc.corpus, tc.needle, got, tc.want)
			}
		})
	}
}

// TestPackerMarkerNoCompressFalsePositive is the regression guard for the
// packer rule: "compress"/"decompress" must not read as an MPRESS marker,
// while the genuine .mpress1/.mpress2 section names still must.
func TestPackerMarkerNoCompressFalsePositive(t *testing.T) {
	packerNeedles := []string{"upx0", "upx1", "upx!", ".aspack", "themida", "vmprotect", "enigma protector", ".mpress1", ".mpress2"}

	benign := "--compress-program\ndecompress\nuncompressed data\nboth\n"
	if hasAny(benign, packerNeedles...) {
		t.Errorf("benign compression strings matched a packer marker: %q", benign)
	}

	for _, packed := range []string{".mpress1\n", ".mpress2\n", "upx0\n", "themida\n"} {
		if !hasAny(packed, packerNeedles...) {
			t.Errorf("real packer marker %q was not detected", packed)
		}
	}
}

// TestC2NetworkNeedlesNoBenignMatch guards the C2 network-strings rule against
// the "both"/"bottom" substring match that flagged clean system binaries.
func TestC2NetworkNeedlesNoBenignMatch(t *testing.T) {
	substringNeedles := []string{"user-agent", "gate.php", "/api/", "telegram", "discord.com/api/webhooks", "botnet", "bot_id", "bot_token", "botid"}

	match := func(corpus string) bool {
		return hasAny(corpus, substringNeedles...) || hasAnyWord(corpus, "bot")
	}

	benign := []string{
		"both files listed\n",
		"scroll to the bottom\n",
		"ignoreboth\n",
		"_rl_vis_botlin\n",
	}
	for _, corpus := range benign {
		if match(corpus) {
			t.Errorf("benign corpus matched the C2 network rule: %q", corpus)
		}
	}

	malicious := []string{
		"telegram bot\n",
		"botnet controller\n",
		"bot_token=123\n",
		"http://evil/gate.php\n",
		"user-agent: mozilla\n",
	}
	for _, corpus := range malicious {
		if !match(corpus) {
			t.Errorf("malicious corpus failed to match the C2 network rule: %q", corpus)
		}
	}
}
