package main

// Named malware-family fingerprints (improvementprompt-v3 Task 3).
//
// family.go previously emitted only generic buckets ("Information stealer",
// "Remote access trojan"). This adds fingerprints for the commodity families
// that dominate triage queues. Each fingerprint is a multi-signal evidence
// cluster (reusing clusterGroup): the family-name anchor plus corroborating
// behavior/config groups. A named attribution requires the anchor AND at least
// MinGroups corroborating groups, so a lone family-name string (e.g. inside an
// AV report) does not by itself produce a confident named verdict, and generic
// behavior without the name never yields a named verdict at all. The
// research-artifact guard (falsepositive.go) additionally withdraws named
// attribution entirely for signature sets, rule packs and analysis tools, whose
// corpora quote every family name by design.

// familyFingerprint names a specific malware family. Attribution requires two
// things: the Anchor group (family-name markers) MUST match, and at least
// MinGroups of the corroborating Groups must match alongside it.
//
// The anchor is mandatory by construction rather than by convention. An earlier
// version kept the name markers as just another entry in Groups and required
// any MinGroups of them, which let a family be named with no trace of its name
// in the sample at all: "Agent Tesla" fired on any file carrying generic
// "credentials"/"keylog" and "specialfolder"/"mailmessage" strings, which
// mis-attributed a 2001 mass-mailer worm to a 2014 stealer. Requiring the
// anchor keeps the corroboration rule (a bare name string is still not enough)
// while making it impossible to name a family on generic behavior alone.
type familyFingerprint struct {
	Family   string
	Category string
	// Anchor holds the family-name markers. Necessary but not sufficient.
	Anchor clusterGroup
	// Groups hold corroborating evidence clusters.
	Groups []clusterGroup
	// MinGroups is how many corroborating Groups must match in addition to Anchor.
	MinGroups int
}

var familyFingerprints = []familyFingerprint{
	{
		Family: "RedLine Stealer", Category: "stealer", MinGroups: 1,
		Anchor: clusterGroup{"name", []string{"redline"}},
		Groups: []clusterGroup{
			{"scanner", []string{"scanbrowsers", "scannedwallets", "scanfiles", "scanftp", "scanscreen", "getantivirus", "scanchromebrowserspaths"}},
			{"telemetry", []string{"geoplugin.net", "ipinfo.io", "api.ip.sb", "<hwid>", "<machinename>"}},
		},
	},
	{
		Family: "LummaC2 Stealer", Category: "stealer", MinGroups: 1,
		Anchor: clusterGroup{"name", []string{"lummac2", "lumma stealer", "lummac"}},
		Groups: []clusterGroup{
			{"c2", []string{"lid=", "act=life", "/c2sock", "/c2conf", "act=recv_message"}},
			{"libs", []string{"mozglue.dll", "freebl3.dll", "softokn3.dll", "nss3.dll"}},
		},
	},
	{
		Family: "StealC", Category: "stealer", MinGroups: 1,
		Anchor: clusterGroup{"name", []string{"stealc"}},
		Groups: []clusterGroup{
			{"c2", []string{"/c2conf", "block_size=", "fast_init", "screen.jpeg"}},
			{"loot", []string{"browser_extensions", "discord_tokens", "telegram", "outlook"}},
		},
	},
	{
		Family: "Agent Tesla", Category: "stealer", MinGroups: 1,
		Anchor: clusterGroup{"name", []string{"agenttesla", "agent tesla"}},
		Groups: []clusterGroup{
			{"exfil", []string{"smtpclient", "mailmessage", "ftpwebrequest", "api.telegram.org/bot", "specialfolder"}},
			{"capture", []string{"getasynckeystate", "keylog", "vault", "credentials"}},
		},
	},
	{
		Family: "AsyncRAT", Category: "rat", MinGroups: 1,
		Anchor: clusterGroup{"name", []string{"asyncrat", "async rat"}},
		Groups: []clusterGroup{
			{"config", []string{"server certificate", "aes_256", "pastebin.com", "do_uac"}},
			{"ops", []string{"sendinfo", "do_process", "plugin", "anti-vm", "limelogger"}},
		},
	},
	{
		Family: "Quasar RAT", Category: "rat", MinGroups: 1,
		Anchor: clusterGroup{"name", []string{"quasar", "quasarrat", "quasar.common"}},
		Groups: []clusterGroup{
			{"protocol", []string{"doclientreconnect", "getkeyloggerlogsresponse", "getconnectionsresponse", "server certificate"}},
			{"ops", []string{"reverse proxy", "remote desktop", "keylogger"}},
		},
	},
	{
		Family: "Remcos RAT", Category: "rat", MinGroups: 1,
		Anchor: clusterGroup{"name", []string{"remcos"}},
		Groups: []clusterGroup{
			{"author", []string{"breaking-security", "rmc-", "remcos_mutex_inj", "remcos restart"}},
			{"ops", []string{"keylogger", "screenshot", "watchdog", "offline keylogger"}},
		},
	},
	{
		Family: "XWorm", Category: "rat", MinGroups: 1,
		Anchor: clusterGroup{"name", []string{"xworm"}},
		Groups: []clusterGroup{
			{"client", []string{"xclient", "xlogger", "runpe"}},
			{"ops", []string{"ddos", "pcoption", "plugin", "telegram"}},
		},
	},
	{
		Family: "njRAT", Category: "rat", MinGroups: 1,
		Anchor: clusterGroup{"name", []string{"njrat", "bladabindi", "njq8", "njw0rm"}},
		Groups: []clusterGroup{
			{"commands", []string{"netsh firewall", "cmd.exe /c ping", "[endof]", "fudpk"}},
			{"ops", []string{"keylogger", "kl|'|'|", "screenshot"}},
		},
	},
	{
		Family: "Vidar Stealer", Category: "stealer", MinGroups: 1,
		Anchor: clusterGroup{"name", []string{"vidar"}},
		Groups: []clusterGroup{
			{"deaddrop", []string{"steamcommunity.com/profiles", "t.me/", "telegram", "/profile"}},
			{"libs", []string{"freebl3.dll", "softokn3.dll", "sqlite3.dll", "vcruntime140.dll"}},
		},
	},
	{
		Family: "Raccoon/RecordBreaker", Category: "stealer", MinGroups: 1,
		Anchor: clusterGroup{"name", []string{"raccoon", "recordbreaker", "recordstealer"}},
		Groups: []clusterGroup{
			{"libs", []string{"libsqlite", "libcrypto", "libssl", "libwinpthread", "nss3.dll"}},
			{"loot", []string{"machineid", "telegram", "wallets", "/gate"}},
		},
	},
	{
		Family: "FormBook/XLoader", Category: "stealer", MinGroups: 1,
		Anchor: clusterGroup{"name", []string{"formbook", "xloader"}},
		Groups: []clusterGroup{
			{"ops", []string{"explorer.exe", "wininet.dll", "ws2_32.dll", "encrypted strings"}},
			{"inject", []string{"process hollow", "ntmapviewofsection", "zwwritevirtualmemory"}},
		},
	},
}

// matchNamedFamilies returns FamilyMatches for every fingerprint whose anchor
// (family-name markers) is present in the corpus together with at least
// MinGroups corroborating evidence groups. Named matches are scored above the
// generic family buckets so the headline hypothesis is the specific family when
// one is identified.
func matchNamedFamilies(corpus string) []FamilyMatch {
	if corpus == "" {
		return nil
	}
	var out []FamilyMatch
	for _, fp := range familyFingerprints {
		// The anchor gates everything: without the family name somewhere in the
		// corpus there is no evidence tying this sample to this family, only
		// evidence that it behaves like the family's category. Generic buckets
		// in family.go already cover that case, and they say so honestly.
		if !hasAny(corpus, fp.Anchor.Tokens...) {
			continue
		}
		matched := 0
		var ev []string
		for _, g := range fp.Groups {
			if hasAny(corpus, g.Tokens...) {
				matched++
				ev = append(ev, g.Label)
			}
		}
		if matched < fp.MinGroups {
			continue
		}
		ev = append(ev, fp.Anchor.Label)
		// Named families outrank generic buckets (88/90): base 89, +3 per extra
		// corroborating group, capped at 97.
		score := clampInt(89+(matched-fp.MinGroups)*3, 0, 97)
		confidence := "Medium-High"
		if matched > fp.MinGroups {
			confidence = "High"
		}
		out = append(out, FamilyMatch{
			Family:     fp.Family,
			Category:   fp.Category,
			Confidence: confidence,
			Score:      score,
			Evidence:   uniqueSorted(append(ev, "named-family fingerprint")),
		})
	}
	return out
}
