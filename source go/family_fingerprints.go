package main

// Named malware-family fingerprints (improvementprompt-v3 Task 3).
//
// family.go previously emitted only generic buckets ("Information stealer",
// "Remote access trojan"). This adds fingerprints for the commodity families
// that dominate triage queues. Each fingerprint is a multi-signal evidence
// cluster (reusing clusterGroup): the family-name marker plus corroborating
// behavior/config groups. A named attribution requires at least MinGroups
// distinct groups, so a lone family-name string (e.g. inside an AV report) does
// not by itself produce a confident named verdict — and the research-artifact
// guard (falsepositive.go) still caps catalog files.

type familyFingerprint struct {
	Family    string
	Category  string
	Groups    []clusterGroup
	MinGroups int
}

var familyFingerprints = []familyFingerprint{
	{
		Family: "RedLine Stealer", Category: "stealer", MinGroups: 2,
		Groups: []clusterGroup{
			{"name", []string{"redline"}},
			{"scanner", []string{"scanbrowsers", "scannedwallets", "scanfiles", "scanftp", "scanscreen", "getantivirus", "scanchromebrowserspaths"}},
			{"telemetry", []string{"geoplugin.net", "ipinfo.io", "api.ip.sb", "<hwid>", "<machinename>"}},
		},
	},
	{
		Family: "LummaC2 Stealer", Category: "stealer", MinGroups: 2,
		Groups: []clusterGroup{
			{"name", []string{"lummac2", "lumma stealer", "lummac"}},
			{"c2", []string{"lid=", "act=life", "/c2sock", "/c2conf", "act=recv_message"}},
			{"libs", []string{"mozglue.dll", "freebl3.dll", "softokn3.dll", "nss3.dll"}},
		},
	},
	{
		Family: "StealC", Category: "stealer", MinGroups: 2,
		Groups: []clusterGroup{
			{"name", []string{"stealc"}},
			{"c2", []string{"/c2conf", "block_size=", "fast_init", "screen.jpeg"}},
			{"loot", []string{"browser_extensions", "discord_tokens", "telegram", "outlook"}},
		},
	},
	{
		Family: "Agent Tesla", Category: "stealer", MinGroups: 2,
		Groups: []clusterGroup{
			{"name", []string{"agenttesla", "agent tesla"}},
			{"exfil", []string{"smtpclient", "mailmessage", "ftpwebrequest", "api.telegram.org/bot", "specialfolder"}},
			{"capture", []string{"getasynckeystate", "keylog", "vault", "credentials"}},
		},
	},
	{
		Family: "AsyncRAT", Category: "rat", MinGroups: 2,
		Groups: []clusterGroup{
			{"name", []string{"asyncrat", "async rat"}},
			{"config", []string{"server certificate", "aes_256", "pastebin.com", "do_uac"}},
			{"ops", []string{"sendinfo", "do_process", "plugin", "anti-vm", "limelogger"}},
		},
	},
	{
		Family: "Quasar RAT", Category: "rat", MinGroups: 2,
		Groups: []clusterGroup{
			{"name", []string{"quasar", "quasarrat", "quasar.common"}},
			{"protocol", []string{"doclientreconnect", "getkeyloggerlogsresponse", "getconnectionsresponse", "server certificate"}},
			{"ops", []string{"reverse proxy", "remote desktop", "keylogger"}},
		},
	},
	{
		Family: "Remcos RAT", Category: "rat", MinGroups: 2,
		Groups: []clusterGroup{
			{"name", []string{"remcos"}},
			{"author", []string{"breaking-security", "rmc-", "remcos_mutex_inj", "remcos restart"}},
			{"ops", []string{"keylogger", "screenshot", "watchdog", "offline keylogger"}},
		},
	},
	{
		Family: "XWorm", Category: "rat", MinGroups: 2,
		Groups: []clusterGroup{
			{"name", []string{"xworm"}},
			{"client", []string{"xclient", "xlogger", "runpe"}},
			{"ops", []string{"ddos", "pcoption", "plugin", "telegram"}},
		},
	},
	{
		Family: "njRAT", Category: "rat", MinGroups: 2,
		Groups: []clusterGroup{
			{"name", []string{"njrat", "bladabindi", "njq8", "njw0rm"}},
			{"commands", []string{"netsh firewall", "cmd.exe /c ping", "[endof]", "fudpk"}},
			{"ops", []string{"keylogger", "kl|'|'|", "screenshot"}},
		},
	},
	{
		Family: "Vidar Stealer", Category: "stealer", MinGroups: 2,
		Groups: []clusterGroup{
			{"name", []string{"vidar"}},
			{"deaddrop", []string{"steamcommunity.com/profiles", "t.me/", "telegram", "/profile"}},
			{"libs", []string{"freebl3.dll", "softokn3.dll", "sqlite3.dll", "vcruntime140.dll"}},
		},
	},
	{
		Family: "Raccoon/RecordBreaker", Category: "stealer", MinGroups: 2,
		Groups: []clusterGroup{
			{"name", []string{"raccoon", "recordbreaker", "recordstealer"}},
			{"libs", []string{"libsqlite", "libcrypto", "libssl", "libwinpthread", "nss3.dll"}},
			{"loot", []string{"machineid", "telegram", "wallets", "/gate"}},
		},
	},
	{
		Family: "FormBook/XLoader", Category: "stealer", MinGroups: 2,
		Groups: []clusterGroup{
			{"name", []string{"formbook", "xloader"}},
			{"ops", []string{"explorer.exe", "wininet.dll", "ws2_32.dll", "encrypted strings"}},
			{"inject", []string{"process hollow", "ntmapviewofsection", "zwwritevirtualmemory"}},
		},
	},
}

// matchNamedFamilies returns FamilyMatches for every fingerprint whose minimum
// number of evidence groups is present in the corpus. Named matches are scored
// above the generic family buckets so the headline hypothesis is the specific
// family when one is identified.
func matchNamedFamilies(corpus string) []FamilyMatch {
	if corpus == "" {
		return nil
	}
	var out []FamilyMatch
	for _, fp := range familyFingerprints {
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
