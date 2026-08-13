package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This file is the automated proof behind the "False-Positive Guard" claim.
//
// The guard exists because FlatScan's detection is substring-based over a
// file's string corpus, which means any file that *catalogues* malware
// indicators — a rule pack, an AV signature set, an incident report, FlatScan's
// own binary — matches everything and lands at "Likely malicious". The guard
// recognizes breadth (many mutually-exclusive archetypes at once) and caps the
// score.
//
// The risk it introduces is the mirror image: a guard that fires too eagerly
// silently downgrades real malware to "Low suspicion". Both directions are
// therefore pinned below, because a regression in either one is invisible
// without a test — the tool still runs, still reports, and is simply wrong.
//
// Fixtures are synthetic string corpora, never live malware. Each is the string
// corpus a sample of that class would realistically yield; the guard consumes
// only the lowercased corpus, so this exercises exactly what production calls.

// corpusOf lowercases and joins fixture lines the same way the scanner does
// before calling AssessResearchArtifact.
func corpusOf(lines ...string) string {
	return strings.ToLower(strings.Join(lines, "\n"))
}

// --- Fixture corpora -------------------------------------------------------

// Real malware: focused samples. Each stays within one archetype, which is what
// distinguishes a specimen from a catalog.
var (
	// An Android loader: dynamic dex loading plus C2, no other archetype.
	fixtureAPKLoader = corpusOf(
		"dalvik.system.dexclassloader",
		"dalvik.system.pathclassloader",
		"getdeclaredmethod",
		"android.permission.request_install_packages",
		"http://45.66.230.101/api/gate.php",
		"classes.dex",
	)

	// An infostealer exfiltrating over a Discord webhook. One archetype
	// (discord-stealer) plus browser-credential paths.
	fixtureDiscordStealer = corpusOf(
		"https://discord.com/api/webhooks/998877/abcdef",
		`\appdata\local\google\chrome\user data\default\login data`,
		"select origin_url, username_value, password_value from logins",
		"crypt32.dll",
		"cryptunprotectdata",
	)

	// A generic credential stealer: browser DBs and wallet paths, no webhook.
	fixtureBrowserStealer = corpusOf(
		`\appdata\roaming\mozilla\firefox\profiles`,
		"key4.db", "logins.json", "cookies.sqlite",
		`\appdata\roaming\exodus\exodus.wallet`,
		"ftp://194.5.53.12/upload",
	)

	// Packed .NET loader: reflection plus in-memory decrypt/decompress.
	fixturePackedDotNet = corpusOf(
		"system.reflection", "appdomain", "activator", "createinstance",
		"getmethod", "invoke",
		"rijndaelmanaged", "cryptostream", "deflatestream", "frombase64string",
	)

	// Banking trojan: injection chain plus targeted institution strings.
	fixtureBanker = corpusOf(
		"createremotethread", "virtualallocex", "writeprocessmemory",
		"setwindowshookexw", "getasynckeystate",
		"login.bank-example.com", "onlinebanking", "otp code",
	)

	// Ransomware: a single archetype, deliberately including the vssadmin line
	// that overlaps the wiper archetype — real ransomware genuinely does delete
	// shadow copies, so this is the realistic worst case for a false cap.
	fixtureRansomware = corpusOf(
		"your files have been encrypted",
		"vssadmin delete shadows /all /quiet",
		"readme_restore_files.txt",
		"bitcoin", "tor browser",
	)
)

// Detection/analysis artifacts: catalogs that legitimately describe many
// unrelated archetypes at once.
var (
	// A YARA/Sigma rule pack describing six archetypes plus tooling vocabulary.
	fixtureRulePack = corpusOf(
		"yara rule ransomware_generic",
		"your files have been encrypted",
		"stratum+tcp://pool.minexmr.com:4444",
		"xmrig",
		"vssadmin delete shadows",
		"sekurlsa::logonpasswords",
		"mimikatz",
		"https://discord.com/api/webhooks/",
		"eval($_post[",
		"mitre att&ck",
		"sigma rule",
		"detection rule",
		"t1055 t1486 t1003 t1059 t1547 t1027 t1105 t1112",
	)

	// An incident-response report: prose about many archetypes, tool markers,
	// and a dense set of MITRE technique references.
	fixtureIRReport = corpusOf(
		"incident response report",
		"malware analysis summary",
		"indicator of compromise",
		"virustotal",
		"the ransomware displayed 'your files have been encrypted'",
		"the miner connected to stratum+tcp",
		"credential theft via sekurlsa",
		"exfiltration to discord.com/api/webhooks",
		"webshell dropped containing eval($_get",
		"t1486 t1003 t1055 t1059 t1105 t1027 t1547 t1112 t1071",
	)
)

// --- Corpus regression table ----------------------------------------------

// verdictBand is the coarse band a sample must land in. Exact scores are
// deliberately not asserted: they move with rule tuning, whereas a band flip is
// always an analyst-visible regression.
type verdictBand string

const (
	bandMalicious  verdictBand = "malicious"  // >= 80
	bandHigh       verdictBand = "high"       // 55-79
	bandSuspicious verdictBand = "suspicious" // 30-54
	bandLow        verdictBand = "low"        // < 30, where the artifact cap lands
)

func bandOf(score int) verdictBand {
	switch {
	case score >= 80:
		return bandMalicious
	case score >= 55:
		return bandHigh
	case score >= 30:
		return bandSuspicious
	default:
		return bandLow
	}
}

// TestFalsePositiveGuardCorpus is the regression gate. Every case states the
// verdict band and guard decision a maintainer is committing to; a change that
// flips either fails loudly here rather than in an analyst's triage queue.
func TestFalsePositiveGuardCorpus(t *testing.T) {
	tests := []struct {
		name string
		// corpus is the sample's lowercased string corpus.
		corpus string
		// findings are the scored findings the detection stages would produce
		// for this sample, applied before the guard runs.
		findings []Finding
		// wantBenignContext is whether the FP guard should classify this file
		// as a catalog/analysis artifact.
		wantBenignContext bool
		// wantBand is the verdict band after FinalizeRisk.
		wantBand verdictBand
		why      string
	}{
		{
			name:   "apk_loader_stays_malicious",
			corpus: fixtureAPKLoader,
			findings: []Finding{
				{Severity: "Critical", Category: "Loader", Title: "Dynamic dex loading", Evidence: "DexClassLoader", Score: 35},
				{Severity: "High", Category: "C2", Title: "Hardcoded C2 endpoint", Evidence: "gate.php", Score: 22},
				{Severity: "High", Category: "Permissions", Title: "Requests package install", Evidence: "REQUEST_INSTALL_PACKAGES", Score: 22},
				{Severity: "Medium", Category: "Loader", Title: "Reflection", Evidence: "getDeclaredMethod", Score: 10},
			},
			wantBenignContext: false,
			wantBand:          bandMalicious,
			why:               "single-archetype Android loader; the guard must not touch it",
		},
		{
			name:   "discord_stealer_stays_malicious",
			corpus: fixtureDiscordStealer,
			findings: []Finding{
				{Severity: "Critical", Category: "Exfiltration", Title: "Discord webhook exfil", Evidence: "discord.com/api/webhooks", Score: 35},
				{Severity: "High", Category: "Credential Access", Title: "Chrome login data access", Evidence: "Login Data", Score: 22},
				{Severity: "High", Category: "Credential Access", Title: "DPAPI secret decryption", Evidence: "CryptUnprotectData", Score: 22},
				{Severity: "High", Category: "Credential Access", Title: "Credential store SQL query", Evidence: "select origin_url, username_value, password_value from logins", Score: 22},
			},
			wantBenignContext: false,
			wantBand:          bandMalicious,
			why:               "one archetype (discord-stealer); breadth test must not trip",
		},
		{
			name:   "browser_stealer_stays_malicious",
			corpus: fixtureBrowserStealer,
			findings: []Finding{
				{Severity: "Critical", Category: "Credential Access", Title: "Browser credential store access", Evidence: "key4.db", Score: 35},
				{Severity: "High", Category: "Credential Access", Title: "Crypto wallet theft", Evidence: "exodus.wallet", Score: 22},
				{Severity: "High", Category: "Exfiltration", Title: "Hardcoded FTP upload", Evidence: "ftp://194.5.53.12", Score: 22},
				{Severity: "High", Category: "Credential Access", Title: "Cookie database access", Evidence: "cookies.sqlite", Score: 22},
			},
			wantBenignContext: false,
			wantBand:          bandMalicious,
			why:               "zero archetype headline phrases; guard cannot fire",
		},
		{
			name:   "packed_dotnet_stays_malicious",
			corpus: fixturePackedDotNet,
			findings: []Finding{
				{Severity: "Critical", Category: "Loader", Title: "Reflective assembly loading", Evidence: "Assembly.Load", Score: 35},
				{Severity: "High", Category: "Obfuscation", Title: "In-memory decryption", Evidence: "RijndaelManaged+CryptoStream", Score: 22},
				{Severity: "High", Category: "Obfuscation", Title: "Compressed payload", Evidence: "DeflateStream", Score: 22},
				{Severity: "High", Category: "Loader", Title: "Dynamic method invocation", Evidence: "GetMethod+Invoke", Score: 22},
			},
			wantBenignContext: false,
			wantBand:          bandMalicious,
			why:               "packer/loader vocabulary carries no archetype headlines",
		},
		{
			name:   "banker_stays_malicious",
			corpus: fixtureBanker,
			findings: []Finding{
				{Severity: "Critical", Category: "Injection", Title: "Remote process injection", Evidence: "CreateRemoteThread", Score: 35},
				{Severity: "High", Category: "Collection", Title: "Keylogging", Evidence: "SetWindowsHookExW", Score: 22},
				{Severity: "High", Category: "Targeting", Title: "Banking institution strings", Evidence: "onlinebanking", Score: 22},
				{Severity: "High", Category: "Injection", Title: "Remote memory allocation", Evidence: "VirtualAllocEx+WriteProcessMemory", Score: 22},
			},
			wantBenignContext: false,
			wantBand:          bandMalicious,
			why:               "injection chain, no archetype breadth",
		},
		{
			name:   "ransomware_with_shadow_deletion_stays_malicious",
			corpus: fixtureRansomware,
			findings: []Finding{
				{Severity: "Critical", Category: "Ransomware", Title: "Ransom note", Evidence: "your files have been encrypted", Score: 35},
				{Severity: "Critical", Category: "Ransomware", Title: "Shadow copy deletion", Evidence: "vssadmin delete shadows", Score: 35},
				{Severity: "High", Category: "Ransomware", Title: "Ransom payment instructions", Evidence: "bitcoin/tor", Score: 22},
			},
			wantBenignContext: false,
			wantBand:          bandMalicious,
			why: "overlaps two archetypes (ransomware+wiper) because real ransomware deletes " +
				"shadow copies — must stay below the >=4 breadth threshold",
		},
		{
			name:   "rule_pack_capped_to_low",
			corpus: fixtureRulePack,
			findings: []Finding{
				{Severity: "Critical", Category: "Ransomware", Title: "Ransom note strings", Evidence: "encrypted", Score: 35},
				{Severity: "Critical", Category: "Cryptominer", Title: "Mining pool", Evidence: "stratum+tcp", Score: 35},
				{Severity: "Critical", Category: "Credential Access", Title: "Mimikatz strings", Evidence: "sekurlsa", Score: 35},
				{Severity: "High", Category: "Webshell", Title: "PHP webshell", Evidence: "eval($_POST", Score: 22},
			},
			wantBenignContext: true,
			wantBand:          bandLow,
			why:               "six mutually-exclusive archetypes plus tool markers — a catalog, not a specimen",
		},
		{
			name:   "ir_report_capped_to_low",
			corpus: fixtureIRReport,
			findings: []Finding{
				{Severity: "Critical", Category: "Ransomware", Title: "Ransom note strings", Evidence: "encrypted", Score: 35},
				{Severity: "Critical", Category: "Cryptominer", Title: "Mining pool", Evidence: "stratum", Score: 35},
				{Severity: "High", Category: "Credential Access", Title: "Credential dumper", Evidence: "sekurlsa", Score: 22},
			},
			wantBenignContext: true,
			wantBand:          bandLow,
			why:               "analysis prose describing many archetypes plus dense MITRE references",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ScanResult{}
			t.Cleanup(func() { releaseFindingIndex(result) })
			for _, f := range tt.findings {
				addFindingStruct(result, f)
			}

			AssessResearchArtifact(result, tt.corpus)
			gotBenign := result.BenignContext != nil
			if gotBenign != tt.wantBenignContext {
				t.Fatalf("BenignContext = %v, want %v (%s)\nguard detail: %+v",
					gotBenign, tt.wantBenignContext, tt.why, result.BenignContext)
			}

			FinalizeRisk(result)
			if got := bandOf(result.RiskScore); got != tt.wantBand {
				t.Fatalf("verdict band = %q (score %d, verdict %q), want %q (%s)",
					got, result.RiskScore, result.Verdict, tt.wantBand, tt.why)
			}

			if tt.wantBenignContext {
				if result.RiskScore > researchArtifactScoreCap {
					t.Fatalf("artifact score %d exceeds cap %d", result.RiskScore, researchArtifactScoreCap)
				}
				if result.BenignContext.OriginalScore <= researchArtifactScoreCap {
					t.Fatalf("OriginalScore = %d, want > cap %d — the pre-cap score must be preserved for transparency",
						result.BenignContext.OriginalScore, researchArtifactScoreCap)
				}
				if !strings.Contains(result.Verdict, "security tool") {
					t.Fatalf("verdict %q must disclose the artifact context", result.Verdict)
				}
			}
		})
	}
}

// TestFalsePositiveGuardOwnBinary is the documented self-test: FlatScan's own
// binary catalogues every indicator it detects, so scanning it must produce the
// artifact cap rather than "Likely malicious". This is the case most likely to
// be demonstrated live at a booth.
//
// It builds the binary rather than depending on a committed one (the repo
// deliberately ships no build artifacts).
func TestFalsePositiveGuardOwnBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping self-scan build in -short mode")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable")
	}

	bin := filepath.Join(t.TempDir(), "flatscan-selftest")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building self-scan target failed: %v\n%s", err, out)
	}

	// Build the config through parseFlags rather than by hand: the analysis
	// budgets (MaxAnalyzeBytes, MinStringLen, ...) come from there, and a
	// zero-valued budget silently reads zero bytes and scores everything 0.
	cfg, err := parseFlags([]string{"-m", "standard", "-f", bin})
	if err != nil {
		t.Fatalf("parseFlags() error = %v", err)
	}
	cfg.NoProgress = true
	cfg.NoSplash = true
	cfg.Quiet = true
	cfg.NoColor = true
	result, err := ScanFile(cfg, NewProgress(false, os.Stderr))
	if err != nil {
		t.Fatalf("ScanFile(own binary) error = %v", err)
	}

	if result.BenignContext == nil {
		t.Fatalf("FlatScan's own binary was not recognized as an analysis artifact "+
			"(score %d, verdict %q) — the false-positive guard has regressed",
			result.RiskScore, result.Verdict)
	}
	if result.RiskScore > researchArtifactScoreCap {
		t.Fatalf("own binary scored %d, above the artifact cap %d (verdict %q)",
			result.RiskScore, researchArtifactScoreCap, result.Verdict)
	}
}

// --- Unit tests for the guard's decision boundary ---------------------------

// TestAssessResearchArtifactThresholds pins the documented rule: fire at >=4
// archetypes, or at >=3 when backed by explicit security-tooling vocabulary.
// These boundaries are the guard's entire precision/recall tradeoff.
func TestAssessResearchArtifactThresholds(t *testing.T) {
	tests := []struct {
		name   string
		corpus string
		want   bool
	}{
		{
			name:   "three archetypes without tool markers does not fire",
			corpus: corpusOf("your files have been encrypted", "xmrig", "mimikatz"),
			want:   false,
		},
		{
			name: "three archetypes with two tool markers fires",
			corpus: corpusOf("your files have been encrypted", "xmrig", "mimikatz",
				"yara rule", "mitre"),
			want: true,
		},
		{
			name: "three archetypes with eight mitre refs fires",
			corpus: corpusOf("your files have been encrypted", "xmrig", "mimikatz",
				"t1055 t1486 t1003 t1059 t1547 t1027 t1105 t1112"),
			want: true,
		},
		{
			name: "four archetypes fires with no tool vocabulary at all",
			corpus: corpusOf("your files have been encrypted", "xmrig", "mimikatz",
				"discord.com/api/webhooks"),
			want: true,
		},
		{
			name:   "two archetypes never fires regardless of tool markers",
			corpus: corpusOf("your files have been encrypted", "xmrig", "yara rule", "mitre att&ck", "virustotal"),
			want:   false,
		},
		{
			name:   "empty corpus does not fire",
			corpus: "",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ScanResult{}
			t.Cleanup(func() { releaseFindingIndex(result) })
			AssessResearchArtifact(result, tt.corpus)
			if got := result.BenignContext != nil; got != tt.want {
				t.Fatalf("BenignContext set = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestAssessResearchArtifactNilResult confirms the guard tolerates a nil result
// rather than panicking — it runs inside the scan pipeline that A1 hardened.
func TestAssessResearchArtifactNilResult(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("AssessResearchArtifact(nil) panicked: %v", r)
		}
	}()
	AssessResearchArtifact(nil, fixtureRulePack)
}

// TestAssessResearchArtifactReasonIsActionable checks the disclosure an analyst
// reads when a score is capped. A cap without a stated reason is worse than no
// cap: the score is suppressed and nothing explains why.
func TestAssessResearchArtifactReasonIsActionable(t *testing.T) {
	result := &ScanResult{}
	t.Cleanup(func() { releaseFindingIndex(result) })
	AssessResearchArtifact(result, fixtureRulePack)

	if result.BenignContext == nil {
		t.Fatal("expected the rule-pack fixture to trip the guard")
	}
	bc := result.BenignContext

	if len(bc.Archetypes) < 4 {
		t.Fatalf("Archetypes = %v, want >= 4 recorded", bc.Archetypes)
	}
	if len(bc.ToolMarkers) == 0 {
		t.Fatal("ToolMarkers is empty; the evidence behind the cap must be recorded")
	}
	if bc.ScoreCap != researchArtifactScoreCap {
		t.Fatalf("ScoreCap = %d, want %d", bc.ScoreCap, researchArtifactScoreCap)
	}
	for _, want := range []string{"archetypes", "rather than a live specimen"} {
		if !strings.Contains(bc.Reason, want) {
			t.Fatalf("Reason %q missing %q", bc.Reason, want)
		}
	}

	// The cap must also surface as a finding, so it appears in the report rather
	// than only in JSON.
	var found bool
	for _, f := range result.Findings {
		if strings.Contains(f.Title, "security tool") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no Context finding recorded; the capped verdict would be unexplained in the report")
	}
}
