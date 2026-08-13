package main

import "testing"

func TestNamedFamilyRequiresCorroboration(t *testing.T) {
	// Family name alone (e.g. as it would appear in an AV report) is one group —
	// below MinGroups — so no confident named attribution.
	if m := matchNamedFamilies("this report mentions redline somewhere"); len(m) != 0 {
		t.Fatalf("name-only should not attribute a family, got: %#v", m)
	}
}

func TestNamedFamilyFiresWithSignals(t *testing.T) {
	corpus := "redline\nscanbrowsers\nscannedwallets\ngeoplugin.net"
	m := matchNamedFamilies(corpus)
	if len(m) == 0 || m[0].Family != "RedLine Stealer" {
		t.Fatalf("expected RedLine attribution, got: %#v", m)
	}
	if m[0].Score < 89 {
		t.Errorf("named family should outrank generic buckets, score=%d", m[0].Score)
	}
}

func TestNamedFamilyAsyncRAT(t *testing.T) {
	corpus := "asyncrat\nserver certificate\npastebin.com\nsendinfo"
	m := matchNamedFamilies(corpus)
	found := false
	for _, fm := range m {
		if fm.Family == "AsyncRAT" {
			found = true
			if fm.Confidence != "High" {
				t.Errorf("3 groups should be High confidence, got %s", fm.Confidence)
			}
		}
	}
	if !found {
		t.Fatalf("expected AsyncRAT attribution, got: %#v", m)
	}
}

func TestNamedFamilyOutranksGeneric(t *testing.T) {
	result := &ScanResult{
		IOCs: IOCSet{URLs: []string{"http://c2.example.com"}},
		Findings: []Finding{
			{Category: "Credential Access", Title: "x"},
			{Category: "Exfiltration", Title: "y"},
		},
	}
	corpus := "redline\nscanbrowsers\ngeoplugin.net\nlogin data"
	ClassifyMalwareFamiliesWithCorpus(result, nil, corpus)
	if len(result.FamilyMatches) == 0 || result.FamilyMatches[0].Family != "RedLine Stealer" {
		t.Fatalf("RedLine should be the headline family, got: %#v", result.FamilyMatches)
	}
}

// TestNamedFamilyRequiresNameAnchor locks the rule that generic behavior never
// produces a named attribution. The corpus below carries Agent Tesla's "exfil"
// and "capture" corroborating groups but never mentions Agent Tesla. Before the
// anchor was made mandatory this returned a Medium-High "Agent Tesla" match on
// evidence ["capture","exfil"], which mis-attributed unrelated samples — a 2001
// mass-mailer worm among them — to a 2014 stealer.
func TestNamedFamilyRequiresNameAnchor(t *testing.T) {
	corpus := "mailmessage\nspecialfolder\ngetasynckeystate\nkeylog\nvault\ncredentials"
	for _, m := range matchNamedFamilies(corpus) {
		if m.Family == "Agent Tesla" {
			t.Fatalf("named a family with no name evidence in corpus: %#v", m)
		}
	}
}

// TestNamedFamilyAnchorPlusOneGroup confirms the anchor did not raise the bar:
// name plus a single corroborating group still attributes, as it did before.
func TestNamedFamilyAnchorPlusOneGroup(t *testing.T) {
	m := matchNamedFamilies("agenttesla\nmailmessage")
	found := false
	for _, fm := range m {
		if fm.Family == "Agent Tesla" {
			found = true
			if !containsString(fm.Evidence, "name") {
				t.Errorf("evidence should record the name anchor, got %v", fm.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("expected Agent Tesla attribution, got: %#v", m)
	}
}

// TestGenericRansomwareIgnoresGoRuntimeLocked pins the substring collision that
// labelled every Go-compiled binary "Generic ransomware" at High confidence:
// ".locked" is a substring of the Go runtime symbol "exithook.locked".
func TestGenericRansomwareIgnoresGoRuntimeLocked(t *testing.T) {
	result := &ScanResult{}
	corpus := "internal/runtime/exithook.locked\nmp.lockedInt\nruntime.main"
	ClassifyMalwareFamiliesWithCorpus(result, nil, corpus)
	for _, m := range result.FamilyMatches {
		if m.Category == "ransomware" {
			t.Fatalf("Go runtime symbols must not read as ransomware, got: %#v", m)
		}
	}
}

// TestGenericRansomwareStillFiresOnNote keeps the true positive: an actual
// ransom note is specific enough to attribute on its own.
func TestGenericRansomwareStillFiresOnNote(t *testing.T) {
	result := &ScanResult{}
	ClassifyMalwareFamiliesWithCorpus(result, nil, "all your files have been encrypted\n.locked")
	found := false
	for _, m := range result.FamilyMatches {
		if m.Family == "Generic ransomware" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ransom note should attribute ransomware, got: %#v", result.FamilyMatches)
	}
}
