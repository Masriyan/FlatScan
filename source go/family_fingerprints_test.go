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
