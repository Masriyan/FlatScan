package main

import "testing"

// The canonical v3 example: a lone generic credential string must NOT yield a
// high-confidence Credential Access finding, but the full multi-signal cluster
// must.

func TestCorrelationSingleStringDoesNotFire(t *testing.T) {
	result := &ScanResult{}
	// Only a credential-store token, nothing corroborating.
	RunCorrelationClusters(result, "the sam file is referenced here\nlsass\n")
	if hasFindingTitle(result.Findings, "OS credential dumping") {
		t.Fatalf("credential dumping must not fire on store tokens alone: %s", findingTitles(result))
	}
}

func TestCorrelationClusterFiresWithCorroboration(t *testing.T) {
	result := &ScanResult{}
	corpus := "sam lsass minidumpwritedump openprocess readprocessmemory comsvcs.dll"
	RunCorrelationClusters(result, corpus)

	var cred *Finding
	for i := range result.Findings {
		if result.Findings[i].Title == "OS credential dumping" {
			cred = &result.Findings[i]
		}
	}
	if cred == nil {
		t.Fatalf("expected OS credential dumping finding, got: %s", findingTitles(result))
	}
	if cred.EvidenceCount < 3 {
		t.Errorf("expected >=3 evidence groups, got %d", cred.EvidenceCount)
	}
	if cred.Confidence < 80 {
		t.Errorf("expected high confidence with full corroboration, got %d", cred.Confidence)
	}
}

func TestCorrelationBrowserTheft(t *testing.T) {
	result := &ScanResult{}
	corpus := "login data\nlocal state\nencrypted_key\ncryptunprotectdata"
	RunCorrelationClusters(result, corpus)
	if !hasFindingTitle(result.Findings, "Browser credential theft") {
		t.Fatalf("expected browser credential theft, got: %s", findingTitles(result))
	}
}

func TestDefaultSeverityConfidencePopulated(t *testing.T) {
	result := &ScanResult{}
	AddFinding(result, "High", "Test", "x", "y", 10, 0)
	if len(result.Findings) != 1 || result.Findings[0].Confidence == 0 {
		t.Fatalf("AddFinding should populate a default confidence: %#v", result.Findings)
	}
	if result.Findings[0].EvidenceCount != 1 {
		t.Errorf("default evidence count should be 1, got %d", result.Findings[0].EvidenceCount)
	}
}
