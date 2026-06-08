package main

import "testing"

func TestDGAScoreSeparatesBenignFromDGA(t *testing.T) {
	benign := []string{"google.com", "microsoft.com", "github.io", "cloudflare.net", "wikipedia.org"}
	dga := []string{"kq3v9zlx7w2p.com", "asdkfjqweoiru.net", "x7z2q9w1v8b3.top", "vhwqklmnzxcv.xyz"}

	maxBenign := 0.0
	for _, d := range benign {
		s, _ := dgaScore(d)
		if s >= dgaThreshold {
			t.Errorf("benign domain %q scored %.2f (>= threshold %.2f)", d, s, dgaThreshold)
		}
		if s > maxBenign {
			maxBenign = s
		}
	}

	minDGA := 1.0
	for _, d := range dga {
		s, reasons := dgaScore(d)
		if s < dgaThreshold {
			t.Errorf("DGA-style domain %q scored %.2f (< threshold %.2f); reasons=%v", d, s, dgaThreshold, reasons)
		}
		if s < minDGA {
			minDGA = s
		}
	}

	if maxBenign >= minDGA {
		t.Errorf("benign/DGA score ranges overlap: maxBenign=%.2f minDGA=%.2f", maxBenign, minDGA)
	}
}

func TestDGAScoreShortLabelIgnored(t *testing.T) {
	// Short labels are not enough signal; should never flag.
	for _, d := range []string{"ab.com", "x.io", "go.dev"} {
		if s, _ := dgaScore(d); s != 0 {
			t.Errorf("short label %q unexpectedly scored %.2f", d, s)
		}
	}
}

func TestAnalyzeDGADomainsRecordsFindings(t *testing.T) {
	result := &ScanResult{}
	result.IOCs.Domains = []string{"google.com", "kq3v9zlx7w2p.top"}
	AnalyzeDGADomains(result)

	if len(result.DGADomains) != 1 {
		t.Fatalf("expected exactly one DGA domain recorded, got %d (%v)", len(result.DGADomains), result.DGADomains)
	}
	if result.DGADomains[0].Domain != "kq3v9zlx7w2p.top" {
		t.Fatalf("unexpected DGA domain recorded: %q", result.DGADomains[0].Domain)
	}

	var found bool
	for _, f := range result.Findings {
		if f.Technique == "Dynamic Resolution: Domain Generation Algorithms (T1568.002)" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a T1568.002 DGA finding to be recorded")
	}
}
