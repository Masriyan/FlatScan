package main

import "testing"

func TestClassifyIOCValueCategories(t *testing.T) {
	cases := []struct {
		iocType string
		value   string
		want    string
	}{
		{"url", "https://discord.com/api/webhooks/123/abc", iocCatSuspInfra},
		{"url", "https://api.telegram.org/bot123:ABC/sendMessage", iocCatSuspInfra},
		{"url", "https://raw.githubusercontent.com/x/y/main/p.txt", iocCatSuspInfra},
		{"url", "http://schemas.microsoft.com/appx/manifest", iocCatBenignInfra},
		{"url", "http://evil.example.com/payload.exe", iocCatActionable},
		{"domain", "system.net", iocCatNamespace},
		{"domain", "androidx.work", iocCatNamespace},
		{"domain", "discord.com", iocCatBenignInfra},
		{"domain", "index.crates.io", iocCatBuildArtifact},        // Rust registry — build noise
		{"domain", "proxy.golang.org", iocCatBuildArtifact},       // Go module proxy
		{"domain", "openssl.org", iocCatBenignInfra},              // PKI/library artifact
		{"domain", "ocsp.digicert.com", iocCatBenignInfra},        // CA / PKI
		{"domain", "android.googlesource.com", iocCatBenignInfra}, // real domain, NOT a namespace
		{"domain", "android.app", iocCatNamespace},                // two-label namespace fragment
		{"domain", "microsoft.com", iocCatBenignInfra},            // company domain, NOT a namespace
		{"domain", "evil-c2.top", iocCatActionable},
		{"unix_path", "/root/.cargo/registry/src/index.crates.io/foo-1.2/src/lib.rs", iocCatSourcePath},
		{"windows_path", "C:\\Users\\dev\\source\\repos\\proj\\obj\\Release\\app.pdb", iocCatBuildArtifact},
		{"windows_path", "C:\\Windows\\System32\\evil.dll", iocCatActionable},
		{"crypto_wallet", "0x1234567890abcdef1234567890abcdef12345678", iocCatSuspInfra},
	}
	for _, tc := range cases {
		got := classifyIOCValue(tc.iocType, tc.value).Category
		if got != tc.want {
			t.Errorf("classify(%s, %q) = %q, want %q", tc.iocType, tc.value, got, tc.want)
		}
	}
}

func TestActionableIOCsDropsNoise(t *testing.T) {
	iocs := IOCSet{
		Domains:      []string{"evil-c2.top", "system.net", "discord.com"},
		URLs:         []string{"http://evil.example.com/p.exe", "http://schemas.microsoft.com/x"},
		UnixPaths:    []string{"/var/run/legit.sock", "/root/.cargo/registry/src/foo/lib.rs"},
		WindowsPaths: []string{"C:\\Temp\\dropper.exe", "C:\\proj\\obj\\Debug\\app.pdb"},
	}
	got := actionableIOCs(iocs)

	if containsStringFold(got.Domains, "system.net") {
		t.Errorf("namespace domain should be excluded: %#v", got.Domains)
	}
	if !containsStringFold(got.Domains, "evil-c2.top") {
		t.Errorf("real C2 domain should be kept: %#v", got.Domains)
	}
	if containsStringFold(got.UnixPaths, "/root/.cargo/registry/src/foo/lib.rs") {
		t.Errorf("cargo source path should be excluded: %#v", got.UnixPaths)
	}
	if containsStringFold(got.WindowsPaths, "C:\\proj\\obj\\Debug\\app.pdb") {
		t.Errorf("pdb build artifact should be excluded: %#v", got.WindowsPaths)
	}
	if !containsStringFold(got.WindowsPaths, "C:\\Temp\\dropper.exe") {
		t.Errorf("dropper path should be kept: %#v", got.WindowsPaths)
	}
}

func TestClassifyIOCSetPopulates(t *testing.T) {
	iocs := IOCSet{Domains: []string{"evil-c2.top"}, URLs: []string{"http://evil.example.com/p"}}
	ClassifyIOCSet(&iocs)
	if len(iocs.Classified) != 2 {
		t.Fatalf("expected 2 classified entries, got %d", len(iocs.Classified))
	}
}
