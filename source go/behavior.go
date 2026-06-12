package main

import "strings"

// Expected dynamic-behavior prediction (improvementprompt-v3 Task 6).
//
// FlatScan is static-only, but analysts validating a sample in a sandbox/EDR
// want a checklist of what it is *expected* to do at runtime. This derives that
// checklist from the static evidence already gathered (findings, capabilities,
// IOC categories, techniques) and stores it on the profile. It is descriptive,
// not predictive of success — each line is a behavior to look for in telemetry.

// PredictExpectedBehavior maps static evidence to runtime-behavior statements.
func PredictExpectedBehavior(result *ScanResult) {
	if result == nil {
		return
	}
	var out []string
	add := func(s string) { out = appendUnique(out, s) }

	hasTitle := func(substr string) bool {
		for _, f := range result.Findings {
			if strings.Contains(strings.ToLower(f.Title), strings.ToLower(substr)) {
				return true
			}
		}
		return false
	}

	switch {
	case hasTitle("download-and-execute") || hasTitle("downloader") || hasTitle("download cradle"):
		add("Downloads a remote payload and executes it (watch for outbound HTTP[S] then child-process creation)")
	case hasTitle("remote file download"):
		add("Retrieves a remote file (watch for outbound HTTP[S] GET to the extracted URLs)")
	}
	if hasTitle("process injection") || hasTitle("injection api") {
		add("Injects code into another process (watch for cross-process VirtualAllocEx/WriteProcessMemory/CreateRemoteThread)")
	}
	if hasTitle("defender tampering") || hasTitle("disable security") || hasTitle("amsi") {
		add("Attempts to disable or evade endpoint defenses (watch for Defender/AMSI tampering events)")
	}
	if hasTitle("credential") || hasTitle("browser credential") {
		add("Accesses stored credentials/browser secrets (watch for reads of LSASS, Login Data, or Local State)")
	}
	if hasTitle("run-key") || hasTitle("persistence") || hasTitle("scheduled task") || hasTitle("registry run") {
		add("Establishes persistence (watch for Run-key writes, scheduled tasks, or service creation)")
	}
	if hasTitle("keylog") {
		add("Captures keystrokes (watch for low-level keyboard hooks / GetAsyncKeyState loops)")
	}
	if hasTitle("clipboard") {
		add("Monitors or rewrites the clipboard (watch for clipboard reads and wallet-address substitution)")
	}
	if hasTitle("shortcut launches") || hasTitle("powershell") || hasTitle("script") {
		add("Spawns a script interpreter (watch for powershell/cmd/wscript child processes with encoded or remote commands)")
	}
	if hasTitle("anti-vm") || hasTitle("vmware") || hasTitle("hypervisor") || hasTitle("descriptor-table") || hasTitle("rdtsc") {
		add("Performs sandbox/VM evasion checks (may stall or alter behavior under instrumentation)")
	}
	if hasTitle("ransom") || hasTitle("shadow copy") {
		add("May encrypt files and inhibit recovery (watch for mass file rewrites and vssadmin/bcdedit calls)")
	}
	if hasTitle("mining") || hasTitle("stratum") || hasTitle("cryptominer") {
		add("Consumes CPU/GPU for cryptomining (watch for stratum connections and sustained resource use)")
	}
	if webhookExfil(result) {
		add("Exfiltrates data to a chat-app webhook/bot (watch for POSTs to Discord/Telegram endpoints)")
	}

	if len(out) == 0 {
		return
	}
	result.Profile.ExpectedBehavior = out
}

func webhookExfil(result *ScanResult) bool {
	for _, u := range result.IOCs.URLs {
		lu := strings.ToLower(u)
		if strings.Contains(lu, "/api/webhooks") || strings.Contains(lu, "api.telegram.org/bot") {
			return true
		}
	}
	return false
}
