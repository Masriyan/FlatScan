package main

import (
	"fmt"
	"sort"
	"strings"
)

// API-hash database resolution — the reliable, emulator-free form of "resolve
// hashed imports" (the headline Tier-2 capability from improvementprompt-v2).
//
// Malware loaders and shellcode resolve Win32 APIs by a 32-bit hash of the
// function name instead of storing the name as a string, so FlatScan's string
// engine never sees "VirtualAlloc". Rather than emulate the resolver loop (a
// full, fragile CPU emulator), we precompute the well-known hash algorithms
// (ROR13, DJB2, SDBM) over a dictionary of commonly-abused API names and match
// the 32-bit immediates the disassembler collected against those tables — the
// same approach as community HashDB tooling. A match recovers the real API
// name, which is fed back into the reporting/Functions layer.

// apiHashDictionary is the set of frequently-abused Win32/NT API names whose
// hashes we precompute. A 32-bit hash collision against a fixed small dictionary
// is astronomically unlikely, so even a couple of matches are high-confidence.
var apiHashDictionary = []string{
	"LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "GetProcAddress",
	"GetModuleHandleA", "GetModuleHandleW", "GetModuleFileNameA",
	"VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
	"VirtualFree", "HeapCreate", "HeapAlloc",
	"WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
	"CreateRemoteThreadEx", "OpenProcess", "OpenThread", "GetThreadContext",
	"SetThreadContext", "ResumeThread", "SuspendThread", "QueueUserAPC",
	"NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtProtectVirtualMemory",
	"NtCreateThreadEx", "NtMapViewOfSection", "NtUnmapViewOfSection",
	"NtQueueApcThread", "RtlCreateUserThread", "RtlMoveMemory",
	"ZwUnmapViewOfSection",
	"CreateProcessA", "CreateProcessW", "CreateProcessInternalW", "WinExec",
	"ShellExecuteA", "ShellExecuteExA", "CreateThread", "ExitProcess",
	"TerminateProcess", "GetCurrentProcess",
	"CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "DeleteFileA",
	"CreateFileMappingA", "MapViewOfFile", "SetFilePointer",
	"RegOpenKeyExA", "RegSetValueExA", "RegCreateKeyExA", "RegQueryValueExA",
	"InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetConnectA",
	"InternetReadFile", "HttpOpenRequestA", "HttpSendRequestA",
	"URLDownloadToFileA", "URLDownloadToFileW",
	"WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest",
	"WSAStartup", "WSASocketA", "socket", "connect", "send", "recv", "bind",
	"listen", "accept", "gethostbyname", "inet_addr", "closesocket",
	"GetProcAddress", "GetTickCount", "IsDebuggerPresent",
	"CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
	"CreateToolhelp32Snapshot", "Process32First", "Process32Next",
	"CryptAcquireContextA", "CryptEncrypt", "CryptDecrypt",
	"CreateMutexA", "OpenMutexA", "Sleep", "GetUserNameA",
	"AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA",
	"GetAsyncKeyState", "SetWindowsHookExA", "FindWindowA",
}

// hashAlgo names a hashing scheme and its precomputed name->hash table.
type hashAlgo struct {
	name   string
	hashes map[uint32]string
}

var apiHashAlgos []hashAlgo

func init() {
	algos := []struct {
		name string
		fn   func(string) uint32
	}{
		{"ROR13", ror13Hash},
		{"ROR13+null", ror13HashNull},
		{"DJB2", djb2Hash},
		{"SDBM", sdbmHash},
	}
	for _, a := range algos {
		table := make(map[uint32]string, len(apiHashDictionary))
		for _, name := range apiHashDictionary {
			table[a.fn(name)] = name
		}
		apiHashAlgos = append(apiHashAlgos, hashAlgo{name: a.name, hashes: table})
	}
}

func ror13Hash(name string) uint32 {
	var h uint32
	for i := 0; i < len(name); i++ {
		h = (h >> 13) | (h << 19)
		h += uint32(name[i])
	}
	return h
}

func ror13HashNull(name string) uint32 {
	var h uint32
	for i := 0; i <= len(name); i++ { // include the terminating NUL byte
		h = (h >> 13) | (h << 19)
		if i < len(name) {
			h += uint32(name[i])
		}
	}
	return h
}

func djb2Hash(name string) uint32 {
	h := uint32(5381)
	for i := 0; i < len(name); i++ {
		h = h*33 + uint32(name[i])
	}
	return h
}

func sdbmHash(name string) uint32 {
	var h uint32
	for i := 0; i < len(name); i++ {
		h = uint32(name[i]) + (h << 6) + (h << 16) - h
	}
	return h
}

// resolveHashedAPIs matches the disassembled immediates against the API-hash
// tables and records any recovered import names.
func resolveHashedAPIs(result *ScanResult, info *CodeInfo, immediates map[uint32]struct{}) {
	if result == nil || info == nil || len(immediates) == 0 {
		return
	}
	ror13Detected := false
	for _, t := range info.Techniques {
		if strings.HasPrefix(t, "API hashing") {
			ror13Detected = true
		}
	}

	bestAlgo := ""
	var bestNames []string
	for _, algo := range apiHashAlgos {
		seen := make(map[string]struct{})
		var names []string
		for imm := range immediates {
			if name, ok := algo.hashes[imm]; ok {
				if _, dup := seen[name]; !dup {
					seen[name] = struct{}{}
					names = append(names, name)
				}
			}
		}
		if len(names) > len(bestNames) {
			bestNames = names
			bestAlgo = algo.name
		}
	}

	// Require >=2 distinct matches, or >=1 when the disassembler already saw a
	// ROR13 hashing loop — both make a coincidental collision implausible.
	if len(bestNames) == 0 || (len(bestNames) < 2 && !ror13Detected) {
		return
	}

	sort.Strings(bestNames)
	info.ResolvedHashedAPIs = bestNames

	// Feed recovered names into the Functions list so existing renderers and
	// any name-based reporting benefit, tagging known-malicious families.
	for _, name := range bestNames {
		fam, sev := apiNameFamily(name)
		result.Functions = append(result.Functions, FunctionHit{
			Name:     name,
			Family:   fam,
			Severity: sev,
			Source:   "resolved-hash (" + bestAlgo + ")",
		})
	}

	score := 20
	if anyNameFold(bestNames, "WriteProcessMemory", "CreateRemoteThread", "NtWriteVirtualMemory",
		"VirtualAllocEx", "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC") {
		score = 26 // resolved an injection toolkit
	}
	AddFindingDetailed(result, "High", "Behavior",
		"Resolved hash-obfuscated API imports",
		fmt.Sprintf("%s-hashed imports recovered from immediates: %s", bestAlgo, strings.Join(bestNames, ", ")),
		score, info.EntryOffset,
		"Defense Evasion", "Deobfuscate/Decode Files or Information (T1140)",
		"The recovered API set reveals intent (injection/download/persistence); pivot on it as you would a normal import table.")
}

// apiNameFamily maps a recovered API name to a behavior family/severity using
// the same vocabulary as the static apiPatterns table.
func apiNameFamily(name string) (string, string) {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "writeprocessmemory"), strings.Contains(lower, "createremotethread"),
		strings.Contains(lower, "ntwritevirtualmemory"), strings.Contains(lower, "virtualallocex"),
		strings.Contains(lower, "ntcreatethreadex"), strings.Contains(lower, "queueuserapc"),
		strings.Contains(lower, "mapviewofsection"), strings.Contains(lower, "rtlcreateuserthread"):
		return "process injection", "High"
	case strings.Contains(lower, "urldownload"), strings.Contains(lower, "internetopen"),
		strings.Contains(lower, "winhttp"), strings.Contains(lower, "httpsendrequest"),
		strings.Contains(lower, "internetreadfile"):
		return "downloader", "High"
	case strings.Contains(lower, "loadlibrary"), strings.Contains(lower, "getprocaddress"),
		strings.Contains(lower, "getmodulehandle"):
		return "dynamic loading", "Medium"
	case strings.Contains(lower, "winexec"), strings.Contains(lower, "shellexecute"),
		strings.Contains(lower, "createprocess"):
		return "execution", "Medium"
	case strings.Contains(lower, "reg"):
		return "persistence", "Medium"
	case strings.Contains(lower, "isdebuggerpresent"), strings.Contains(lower, "queryinformationprocess"):
		return "anti-analysis", "Medium"
	}
	return "api", "Low"
}

func anyNameFold(haystack []string, needles ...string) bool {
	for _, h := range haystack {
		for _, n := range needles {
			if strings.EqualFold(h, n) {
				return true
			}
		}
	}
	return false
}
