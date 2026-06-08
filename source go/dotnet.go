package main

import "strings"

// .NET / managed-code detection.
//
// FlatScan reads a managed PE as largely opaque: a .NET assembly has almost no
// native import table, so the generic native API signatures and behavioral
// chains rarely fire on .NET malware. The 2026-06-07 sample sweep surfaced this
// recall gap — a reflective .NET loader (decrypt + decompress an embedded blob,
// then load it via reflection) scored on packing/entropy alone.
//
// These checks look for the managed-specific behaviors that real .NET malware
// uses. They are gated to managed binaries and require evidence *combinations*,
// because the individual primitives (reflection, AES, AppDomain) are ubiquitous
// and benign in ordinary .NET applications — only their co-occurrence with
// in-memory payload decoding or native injection is suspicious.

func isDotNetAssembly(result *ScanResult) bool {
	return result != nil && result.PE != nil && result.PE.ManagedRuntime
}

// dotNetObfuscators lists managed protector/obfuscator fingerprints in priority
// order (a slice, not a map, so the reported marker is deterministic).
var dotNetObfuscators = []struct {
	Needle string
	Name   string
}{
	{"confusedby", "ConfuserEx"},
	{"confuser", "Confuser"},
	{"powered by smartassembly", "SmartAssembly"},
	{"smartassembly", "SmartAssembly"},
	{"eazfuscator", "Eazfuscator.NET"},
	{"babelobfuscator", "Babel"},
	{"babel.obfuscator", "Babel"},
	{"dotfuscator", "Dotfuscator"},
	{"agile.net", "Agile.NET"},
	{".net reactor", ".NET Reactor"},
	{"netreactor", ".NET Reactor"},
	{"obfuscar", "Obfuscar"},
	{"ilprotector", "ILProtector"},
	{"goliath.net", "Goliath.NET"},
}

// AnalyzeDotNet adds managed-code behavioral findings. It must run after format
// analysis (it reads result.PE) and uses the shared lowercase corpus.
func AnalyzeDotNet(result *ScanResult, corpus string) {
	if !isDotNetAssembly(result) || corpus == "" {
		return
	}

	// Reflective dynamic invocation: System.Reflection together with dynamic
	// type/assembly resolution and method invocation. Common to .NET loaders,
	// crypters, and RunPE stagers — but also to legitimate plugin hosts, so it
	// is only scored when paired with in-memory payload decoding below.
	reflectInvoke := strings.Contains(corpus, "system.reflection") &&
		hasAny(corpus, "assembly.load", "appdomain", "activator", "reflection.assembly") &&
		hasAny(corpus, "createinstance", "getmethod", "invokemember", "entrypoint")

	// In-memory payload decode primitives used to unpack an embedded blob.
	inMemoryDecrypt := hasAny(corpus, "rijndael", "aesmanaged", "aescryptoserviceprovider",
		"tripledes", "rc2cryptoserviceprovider", "cryptostream")
	inMemoryDecompress := hasAny(corpus, "deflatestream", "gzipstream")

	switch {
	case reflectInvoke && inMemoryDecrypt && inMemoryDecompress:
		AddFindingDetailed(result, "High", "Loader",
			"In-memory .NET assembly loading with encrypted, compressed payload",
			"managed reflection (Activator/AppDomain/Assembly.Load) co-occurs with both symmetric decryption and stream decompression — a reflective payload-staging pattern",
			22, 0,
			"Defense Evasion", "Reflective Code Loading (T1620)",
			"Dump the decoded second-stage assembly from memory and analyze it; treat the high-entropy resource section as the packed payload.")
	case reflectInvoke && (inMemoryDecrypt || inMemoryDecompress):
		AddFindingDetailed(result, "Medium", "Loader",
			"Managed reflection with in-memory payload decoding",
			"managed reflection co-occurs with in-memory decryption or decompression — possible reflective loader",
			12, 0,
			"Defense Evasion", "Reflective Code Loading (T1620)",
			"Confirm whether reflection is loading an embedded/downloaded assembly rather than a legitimate plugin or config blob.")
	}

	// Managed process injection: P/Invoke or delegate marshaling into native
	// injection primitives. Benign managed code almost never does this.
	if hasAny(corpus, "dllimport", "getdelegateforfunctionpointer", "marshal.copy",
		"marshal.getdelegateforfunctionpointer", "marshal.allochglobal") &&
		hasAny(corpus, "virtualalloc", "virtualallocex", "writeprocessmemory",
			"createremotethread", "ntcreatethreadex", "setthreadcontext", "mapviewofsection") {
		AddFindingDetailed(result, "High", "Behavior",
			"Managed P/Invoke into native injection APIs",
			"a .NET binary references P/Invoke or delegate marshaling together with native memory-allocation or remote-thread APIs",
			22, 0,
			"Defense Evasion", "Process Injection (T1055)",
			"Inspect the P/Invoke signatures and any shellcode buffers; managed code calling VirtualAlloc/WriteProcessMemory/CreateRemoteThread is a strong injection signal.")
	}

	// .NET obfuscator / protector fingerprint — the managed equivalent of the
	// native packer marker.
	for _, obf := range dotNetObfuscators {
		if strings.Contains(corpus, obf.Needle) {
			AddFinding(result, "Medium", "Packing",
				"Known .NET obfuscator/protector marker",
				obf.Name+" marker present in managed metadata", 13, 0)
			break
		}
	}
}
