package main

import "strings"

// IOC confidence & categorization engine (improvementprompt-v3 Task 1).
//
// FlatScan's IOC triage previously only *suppressed* a small PKI/schema/OID
// allowlist; everything else was exported flat, as if equally actionable. That
// floods analysts with build artifacts, compiler/runtime metadata, source paths
// (Rust `…/.cargo/registry/…`, Go module paths), PDB paths, and .NET/Java
// package namespaces that the extraction regexes pick up as "domains" or
// "paths". This engine attaches a category + confidence + context to every
// extracted value and lets the export paths drop the non-actionable noise while
// keeping the flat slices unchanged for backward compatibility.

const (
	iocCatActionable    = "ioc"
	iocCatSuspInfra     = "suspicious-infra"
	iocCatBenignInfra   = "benign-infra"
	iocCatBuildArtifact = "build-artifact"
	iocCatCompilerMeta  = "compiler-runtime-metadata"
	iocCatSourcePath    = "source-path"
	iocCatNamespace     = "package-namespace"
)

// actionableIOCCategory reports whether a category should appear in actionable
// IOC exports (`--extract-ioc`, STIX). Build/compiler/source/namespace noise is
// excluded; benign-infra is kept (labeled) because analysts still want it noted.
func actionableIOCCategory(category string) bool {
	switch category {
	case iocCatBuildArtifact, iocCatCompilerMeta, iocCatSourcePath, iocCatNamespace:
		return false
	}
	return true
}

// ClassifyIOCSet populates iocs.Classified by categorizing every value in the
// flat slices. Idempotent; safe to call after triage.
func ClassifyIOCSet(iocs *IOCSet) {
	if iocs == nil {
		return
	}
	iocs.Classified = iocs.Classified[:0]
	add := func(t string, values []string) {
		for _, v := range values {
			iocs.Classified = append(iocs.Classified, classifyIOCValue(t, v))
		}
	}
	add("url", iocs.URLs)
	add("domain", iocs.Domains)
	add("ipv4", iocs.IPv4)
	add("ipv6", iocs.IPv6)
	add("email", iocs.Emails)
	add("registry_key", iocs.RegistryKeys)
	add("windows_path", iocs.WindowsPaths)
	add("unix_path", iocs.UnixPaths)
	add("mutex", iocs.Mutexes)
	add("named_pipe", iocs.NamedPipes)
	add("crypto_wallet", iocs.CryptoWallets)
	add("md5", iocs.MD5)
	add("sha1", iocs.SHA1)
	add("sha256", iocs.SHA256)
	add("sha256", iocs.SHA512)
}

// classifyIOCValue categorizes a single indicator. Confidence doubles as the
// evidence weight consumed by the correlation/scoring layer (v3 Task 2):
// hardcoded C2/webhook/token very high; network IOC high; path/registry medium;
// benign/namespace/build-artifact low.
func classifyIOCValue(iocType, value string) ClassifiedIOC {
	lv := strings.ToLower(value)
	c := ClassifiedIOC{Type: iocType, Value: value, Category: iocCatActionable, Confidence: 50}

	switch iocType {
	case "url":
		switch {
		case hasAny(lv, "discord.com/api/webhooks", "discordapp.com/api/webhooks"):
			c.Category, c.Confidence, c.Context = iocCatSuspInfra, 95, "Discord webhook — exfiltration endpoint"
		case hasAny(lv, "api.telegram.org/bot"):
			c.Category, c.Confidence, c.Context = iocCatSuspInfra, 92, "Telegram bot API — C2/exfil channel"
		case hasAny(lv, "pastebin.com/raw", "raw.githubusercontent.com", "transfer.sh", "anonfiles", "tmpfiles.org", "cdn.discordapp.com/attachments"):
			c.Category, c.Confidence, c.Context = iocCatSuspInfra, 80, "raw/paste/file-host — common payload staging URL"
		case isBenignSchemaURL(lv):
			c.Category, c.Confidence, c.Context = iocCatBenignInfra, 15, "PKI/schema/namespace URL"
		default:
			c.Confidence, c.Context = 72, "network URL"
		}
	case "domain":
		switch {
		case isNamespaceLike(lv):
			c.Category, c.Confidence, c.Context = iocCatNamespace, 8, "code namespace misread as a domain"
		case isPackageRegistryDomain(lv):
			c.Category, c.Confidence, c.Context = iocCatBuildArtifact, 8, "package/dependency registry embedded at build time"
		case isPKIDomain(lv):
			c.Category, c.Confidence, c.Context = iocCatBenignInfra, 12, "certificate-authority / PKI domain (library artifact)"
		case isBenignService(lv):
			c.Category, c.Confidence, c.Context = iocCatBenignInfra, 25, "common benign service (context-dependent)"
		default:
			c.Confidence, c.Context = 55, "domain"
		}
	case "windows_path", "unix_path":
		switch {
		case isBuildArtifactPath(lv):
			// Checked before source paths: a .pdb/obj/target output under a
			// source tree is still a build artifact (the more specific label).
			c.Category, c.Confidence, c.Context = iocCatBuildArtifact, 10, "build/compiler artifact path"
		case isSourcePath(lv):
			c.Category, c.Confidence, c.Context = iocCatSourcePath, 8, "build-time source path"
		default:
			c.Confidence, c.Context = 42, "filesystem path"
		}
	case "ipv4", "ipv6":
		c.Confidence, c.Context = 65, "network address"
	case "crypto_wallet":
		c.Category, c.Confidence, c.Context = iocCatSuspInfra, 85, "cryptocurrency wallet address"
	case "mutex", "named_pipe":
		c.Confidence, c.Context = 68, iocType+" name"
	case "registry_key":
		c.Confidence, c.Context = 52, "registry key"
	case "md5", "sha1", "sha256":
		c.Confidence, c.Context = 58, "embedded hash"
	case "email":
		c.Confidence, c.Context = 45, "email address"
	}
	return c
}

// isNamespaceLike detects .NET/Java/Android/Go package fragments that the domain
// regex misreads as hostnames because their final segment collides with a TLD
// (e.g. "System.Net", "androidx.work", "com.google.android"). It is deliberately
// conservative: broad single-word roots like "android."/"java."/"microsoft."
// are NOT used because they collide with real domains (android.googlesource.com,
// java.net, microsoft.com). Only fragments with no plausible registrable-domain
// meaning are matched.
func isNamespaceLike(lv string) bool {
	// Reverse-DNS package roots (com.google.x, org.apache.x): always namespaces.
	revDNS := []string{
		"androidx.", "kotlin.", "kotlinx.", "javax.", "mscorlib.",
		"com.google.", "com.android.", "com.sun.", "com.microsoft.",
		"org.apache.", "org.json.", "org.bouncycastle.", "org.jetbrains.",
		"io.netty.", "io.reactivex.", "okhttp3.", "okio.", "retrofit2.",
		"google.protobuf.", "google.api.", "dalvik.system.",
	}
	for _, p := range revDNS {
		if strings.HasPrefix(lv, p) {
			return true
		}
	}
	// Curated two-label .NET/Android namespace fragments whose second label is a
	// TLD. Exact-matched (not prefix) so company domains (microsoft.com,
	// android.com) are never mistaken for namespaces.
	exact := map[string]bool{
		"system.net": true, "system.io": true, "system.web": true, "system.data": true,
		"system.text": true, "system.xml": true, "system.core": true, "system.linq": true,
		"system.drawing": true, "system.runtime": true, "system.security": true,
		"system.threading": true, "system.reflection": true, "system.diagnostics": true,
		"system.management": true, "system.collections": true, "system.componentmodel": true,
		"android.app": true, "android.os": true, "android.media": true, "android.support": true,
		"android.content": true, "android.widget": true, "android.graphics": true,
	}
	return exact[lv]
}

// isBenignService lists ubiquitous services that are benign infrastructure on
// their own (their *URLs* may still be suspicious — handled in the url branch).
func isBenignService(lv string) bool {
	hosts := []string{
		"discord.com", "discordapp.com", "github.com", "githubusercontent.com",
		"google.com", "gstatic.com", "googleapis.com", "microsoft.com",
		"windows.com", "office.com", "live.com", "mozilla.org", "cloudflare.com",
		"akamai.net", "amazonaws.com", "azureedge.net", "gmail.com",
		"telegram.org", "cloudfront.net", "jsdelivr.net", "fontawesome.com",
		"googlesource.com", "gitlab.com", "bitbucket.org", "sourceforge.net",
		"apple.com", "android.com", "java.com", "oracle.com",
	}
	for _, h := range hosts {
		if lv == h || strings.HasSuffix(lv, "."+h) {
			return true
		}
	}
	return false
}

// isPackageRegistryDomain flags dependency-registry hosts that compilers/build
// tools embed (e.g. Rust's index.crates.io, Go module proxy, npm, PyPI, Maven).
// These dominate IOC counts on Rust/Go binaries but are never operational C2.
func isPackageRegistryDomain(lv string) bool {
	hosts := []string{
		"crates.io", "static.crates.io", "index.crates.io",
		"proxy.golang.org", "sum.golang.org", "pkg.go.dev", "gopkg.in",
		"registry.npmjs.org", "npmjs.com", "pypi.org", "files.pythonhosted.org",
		"repo.maven.apache.org", "repo1.maven.org", "rubygems.org", "nuget.org",
		"golang.org", "golang.google.cn",
	}
	for _, h := range hosts {
		if lv == h || strings.HasSuffix(lv, "."+h) {
			return true
		}
	}
	return false
}

// isPKIDomain flags certificate-authority / PKI hosts that appear in embedded
// cert chains and CRL/OCSP references — library artifacts, not infrastructure.
func isPKIDomain(lv string) bool {
	hosts := []string{
		"digicert.com", "verisign.com", "globalsign.com", "sectigo.com",
		"comodoca.com", "comodo.com", "entrust.net", "thawte.com",
		"symantec.com", "godaddy.com", "ssl.com", "usertrust.com",
		"letsencrypt.org", "openssl.org", "geotrust.com", "rapidssl.com",
		"amazontrust.com", "pki.goog", "msocsp.com", "windowsupdate.com",
	}
	for _, h := range hosts {
		if lv == h || strings.HasSuffix(lv, "."+h) {
			return true
		}
	}
	return false
}

func isBenignSchemaURL(lv string) bool {
	return hasAny(lv, "schemas.microsoft.com", "schemas.openxmlformats.org",
		"www.w3.org", "purl.org", "dublincore.org", "://crl", "://ocsp",
		"ocsp.", "crl.", "schemas.android.com", "schemas.xmlsoap.org")
}

// isSourcePath detects build-time source/toolchain paths embedded by compilers.
func isSourcePath(lv string) bool {
	return hasAny(lv,
		"/.cargo/registry", "\\.cargo\\registry", "/rustc/", "\\rustc\\",
		"/go/pkg/mod/", "\\go\\pkg\\mod\\", "/usr/local/go/src", "/usr/lib/go",
		"\\source\\repos\\", "/source/repos/", "src\\github.com\\", "src/github.com/",
		"/root/go/", "\\go\\src\\", "/_cgo_", "/checkout/src", "\\rust\\",
		".rs\x00", "/cargo/", "\\cargo\\")
}

// isBuildArtifactPath detects compiler/build output paths and debug symbols.
func isBuildArtifactPath(lv string) bool {
	return hasAny(lv,
		".pdb", "\\obj\\", "/obj/", "\\bin\\debug", "\\bin\\release",
		"/bin/debug", "/bin/release", "\\target\\release", "\\target\\debug",
		"/target/release", "/target/debug", "go-build", "\\intermediate\\",
		".natvis", "\\release\\net", "\\debug\\net")
}

// actionableIOCs returns a copy of the IOC set with non-actionable categories
// (build artifact / compiler metadata / source path / namespace) removed from
// the noise-prone slices (urls/domains/paths). Used by exporters so generated
// IOC lists and STIX bundles stay trustworthy; the original set is unchanged.
func actionableIOCs(iocs IOCSet) IOCSet {
	out := iocs
	out.URLs = filterActionable("url", iocs.URLs)
	out.Domains = filterActionable("domain", iocs.Domains)
	out.WindowsPaths = filterActionable("windows_path", iocs.WindowsPaths)
	out.UnixPaths = filterActionable("unix_path", iocs.UnixPaths)
	out.Classified = nil
	return out
}

func filterActionable(iocType string, values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if actionableIOCCategory(classifyIOCValue(iocType, v).Category) {
			out = append(out, v)
		}
	}
	return out
}
