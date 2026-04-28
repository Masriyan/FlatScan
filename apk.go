package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

const (
	axmlStringPoolType  = 0x0001
	axmlXMLType         = 0x0003
	axmlStartElement    = 0x0102
	axmlEndElement      = 0x0103
	axmlNoIndex         = uint32(0xffffffff)
	axmlUTF8Flag        = 0x00000100
	dexHeaderSize       = 112
	apkManifestReadMax  = int64(8 * 1024 * 1024)
	apkAssetReportLimit = 80
)

type androidManifestEvent struct {
	Start bool
	Name  string
	Attrs map[string]string
}

type androidAPIPattern struct {
	Category  string
	Indicator string
	Severity  string
	Needles   []string
}

var androidDangerousPermissions = map[string]string{
	"ACCEPT_HANDOVER":            "phone",
	"ACCESS_BACKGROUND_LOCATION": "location",
	"ACCESS_COARSE_LOCATION":     "location",
	"ACCESS_FINE_LOCATION":       "location",
	"ACCESS_MEDIA_LOCATION":      "storage",
	"ACTIVITY_RECOGNITION":       "sensors",
	"ADD_VOICEMAIL":              "phone",
	"ANSWER_PHONE_CALLS":         "phone",
	"BLUETOOTH_CONNECT":          "nearby devices",
	"BLUETOOTH_SCAN":             "nearby devices",
	"BODY_SENSORS":               "sensors",
	"BODY_SENSORS_BACKGROUND":    "sensors",
	"CALL_PHONE":                 "phone",
	"CAMERA":                     "camera",
	"GET_ACCOUNTS":               "accounts",
	"NEARBY_WIFI_DEVICES":        "nearby devices",
	"POST_NOTIFICATIONS":         "notifications",
	"PROCESS_OUTGOING_CALLS":     "phone",
	"READ_CALENDAR":              "calendar",
	"READ_CALL_LOG":              "phone",
	"READ_CONTACTS":              "contacts",
	"READ_EXTERNAL_STORAGE":      "storage",
	"READ_MEDIA_AUDIO":           "storage",
	"READ_MEDIA_IMAGES":          "storage",
	"READ_MEDIA_VIDEO":           "storage",
	"READ_PHONE_NUMBERS":         "phone",
	"READ_PHONE_STATE":           "phone",
	"READ_SMS":                   "sms",
	"RECEIVE_MMS":                "sms",
	"RECEIVE_SMS":                "sms",
	"RECEIVE_WAP_PUSH":           "sms",
	"RECORD_AUDIO":               "microphone",
	"SEND_SMS":                   "sms",
	"USE_SIP":                    "phone",
	"WRITE_CALENDAR":             "calendar",
	"WRITE_CALL_LOG":             "phone",
	"WRITE_CONTACTS":             "contacts",
	"WRITE_EXTERNAL_STORAGE":     "storage",
}

var androidSpecialPermissions = map[string]string{
	"BIND_ACCESSIBILITY_SERVICE": "accessibility service",
	"BIND_DEVICE_ADMIN":          "device administrator",
	"PACKAGE_USAGE_STATS":        "usage access",
	"QUERY_ALL_PACKAGES":         "package inventory",
	"REQUEST_INSTALL_PACKAGES":   "package installation",
	"SYSTEM_ALERT_WINDOW":        "screen overlay",
	"WRITE_SETTINGS":             "system settings",
}

var androidAPIPatterns = []androidAPIPattern{
	{"sms", "SMS manager or SMS permission", "High", []string{"landroid/telephony/smsmanager;", "smssmanager", "sendtextmessage", "android.permission.send_sms", "android.permission.read_sms", "android.provider.telephony.sms_received"}},
	{"contacts", "Contacts provider access", "Medium", []string{"android.provider.contactscontract", "android.permission.read_contacts", "android.permission.write_contacts"}},
	{"location", "Location access", "Medium", []string{"landroid/location/locationmanager;", "fusedlocationprovider", "android.permission.access_fine_location", "android.permission.access_coarse_location", "android.permission.access_background_location"}},
	{"recording", "Microphone or camera access", "Medium", []string{"android.permission.record_audio", "android.media.mediarecorder", "landroid/hardware/camera", "landroid/hardware/camera2", "android.permission.camera"}},
	{"accessibility", "Accessibility service references", "Medium", []string{"landroid/accessibilityservice/accessibilityservice;", "android.accessibilityservice.accessibilityservice", "bind_accessibility_service", "performglobalaction"}},
	{"overlay", "Overlay window capability", "Medium", []string{"system_alert_window", "action_manage_overlay_permission", "can drawoverlays", "candrawoverslays"}},
	{"device-admin", "Device administrator references", "Medium", []string{"landroid/app/admin/deviceadminreceiver;", "android.app.action.device_admin_enabled", "bind_device_admin", "devicepolicymanager"}},
	{"runtime-exec", "Runtime command execution", "Medium", []string{"ljava/lang/runtime;", "java.lang.runtime", "processbuilder", "runtime.exec"}},
	{"dynamic-code", "Dynamic class or DEX loading", "Medium", []string{"ldalvik/system/dexclassloader;", "dalvik.system.dexclassloader", "ldalvik/system/pathclassloader;", "inmemorydexclassloader", "optimizeddirectory"}},
	{"webview-bridge", "WebView JavaScript bridge", "Medium", []string{"addjavascriptinterface", "setjavascriptenabled", "webviewclient", "shouldoverrideurlloading"}},
	{"native-loading", "Native code loading", "Medium", []string{"system.loadlibrary", "loadlibrary", "dlopen", "jnionload"}},
	{"package-install", "Package installation capability", "Medium", []string{"request_install_packages", "packageinstaller", "action_install_package", "install_existing_package"}},
	{"network", "HTTP client or network stack", "Low", []string{"java/net/httpurlconnection", "okhttp3/", "retrofit2/", "org/apache/http", "android.permission.internet"}},
	{"crypto", "Android/Java cryptography use", "Medium", []string{"javax/crypto/cipher", "secretkeyspec", "aes/", "rsa/", "pbkdf2", "messageDigest"}},
}

func analyzeAPK(result *ScanResult, cfg Config, debugf debugLogger) error {
	reader, err := zip.OpenReader(result.Target)
	if err != nil {
		return err
	}
	defer reader.Close()

	info := &APKInfo{
		ManifestFormat: "not found",
		FileCount:      len(reader.File),
	}
	dexLimit := dexFileLimitForMode(cfg.Mode)
	dexParsed := 0

	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		name := cleanAPKEntryName(file.Name)
		lower := strings.ToLower(name)

		switch {
		case lower == "androidmanifest.xml":
			data, truncated, err := readZipEntryLimited(file, apkManifestReadMax)
			if err != nil {
				debugf("apk manifest read failed: %v", err)
				continue
			}
			manifestInfo, manifestStrings, err := parseAPKManifest(data)
			if err != nil {
				debugf("apk manifest parse failed: %v", err)
				AddFindingDetailed(result, "Low", "Android", "Android manifest parser warning", err.Error(), 2, 0, "Discovery", "Application Discovery", "Parse AndroidManifest.xml with a dedicated Android reverse engineering tool if APK triage remains important.")
			} else {
				mergeAPKManifestInfo(info, manifestInfo)
				if truncated {
					info.ManifestFormat += " (truncated)"
				}
				MergeIOCSet(&result.IOCs, ExtractIOCsFromStringValues(manifestStrings))
			}
		case strings.HasSuffix(lower, ".dex"):
			if dexParsed >= dexLimit {
				continue
			}
			data, truncated, err := readZipEntryLimited(file, apkEntryReadMax(cfg))
			if err != nil {
				debugf("apk dex read failed for %s: %v", name, err)
				continue
			}
			dex := analyzeDEXData(name, data, cfg)
			dex.StringsTruncated = dex.StringsTruncated || truncated
			result.DEXFiles = append(result.DEXFiles, dex)
			mergeDEXEvidence(result, dex)
			dexParsed++
		}

		switch {
		case strings.HasPrefix(lower, "lib/") && strings.HasSuffix(lower, ".so"):
			info.NativeLibraries = appendUnique(info.NativeLibraries, name)
		case strings.HasPrefix(lower, "meta-inf/") && hasAny(lower, ".rsa", ".dsa", ".ec", ".sf", ".mf"):
			info.SignatureFiles = appendUnique(info.SignatureFiles, name)
		case strings.Contains(lower, "network_security_config") && strings.HasSuffix(lower, ".xml"):
			info.NetworkSecurityConfig = appendUnique(info.NetworkSecurityConfig, name)
		case strings.HasPrefix(lower, "assets/") || strings.HasPrefix(lower, "res/raw/"):
			if len(info.AssetFiles) < apkAssetReportLimit {
				info.AssetFiles = appendUnique(info.AssetFiles, name)
			}
		}

		if isEmbeddedAndroidPayload(lower) {
			info.EmbeddedPayloads = appendUnique(info.EmbeddedPayloads, name)
		}
	}

	sortAPKInfo(info)
	result.APK = info
	addAPKFindings(result)
	return nil
}

func analyzeStandaloneDEX(result *ScanResult, cfg Config, data []byte, debugf debugLogger) error {
	dex := analyzeDEXData(result.FileName, data, cfg)
	result.DEXFiles = append(result.DEXFiles, dex)
	mergeDEXEvidence(result, dex)
	addDEXFindings(result)
	if dex.StringsTotal == 0 {
		debugf("standalone dex parser produced no strings")
	}
	return nil
}

func mergeAPKManifestInfo(dst *APKInfo, src APKInfo) {
	dst.PackageName = src.PackageName
	dst.VersionCode = src.VersionCode
	dst.VersionName = src.VersionName
	dst.MinSDK = src.MinSDK
	dst.TargetSDK = src.TargetSDK
	dst.ManifestFormat = src.ManifestFormat
	dst.Permissions = append(dst.Permissions, src.Permissions...)
	dst.Components = append(dst.Components, src.Components...)
	dst.ExportedComponents = append(dst.ExportedComponents, src.ExportedComponents...)
	dst.NetworkSecurityConfig = appendUnique(dst.NetworkSecurityConfig, src.NetworkSecurityConfig...)
}

func sortAPKInfo(info *APKInfo) {
	if info == nil {
		return
	}
	sort.SliceStable(info.Permissions, func(i, j int) bool {
		return info.Permissions[i].Name < info.Permissions[j].Name
	})
	sort.SliceStable(info.Components, func(i, j int) bool {
		if info.Components[i].Type == info.Components[j].Type {
			return info.Components[i].Name < info.Components[j].Name
		}
		return info.Components[i].Type < info.Components[j].Type
	})
	sort.SliceStable(info.ExportedComponents, func(i, j int) bool {
		if info.ExportedComponents[i].Type == info.ExportedComponents[j].Type {
			return info.ExportedComponents[i].Name < info.ExportedComponents[j].Name
		}
		return info.ExportedComponents[i].Type < info.ExportedComponents[j].Type
	})
	info.NativeLibraries = uniqueSorted(info.NativeLibraries)
	info.EmbeddedPayloads = uniqueSorted(info.EmbeddedPayloads)
	info.NetworkSecurityConfig = uniqueSorted(info.NetworkSecurityConfig)
	info.AssetFiles = uniqueSorted(info.AssetFiles)
	info.SignatureFiles = uniqueSorted(info.SignatureFiles)
}

func addAPKFindings(result *ScanResult) {
	if result == nil || result.APK == nil {
		addDEXFindings(result)
		return
	}
	info := result.APK
	dangerous := androidPermissionsByMinimumRisk(info.Permissions, "Medium")
	highRisk := androidPermissionsByMinimumRisk(info.Permissions, "High")

	if len(info.Permissions) > 0 {
		AddFindingDetailed(result, "Info", "Android", "Android manifest metadata extracted", fmt.Sprintf("%d permissions and %d components parsed", len(info.Permissions), len(info.Components)), 0, 0, "Discovery", "Application Discovery", "Review package identity, permissions, exported components, and network configuration before allowing installation.")
	}
	if len(dangerous) >= 8 {
		AddFindingDetailed(result, "Medium", "Android", "Broad dangerous Android permission set", fmt.Sprintf("%d dangerous/special permissions: %s", len(dangerous), strings.Join(firstPermissionNames(dangerous, 8), ", ")), 10, 0, "Collection", "Protected User Data Access", "Validate whether the app needs each dangerous permission and test behavior in an isolated Android lab.")
	} else if len(dangerous) >= 4 {
		AddFindingDetailed(result, "Low", "Android", "Multiple dangerous Android permissions", fmt.Sprintf("%d dangerous/special permissions: %s", len(dangerous), strings.Join(firstPermissionNames(dangerous, 6), ", ")), 4, 0, "Collection", "Protected User Data Access", "Review requested permissions against expected business purpose.")
	}
	if len(highRisk) > 0 {
		AddFindingDetailed(result, "Medium", "Android", "High-risk Android special permissions", strings.Join(firstPermissionNames(highRisk, 8), ", "), 12, 0, "Privilege Escalation", "Abuse Elevation Control Mechanism", "Require manual approval and dynamic validation for special-access permissions.")
	}
	if hasAndroidPermission(info, "SYSTEM_ALERT_WINDOW") || hasAndroidDEXHit(*result, "overlay") {
		AddFindingDetailed(result, "Medium", "Android", "Android overlay capability", "overlay permission or overlay API references are present", 12, 0, "Defense Evasion", "Overlay Window Abuse", "Check for phishing overlays, tapjacking behavior, and accessibility-assisted UI control in dynamic analysis.")
	}
	if hasAndroidPermission(info, "REQUEST_INSTALL_PACKAGES") || hasAndroidDEXHit(*result, "package-install") {
		AddFindingDetailed(result, "Medium", "Android", "Android package installation capability", "REQUEST_INSTALL_PACKAGES or package installer APIs are present", 11, 0, "Execution", "Install Additional Application", "Verify whether the app can stage or install secondary APKs outside trusted distribution channels.")
	}
	if hasAndroidPermission(info, "SEND_SMS") && (hasAndroidPermission(info, "READ_SMS") || hasAndroidPermission(info, "RECEIVE_SMS") || hasAndroidDEXHit(*result, "sms")) {
		AddFindingDetailed(result, "High", "Android", "Android SMS collection or sending capability", "SMS permissions and SMS APIs are present", 20, 0, "Collection", "SMS Collection", "Do not install on production devices until dynamic analysis confirms no SMS theft, premium SMS abuse, or OTP interception.")
	}
	if hasComponentPermission(info, "BIND_ACCESSIBILITY_SERVICE") {
		AddFindingDetailed(result, "High", "Android", "Android accessibility service capability", "accessibility service permission or APIs are present", 18, 0, "Collection", "Input Capture / Accessibility Abuse", "Inspect accessibility service configuration and runtime behavior for credential capture or automated UI control.")
	}
	if hasComponentPermission(info, "BIND_DEVICE_ADMIN") || hasComponentAction(info, "DEVICE_ADMIN") {
		AddFindingDetailed(result, "High", "Android", "Android device administrator capability", "device-admin receiver, permission, or API references are present", 18, 0, "Persistence", "Device Administrator Abuse", "Validate whether device-admin capability can prevent removal, lock the device, or alter security policy.")
	}
	if hasComponentAction(info, "BOOT_COMPLETED") {
		AddFindingDetailed(result, "Medium", "Android", "Android boot persistence receiver", "receiver listens for BOOT_COMPLETED", 10, 0, "Persistence", "Boot or Logon Autostart Execution", "Review receiver behavior and first-run telemetry after device reboot.")
	}
	exportedWithoutPermission := exportedComponentsWithoutPermission(info)
	if len(exportedWithoutPermission) >= 5 {
		AddFindingDetailed(result, "Medium", "Android", "Multiple exported Android components without permission guard", fmt.Sprintf("%d exported components appear unguarded", len(exportedWithoutPermission)), 10, 0, "Initial Access", "Exposed Application Component", "Review exported components for intent spoofing, deep-link abuse, and unauthorized IPC entry points.")
	} else if len(exportedWithoutPermission) > 0 {
		AddFindingDetailed(result, "Low", "Android", "Exported Android components without permission guard", fmt.Sprintf("%d exported components appear unguarded", len(exportedWithoutPermission)), 4, 0, "Initial Access", "Exposed Application Component", "Confirm the exported components are intentional and validate input handling.")
	}
	if len(info.EmbeddedPayloads) > 0 {
		AddFindingDetailed(result, "Medium", "Android", "Embedded executable or secondary payload in APK", strings.Join(firstStrings(info.EmbeddedPayloads, 8), ", "), 12, 0, "Defense Evasion", "Obfuscated Files or Information", "Inspect embedded JAR/DEX/SO/APK assets for staged payload behavior.")
	}
	if len(info.NativeLibraries) > 0 {
		AddFindingDetailed(result, "Info", "Android", "Native libraries packaged in APK", fmt.Sprintf("%d native libraries present", len(info.NativeLibraries)), 0, 0, "Discovery", "Software Discovery", "Reverse native libraries if Android behavior cannot be explained from DEX and manifest evidence.")
	}
	addDEXFindings(result)
}

func addDEXFindings(result *ScanResult) {
	if result == nil {
		return
	}
	if hasAndroidDEXHit(*result, "accessibility") {
		AddFindingDetailed(result, "Low", "Android", "Accessibility API references in DEX", "accessibility-related Android API strings are present", 4, 0, "Collection", "Input Capture / Accessibility Abuse", "Confirm whether these are app-owned services or only framework/support-library references.")
	}
	if hasAndroidDEXHit(*result, "device-admin") {
		AddFindingDetailed(result, "Low", "Android", "Device administrator API references in DEX", "device-admin Android API strings are present", 4, 0, "Persistence", "Device Administrator Abuse", "Confirm whether the manifest declares an active device-admin receiver before treating this as a capability.")
	}
	if hasAndroidDEXHit(*result, "runtime-exec") && dexContainsAny(*result, "/system/bin/sh", "su -c", "chmod ", "chown ", "pm install", "toybox", "busybox") {
		AddFindingDetailed(result, "High", "Android", "Runtime command execution references in DEX", "Runtime.exec or ProcessBuilder references appear with shell or system command strings", 18, 0, "Execution", "Command and Scripting Interpreter", "Trace call sites in decompiled DEX and validate whether commands are controlled by network or IPC input.")
	} else if hasAndroidDEXHit(*result, "runtime-exec") {
		AddFindingDetailed(result, "Medium", "Android", "Runtime execution API references in DEX", "Runtime.exec or ProcessBuilder references are present without strong shell-command context", 10, 0, "Execution", "Command and Scripting Interpreter", "Trace call sites before treating this as confirmed command execution capability.")
	}
	if hasAndroidDEXHit(*result, "dynamic-code") {
		severity := "Medium"
		score := 10
		evidence := "DexClassLoader, PathClassLoader, or InMemoryDexClassLoader references are present"
		if result.APK != nil && len(result.APK.EmbeddedPayloads) > 0 {
			severity = "High"
			score = 16
			evidence = "dynamic class loading references appear with embedded executable payloads"
		}
		AddFindingDetailed(result, severity, "Android", "Dynamic DEX or class loading references", evidence, score, 0, "Defense Evasion", "Dynamic Code Loading", "Inspect assets, downloads, and code paths that load secondary classes at runtime.")
	}
	if hasAndroidDEXHit(*result, "webview-bridge") {
		AddFindingDetailed(result, "Medium", "Android", "WebView JavaScript bridge references", "addJavascriptInterface or JavaScript-enabled WebView APIs are present", 10, 0, "Execution", "User Execution / WebView Bridge", "Review exposed JavaScript interfaces and remote content loading for credential theft or remote command paths.")
	}
	if hasAndroidDEXHit(*result, "native-loading") {
		AddFindingDetailed(result, "Low", "Android", "Native loading references in DEX", "System.loadLibrary, dlopen, or JNI references are present", 4, 0, "Defense Evasion", "Native API", "Cross-reference native loading calls with packaged libraries and suspicious exported JNI methods.")
	}
	if hasAndroidDEXHit(*result, "crypto") {
		AddFindingDetailed(result, "Low", "Cryptography", "Java cryptography references in DEX", "Cipher, SecretKeySpec, AES/RSA, PBKDF, or MessageDigest strings are present", 4, 0, "Defense Evasion", "Obfuscated Files or Information", "Determine whether crypto protects legitimate traffic or hides configuration, payloads, or stolen data.")
	}
}

func parseAPKManifest(data []byte) (APKInfo, []string, error) {
	events, stringsFound, format, err := parseAndroidManifestEvents(data)
	if err != nil {
		return APKInfo{}, stringsFound, err
	}
	info := buildAPKInfoFromManifest(events)
	info.ManifestFormat = format
	return info, stringsFound, nil
}

func parseAndroidManifestEvents(data []byte) ([]androidManifestEvent, []string, string, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '<' {
		events, stringsFound, err := parsePlainXMLManifest(data)
		return events, stringsFound, "plain XML", err
	}
	events, stringsFound, err := parseAXMLManifest(data)
	return events, stringsFound, "binary AXML", err
}

func parsePlainXMLManifest(data []byte) ([]androidManifestEvent, []string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var events []androidManifestEvent
	var stringValues []string
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return events, stringValues, err
		}
		switch typed := token.(type) {
		case xml.StartElement:
			attrs := make(map[string]string)
			for _, attr := range typed.Attr {
				key := attr.Name.Local
				attrs[key] = attr.Value
				stringValues = append(stringValues, attr.Value)
			}
			events = append(events, androidManifestEvent{Start: true, Name: typed.Name.Local, Attrs: attrs})
		case xml.EndElement:
			events = append(events, androidManifestEvent{Start: false, Name: typed.Name.Local})
		}
	}
	return events, uniqueSorted(stringValues), nil
}

func parseAXMLManifest(data []byte) ([]androidManifestEvent, []string, error) {
	if len(data) < 8 {
		return nil, nil, fmt.Errorf("AXML too small")
	}
	if binary.LittleEndian.Uint16(data[0:2]) != axmlXMLType {
		return nil, nil, fmt.Errorf("missing AXML XML chunk")
	}

	var stringPool []string
	var events []androidManifestEvent
	offset := int(binary.LittleEndian.Uint16(data[2:4]))
	if offset < 8 {
		offset = 8
	}
	for offset+8 <= len(data) {
		chunkType := binary.LittleEndian.Uint16(data[offset : offset+2])
		headerSize := int(binary.LittleEndian.Uint16(data[offset+2 : offset+4]))
		chunkSize := int(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
		if headerSize < 8 || chunkSize < headerSize || offset+chunkSize > len(data) {
			break
		}
		chunk := data[offset : offset+chunkSize]
		switch chunkType {
		case axmlStringPoolType:
			pool, err := parseAXMLStringPool(chunk)
			if err != nil {
				return events, stringPool, err
			}
			stringPool = pool
		case axmlStartElement:
			event, ok := parseAXMLStartElement(chunk, stringPool)
			if ok {
				events = append(events, event)
			}
		case axmlEndElement:
			event, ok := parseAXMLEndElement(chunk, stringPool)
			if ok {
				events = append(events, event)
			}
		}
		offset += chunkSize
	}
	if len(events) == 0 {
		return events, stringPool, fmt.Errorf("no AXML elements parsed")
	}
	return events, uniqueSorted(stringPool), nil
}

func parseAXMLStringPool(chunk []byte) ([]string, error) {
	if len(chunk) < 28 {
		return nil, fmt.Errorf("AXML string pool too small")
	}
	headerSize := int(binary.LittleEndian.Uint16(chunk[2:4]))
	stringCount := int(binary.LittleEndian.Uint32(chunk[8:12]))
	flags := binary.LittleEndian.Uint32(chunk[16:20])
	stringsStart := int(binary.LittleEndian.Uint32(chunk[20:24]))
	if headerSize < 28 || stringsStart <= 0 || stringsStart > len(chunk) {
		return nil, fmt.Errorf("invalid AXML string pool header")
	}
	offsetTable := headerSize
	if offsetTable+stringCount*4 > len(chunk) {
		return nil, fmt.Errorf("invalid AXML string pool offsets")
	}
	utf8Pool := flags&axmlUTF8Flag != 0
	out := make([]string, 0, stringCount)
	for i := 0; i < stringCount; i++ {
		relative := int(binary.LittleEndian.Uint32(chunk[offsetTable+i*4 : offsetTable+i*4+4]))
		start := stringsStart + relative
		if start < 0 || start >= len(chunk) {
			out = append(out, "")
			continue
		}
		if utf8Pool {
			out = append(out, decodeAXMLUTF8String(chunk[start:]))
		} else {
			out = append(out, decodeAXMLUTF16String(chunk[start:]))
		}
	}
	return out, nil
}

func parseAXMLStartElement(chunk []byte, pool []string) (androidManifestEvent, bool) {
	if len(chunk) < 36 {
		return androidManifestEvent{}, false
	}
	name := axmlString(pool, binary.LittleEndian.Uint32(chunk[20:24]))
	attrStart := int(binary.LittleEndian.Uint16(chunk[24:26]))
	attrSize := int(binary.LittleEndian.Uint16(chunk[26:28]))
	attrCount := int(binary.LittleEndian.Uint16(chunk[28:30]))
	if attrSize <= 0 {
		attrSize = 20
	}
	attrBase := 16 + attrStart
	if name == "" || attrBase < 0 || attrBase > len(chunk) {
		return androidManifestEvent{}, false
	}
	attrs := make(map[string]string)
	for i := 0; i < attrCount; i++ {
		start := attrBase + i*attrSize
		if start+20 > len(chunk) {
			break
		}
		attrName := axmlString(pool, binary.LittleEndian.Uint32(chunk[start+4:start+8]))
		if attrName == "" {
			continue
		}
		rawValue := binary.LittleEndian.Uint32(chunk[start+8 : start+12])
		valueType := chunk[start+15]
		data := binary.LittleEndian.Uint32(chunk[start+16 : start+20])
		attrs[attrName] = axmlAttributeValue(pool, rawValue, valueType, data)
	}
	return androidManifestEvent{Start: true, Name: name, Attrs: attrs}, true
}

func parseAXMLEndElement(chunk []byte, pool []string) (androidManifestEvent, bool) {
	if len(chunk) < 24 {
		return androidManifestEvent{}, false
	}
	name := axmlString(pool, binary.LittleEndian.Uint32(chunk[20:24]))
	if name == "" {
		return androidManifestEvent{}, false
	}
	return androidManifestEvent{Start: false, Name: name}, true
}

func axmlString(pool []string, index uint32) string {
	if index == axmlNoIndex || int(index) < 0 || int(index) >= len(pool) {
		return ""
	}
	return pool[index]
}

func axmlAttributeValue(pool []string, rawValue uint32, valueType byte, data uint32) string {
	if rawValue != axmlNoIndex {
		return axmlString(pool, rawValue)
	}
	switch valueType {
	case 0x03:
		return axmlString(pool, data)
	case 0x10:
		return strconv.FormatInt(int64(int32(data)), 10)
	case 0x11:
		return fmt.Sprintf("0x%x", data)
	case 0x12:
		if data == 0 {
			return "false"
		}
		return "true"
	case 0x01:
		return fmt.Sprintf("@0x%08x", data)
	default:
		if data != 0 {
			return strconv.FormatUint(uint64(data), 10)
		}
		return ""
	}
}

func decodeAXMLUTF8String(data []byte) string {
	_, n1, ok := readAXMLLength8(data)
	if !ok {
		return ""
	}
	byteLen, n2, ok := readAXMLLength8(data[n1:])
	if !ok {
		return ""
	}
	start := n1 + n2
	end := start + byteLen
	if start < 0 || end > len(data) {
		return ""
	}
	return strings.ToValidUTF8(string(data[start:end]), "")
}

func decodeAXMLUTF16String(data []byte) string {
	charLen, n, ok := readAXMLLength16(data)
	if !ok {
		return ""
	}
	start := n
	end := start + charLen*2
	if start < 0 || end > len(data) {
		return ""
	}
	values := make([]uint16, 0, charLen)
	for i := start; i+1 < end; i += 2 {
		values = append(values, binary.LittleEndian.Uint16(data[i:i+2]))
	}
	return string(utf16.Decode(values))
}

func readAXMLLength8(data []byte) (int, int, bool) {
	if len(data) < 1 {
		return 0, 0, false
	}
	if data[0]&0x80 == 0 {
		return int(data[0]), 1, true
	}
	if len(data) < 2 {
		return 0, 0, false
	}
	return int(data[0]&0x7f)<<8 | int(data[1]), 2, true
}

func readAXMLLength16(data []byte) (int, int, bool) {
	if len(data) < 2 {
		return 0, 0, false
	}
	first := binary.LittleEndian.Uint16(data[0:2])
	if first&0x8000 == 0 {
		return int(first), 2, true
	}
	if len(data) < 4 {
		return 0, 0, false
	}
	second := binary.LittleEndian.Uint16(data[2:4])
	return int(first&0x7fff)<<16 | int(second), 4, true
}

func buildAPKInfoFromManifest(events []androidManifestEvent) APKInfo {
	var info APKInfo
	currentComponent := -1
	for _, event := range events {
		name := strings.ToLower(event.Name)
		if !event.Start {
			if isAndroidComponentTag(name) {
				currentComponent = -1
			}
			continue
		}
		switch name {
		case "manifest":
			info.PackageName = manifestAttr(event.Attrs, "package")
			info.VersionCode = manifestAttr(event.Attrs, "versionCode", "android:versionCode")
			info.VersionName = manifestAttr(event.Attrs, "versionName", "android:versionName")
		case "uses-sdk":
			info.MinSDK = manifestAttr(event.Attrs, "minSdkVersion", "android:minSdkVersion")
			info.TargetSDK = manifestAttr(event.Attrs, "targetSdkVersion", "android:targetSdkVersion")
		case "uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m":
			permission := manifestAttr(event.Attrs, "name", "android:name")
			if permission != "" {
				info.Permissions = appendPermissionUnique(info.Permissions, classifyAndroidPermission(permission))
			}
		case "application":
			config := manifestAttr(event.Attrs, "networkSecurityConfig", "android:networkSecurityConfig")
			if config != "" {
				info.NetworkSecurityConfig = appendUnique(info.NetworkSecurityConfig, config)
			}
		case "activity", "activity-alias", "service", "receiver", "provider":
			componentName := manifestAttr(event.Attrs, "name", "android:name")
			component := AndroidComponent{
				Type:       name,
				Name:       canonicalAndroidComponentName(componentName, info.PackageName),
				Permission: manifestAttr(event.Attrs, "permission", "android:permission", "readPermission", "writePermission"),
			}
			exported := manifestAttr(event.Attrs, "exported", "android:exported")
			if exported != "" {
				component.ExportedDeclared = true
				component.Exported = strings.EqualFold(exported, "true")
			}
			info.Components = append(info.Components, component)
			currentComponent = len(info.Components) - 1
		case "action":
			if currentComponent >= 0 {
				action := manifestAttr(event.Attrs, "name", "android:name")
				info.Components[currentComponent].IntentActions = appendUnique(info.Components[currentComponent].IntentActions, action)
			}
		case "category":
			if currentComponent >= 0 {
				category := manifestAttr(event.Attrs, "name", "android:name")
				info.Components[currentComponent].IntentCategories = appendUnique(info.Components[currentComponent].IntentCategories, category)
			}
		}
	}
	for i := range info.Components {
		info.Components[i].IntentActions = uniqueSorted(info.Components[i].IntentActions)
		info.Components[i].IntentCategories = uniqueSorted(info.Components[i].IntentCategories)
		if !info.Components[i].ExportedDeclared && len(info.Components[i].IntentActions) > 0 {
			info.Components[i].Exported = true
		}
		if info.Components[i].Exported {
			info.ExportedComponents = append(info.ExportedComponents, info.Components[i])
		}
	}
	info.NetworkSecurityConfig = uniqueSorted(info.NetworkSecurityConfig)
	return info
}

func analyzeDEXData(name string, data []byte, cfg Config) DEXInfo {
	info := DEXInfo{Name: name}
	stringsFound, total, truncated, version := parseDEXStrings(data, dexStringLimitForMode(cfg.Mode))
	info.Version = version
	info.StringsTotal = total
	info.StringsParsed = len(stringsFound)
	info.StringsTruncated = truncated
	info.APIHits = detectAndroidAPIHits(name, stringsFound)
	info.SuspiciousStrings = androidSuspiciousSamples(stringsFound, 40)
	info.IOCs = ExtractIOCsFromStringValues(stringsFound)
	return info
}

func parseDEXStrings(data []byte, limit int) ([]string, int, bool, string) {
	if len(data) < dexHeaderSize || !bytes.HasPrefix(data, []byte("dex\n")) {
		return nil, 0, false, ""
	}
	version := strings.TrimRight(string(data[4:7]), "\x00")
	stringIDsSize := int(binary.LittleEndian.Uint32(data[56:60]))
	stringIDsOff := int(binary.LittleEndian.Uint32(data[60:64]))
	if stringIDsSize < 0 || stringIDsOff < 0 || stringIDsOff+stringIDsSize*4 > len(data) {
		return nil, stringIDsSize, false, version
	}
	parseLimit := stringIDsSize
	truncated := false
	if limit > 0 && parseLimit > limit {
		parseLimit = limit
		truncated = true
	}
	out := make([]string, 0, parseLimit)
	for i := 0; i < parseLimit; i++ {
		offset := stringIDsOff + i*4
		stringDataOff := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		if stringDataOff < 0 || stringDataOff >= len(data) {
			continue
		}
		value := decodeDEXString(data[stringDataOff:])
		if value != "" {
			out = append(out, value)
		}
	}
	return out, stringIDsSize, truncated, version
}

func decodeDEXString(data []byte) string {
	_, consumed, ok := readULEB128(data)
	if !ok || consumed >= len(data) {
		return ""
	}
	end := consumed
	for end < len(data) && data[end] != 0x00 {
		end++
	}
	if end <= consumed {
		return ""
	}
	return strings.ToValidUTF8(string(data[consumed:end]), "")
}

func readULEB128(data []byte) (uint32, int, bool) {
	var value uint32
	for i := 0; i < 5 && i < len(data); i++ {
		b := data[i]
		value |= uint32(b&0x7f) << uint(7*i)
		if b&0x80 == 0 {
			return value, i + 1, true
		}
	}
	return 0, 0, false
}

func detectAndroidAPIHits(source string, values []string) []AndroidAPIHit {
	seen := map[string]struct{}{}
	var hits []AndroidAPIHit
	for _, value := range values {
		lower := strings.ToLower(value)
		for _, pattern := range androidAPIPatterns {
			if !hasAny(lower, pattern.Needles...) {
				continue
			}
			key := pattern.Category + "|" + pattern.Indicator
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			hits = append(hits, AndroidAPIHit{
				Category:  pattern.Category,
				Indicator: pattern.Indicator,
				Severity:  pattern.Severity,
				Source:    source,
			})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if severityRank(hits[i].Severity) == severityRank(hits[j].Severity) {
			return hits[i].Category < hits[j].Category
		}
		return severityRank(hits[i].Severity) > severityRank(hits[j].Severity)
	})
	return hits
}

func androidSuspiciousSamples(values []string, limit int) []string {
	keywords := []string{
		"android.permission.", "dexclassloader", "pathclassloader", "inmemorydexclassloader",
		"runtime.exec", "processbuilder", "smsmanager", "sendtextmessage", "accessibilityservice",
		"deviceadminreceiver", "system_alert_window", "request_install_packages", "addjavascriptinterface",
		"setjavascriptenabled", "loadlibrary", "secretkeyspec", "javax/crypto", "http://", "https://",
	}
	var out []string
	seen := map[string]struct{}{}
	for _, value := range values {
		lower := strings.ToLower(value)
		if !hasAny(lower, keywords...) {
			continue
		}
		preview := previewString(value, 180)
		if _, ok := seen[preview]; ok {
			continue
		}
		seen[preview] = struct{}{}
		out = append(out, preview)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func mergeDEXEvidence(result *ScanResult, dex DEXInfo) {
	MergeIOCSet(&result.IOCs, dex.IOCs)
	for _, hit := range dex.APIHits {
		result.Functions = append(result.Functions, FunctionHit{
			Name:     hit.Indicator,
			Family:   "android " + hit.Category,
			Severity: hit.Severity,
			Source:   "dex:" + dex.Name,
		})
	}
	for _, sample := range dex.SuspiciousStrings {
		result.SuspiciousStrings = appendUnique(result.SuspiciousStrings, "dex:"+dex.Name+": "+sample)
	}
}

func classifyAndroidPermission(name string) AndroidPermission {
	base := androidPermissionBase(name)
	permission := AndroidPermission{Name: name, Risk: "Info", Protection: "normal"}
	if category, ok := androidDangerousPermissions[base]; ok {
		permission.Risk = "Medium"
		permission.Protection = "dangerous"
		permission.Category = category
	}
	if category, ok := androidSpecialPermissions[base]; ok {
		permission.Risk = "High"
		permission.Protection = "special/signature"
		permission.Category = category
		if base == "QUERY_ALL_PACKAGES" || base == "REQUEST_INSTALL_PACKAGES" || base == "WRITE_SETTINGS" {
			permission.Risk = "Medium"
		}
	}
	return permission
}

func appendPermissionUnique(values []AndroidPermission, permission AndroidPermission) []AndroidPermission {
	if permission.Name == "" {
		return values
	}
	for _, existing := range values {
		if existing.Name == permission.Name {
			return values
		}
	}
	return append(values, permission)
}

func androidPermissionBase(name string) string {
	name = strings.TrimSpace(name)
	if idx := strings.LastIndex(name, "."); idx >= 0 && idx+1 < len(name) {
		name = name[idx+1:]
	}
	return strings.ToUpper(name)
}

func androidPermissionsByMinimumRisk(values []AndroidPermission, minimum string) []AndroidPermission {
	minRank := severityRank(minimum)
	var out []AndroidPermission
	for _, value := range values {
		if severityRank(value.Risk) >= minRank {
			out = append(out, value)
		}
	}
	return out
}

func firstPermissionNames(values []AndroidPermission, limit int) []string {
	out := make([]string, 0, len(values))
	for i, permission := range values {
		if limit > 0 && i >= limit {
			break
		}
		out = append(out, permission.Name)
	}
	return out
}

func hasAndroidPermission(info *APKInfo, base string) bool {
	if info == nil {
		return false
	}
	base = strings.ToUpper(base)
	for _, permission := range info.Permissions {
		if androidPermissionBase(permission.Name) == base {
			return true
		}
	}
	return false
}

func hasComponentPermission(info *APKInfo, base string) bool {
	if info == nil {
		return false
	}
	base = strings.ToUpper(base)
	for _, component := range info.Components {
		if androidPermissionBase(component.Permission) == base {
			return true
		}
	}
	return false
}

func hasComponentAction(info *APKInfo, needle string) bool {
	if info == nil {
		return false
	}
	needle = strings.ToLower(needle)
	for _, component := range info.Components {
		for _, action := range component.IntentActions {
			if strings.Contains(strings.ToLower(action), needle) {
				return true
			}
		}
	}
	return false
}

func hasAndroidDEXHit(result ScanResult, category string) bool {
	for _, dex := range result.DEXFiles {
		for _, hit := range dex.APIHits {
			if strings.EqualFold(hit.Category, category) {
				return true
			}
		}
	}
	return false
}

func dexContainsAny(result ScanResult, needles ...string) bool {
	for _, dex := range result.DEXFiles {
		for _, sample := range dex.SuspiciousStrings {
			if hasAny(strings.ToLower(sample), needles...) {
				return true
			}
		}
	}
	return false
}

func exportedComponentsWithoutPermission(info *APKInfo) []AndroidComponent {
	if info == nil {
		return nil
	}
	var out []AndroidComponent
	for _, component := range info.ExportedComponents {
		if isLauncherActivity(component) {
			continue
		}
		if strings.TrimSpace(component.Permission) == "" {
			out = append(out, component)
		}
	}
	return out
}

func isLauncherActivity(component AndroidComponent) bool {
	if component.Type != "activity" && component.Type != "activity-alias" {
		return false
	}
	hasMain := false
	hasLauncher := false
	for _, action := range component.IntentActions {
		if strings.EqualFold(action, "android.intent.action.MAIN") {
			hasMain = true
			break
		}
	}
	for _, category := range component.IntentCategories {
		if strings.EqualFold(category, "android.intent.category.LAUNCHER") {
			hasLauncher = true
			break
		}
	}
	return hasMain && hasLauncher
}

func isAndroidComponentTag(name string) bool {
	switch strings.ToLower(name) {
	case "activity", "activity-alias", "service", "receiver", "provider":
		return true
	default:
		return false
	}
}

func canonicalAndroidComponentName(name, packageName string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if strings.HasPrefix(name, ".") && packageName != "" {
		return packageName + name
	}
	if !strings.Contains(name, ".") && packageName != "" {
		return packageName + "." + name
	}
	return name
}

func manifestAttr(attrs map[string]string, names ...string) string {
	if len(attrs) == 0 {
		return ""
	}
	for _, name := range names {
		for key, value := range attrs {
			cleanKey := strings.TrimPrefix(key, "android:")
			cleanName := strings.TrimPrefix(name, "android:")
			if strings.EqualFold(key, name) || strings.EqualFold(cleanKey, cleanName) {
				return strings.TrimSpace(value)
			}
		}
	}
	return ""
}

func ExtractIOCsFromStringValues(values []string) IOCSet {
	extracted := make([]ExtractedString, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			extracted = append(extracted, ExtractedString{Value: value, Encoding: "apk"})
		}
	}
	return ExtractIOCsFromStrings(extracted)
}

func readZipEntryLimited(file *zip.File, maxBytes int64) ([]byte, bool, error) {
	handle, err := file.Open()
	if err != nil {
		return nil, false, err
	}
	defer handle.Close()
	data, err := io.ReadAll(io.LimitReader(handle, maxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > maxBytes {
		return data[:maxBytes], true, nil
	}
	return data, false, nil
}

func apkEntryReadMax(cfg Config) int64 {
	switch cfg.Mode {
	case "quick":
		return 12 * 1024 * 1024
	case "standard":
		return 32 * 1024 * 1024
	default:
		return 96 * 1024 * 1024
	}
}

func dexStringLimitForMode(mode string) int {
	switch mode {
	case "quick":
		return 5000
	case "standard":
		return 25000
	default:
		return 100000
	}
}

func dexFileLimitForMode(mode string) int {
	switch mode {
	case "quick":
		return 1
	case "standard":
		return 3
	default:
		return 12
	}
}

func cleanAPKEntryName(name string) string {
	return strings.TrimPrefix(strings.ReplaceAll(filepath.Clean(strings.ReplaceAll(name, "\\", "/")), "\\", "/"), "./")
}

func isEmbeddedAndroidPayload(lowerName string) bool {
	if lowerName == "classes.dex" || strings.HasPrefix(lowerName, "classes") && strings.HasSuffix(lowerName, ".dex") {
		return false
	}
	if strings.HasPrefix(lowerName, "lib/") && strings.HasSuffix(lowerName, ".so") {
		return false
	}
	return strings.HasSuffix(lowerName, ".dex") ||
		strings.HasSuffix(lowerName, ".jar") ||
		strings.HasSuffix(lowerName, ".apk") ||
		strings.HasSuffix(lowerName, ".so") ||
		strings.HasSuffix(lowerName, ".elf")
}

func firstStrings(values []string, limit int) []string {
	if limit <= 0 || len(values) <= limit {
		return values
	}
	return values[:limit]
}
