rule FlatScan_vidar_a758ff0a {
  meta:
    author = "FlatScan by sudo3rs"
    description = "Auto-generated static hunting rule from FlatScan analysis"
    generated_utc = "2026-08-13T18:18:29Z"
    sample_name = "vidar.exe"
    sha256 = "a758ff0a172386bd3d1efaba38bc94cd899080eb53039097c1b043c2c8c8bafc"
    verdict = "Likely malicious"
    risk_score = 100
    malware_type = "AsyncRAT, FormBook/XLoader, Generic ransomware, XWorm"
    pe_import_hash = "5292ba861fbedd8ccd6f23c56196bc91"
    rule_quality_score = 68
    expected_fp_risk = "medium"
  strings:
    $url001 = "https://go.dev/issue/66821):" ascii wide
    $dom001 = "eq.io" ascii wide nocase
    $dom002 = "go.dev" ascii wide nocase
    $dom003 = "godebugs.info" ascii wide nocase
    $dom004 = "time.local" ascii wide nocase
    $str001 = "Decrypt" ascii wide nocase
    $str002 = "Encrypt" ascii wide nocase
    $str003 = "lock: lock countbad system huge page sizearena already initialized to unused region of span bytes failed with errno=runtime: VirtualAlloc of /sched/gomaxprocs:threadsmissing typ..." ascii wide nocase
    $str004 = "crypto/internal/fips140/aes.encryptBlock" ascii wide nocase
    $str005 = "crypto/internal/fips140/aes.decryptBlock" ascii wide nocase
    $str006 = "crypto/internal/fips140/aes.encryptBlockGeneric" ascii wide nocase
    $str007 = "crypto/internal/fips140/aes.decryptBlockGeneric" ascii wide nocase
    $str008 = "crypto/internal/fips140/aes.(*CBCEncrypter).CryptBlocks" ascii wide nocase
    $str009 = "crypto/internal/fips140/aes.(*CBCDecrypter).CryptBlocks" ascii wide nocase
    $str010 = "crypto/internal/fips140/aes.NewCBCEncrypter" ascii wide nocase
    $str011 = "crypto/internal/fips140/aes.NewCBCDecrypter" ascii wide nocase
    $str012 = "crypto/internal/fips140/aes.encryptBlockAsm" ascii wide nocase
    $str013 = "crypto/internal/fips140/aes.decryptBlockAsm" ascii wide nocase
    $str014 = "crypto/internal/fips140/aes.EncryptBlockInternal" ascii wide nocase
    $str015 = "VirtualAlloc" ascii wide nocase
    $str016 = "crypto/internal/fips140/aes.encryptBlockAsm.abi0" ascii wide nocase
    $str017 = "crypto/internal/fips140/aes.decryptBlockAsm.abi0" ascii wide nocase
  condition:
    uint16(0) == 0x5a4d and (
      any of ($url*) or
      any of ($dom*) or
      2 of ($str*)
    )
}
