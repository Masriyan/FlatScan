rule FlatScan_mercuristealer_ee77c051 {
  meta:
    author = "FlatScan by sudo3rs"
    description = "Auto-generated static hunting rule from FlatScan analysis"
    generated_utc = "2026-04-26T14:48:59Z"
    sample_name = "mercuristealer"
    sha256 = "ee77c05139a72dc3f1c86391c2bb0c16f198249ae4f099adf3f27ec3a7f0cf4b"
    verdict = "Likely malicious"
    risk_score = 100
    malware_type = "Browser credential stealer, Discord token/webhook stealer, Information stealer, Persistent Windows malware"
    pe_import_hash = "ca9c1a21c844044339d322ce95f7ca48"
  strings:
    $url001 = "http://ip-api.com//json/" ascii wide
    $url002 = "https://cdn.discordapp.com/avatars/" ascii wide
    $url003 = "https://discord.com/api/webhooks/916761581130489898/1CYGjUXn8d32Ju3UPg9zytSEyvPzaB1aXQhFvkHjipi_WnYU1XfqIqvCYbuhVxLYUE2e" ascii wide
    $url004 = "https://discordapp.com/api/v8/users/@me" ascii wide
    $url005 = "https://i.imgur.com/vgxBhmx.png" ascii wide
    $url006 = "https://ip4.seeip.org" ascii wide
    $url007 = "https://www.countryflags.io/" ascii wide
    $dom001 = "cdn.discordapp.com" ascii wide nocase
    $dom002 = "discord.com" ascii wide nocase
    $dom003 = "discordapp.com" ascii wide nocase
    $dom004 = "github.com" ascii wide nocase
    $dom005 = "i.imgur.com" ascii wide nocase
    $dom006 = "ip-api.com" ascii wide nocase
    $dom007 = "ip4.seeip.org" ascii wide nocase
    $dom008 = "myapplication.app" ascii wide nocase
    $dom009 = "roblox.com" ascii wide nocase
    $dom010 = "system.io" ascii wide nocase
    $dom011 = "system.net" ascii wide nocase
    $dom012 = "www.countryflags.io" ascii wide nocase
    $str001 = "Decrypt" ascii wide nocase
    $str002 = "BCryptEncrypt" ascii wide nocase
    $str003 = "BCryptDecrypt" ascii wide nocase
    $str004 = "DecryptWithKey" ascii wide nocase
    $str005 = "encryptedData" ascii wide nocase
    $str006 = "vmware" ascii wide nocase
    $str007 = "SYSTEM\\CurrentControlSet\\Enum\\SCSI\\Disk&Ven_VMware_&Prod_VMware_Virtual_S" ascii wide nocase
    $str008 = "SOFTWARE\\VMWare, Inc.\\VMWare Tools" ascii wide nocase
    $str009 = "HARDWARE\\ACPI\\DSDT\\VBOX_" ascii wide nocase
    $str010 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $str011 = "https://discord.com/api/webhooks/916761581130489898/1CYGjUXn8d32Ju3UPg9zytSEyvPzaB1aXQhFvkHjipi_WnYU1XfqIqvCYbuhVxLYUE2e" ascii wide nocase
    $str012 = "BCrypt.BCryptDecrypt() (get size) failed with status code: {0}" ascii wide nocase
    $str013 = "BCrypt.BCryptDecrypt(): authentication tag mismatch" ascii wide nocase
    $str014 = "BCrypt.BCryptDecrypt() failed with status code:{0}" ascii wide nocase
    $str015 = "\"encrypted_key\":\"(.*?)\"" ascii wide nocase
    $str016 = "Unable to decrypt" ascii wide nocase
    $type001 = "Browser credential stealer" ascii wide nocase
    $type002 = "Discord token/webhook stealer" ascii wide nocase
    $type003 = "Information stealer" ascii wide nocase
    $type004 = "Persistent Windows malware" ascii wide nocase
  condition:
    uint16(0) == 0x5a4d and (
      any of ($url*) or
      any of ($dom*) or
      2 of ($str*) or
      any of ($type*)
    )
}
