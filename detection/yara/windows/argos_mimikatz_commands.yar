rule ARGOS_Mimikatz_Commands_Script
{
    meta:
        description = "Detects mimikatz commands in plaintext scripts - T1003.001"
        author = "ARGOS SOC - Miguel Reguero"
        date = "2026-08-20"
        reference = "ESC21/ESC22 - ARGOS TFM - T1003.001"
        mitre = "T1003.001"
        score = 90
    strings:
        $cmd_logonpass = "sekurlsa::logonpasswords" ascii wide nocase
        $cmd_dcsync    = "lsadump::dcsync" ascii wide nocase
        $cmd_sam       = "lsadump::sam" ascii wide nocase
        $cmd_cache     = "lsadump::cache" ascii wide nocase
        $cmd_golden    = "kerberos::golden" ascii wide nocase
        $cmd_silver    = "kerberos::silver" ascii wide nocase
        $cmd_pth       = "sekurlsa::pth" ascii wide nocase
        $invoke_mimi   = "Invoke-Mimikatz" ascii wide nocase
        $invoke_cred   = "Invoke-CredentialInjection" ascii wide nocase
        $dumpcreds     = "-dumpcreds" ascii wide nocase
    condition:
        filesize < 10MB
        and 1 of them
}
