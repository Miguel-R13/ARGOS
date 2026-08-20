rule ARGOS_PS_AMSI_Bypass
{
    meta:
        description = "Detects PowerShell AMSI bypass techniques - T1562.001"
        author = "ARGOS SOC - Miguel Reguero"
        date = "2026-08-20"
        mitre = "T1562.001"
        score = 90
    strings:
        $amsi_ctx    = "amsiContext" ascii wide nocase
        $amsi_scan   = "AmsiScanBuffer" ascii wide nocase
        $amsi_failed = "amsiInitFailed" ascii wide nocase
        $amsi_utils  = "AmsiUtils" ascii wide nocase
    condition:
        filesize < 5MB
        and 1 of them
}
