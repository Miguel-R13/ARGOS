rule ARGOS_PS_SecureString_Obfuscation
{
    meta:
        description = "Detects PowerShell SecureString obfuscation technique - T1027.010"
        author = "ARGOS SOC - Miguel Reguero"
        date = "2026-08-20"
        mitre = "T1027"
        score = 80
    strings:
        $secure_str = "ConvertTo-SecureString" ascii wide nocase
        $bstr       = "SecureStringToBSTR" ascii wide nocase
        $iex        = "IEX" ascii wide nocase
        $invoke     = "Invoke-Expression" ascii wide nocase
    condition:
        filesize < 5MB
        and $secure_str
        and ($bstr or 1 of ($iex, $invoke))
}
