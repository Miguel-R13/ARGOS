rule ARGOS_PS_String_Obfuscation
{
    meta:
        description = "Detects PowerShell string manipulation obfuscation - T1027.010"
        author = "ARGOS SOC - Miguel Reguero"
        date = "2026-08-20"
        mitre = "T1027"
        score = 75
    strings:
        $iex        = "IEX" ascii wide nocase
        $invoke     = "Invoke-Expression" ascii wide nocase
        $str_join   = "-Join" ascii wide nocase
        $str_rev    = "RightToLeft" ascii wide nocase
        $char_cast  = "[char]" ascii wide nocase
        $str_format = "-f '" ascii wide nocase
    condition:
        filesize < 5MB
        and 1 of ($iex, $invoke)
        and 2 of ($str_join, $str_rev, $char_cast, $str_format)
}
