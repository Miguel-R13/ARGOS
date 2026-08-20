rule ARGOS_PS_Compression_Obfuscation
{
    meta:
        description = "Detects PowerShell GZip/Deflate compression obfuscation - T1027.010"
        author = "ARGOS SOC - Miguel Reguero"
        date = "2026-08-20"
        mitre = "T1027"
        score = 80
    strings:
        $gzip    = "GzipStream" ascii wide nocase
        $deflate = "DeflateStream" ascii wide nocase
        $iex     = "IEX" ascii wide nocase
        $invoke  = "Invoke-Expression" ascii wide nocase
    condition:
        filesize < 5MB
        and 1 of ($gzip, $deflate)
        and 1 of ($iex, $invoke)
}
