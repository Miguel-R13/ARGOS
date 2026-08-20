rule ARGOS_PS_EncodedCommand
{
    meta:
        description = "Detects PowerShell EncodedCommand and Base64 Unicode decode - T1027.010"
        author = "ARGOS SOC - Miguel Reguero"
        date = "2026-08-20"
        mitre = "T1027"
        score = 80
    strings:
        $enc_cmd   = "-EncodedCommand" ascii wide nocase
        $enc_short = " -enc " ascii wide nocase
        $enc_ec    = " -ec " ascii wide nocase
        $from_b64  = "FromBase64String" ascii wide nocase
        $unicode   = "Unicode.GetString" ascii wide nocase
    condition:
        filesize < 5MB
        and (
            1 of ($enc_cmd, $enc_short, $enc_ec)
            or
            ($from_b64 and $unicode)
        )
}
