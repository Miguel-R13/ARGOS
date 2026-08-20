rule ARGOS_PowerShell_Base64_Decoder
{
    meta:
        description = "Detects PowerShell scripts decoding Base64 payload and writing to disk - T1027"
        author = "ARGOS SOC - Miguel Reguero"
        date = "2026-08-20"
        reference = "ESC20 - ARGOS TFM - T1027"
        mitre = "T1027"
        score = 80
    strings:
        $from_b64    = "FromBase64String" ascii wide nocase
        $write_bytes = "WriteAllBytes" ascii wide nocase
        $io_file     = "[IO.File]" ascii wide nocase
        $io_file2    = "[System.IO.File]" ascii wide nocase
        $convert     = "[Convert]::" ascii wide nocase
        $out_file    = "Out-File" ascii wide nocase
    condition:
        filesize < 5MB
        and $from_b64
        and (
            1 of ($write_bytes, $io_file, $io_file2)
            or
            ($convert and $out_file)
        )
}
