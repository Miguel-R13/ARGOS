rule ARGOS_Certutil_Base64_Decode_Script
{
    meta:
        description = "Detects scripts using certutil -decode to reconstruct binaries from Base64 - T1027"
        author = "ARGOS SOC - Miguel Reguero"
        date = "2026-08-20"
        reference = "ESC20 - ARGOS TFM - T1027"
        mitre = "T1027"
        score = 80
    strings:
        $cert_decode  = "certutil" ascii wide nocase
        $decode_flag  = "-decode" ascii wide nocase
        $cert_header  = "BEGIN CERTIFICATE" ascii wide
        $echo_begin   = "echo -----BEGIN CERTIFICATE-----" ascii wide nocase
        $echo_end     = "echo -----END CERTIFICATE-----" ascii wide nocase
    condition:
        filesize < 5MB
        and (
            ($cert_decode and $decode_flag)
            or
            ($echo_begin and $echo_end)
            or
            ($cert_decode and $cert_header)
        )
}
