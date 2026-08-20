rule ARGOS_LOLBAS_Proxy_URL
{
    meta:
        description = "Detects regsvr32/rundll32 executing remote URLs - T1218"
        author = "ARGOS SOC - Miguel Reguero"
        date = "2026-08-20"
        reference = "ESC23 - ARGOS TFM - T1218"
        mitre = "T1218"
        score = 80
    strings:
        $regsvr32_url = /regsvr32\s+.{0,50}https?:\/\// ascii wide nocase
        $rundll32_url = /rundll32\s+.{0,50}https?:\/\// ascii wide nocase
    condition:
        filesize < 5MB
        and 1 of them
}
