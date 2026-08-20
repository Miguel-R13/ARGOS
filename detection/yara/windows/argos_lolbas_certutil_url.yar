rule ARGOS_LOLBAS_Certutil_URL
{
    meta:
        description = "Detects certutil downloading or processing remote URLs - T1105/T1218"
        author = "ARGOS SOC - Miguel Reguero"
        date = "2026-08-20"
        reference = "ESC23 - ARGOS TFM - T1105/T1218"
        mitre = "T1105"
        score = 80
    strings:
        $certutil  = "certutil" ascii wide nocase
        $urlcache  = "-urlcache" ascii wide nocase
        $split     = "-split" ascii wide nocase
        $url_http  = "http://" ascii wide nocase
        $url_https = "https://" ascii wide nocase
    condition:
        filesize < 5MB
        and $certutil
        and ($urlcache or $split)
        and 1 of ($url_http, $url_https)
}
