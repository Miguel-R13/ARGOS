rule ARGOS_LOLBAS_Download_URL
{
    meta:
        description = "Detects bitsadmin/msiexec/wmic downloading from remote URLs - T1218"
        author = "ARGOS SOC - Miguel Reguero"
        date = "2026-08-20"
        reference = "ESC23 - ARGOS TFM - T1218"
        mitre = "T1218"
        score = 80
    strings:
        $bits_transfer = /bitsadmin\s+\/transfer\s+.{0,100}https?:\/\// ascii wide nocase
        $bits_download = /bitsadmin\s+\/download\s+.{0,100}https?:\/\// ascii wide nocase
        $msiexec_url   = /msiexec\s+\/i\s+https?:\/\// ascii wide nocase
        $wmic_url      = /wmic\s+process\s+call\s+create\s+.{0,100}https?:\/\// ascii wide nocase
    condition:
        filesize < 5MB
        and 1 of them
}
