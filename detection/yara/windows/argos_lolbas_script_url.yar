rule ARGOS_LOLBAS_Script_URL
{
    meta:
        description = "Detects mshta/wscript/cscript executing remote URLs - T1218"
        author = "ARGOS SOC - Miguel Reguero"
        date = "2026-08-20"
        reference = "ESC23 - ARGOS TFM - T1218"
        mitre = "T1218"
        score = 80
    strings:
        $mshta_url   = /mshta\s+https?:\/\// ascii wide nocase
        $wscript_url = /wscript\s+https?:\/\// ascii wide nocase
        $cscript_url = /cscript\s+https?:\/\// ascii wide nocase
    condition:
        filesize < 5MB
        and 1 of them
}
