rule ARGOS_LSASS_Minidump
{
    meta:
        description = "Detects LSASS memory dump files used for credential extraction - T1003.001"
        author = "ARGOS SOC - Miguel Reguero"
        date = "2026-08-20"
        reference = "ESC21/ESC22 - ARGOS TFM - T1003.001"
        mitre = "T1003.001"
        score = 95
    strings:
        $mdmp_magic = { 4D 44 4D 50 }
        $lsass_ref  = "lsass.exe" ascii wide nocase
        $lsass_ref2 = "lsass" ascii wide nocase
    condition:
        filesize > 10MB
        and filesize < 1000MB
        and $mdmp_magic at 0
        and 1 of ($lsass_ref, $lsass_ref2)
}
