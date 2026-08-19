rule ARGOS_SMB_Lateral_Movement_Tool
{
    meta:
        description = "Detects offensive tools deposited via SMB for lateral movement - T1570"
        author = "ARGOS SOC - Miguel Reguero"
        date = "2026-08-19"
        reference = "ESC17/ESC18 - ARGOS TFM - T1570"
        mitre = "T1570"
        score = 90
    strings:
        $mz_magic       = { 4D 5A }
        $mimi_sekurlsa  = "sekurlsa" ascii wide nocase
        $mimi_lsadump   = "lsadump" ascii wide nocase
        $mimi_privilege = "privilege::debug" ascii wide nocase
        $mimi_kerberos  = "kerberos::" ascii wide nocase
        $psexec_svc     = "PSEXESVC" ascii wide
        $c2_meterpreter = "meterpreter" ascii wide nocase
        $c2_reflective  = "ReflectiveDll" ascii
        $c2_cobalt      = "cobaltstrike" ascii wide nocase
        $c2_sliver      = "sliver-implant" ascii wide nocase
        $c2_havoc       = "HavocC2" ascii wide nocase
        $c2_chisel      = "jpillora/chisel" ascii
        $c2_ligolo      = "ligolo-ng" ascii wide nocase
    condition:
        filesize < 50MB
        and $mz_magic at 0
        and (
            1 of ($mimi_*)
            or
            $psexec_svc
            or
            1 of ($c2_*)
        )
}
