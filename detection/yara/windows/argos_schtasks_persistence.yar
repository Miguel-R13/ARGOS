rule ARGOS_PowerShell_Schtasks_Persistence
{
    meta:
        description = "Detects scripts creating scheduled tasks with malicious payload - T1053.005"
        author = "ARGOS SOC - Miguel Reguero"
        date = "2026-08-19"
        reference = "ESC16 - ARGOS TFM - T1053.005"
        mitre = "T1053.005"
        score = 80
    strings:
        $schtasks = "schtasks" ascii wide nocase
        $create   = "/create" ascii wide nocase
        $tr       = "/tr" ascii wide nocase
        $ps_exe   = "powershell" ascii wide nocase
        $cmd_exe  = "cmd.exe" ascii wide nocase
        $hidden   = "/windowstyle hidden" ascii wide nocase
        $bypass   = "bypass" ascii wide nocase
        $encoded  = "-EncodedCommand" ascii wide nocase
        $appdata  = "AppData" ascii wide nocase
        $pub      = "C:\\Users\\Public" ascii wide nocase
        $tmp      = "\\Temp\\" ascii wide nocase
    condition:
        filesize < 5MB
        and $schtasks
        and $create
        and $tr
        and (
            1 of ($ps_exe, $cmd_exe)
            or
            1 of ($hidden, $bypass, $encoded)
            or
            1 of ($appdata, $pub, $tmp)
        )
}
