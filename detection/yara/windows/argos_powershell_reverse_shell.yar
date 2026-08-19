rule ARGOS_PowerShell_Reverse_Shell
{
    meta:
        description = "Detects PowerShell reverse shell scripts using TCPClient pattern - T1059.001"
        author = "ARGOS SOC - Miguel Reguero"
        date = "2026-08-19"
        reference = "ESC15 - ARGOS TFM - T1059.001"
        reference2 = "SigmaHQ proc_creation_win_powershell_reverse_shell - TCPClient+GetStream pattern confirmed"
        mitre = "T1059.001"
        score = 85
    strings:
        $net_tcp    = "Net.Sockets.TCPClient" ascii wide nocase
        $get_stream = "GetStream" ascii wide nocase
        $stream_rd  = "StreamReader" ascii wide nocase
        $stream_wr  = "StreamWriter" ascii wide nocase
        $iex        = "iex " ascii wide nocase
        $invoke     = "Invoke-Expression" ascii wide nocase
    condition:
        filesize < 5MB
        and $net_tcp
        and $get_stream
        and 1 of ($iex, $invoke, $stream_rd, $stream_wr)
}
