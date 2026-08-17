rule ARGOS_Bash_Reverse_Shell_Script
{
    meta:
        description = "Detects bash reverse shell scripts using /dev/tcp redirection - multiple variants"
        author = "ARGOS SOC - Miguel Reguero"
        date = "2026-08-17"
        reference = "ESC05 - ARGOS TFM - T1059.004"
        reference2 = "Inspired by Neo23x0/apt_eqgrp_apr17 - extended for generic bash reverse shell variants"
        mitre = "T1059.004"
        score = 80

    strings:
        $dev_tcp   = "/dev/tcp/" ascii nocase
        $bash_i    = "bash -i" ascii nocase
        $redirect1 = ">&" ascii
        $redirect2 = "0>&1" ascii
        $exec_bash = "exec bash" ascii nocase
        $bin_bash  = "/bin/bash" ascii nocase

    condition:
        filesize < 2MB
        and $dev_tcp
        and 2 of ($bash_i, $redirect1, $redirect2, $exec_bash, $bin_bash)
}
