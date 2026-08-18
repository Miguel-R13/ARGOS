rule ARGOS_Bash_Crontab_Persistence
{
    meta:
        description = "Detects malicious payloads in crontab files - multiple vectors"
        author = "ARGOS SOC - Miguel Reguero"
        date = "2026-08-18"
        reference = "ESC06 - ARGOS TFM - T1053.003"
        reference2 = "No equivalent rule in Neo23x0/signature-base, ANY.RUN/YARA or ReversingLabs"
        mitre = "T1053.003"
        score = 90

    strings:
        // Expresiones temporales cron
        $cron1     = "* * * * *" ascii
        $cron2     = "@reboot" ascii nocase
        $cron3     = "@hourly" ascii nocase
        $cron4     = "/etc/cron" ascii nocase

        // Vector 1: bash reverse shell via /dev/tcp
        $dev_tcp   = "/dev/tcp/" ascii nocase
        $bash_i    = "bash -i" ascii nocase
        $redirect1 = ">&" ascii
        $redirect2 = "0>&1" ascii

        // Vector 2: descarga y ejecucion remota
        $curl_pipe = "curl" ascii nocase
        $wget_pipe = "wget" ascii nocase
        $pipe_bash = "| bash" ascii nocase
        $pipe_sh   = "| sh" ascii nocase

        // Vector 3: netcat reverse shell
        $nc_e1     = "nc -e" ascii nocase
        $nc_e2     = "ncat -e" ascii nocase
        $nc_bash   = "/bin/bash" ascii nocase

        // Vector 4: ejecucion desde /tmp (ruta de staging de atacantes)
        $tmp_exec  = "/tmp/" ascii

        // Vector 5: decodificacion base64 en cron
        $b64_decode = "base64 -d" ascii nocase
    
    condition:
        filesize < 1MB
        and 1 of ($cron1, $cron2, $cron3, $cron4)
        and (
            ($dev_tcp and 1 of ($bash_i, $redirect1, $redirect2))
            or
            (1 of ($curl_pipe, $wget_pipe) and 1 of ($pipe_bash, $pipe_sh))
            or
            (1 of ($nc_e1, $nc_e2) and $nc_bash)
            or
            $tmp_exec
            or
            $b64_decode
        )
}
