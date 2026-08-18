rule ARGOS_Reverse_Shell_Interpreted_Languages
{
    meta:
        description = "Detects reverse shell scripts in Python and Perl - T1059.006/T1059.003"
        author = "ARGOS SOC - Miguel Reguero"
        date = "2026-08-18"
        reference = "ESC10 - ARGOS TFM - T1059.006/T1059.003"
        reference2 = "Neo23x0 gen_python_reverse_shell covers only Base64 encoded Python - ARGOS extends to plaintext Python and Perl"
        mitre = "T1059.006"
        score = 80

    strings:
        // Python - imports de red invariantes
        $py_socket   = "import socket" ascii nocase
        $py_connect  = ".connect(" ascii
        $py_dup2     = "dup2(" ascii
        $py_popen    = "popen(" ascii nocase
        $py_sub      = "subprocess" ascii nocase
        $py_recv     = ".recv(" ascii

        // Python - ejecucion de comandos
        $py_os_sys   = "os.system(" ascii nocase
        $py_shell    = "shell=True" ascii

        // Perl - imports y funciones de red invariantes
        $pl_socket   = "use Socket" ascii
        $pl_connect  = "connect(S," ascii
        $pl_exec     = "exec(\"/bin/sh" ascii
        $pl_fork     = "fork()" ascii
        $pl_inet     = "INET_ATON" ascii nocase

        // Indicadores de reverse shell en ambos lenguajes
        $rs_stdin    = "STDIN" ascii
        $rs_stdout   = "STDOUT" ascii

    condition:
        filesize < 5MB
        and (
            ($py_socket and $py_connect and 1 of ($py_dup2, $py_popen, $py_sub, $py_os_sys))
            or
            ($py_socket and $py_connect and $py_recv and $py_shell)
            or
            ($pl_socket and $pl_connect and $pl_exec)
            or
            ($pl_socket and $pl_inet and $pl_fork and 1 of ($rs_stdin, $rs_stdout))
        )
}
