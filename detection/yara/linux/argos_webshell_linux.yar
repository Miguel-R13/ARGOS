rule ARGOS_Webshell_Linux
{
    meta:
        description = "Detects PHP and Python webshells on Linux endpoints - T1505.003"
        author = "ARGOS SOC - Miguel Reguero"
        date = "2026-08-18"
        reference = "ARGOS TFM - T1505.003"
        reference2 = "Neo23x0 gen_webshells uses external variables not available in ARGOS AR pipeline - ARGOS uses universal regex patterns"
        mitre = "T1505.003"
        score = 85

    strings:
        // PHP tag de apertura obligatorio
        $php_tag = "<?php" ascii nocase

        // PHP webshell - patron universal: funcion de ejecucion + input HTTP
        $php_exec_input = /(\beval|\bassert|\bsystem|\bexec|\bshell_exec|\bpassthru|\bcreate_function|\bpreg_replace)\s*\(.{0,100}\$_(GET|POST|REQUEST|COOKIE|SERVER)/ nocase

        // China Chopper y variantes minimalistas - invariantes absolutos
        $chopper1 = "eval($_POST[" ascii nocase
        $chopper2 = "assert($_POST[" ascii nocase
        $chopper3 = "assert($_GET[" ascii nocase

        // Python webshell - patron universal: input HTTP + ejecucion de comandos
        $py_exec_input = /(os\.system|subprocess|eval|exec|compile)\s*\(.{0,100}\b(request\.|cgi\.|environ)/ nocase

    condition:
        filesize < 500KB
        and (
            ($php_tag and $php_exec_input)
            or
            1 of ($chopper1, $chopper2, $chopper3)
            or
            $py_exec_input
        )
}
