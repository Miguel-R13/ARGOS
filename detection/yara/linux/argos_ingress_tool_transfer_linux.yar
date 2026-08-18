rule ARGOS_Ingress_Tool_Transfer_Linux
{
    meta:
        description = "Detects ELF executables in attacker staging paths - T1105"
        author = "ARGOS SOC - Miguel Reguero"
        date = "2026-08-18"
        reference = "ESC10 - ARGOS TFM - T1105"
        mitre = "T1105"
        score = 75

    strings:
        // Magic byte ELF - invariante absoluto de cualquier ejecutable Linux
        $elf_magic = { 7F 45 4C 46 }

        // C2 Frameworks modernos - strings invariantes documentados
        $c2_meterpreter  = "meterpreter" ascii nocase
        $c2_metasploit   = "metasploit" ascii nocase
        $c2_msfvenom     = "msfvenom" ascii nocase
        $c2_cobalt       = "cobaltstrike" ascii nocase
        $c2_beacon       = "ReflectiveDll" ascii
        $c2_sliver       = "sliver-implant" ascii nocase
        $c2_havoc        = "HavocC2" ascii nocase
        $c2_chisel       = "jpillora/chisel" ascii
        $c2_ligolo       = "ligolo-ng" ascii nocase

        // Argumentos sospechosos embebidos en binarios en rutas de staging
        $arg_listen_exec = "--listen" ascii nocase
        $arg_exec        = "--exec" ascii nocase
        $arg_reverse     = "reverse_tcp" ascii nocase
        $arg_stageless   = "stageless" ascii nocase
        $arg_shellcode   = "shellcode" ascii nocase

    condition:
        filesize < 50MB
        and $elf_magic at 0
        and (
            1 of ($c2_*)
            or
            2 of ($arg_*)
        )
}
