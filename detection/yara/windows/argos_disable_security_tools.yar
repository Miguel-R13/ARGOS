rule ARGOS_PowerShell_Disable_Security_Tools
{
    meta:
        description = "Detects scripts disabling security tools - multiple vectors - T1562.001"
        author = "ARGOS SOC - Miguel Reguero"
        date = "2026-08-19"
        reference = "ESC19 - ARGOS TFM - T1562.001"
        mitre = "T1562.001"
        score = 85
    strings:
        $mp_set            = "Set-MpPreference" ascii wide nocase
        $mp_disable_rt     = "DisableRealtimeMonitoring" ascii wide nocase
        $mp_disable_beh    = "DisableBehaviorMonitoring" ascii wide nocase
        $mp_disable_script = "DisableScriptScanning" ascii wide nocase
        $mp_disable_block  = "DisableBlockAtFirstSeen" ascii wide nocase
        $mp_add            = "Add-MpPreference" ascii wide nocase
        $exclusion_path    = "ExclusionPath" ascii wide nocase
        $exclusion_proc    = "ExclusionProcess" ascii wide nocase
        $mpcmdrun          = "MpCmdRun" ascii wide nocase
        $remove_def        = "RemoveDefinitions" ascii wide nocase
        $stop_service      = "Stop-Service" ascii wide nocase
        $net_stop          = "net stop" ascii wide nocase
        $sc_config         = "sc config" ascii wide nocase
        $svc_defender      = "WinDefend" ascii wide nocase
        $svc_wazuh         = "WazuhSvc" ascii wide nocase
        $svc_sysmon        = "Sysmon" ascii wide nocase
        $wevtutil_cl       = "wevtutil cl" ascii wide nocase
        $wevtutil_clr      = "wevtutil.exe cl" ascii wide nocase
    condition:
        filesize < 5MB
        and (
            ($mp_set and 1 of ($mp_disable_rt, $mp_disable_beh, $mp_disable_script, $mp_disable_block))
            or
            ($mp_add and 1 of ($exclusion_path, $exclusion_proc))
            or
            ($mpcmdrun and $remove_def)
            or
            (1 of ($stop_service, $net_stop, $sc_config) and 1 of ($svc_defender, $svc_wazuh, $svc_sysmon))
            or
            1 of ($wevtutil_cl, $wevtutil_clr)
        )
}
