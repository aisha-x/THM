@{
    ModuleVersion = '1.0'
    GUID = 'f420a47d-0079-41df-8fec-f9ac1ee8d704'
    Author = 'THM/uJohn'
    Description = 'TryHackMe Module that summarises Windows log files for an emulation exercise.'
    PowerShellVersion = '5.1'
    FunctionsToExport = 'THM-LogStats-All', 'THM-LogStats-Application', 'THM-LogStats-Security', 'THM-LogStats-System', 'THM-LogStats-Powershell', 'THM-LogStats-PowerShell-Operational', 'THM-LogStats-Aurora', 'THM-LogStats-Sysmon', 'THM-LogClear-All', 'THM-LogStats-Flag'
    AliasesToExport = '*'
    CmdletsToExport = '*'
    VariablesToExport = '*'
    RootModule = 'THM-Utils.psm1'
    PrivateData = @{
        PSData = @{
            Tags = @('ExcludeLogging')
            LicenseUri = ''
            ProjectUri = ''
            ReleaseNotes = ''
        }
    }
}
