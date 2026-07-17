@{
    RootModule        = 'HardeningTomcat.psm1'
    ModuleVersion     = '0.11.0'
    GUID              = '8f3a1c2e-4b5d-4e6f-9a0b-1c2d3e4f5a6b'
    Author            = 'Alex'
    Description       = 'Modular, handler-based Windows configuration audit & hardening engine (beta). Inspired by HardeningKitty, rebuilt with a pluggable handler architecture and a unified audit/apply loop.'
    PowerShellVersion = '5.1'
    # Works on both Windows PowerShell 5.1 (Desktop) and PowerShell 7+ (Core) on Windows.
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport = @('Invoke-HardeningTomcat')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData = @{
        PSData = @{
            Tags         = @('Security', 'Hardening', 'Windows', 'Audit', 'CIS', 'Intune', 'STIG', 'Compliance')
            ReleaseNotes = 'v0.11.0 beta: CIS Intune finding lists (Windows 11 v5.0.0, Office v1.1.0), autoSelect list flag, literal registry value-name reads, shared secedit export helper, user-scope list guard, expanded Pester suite (engine end-to-end, auto-select, load-time validation).'
        }
    }
}
