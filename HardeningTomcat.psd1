@{
    RootModule        = 'HardeningTomcat.psm1'
    ModuleVersion     = '0.6.1'
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
            Tags         = @('Security', 'Hardening', 'Windows', 'Audit', 'CIS')
            ReleaseNotes = 'v0.1.0 beta: engine core, JSON finding format, handlers for Registry/service/auditpol/secedit. Recon+Survey+Strike modes. Strike (apply) gated behind -Force.'
        }
    }
}
