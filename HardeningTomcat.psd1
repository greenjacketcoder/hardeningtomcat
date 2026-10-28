@{
    RootModule        = 'HardeningTomcat.psm1'
    ModuleVersion     = '0.12.0'
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
            ReleaseNotes = 'v0.12.0 beta: accuracy fixes -- CIS/STIG user-rights findings now use set= (were false-failing), =|0 honors absence with a defaultValue, != findings are never applied, contains applies additively for auditpol, relocated lists pass the integrity gate; speed -- one secedit export per run, .NET registry reads, header-only auto-select scan, cached service/SID/binary lookups.'
        }
    }
}
