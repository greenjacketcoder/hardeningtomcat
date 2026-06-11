<#
.SYNOPSIS
    Signs every PowerShell file in the HardeningTomcat module tree.
.DESCRIPTION
    Run this ONCE the code has stabilized — not during active development, since
    every edit invalidates the signature. Under AllSigned, the engine dot-sources
    handler .ps1 files at runtime, so EVERY script must be signed, not just the
    root .psm1/.psd1. This globs the whole tree to handle that.
.EXAMPLE
    .\Sign-Module.ps1 -CertSubject "CN=Alex HardeningTomcat Signing"
.NOTES
    Create the cert once (elevated):
      New-SelfSignedCertificate -Subject "CN=Alex HardeningTomcat Signing" `
        -Type CodeSigningCert -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(5)
    Then trust it: export the .cer and Import-Certificate into
      Cert:\CurrentUser\Root  and  Cert:\CurrentUser\TrustedPublisher
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $CertSubject,

    [string] $TimestampServer = 'http://timestamp.digicert.com'
)

$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
        Where-Object { $_.Subject -eq $CertSubject } |
        Select-Object -First 1

if (-not $cert) { throw "No code-signing cert found with subject '$CertSubject' in Cert:\CurrentUser\My" }

$root  = $PSScriptRoot
$files = Get-ChildItem -Path $root -Recurse -Include '*.ps1', '*.psm1', '*.psd1'

Write-Host "Signing $($files.Count) files with $($cert.Subject)..." -ForegroundColor Cyan
foreach ($f in $files) {
    $res = Set-AuthenticodeSignature -FilePath $f.FullName -Certificate $cert `
        -HashAlgorithm SHA256 -TimestampServer $TimestampServer
    $color = if ($res.Status -eq 'Valid') { 'Green' } else { 'Red' }
    Write-Host ("  [{0}] {1}" -f $res.Status, $f.Name) -ForegroundColor $color
}
Write-Host "Done. Verify with: Get-AuthenticodeSignature <file> | Format-List Status,SignerCertificate" -ForegroundColor Cyan
