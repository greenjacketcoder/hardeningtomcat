<#
.SYNOPSIS
    Signs every PowerShell file in the HardeningTomcat module tree, and creates +
    signs a file catalog (.cat) covering the data files (finding lists + manifest).
.DESCRIPTION
    Run this ONCE the code has stabilized -- not during active development, since
    every edit invalidates the signature. Under AllSigned, the engine dot-sources
    handler .ps1 files at runtime, so EVERY script must be signed, not just the
    root .psm1/.psd1. This globs the whole tree to handle that.

    Two complementary protections are produced:
      1. Authenticode signatures on each .ps1/.psm1/.psd1 -- protects the CODE. A
         tampered handler (e.g. one edited to silently pass every check) fails its
         signature and will not load under AllSigned. This is the control that the
         finding-list manifest CANNOT provide, because the manifest only covers data.
      2. A signed file catalog (HardeningTomcat.cat) over the finding lists and the
         integrity manifest -- protects the DATA with a real, verifiable signature
         (a plain .sha256 text file cannot itself carry an Authenticode signature, so
         a catalog is the correct mechanism). _Integrity.ps1 can then verify the
         catalog signature, closing the manifest-tampering gap.

    Together: signing protects the handlers/engine; the manifest (now catalog-signed)
    protects the lists. Neither alone is sufficient; both are needed.
.EXAMPLE
    .\Sign-Module.ps1 -CertSubject "CN=Alex HardeningTomcat Signing"
.NOTES
    Create the cert once (elevated). Mark the private key NON-EXPORTABLE so it cannot
    be copied off this machine -- a signing key that can be exported is a signing key
    that can be stolen and used to sign malicious code in your name:

      New-SelfSignedCertificate -Subject "CN=Alex HardeningTomcat Signing" `
        -Type CodeSigningCert -KeySpec Signature -KeyExportPolicy NonExportable `
        -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(5)

    Then trust it: export the PUBLIC cert (.cer -- this contains no private key) and
    Import-Certificate into Cert:\CurrentUser\Root and Cert:\CurrentUser\TrustedPublisher:

      $c = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
           Where-Object Subject -eq "CN=Alex HardeningTomcat Signing"
      Export-Certificate -Cert $c -FilePath "$env:USERPROFILE\ht-signing.cer"
      Import-Certificate -FilePath "$env:USERPROFILE\ht-signing.cer" -CertStoreLocation Cert:\CurrentUser\Root
      Import-Certificate -FilePath "$env:USERPROFILE\ht-signing.cer" -CertStoreLocation Cert:\CurrentUser\TrustedPublisher

    Signing only BUYS protection if the machine runs under a signature-enforcing
    execution policy. After signing, set (per-machine, elevated):
      Set-ExecutionPolicy AllSigned          # strictest: every script must be signed
    or at minimum RemoteSigned. Under Bypass, signatures are decorative.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $CertSubject,

    [string] $TimestampServer = 'http://timestamp.digicert.com',

    # Skip the file-catalog step (sign code only). Catalog needs PS 5.1+ on Windows.
    [switch] $NoCatalog
)

# Guard: signing is a Windows-only operation (cert store + Authenticode).
if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) {
    throw "Signing must run on Windows (Authenticode + certificate store are Windows-only)."
}

$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
        Where-Object { $_.Subject -eq $CertSubject } |
        Select-Object -First 1

if (-not $cert) { throw "No code-signing cert found with subject '$CertSubject' in Cert:\CurrentUser\My" }

$root = $PSScriptRoot

# ---- 1) Sign the code (every script the engine may dot-source) ----------------
$files = Get-ChildItem -Path $root -Recurse -Include '*.ps1', '*.psm1', '*.psd1'
Write-Host "Signing $($files.Count) script file(s) with $($cert.Subject)..." -ForegroundColor Cyan
$failed = 0
foreach ($f in $files) {
    $res = Set-AuthenticodeSignature -FilePath $f.FullName -Certificate $cert `
        -HashAlgorithm SHA256 -TimestampServer $TimestampServer
    $color = if ($res.Status -eq 'Valid') { 'Green' } else { 'Red' }
    if ($res.Status -ne 'Valid') { $failed++ }
    Write-Host ("  [{0}] {1}" -f $res.Status, $f.Name) -ForegroundColor $color
}

# ---- 2) Create + sign a file catalog over the DATA (lists + manifest) ---------
# A catalog (.cat) hashes a set of files and is itself Authenticode-signed, giving the
# finding lists and the integrity manifest a real signature a plain text file can't hold.
if (-not $NoCatalog) {
    $catPath = Join-Path $root 'HardeningTomcat.cat'
    $listsRoot = Join-Path $root 'lists'
    if (Test-Path $listsRoot) {
        Write-Host "Creating file catalog over lists/ ..." -ForegroundColor Cyan
        try {
            # CatalogVersion 2 = SHA256 catalog (modern). Covers every file under lists/.
            New-FileCatalog -Path $listsRoot -CatalogFilePath $catPath -CatalogVersion 2 -ErrorAction Stop | Out-Null
            $catSig = Set-AuthenticodeSignature -FilePath $catPath -Certificate $cert `
                -HashAlgorithm SHA256 -TimestampServer $TimestampServer
            $cc = if ($catSig.Status -eq 'Valid') { 'Green' } else { 'Red' }
            Write-Host ("  [{0}] HardeningTomcat.cat (covers $((Get-ChildItem $listsRoot -Recurse -File).Count) data files)" -f $catSig.Status) -ForegroundColor $cc
            Write-Host "  Verify a list against the catalog with: Test-FileCatalog -CatalogFilePath '$catPath' -Path '$listsRoot'" -ForegroundColor DarkGray
        } catch {
            Write-Host "  Catalog step failed: $($_.Exception.Message)" -ForegroundColor Red
            $failed++
        }
    } else {
        Write-Host "  (no lists/ directory found; skipping catalog)" -ForegroundColor DarkYellow
    }
}

Write-Host ""
if ($failed -eq 0) {
    Write-Host "Done. All signatures valid." -ForegroundColor Green
} else {
    Write-Host "Done with $failed failure(s) -- review the [ ] statuses above." -ForegroundColor Red
}
Write-Host "Verify code:    Get-AuthenticodeSignature <file> | Format-List Status,SignerCertificate" -ForegroundColor Cyan
Write-Host "Reminder: set 'Set-ExecutionPolicy AllSigned' for signatures to be enforced." -ForegroundColor Cyan
