# Finding-list integrity verification against lists/manifest.sha256.
# Defense against a tampered list weaponizing the tool. Strike refuses mismatches;
# Recon/Survey warn but proceed (read-only can't harm the system).

function Test-HtListIntegrity {
    param(
        [string] $FindingList,   # path to the list being used
        [string] $ModuleRoot
    )
    $manifestPath = Join-Path $ModuleRoot 'lists/manifest.sha256'
    $result = [pscustomobject]@{
        Status   = 'unknown'   # verified | mismatch | not-listed | no-manifest
        Expected = $null
        Actual   = $null
        Message  = ''
    }

    if (-not (Test-Path $manifestPath)) {
        $result.Status = 'no-manifest'
        $result.Message = "No integrity manifest (lists/manifest.sha256). Run Update-ListManifest.ps1 to create one."
        return $result
    }

    # If the manifest itself is signed (manifest.sha256 with an Authenticode catalog,
    # or a sidecar .p7s), verify that signature first so a tampered manifest is caught.
    # Activated once you run the signing step (#9); until then, the unsigned manifest is
    # used and a note is logged. This makes signing a pure "run the signer" step later.
    $sig = $null
    try { $sig = Get-AuthenticodeSignature -FilePath $manifestPath -ErrorAction SilentlyContinue } catch {}
    if ($sig -and $sig.Status -eq 'Valid') {
        $result | Add-Member -NotePropertyName ManifestSigned -NotePropertyValue $true -Force
    } elseif ($sig -and $sig.Status -in 'HashMismatch','NotTrusted') {
        # A present-but-invalid signature means the manifest was tampered with — refuse to trust it.
        $result.Status = 'manifest-tampered'
        $result.Message = "The integrity manifest's signature is invalid ($($sig.Status)). The manifest may have been altered."
        return $result
    }

    $actual = (Get-FileHash -Path $FindingList -Algorithm SHA256).Hash.ToLower()
    $result.Actual = $actual

    # Match by hash directly — path-independent, so a list is trusted wherever it sits
    # as long as its content hash is in the manifest.
    $known = @{}
    foreach ($line in (Get-Content $manifestPath)) {
        if ($line -match '^\s*#' -or -not $line.Trim()) { continue }
        if ($line -match '^([0-9a-fA-F]{64})\s+(.+)$') { $known[$matches[1].ToLower()] = $matches[2].Trim() }
    }

    if ($known.ContainsKey($actual)) {
        $result.Status = 'verified'
        $result.Expected = $actual
        $result.Message = "List integrity verified ($($known[$actual]))."
    } else {
        $result.Status = 'not-listed'
        $result.Message = "List hash $($actual.Substring(0,12))... is NOT in the integrity manifest. " +
                          "The list may have been edited or tampered with. If you trust it, re-run Update-ListManifest.ps1."
    }
    return $result
}
