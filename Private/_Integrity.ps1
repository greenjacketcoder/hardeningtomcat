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

    # ---- Catalog signature check (Finding 1) ---------------------------------
    # A plain .sha256 text file cannot itself carry an Authenticode signature, so the
    # correct mechanism is a SIGNED FILE CATALOG (HardeningTomcat.cat) produced by
    # Sign-Module.ps1, covering everything under lists/ (the manifest AND the lists).
    # When the catalog is present we verify it: a Valid catalog whose signature chains
    # to a trusted publisher means the lists+manifest are exactly as signed. A present-
    # but-invalid catalog means tampering -> refuse to trust, in all modes.
    $catPath = Join-Path $ModuleRoot 'HardeningTomcat.cat'
    if (Test-Path $catPath) {
        $catSig = $null
        try { $catSig = Get-AuthenticodeSignature -FilePath $catPath -ErrorAction Stop } catch {
            # FAIL CLOSED: if the catalog's signature cannot even be READ, treat that the
            # same as an invalid signature. Swallowing the error here would silently skip
            # the tamper check -- an integrity gate must not fail open.
            $result.Status = 'manifest-tampered'
            $result.Message = "Could not read the signed catalog's signature ($($_.Exception.Message)). Failing closed: refusing to trust lists/manifest."
            return $result
        }
        if ($catSig -and $catSig.Status -ne 'Valid') {
            $result.Status = 'manifest-tampered'
            $result.Message = "The signed file catalog's signature is invalid ($($catSig.Status)). The lists or manifest may have been altered."
            return $result
        }
        # Catalog signature is valid; confirm the actual files still match the catalog.
        if (Get-Command Test-FileCatalog -ErrorAction SilentlyContinue) {
            $listsRoot = Join-Path $ModuleRoot 'lists'
            try {
                $catStatus = Test-FileCatalog -CatalogFilePath $catPath -Path $listsRoot -Detailed -ErrorAction Stop
                if ($catStatus.Status -ne 'Valid') {
                    $result.Status = 'manifest-tampered'
                    $result.Message = "File catalog verification failed ($($catStatus.Status)): a file under lists/ does not match the signed catalog."
                    return $result
                }
                $result | Add-Member -NotePropertyName CatalogVerified -NotePropertyValue $true -Force
            } catch {
                # Test-FileCatalog threw; fall through to hash-manifest check rather than
                # hard-failing, but record that catalog verification was inconclusive.
                $result | Add-Member -NotePropertyName CatalogVerified -NotePropertyValue $false -Force
            }
        }
    }

    $actual = (Get-FileHash -Path $FindingList -Algorithm SHA256).Hash.ToLower()
    $result.Actual = $actual

    # Match by hash directly -- path-independent, so a list is trusted wherever it sits
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
