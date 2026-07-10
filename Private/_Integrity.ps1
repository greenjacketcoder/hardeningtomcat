# Finding-list integrity verification against lists/manifest.sha256.
# Defense against a tampered list weaponizing the tool. Strike refuses mismatches;
# Recon/Survey warn but proceed (read-only can't harm the system).

function Test-HtListIntegrity {
    param(
        [string] $FindingList,   # path to the list being used (used for its NAME only)
        [string] $ModuleRoot,
        # SHA256 (lowercase hex) of the EXACT in-memory buffer the engine will parse.
        # TOCTOU defense: the caller reads the file's bytes once, hashes THAT buffer, and
        # passes the hash here so integrity verification and JSON parsing operate on the
        # same bytes -- never re-opening the path (which a racing writer could swap between
        # the hash and the parse). When omitted (e.g. standalone/test callers), we fall
        # back to hashing the path directly.
        [string] $ActualHash
    )
    $manifestPath = Join-Path $ModuleRoot 'lists/manifest.sha256'
    $result = [pscustomobject]@{
        Status   = 'unknown'   # verified | mismatch | not-listed | no-manifest
        Expected = $null
        Actual   = $null
        Message  = ''
        # Whether a SIGNED catalog exists at all. Without one, the plain-text hash
        # manifest only detects accidental corruption -- the engine warns Strike users.
        CatalogPresent = (Test-Path (Join-Path $ModuleRoot 'HardeningTomcat.cat'))
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
                # FAIL CLOSED: a signed catalog is PRESENT but the files under lists/
                # could not be confirmed against it. Falling through to the weaker
                # plain-text hash check here would be a fail-open path in the exact
                # component whose job is to not fail open.
                $result.Status = 'manifest-tampered'
                $result.Message = "File catalog verification could not complete ($($_.Exception.Message)). " +
                                  "Failing closed: a signed catalog is present but lists/ cannot be confirmed against it."
                return $result
            }
        }
    }

    # Use the caller's in-memory-buffer hash when provided (TOCTOU-safe); otherwise fall
    # back to hashing the path directly (standalone/test callers).
    if ($ActualHash) {
        $actual = $ActualHash.ToLower()
    } else {
        $actual = (Get-FileHash -Path $FindingList -Algorithm SHA256).Hash.ToLower()
    }
    $result.Actual = $actual

    # Match by hash directly -- path-independent, so a list is trusted wherever it sits
    # as long as its content hash is in the manifest.
    $known = @{}
    foreach ($line in (Get-Content $manifestPath)) {
        if ($line -match '^\s*#' -or -not $line.Trim()) { continue }
        if ($line -match '^([0-9a-fA-F]{64})\s+(.+)$') { $known[$matches[1].ToLower()] = $matches[2].Trim() }
    }

    if ($known.ContainsKey($actual)) {
        # The hash matched a manifest entry, but also require the RECORDED PATH to match:
        # hash-only matching would let any trusted list's content stand in for any other
        # (e.g. a Domain Controller list swapped into the Win11 file would still read
        # "verified" -- and then be applied to the wrong system). Compare the FULL relative
        # path the manifest records (relative to lists/), not just the filename leaf: two
        # lists in different subdirectories (lists/cis/win11.json vs lists/stig/win11.json)
        # can share a leaf, and leaf-only matching would let one masquerade as the other.
        $recordedRel = ($known[$actual] -replace '\\','/').TrimStart('/')
        $listsRootN  = (Join-Path $ModuleRoot 'lists') -replace '\\','/'
        $actualFull  = try { (Resolve-Path -LiteralPath $FindingList -ErrorAction Stop).Path } catch { $FindingList }
        $actualRel   = (($actualFull -replace '\\','/') -replace [regex]::Escape($listsRootN), '').TrimStart('/')
        # If the list lives outside lists/ we cannot form a relative path; fall back to the
        # leaf comparison in that case rather than failing a legitimately-relocated list.
        $recordedCmp = if ($actualRel -match '/') { $recordedRel } else { Split-Path $recordedRel -Leaf }
        $actualCmp   = if ($actualRel -match '/') { $actualRel }   else { Split-Path $actualFull -Leaf }
        if ($recordedCmp -and $actualCmp -and ($recordedCmp -ne $actualCmp)) {
            $result.Status = 'not-listed'
            $result.Message = "List content matches manifest entry '$($known[$actual])' but the file resolves to " +
                              "'$actualCmp' -- a trusted list's content appears under a different path/name. " +
                              "If this relocation is intentional, re-run Update-ListManifest.ps1."
            return $result
        }
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
