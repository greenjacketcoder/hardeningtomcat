# OS detection + default finding-list resolution.
# Used by Recon/Survey when -FindingList is omitted. Strike never calls this.

function Get-HtOsIdentity {
    <#
      Returns a normalized descriptor of the running Windows OS so we can match a list.
      Output: @{ Product='Windows 11'|'Windows 10'|'Windows Server 2022'...; Release='24H2'|''; Role='machine' }
    #>
    $os = $null
    try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop } catch {}
    $caption = if ($os) { $os.Caption } else { '' }   # e.g. "Microsoft Windows 11 Pro"
    $build   = if ($os) { [int]($os.BuildNumber) } else { 0 }

    # DisplayVersion (24H2 etc.) lives in the registry.
    $release = ''
    try {
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        if ($cv.DisplayVersion) { $release = $cv.DisplayVersion }      # "24H2"
        elseif ($cv.ReleaseId)  { $release = $cv.ReleaseId }
    } catch {}

    # Product family
    $product =
        if     ($caption -match 'Server 2025') { 'Windows Server 2025' }
        elseif ($caption -match 'Server 2022') { 'Windows Server 2022' }
        elseif ($caption -match 'Server 2019') { 'Windows Server 2019' }
        elseif ($caption -match 'Server 2016') { 'Windows Server 2016' }
        elseif ($caption -match 'Server')      { 'Windows Server' }
        elseif ($caption -match 'Windows 11')  { 'Windows 11' }
        elseif ($caption -match 'Windows 10')  { 'Windows 10' }
        # Win11 reports build >= 22000 even though Caption sometimes says "Windows 10"
        elseif ($build -ge 22000)              { 'Windows 11' }
        else                                   { 'Windows' }

    [pscustomobject]@{ Product = $product; Release = $release; Build = $build; Caption = $caption }
}

function Resolve-HtDefaultList {
    <#
      Finds the best-matching finding list under lists/ for the running OS.
      Returns a file path, or $null if nothing matches (caller then errors clearly).
      Matching is fuzzy: product family must match; release (24H2) preferred but optional.
    #>
    param([string] $ModuleRoot)

    $os = Get-HtOsIdentity
    $listDir = Join-Path $ModuleRoot 'lists'
    $candidates = Get-ChildItem -Path $listDir -Recurse -Filter '*.json' -ErrorAction SilentlyContinue
    if (-not $candidates) { return [pscustomobject]@{ Path=$null; Os=$os; Reason='no lists found' } }

    # Score each list by how well its listName/filename matches the OS.
    $best = $null; $bestScore = 0
    foreach ($c in $candidates) {
        $hay = "$($c.BaseName)"
        try { $hay += ' ' + (Get-Content $c.FullName -Raw | ConvertFrom-Json).listName } catch {}
        $score = 0
        # Product family tokens
        switch -Regex ($os.Product) {
            'Server 2025' { if ($hay -match 'Server.*2025') { $score += 10 } }
            'Server 2022' { if ($hay -match 'Server.*2022') { $score += 10 } }
            'Server 2019' { if ($hay -match 'Server.*2019') { $score += 10 } }
            'Server 2016' { if ($hay -match 'Server.*2016') { $score += 10 } }
            'Windows 11'  { if ($hay -match 'Windows 11|Win11|11 ') { $score += 10 } }
            'Windows 10'  { if ($hay -match 'Windows 10|Win10|10 ') { $score += 10 } }
        }
        # Release bonus (24H2 etc.)
        if ($os.Release -and $hay -match [regex]::Escape($os.Release)) { $score += 5 }
        # Prefer machine/member-server lists over DC by default (least surprising).
        # Match both spaced ("Member Server", from listName) and underscored
        # ("Member_Server", from the importer's safe filename).
        if ($hay -match 'Member.Server|Machine') { $score += 1 }
        if ($score -gt $bestScore) { $bestScore = $score; $best = $c }
    }

    # Build any cautions about the auto-pick so the engine can surface them at runtime.
    $warnings = @()
    if ($best -and $bestScore -ge 10) {
        $chosen = $best.BaseName
        # Server role ambiguity: auto-detect knows the OS but NOT whether this box is a
        # Domain Controller or Member Server (they report the same OS). If we defaulted to
        # a Member Server / Machine list on a Server OS, warn — a DC needs its own list.
        if ($os.Product -match 'Server' -and $chosen -match 'Member.Server|Machine') {
            $warnings += "Detected $($os.Product); defaulted to a Member Server/Machine list. " +
                         "If THIS box is a Domain Controller, specify -FindingList explicitly — " +
                         "auto-detect cannot tell DC from member server."
        }
        # Release mismatch: product matched but the chosen list is for a different release.
        if ($os.Release -and $chosen -notmatch [regex]::Escape($os.Release)) {
            $warnings += "Running release is $($os.Release) but the closest list is '$chosen' " +
                         "(different release). Values may not fully match this build."
        }
    }

    [pscustomobject]@{
        Path     = if ($best -and $bestScore -ge 10) { $best.FullName } else { $null }
        Os       = $os
        Reason   = if ($best -and $bestScore -ge 10) { "matched '$($best.Name)' (score $bestScore)" } else { 'no list matched this OS' }
        Warnings = $warnings
    }
}
