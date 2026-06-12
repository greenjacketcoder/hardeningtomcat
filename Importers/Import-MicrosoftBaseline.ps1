#Requires -Version 5.1
<#
.SYNOPSIS
    Imports a Microsoft Security Compliance Toolkit (SCT) baseline directly into a
    HardeningTomcat JSON finding list. No HardeningKitty or other third-party
    translation in the path — this reads Microsoft's own GPO-backup artifacts.

.DESCRIPTION
    Point this at an unzipped SCT baseline's GPO-backup folder (the one containing
    DomainSysvol\...). It walks the registry.pol, GptTmpl.inf, and audit.csv files,
    parses each, maps settings onto HardeningTomcat methods (Registry / secedit /
    auditpol), and writes one JSON finding list.

    This is the SUSTAINABLE path: every future Microsoft baseline release works with
    this importer unchanged, because the artifact formats are stable.

.PARAMETER BaselinePath
    Folder of an unzipped GPO backup (search is recursive, so the SCT baseline root
    usually works too).

.PARAMETER OutFile
    Destination JSON list. Default: lists\microsoft\<name>.json

.PARAMETER ListName
    Human name for the list metadata.

.PARAMETER DefaultSeverity
    Severity assigned to imported findings (Microsoft baselines don't carry a CIS-style
    severity). Default 'Medium'. Tune later per-finding or via an override map.

.EXAMPLE
    .\Import-MicrosoftBaseline.ps1 -BaselinePath "C:\SCT\Windows 11 v24H2 Security Baseline\GPOs" `
        -ListName "Microsoft Windows 11 24H2 - Machine" -OutFile .\lists\microsoft\win11-24h2-machine.json

.NOTES
    Validation must happen against a REAL SCT download on a Windows box. The registry.pol
    parser is proven against the format spec; INF/CSV are plain text. Run, then spot-check
    a handful of findings against the Microsoft baseline spreadsheet that ships in the SCT.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $BaselinePath,
    [string] $OutFile,
    [string] $ListName = 'Microsoft Security Baseline (imported)',
    [ValidateSet('Low','Medium','High')][string] $DefaultSeverity = 'Medium',
    [ValidateSet('machine','user')][string] $Scope = 'machine',

    # GPO selection (server baselines bundle mutually-exclusive roles). Pick ONE approach:
    #   -Role MemberServer|DomainController|Client   (preset: role GPO + common layers)
    #   -IncludeGpo '*Member Server*','*Defender*'    (manual wildcard patterns vs display name)
    # With neither, if the baseline has a manifest the script LISTS available GPOs and stops.
    [string[]] $IncludeGpo,
    [ValidateSet('MemberServer','DomainController','Client')][string] $Role
)

$here = $PSScriptRoot
. (Join-Path $here 'RegistryPolParser.ps1')
. (Join-Path $here 'GptTmplInfParser.ps1')
. (Join-Path $here 'AuditCsvParser.ps1')
. (Join-Path $here 'SctManifest.ps1')

if (-not (Test-Path $BaselinePath)) { throw "BaselinePath not found: $BaselinePath" }

# ---- Resolve which GPO folders to import -----------------------------------
$resolution = Resolve-SctGpoSelection -GposPath $BaselinePath -IncludeGpo $IncludeGpo -Role $Role

if ($resolution.Mode -eq 'ListOnly') {
    Write-Host ""
    Write-Host "This baseline bundles multiple GPOs. Choose which to import." -ForegroundColor Yellow
    Write-Host "Available GPOs (from manifest.xml):" -ForegroundColor Cyan
    $resolution.Manifest | ForEach-Object { Write-Host "  - $($_.DisplayName)" }
    Write-Host ""
    Write-Host "Re-run with a selection, e.g.:" -ForegroundColor Yellow
    Write-Host "  -Role MemberServer        (member server + Defender/IE/Domain Security layers)" -ForegroundColor DarkGray
    Write-Host "  -Role DomainController     (DC + common layers)" -ForegroundColor DarkGray
    Write-Host "  -IncludeGpo '*Member Server*','*Defender*'   (manual patterns)" -ForegroundColor DarkGray
    return
}

if ($resolution.Mode -eq 'Selected') {
    Write-Host "Selected GPOs:" -ForegroundColor Cyan
    $resolution.Selected | ForEach-Object { Write-Host "  + $($_.DisplayName)" -ForegroundColor Green }
    if (-not $resolution.Folders) { throw "Selection matched no GPOs. Check -Role/-IncludeGpo patterns against the listed names." }
}

# Folders to scan: either the selected GPO folders, or the whole path (single-GPO/no-manifest case).
$scanRoots = $resolution.Folders

$findings = New-Object System.Collections.Generic.List[object]
$idSeed = 10000
function Next-Id { $script:idSeed++; "$script:idSeed" }

# Map a registry.pol REG type to a HardeningTomcat args.type
function Get-HtRegType($typeName) {
    switch ($typeName) {
        'REG_DWORD' { 'DWord' }
        'REG_QWORD' { 'QWord' }
        'REG_SZ'    { 'String' }
        'REG_EXPAND_SZ' { 'ExpandString' }
        'REG_MULTI_SZ'  { 'MultiString' }
        'REG_BINARY'    { 'Binary' }
        default { 'String' }
    }
}

# registry.pol keys are relative to HKLM (machine GPO) or HKCU (user GPO).
$hive = if ($Scope -eq 'user') { 'HKCU:' } else { 'HKLM:' }

# ---- 1) registry.pol files -------------------------------------------------
$polFiles = $scanRoots | ForEach-Object { Get-ChildItem -Path $_ -Recurse -Filter 'registry.pol' -ErrorAction SilentlyContinue }
Write-Host "Found $($polFiles.Count) registry.pol file(s)." -ForegroundColor Cyan
foreach ($pol in $polFiles) {
    try { $recs = ConvertFrom-RegistryPol -Path $pol.FullName }
    catch { Write-Warning "Skipping $($pol.FullName): $($_.Exception.Message)"; continue }
    foreach ($r in $recs) {
        # A '**del.' value name or DELVALS marker means "delete" — skip for an audit baseline.
        if ($r.ValueName -match '^\*\*del') { continue }
        $findings.Add([pscustomobject]@{
            id   = Next-Id
            name = "$($r.Key)\$($r.ValueName)"
            category = 'Registry (MS baseline)'
            method = 'Registry'
            args = @{ path = "$hive\$($r.Key)"; name = $r.ValueName; type = (Get-HtRegType $r.TypeName) }
            operator = '='
            recommendedValue = "$($r.Data)"
            defaultValue = ''
            severity = $DefaultSeverity
        })
    }
}

# ---- 2) GptTmpl.inf files --------------------------------------------------
$infFiles = $scanRoots | ForEach-Object { Get-ChildItem -Path $_ -Recurse -Filter 'GptTmpl.inf' -ErrorAction SilentlyContinue }
Write-Host "Found $($infFiles.Count) GptTmpl.inf file(s)." -ForegroundColor Cyan
foreach ($inf in $infFiles) {
    try { $recs = ConvertFrom-GptTmplInf -Path $inf.FullName }
    catch { Write-Warning "Skipping $($inf.FullName): $($_.Exception.Message)"; continue }
    foreach ($r in $recs) {
        switch ($r.Section) {
            'System Access' {
                # password/lockout policy -> secedit findings (handler reads args.key)
                $findings.Add([pscustomobject]@{
                    id = Next-Id; name = "System Access: $($r.Key)"
                    category = 'Account Policy (MS baseline)'; method = 'secedit'
                    args = @{ key = $r.Key }
                    operator = '='; recommendedValue = "$($r.Value)"; defaultValue = ''
                    severity = $DefaultSeverity
                })
            }
            'Registry Values' {
                # Format: MACHINE\Path\Value=type,data  -> Registry finding
                if ($r.Value -match '^(\d+),(.*)$') {
                    $regType = [int]$matches[1]; $regData = $matches[2]
                    $fullKey = $r.Key -replace '^MACHINE\\', ''
                    $leaf = Split-Path $fullKey -Leaf
                    $parent = Split-Path $fullKey -Parent
                    $tn = @{1='REG_SZ';2='REG_EXPAND_SZ';3='REG_BINARY';4='REG_DWORD';7='REG_MULTI_SZ';11='REG_QWORD'}[$regType]
                    $findings.Add([pscustomobject]@{
                        id = Next-Id; name = "$fullKey"
                        category = 'Security Options (MS baseline)'; method = 'Registry'
                        args = @{ path = "$hive\$parent"; name = $leaf; type = (Get-HtRegType $tn) }
                        operator = '='; recommendedValue = "$regData"; defaultValue = ''
                        severity = $DefaultSeverity
                    })
                }
            }
            default { }  # Privilege Rights / Event Audit handled once accesschk handler exists
        }
    }
}

# ---- 3) audit.csv files ----------------------------------------------------
$auditFiles = $scanRoots | ForEach-Object { Get-ChildItem -Path $_ -Recurse -Filter 'audit.csv' -ErrorAction SilentlyContinue }
Write-Host "Found $($auditFiles.Count) audit.csv file(s)." -ForegroundColor Cyan
foreach ($ac in $auditFiles) {
    try { $recs = ConvertFrom-AuditCsv -Path $ac.FullName }
    catch { Write-Warning "Skipping $($ac.FullName): $($_.Exception.Message)"; continue }
    foreach ($r in $recs) {
        $findings.Add([pscustomobject]@{
            id = Next-Id; name = "Audit: $($r.Subcategory)"
            category = 'Audit Policy (MS baseline)'; method = 'auditpol'
            args = @{ subcategory = $r.Subcategory }
            operator = '='; recommendedValue = "$($r.Setting)"; defaultValue = 'No Auditing'
            severity = $DefaultSeverity
        })
    }
}

# ---- write the list --------------------------------------------------------
if (-not $OutFile) {
    $safe = ($ListName -replace '[^\w\-]', '_')
    $dir = Join-Path (Split-Path $here -Parent) 'lists\microsoft'
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $OutFile = Join-Path $dir "$safe.json"
}

$list = [ordered]@{
    listName    = $ListName
    version     = (Get-Date -Format 'yyyy.MM.dd')
    scope       = $Scope
    description = "Imported directly from a Microsoft SCT baseline by Import-MicrosoftBaseline.ps1. Severity defaulted to $DefaultSeverity; review before Strike."
    findings    = $findings
}

$list | ConvertTo-Json -Depth 6 | Set-Content -Path $OutFile -Encoding UTF8
Write-Host ""
Write-Host "Wrote $($findings.Count) findings to $OutFile" -ForegroundColor Green
Write-Host "Breakdown:" -ForegroundColor Cyan
$findings | Group-Object method | ForEach-Object { Write-Host ("  {0,-10} {1}" -f $_.Name, $_.Count) }
Write-Host ""
Write-Host "NEXT: spot-check ~5 findings against the baseline spreadsheet in the SCT, then run:" -ForegroundColor Yellow
Write-Host "  Invoke-HardeningTomcat -Mode Recon -FindingList `"$OutFile`" -Report" -ForegroundColor Yellow
