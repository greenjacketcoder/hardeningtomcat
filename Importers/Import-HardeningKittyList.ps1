# Import-HardeningKittyList.ps1
# Converts a HardeningKitty finding-list CSV into a HardeningTomcat JSON list.
# Source lists (incl. their CIS L1/L2 variants) are Apache-2.0; derived lists carry an
# attribution note. The level is inferred from the source filename (_level1 / _level1_level2).
#
#   .\Import-HardeningKittyList.ps1 -CsvPath <file.csv> -ListName "CIS Windows 11 25H2 L1"
#
# Maps each HK method's columns to the args shape HardeningTomcat handlers expect.

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $CsvPath,
    [Parameter(Mandatory)][string] $ListName,
    [string] $OutDir = (Join-Path (Split-Path $PSScriptRoot -Parent) 'lists/cis'),
    [ValidateSet('1','2','')][string] $Level = ''
)

if (-not (Test-Path $CsvPath)) { throw "CSV not found: $CsvPath" }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# Infer level from filename if not given explicitly.
if (-not $Level) {
    if     ($CsvPath -match '_level1_level2') { $Level = '2' }   # combined L1+L2 set
    elseif ($CsvPath -match '_level1')        { $Level = '1' }
}

$rows = Import-Csv -Path $CsvPath
$findings = New-Object System.Collections.Generic.List[object]

foreach ($r in $rows) {
    $args = @{}
    switch ($r.Method) {
        'Registry'        { $args = @{ path = $r.RegistryPath; name = $r.RegistryItem } }
        'accesschk'       { $args = @{ privilege = $r.MethodArgument } }
        'service'         { $args = @{ name = $r.MethodArgument } }
        'auditpol'        { $args = @{ subcategory = $r.MethodArgument } }  # CIS uses GUID; see note
        'secedit'         { $args = @{ key = ($r.MethodArgument -replace '^System Access\\','') } }
        'accountpolicy'   { $args = @{ } }                                  # resolved by name in handler
        'localaccount'    { $args = @{ rid = $r.MethodArgument } }
        'MpPreferenceAsr' { $args = @{ ruleId = $r.MethodArgument } }
        default           { $args = @{ raw = $r.MethodArgument } }
    }
    $sev = if ($r.Severity) { $r.Severity } else { 'Medium' }
    $obj = [ordered]@{
        id = $r.ID; name = $r.Name; category = $r.Category; method = $r.Method
        args = $args; operator = $r.Operator
        recommendedValue = $r.RecommendedValue; defaultValue = $r.DefaultValue
        severity = $sev
    }
    if ($Level) { $obj.level = [int]$Level }
    $findings.Add([pscustomobject]$obj)
}

$levelVal = $null
if ($Level) { $levelVal = [int]$Level }
$out = [ordered]@{
    listName = $ListName
    version  = (Get-Date -Format 'yyyy.MM.dd')
    source   = "Derived from HardeningKitty finding list (Apache-2.0): $(Split-Path $CsvPath -Leaf)"
    level    = $levelVal
    findings = $findings
}
$safe = ($ListName -replace '[^\w\-]', '_')
$outPath = Join-Path $OutDir "$safe.json"
$out | ConvertTo-Json -Depth 8 | Set-Content -Path $outPath -Encoding UTF8
Write-Host "Wrote $($findings.Count) findings -> $outPath" -ForegroundColor Green
if ($Level) { Write-Host "  Level tag: L$Level" -ForegroundColor Cyan }
Write-Host "  NOTE: CIS auditpol findings use GUID subcategories; verify the auditpol handler resolves GUIDs (see README)." -ForegroundColor DarkYellow
