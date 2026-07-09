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
    [string] $OutDir,
    # Optional L1 reference CSV. When $CsvPath is a combined L1+L2 list, findings whose ID
    # appears in this L1 file are tagged level 1; the rest are level 2. This produces the
    # correct PER-FINDING level (the filename alone only tells you the file's scope).
    [string] $Level1RefCsv
)

if (-not (Test-Path $CsvPath)) { throw "CSV not found: $CsvPath" }
# Auto-route output by benchmark family unless an explicit -OutDir is given.
if (-not $OutDir) {
    $listsRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'lists'
    $sub = if ($CsvPath -match 'stig' -or $ListName -match 'STIG') { 'stig' }
           elseif ($CsvPath -match 'bsi' -or $ListName -match 'BSI') { 'bsi' }
           else { 'cis' }
    $OutDir = Join-Path $listsRoot $sub
}
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# Map CIS account-policy finding names -> secedit [System Access] keys. Baking the key
# into args at import time avoids fragile exact-name matching at runtime (CIS wording
# varies by version/OS). Matching is done case-insensitively on a normalized name.
$acctPolicyKeys = @{
    'length of password history maintained' = 'PasswordHistorySize'
    'maximum password age'                  = 'MaximumPasswordAge'
    'minimum password age'                  = 'MinimumPasswordAge'
    'minimum password length'               = 'MinimumPasswordLength'
    'password must meet complexity requirements' = 'PasswordComplexity'
    'store passwords using reversible encryption' = 'ClearTextPassword'
    'account lockout duration'              = 'LockoutDuration'
    'account lockout threshold'             = 'LockoutBadCount'
    'reset account lockout counter'         = 'ResetLockoutCount'
    'reset account lockout counter after'   = 'ResetLockoutCount'
    'allow administrator account lockout'   = 'AllowAdministratorLockout'
}

# Determine how to assign levels.
#  - If an L1 reference is given: per-finding (id in L1 ref -> 1, else -> 2). Combined list.
#  - Else if filename says _level1 (and not _level2): every finding is level 1.
#  - Else: no level tagging (e.g. a plain non-CIS list).
$l1Ids = $null
$flatLevel = $null
if ($Level1RefCsv) {
    if (-not (Test-Path $Level1RefCsv)) { throw "Level1RefCsv not found: $Level1RefCsv" }
    $l1Ids = @{}
    foreach ($row in (Import-Csv $Level1RefCsv)) { $l1Ids[$row.ID] = $true }
    Write-Host "Per-finding levels from L1 reference ($($l1Ids.Count) L1 ids)." -ForegroundColor Cyan
} elseif ($CsvPath -match '_level1' -and $CsvPath -notmatch '_level1_level2') {
    $flatLevel = 1
} elseif ($CsvPath -match '_level1_level2') {
    Write-Warning "Combined L1+L2 list given without -Level1RefCsv; cannot distinguish per-finding levels. All findings will be tagged level 2. Pass -Level1RefCsv for correct L1/L2 split."
    $flatLevel = 2
}

$rows = Import-Csv -Path $CsvPath
$findings = New-Object System.Collections.Generic.List[object]

# Track IDs to keep them unique. STIG benchmarks reuse one V-ID across many settings
# (e.g. one requirement covers ~30 process-mitigation properties), which the engine's
# duplicate-id check rejects. We append -2, -3, ... to repeats and keep the original
# STIG ID in a separate 'sourceId' field so the report still shows the real ID.
$idCounts = @{}

foreach ($r in $rows) {
    # NOTE: named $fargs (finding args), not $args -- $args is a PowerShell automatic
    # variable and assigning to it is fragile (breaks under StrictMode/refactoring).
    $fargs = @{}
    switch ($r.Method) {
        'Registry'        { $fargs = @{ path = $r.RegistryPath; name = $r.RegistryItem } }
        'RegistryList'    { $fargs = @{ path = $r.RegistryPath; item = $r.RegistryItem } }
        'accesschk'       { $fargs = @{ privilege = $r.MethodArgument } }
        'service'         { $fargs = @{ name = $r.MethodArgument } }
        'auditpol'        { $fargs = @{ subcategory = $r.MethodArgument } }  # CIS uses GUID; see note
        'secedit'         { $fargs = @{ key = ($r.MethodArgument -replace '^System Access\\','') } }
        'accountpolicy'   {
            # Resolve the secedit key now (case-insensitive) so the handler doesn't
            # depend on exact runtime name matching. Falls back to empty if unknown.
            $k = $acctPolicyKeys[$r.Name.Trim().ToLower()]
            $fargs = @{ key = $k }
            if (-not $k) { Write-Warning "No account-policy key mapping for '$($r.Name)' (id $($r.ID)) -- will Skip at runtime." }
        }
        'localaccount'    { $fargs = @{ rid = $r.MethodArgument } }
        'MpPreferenceAsr' { $fargs = @{ ruleId = $r.MethodArgument } }
        'ProcessmitigationApplication' { $fargs = @{ target = $r.MethodArgument } }
        default           { $fargs = @{ raw = $r.MethodArgument } }
    }
    $sev = if ($r.Severity) { $r.Severity } else { 'Medium' }
    # Normalize "X or Y" recommended values (CIS lists some settings as "either
    # acceptable", e.g. "1 or 2", "256 or 287"). With operator '=' these produce false
    # failures on audit (observed never equals the literal prose) and write garbage on
    # apply. Switch such Registry findings to the '=or' operator, which passes if the
    # observed value matches any listed option; the Registry apply path resolves the
    # same prose to the first listed value when writing. (Root-cause fix so regenerated
    # lists are correct, not just the committed JSON.)
    $thisOp = $r.Operator
    if ($r.Method -eq 'Registry' -and $r.RecommendedValue -match '^\s*[\w-]+\s+or\s+[\w-]+' -and $thisOp -eq '=') {
        $thisOp = '=or'
    }
    # Make the ID unique: first occurrence keeps the raw ID; repeats get -2, -3, ...
    $rawId = $r.ID
    if ($idCounts.ContainsKey($rawId)) {
        $idCounts[$rawId]++
        $uniqueId = "$rawId-$($idCounts[$rawId])"
    } else {
        $idCounts[$rawId] = 1
        $uniqueId = $rawId
    }
    $obj = [ordered]@{
        id = $uniqueId; sourceId = $rawId; name = $r.Name; category = $r.Category; method = $r.Method
        args = $fargs; operator = $thisOp
        recommendedValue = $r.RecommendedValue; defaultValue = $r.DefaultValue
        severity = $sev
    }
    # Per-finding level.
    $thisLevel = $null
    if ($l1Ids)            { $thisLevel = if ($l1Ids.ContainsKey($r.ID)) { 1 } else { 2 } }
    elseif ($flatLevel)    { $thisLevel = $flatLevel }
    if ($thisLevel)        { $obj.level = $thisLevel }
    $findings.Add([pscustomobject]$obj)
}

# Top-level 'level' = the highest level present (the file's scope).
$scopeLevel = $null
if ($l1Ids)         { $scopeLevel = 2 }
elseif ($flatLevel) { $scopeLevel = $flatLevel }
$out = [ordered]@{
    listName = $ListName
    version  = (Get-Date -Format 'yyyy.MM.dd')
    source   = "Derived from HardeningKitty finding list (Apache-2.0): $(Split-Path $CsvPath -Leaf)"
    level    = $scopeLevel
    findings = $findings
}
$safe = ($ListName -replace '[^\w\-]', '_')
$outPath = Join-Path $OutDir "$safe.json"
$out | ConvertTo-Json -Depth 8 | Set-Content -Path $outPath -Encoding UTF8
Write-Host "Wrote $($findings.Count) findings -> $outPath" -ForegroundColor Green
if ($l1Ids) {
    $l1c = ($findings | Where-Object { $_.level -eq 1 }).Count
    $l2c = ($findings | Where-Object { $_.level -eq 2 }).Count
    Write-Host "  Per-finding levels: $l1c L1, $l2c L2" -ForegroundColor Cyan
} elseif ($flatLevel) {
    Write-Host "  Level tag: L$flatLevel (all findings)" -ForegroundColor Cyan
}
Write-Host "  NOTE: CIS auditpol findings use GUID subcategories; verify the auditpol handler resolves GUIDs (see README)." -ForegroundColor DarkYellow
