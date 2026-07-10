<#
.SYNOPSIS
    Imports a DISA SCAP 1.3 benchmark (XCCDF + OVAL) into a HardeningTomcat JSON list.
.DESCRIPTION
    DISA STIGs ship as a SCAP data-stream: an XCCDF benchmark (rules, IDs, severity,
    fixtext) plus an OVAL document (the machine-readable check logic). Each XCCDF Rule
    points to an OVAL definition; the definition's criteria reference OVAL tests; each
    test references an object (what to read) and a state (the expected value + operator).
    Many definitions are thin wrappers that extend_definition into the real check, so the
    resolver follows those chains.

    Roughly 90% of a Windows STIG maps to existing HardeningTomcat handlers (registry,
    audit policy, account/lockout policy, user rights). The remainder use OVAL test types
    with no handler (WMI, NTFS effective rights, SID membership); those are emitted with
    method 'manual' and operator 'manual' so they appear in the list (with their real V-ID
    and fixtext) but are reported as Skipped rather than silently dropped or falsely passed.

    Provenance: this parses the AUTHORITATIVE DISA SCAP content directly -- not a third
    party's interpretation.
.EXAMPLE
    .\Import-DisaStigScap.ps1 -ScapXml "C:\...\U_MS_Windows_11_V2R8_STIG_SCAP_1-3_Benchmark.xml" `
        -ListName "DoD STIG Windows 11 V2R8"
#>
[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'ACCTFIELD2KEY', Justification = 'Staged mapping (OVAL account-policy fields -> secedit keys) for the planned conversion of the ~83 mappable-but-manual STIG findings; kept so the derived mapping knowledge is not lost.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helpers Resolve-TestRefs / Get-RegistryArgs return sets; the plural is the accurate name and these are not exported cmdlets.')]
param(
    [Parameter(Mandatory)][string] $ScapXml,
    [Parameter(Mandatory)][string] $ListName,
    [string] $OutDir
)

if (-not (Test-Path $ScapXml)) { throw "SCAP XML not found: $ScapXml" }
if (-not $OutDir) { $OutDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'lists/stig' }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# XXE-safe load: on Windows PowerShell 5.1 (.NET Framework) the [xml] accelerator's
# XmlDocument resolves external entities/DTDs by default, so a hostile SCAP file could
# exfiltrate local files or trigger SSRF. Load through an XmlReader that PROHIBITS DTDs
# and uses no resolver (also defeats billion-laughs). SCAP/XCCDF carries no DTD, so
# Prohibit is the strictest safe setting.
$xmlSettings = New-Object System.Xml.XmlReaderSettings
$xmlSettings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
$xmlSettings.XmlResolver   = $null
$xmlReader = [System.Xml.XmlReader]::Create($ScapXml, $xmlSettings)
try {
    $doc = New-Object System.Xml.XmlDocument
    $doc.Load($xmlReader)
} finally { $xmlReader.Dispose() }

# Namespace manager
$nsm = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
$nsm.AddNamespace('ss',   'http://scap.nist.gov/schema/scap/source/1.2')
$nsm.AddNamespace('xccdf','http://checklists.nist.gov/xccdf/1.2')
$nsm.AddNamespace('od',   'http://oval.mitre.org/XMLSchema/oval-definitions-5')
$nsm.AddNamespace('win',  'http://oval.mitre.org/XMLSchema/oval-definitions-5#windows')

# ---- Index OVAL by full id (window11: wrappers and defs: reals coexist) -------
$script:defs = @{}; $script:tests = @{}; $script:objs = @{}; $script:states = @{}
$script:nsm = $nsm
foreach ($ovalNode in $doc.SelectNodes('//od:oval_definitions', $nsm)) {
    # Skip the CPE inventory component (platform applicability, not STIG checks)
    foreach ($d in $ovalNode.SelectNodes('./od:definitions/od:definition', $nsm)) { $script:defs[$d.id] = $d }
    foreach ($t in $ovalNode.SelectNodes('./od:tests/*',   $nsm)) { $script:tests[$t.id]  = $t }
    foreach ($o in $ovalNode.SelectNodes('./od:objects/*', $nsm)) { $script:objs[$o.id]   = $o }
    foreach ($s in $ovalNode.SelectNodes('./od:states/*',  $nsm)) { $script:states[$s.id] = $s }
}

# Resolve a definition id to its concrete test_refs, following extend_definition chains.
function Resolve-TestRefs {
    param([string]$DefId, [System.Collections.Generic.HashSet[string]]$Seen)
    if (-not $Seen) { $Seen = [System.Collections.Generic.HashSet[string]]::new() }
    if (-not $Seen.Add($DefId)) { return @() }
    $d = $script:defs[$DefId]; if (-not $d) { return @() }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($crit in $d.SelectNodes('.//od:criteria/od:criterion', $script:nsm)) { $out.Add($crit.test_ref) }
    foreach ($ext in $d.SelectNodes('.//od:criteria/od:extend_definition', $script:nsm)) {
        foreach ($r in (Resolve-TestRefs -DefId $ext.definition_ref -Seen $Seen)) { $out.Add($r) }
    }
    return $out
}

# OVAL operation -> HardeningTomcat operator
function Convert-Operation {
    param([string]$Op)
    switch ($Op) {
        'greater than or equal' { '>=' }
        'less than or equal'    { '<=' }
        'greater than'          { '>' }
        'less than'             { '<' }
        'not equal'             { '!=' }
        default                 { '=' }   # 'equals' or unspecified
    }
}

# OVAL test type -> HardeningTomcat method
$TYPE2METHOD = @{
    'registry_test'                       = 'Registry'
    'ntuser_test'                         = 'Registry'
    'auditeventpolicysubcategories_test'  = 'auditpol'
    'passwordpolicy_test'                 = 'accountpolicy'
    'lockoutpolicy_test'                  = 'accountpolicy'
    'accesstoken_test'                    = 'accesschk'
}

# Map OVAL account-policy state field -> secedit [System Access] key (for accountpolicy)
$ACCTFIELD2KEY = @{
    'password_hist_len'    = 'PasswordHistorySize'
    'max_passwd_age'       = 'MaximumPasswordAge'
    'min_passwd_age'       = 'MinimumPasswordAge'
    'min_passwd_len'       = 'MinimumPasswordLength'
    'password_complexity'  = 'PasswordComplexity'
    'reversible_encryption'= 'ClearTextPassword'
    'lockout_duration'     = 'LockoutDuration'
    'lockout_threshold'    = 'LockoutBadCount'
    'lockout_observation_window' = 'ResetLockoutCount'
}

# ---- Helpers to read an OVAL test's object + state ----------------------------
function Get-RegistryArgs {
    param($Test)
    $objRef = $Test.SelectSingleNode('./win:object', $script:nsm).object_ref
    $o = $script:objs[$objRef]; if (-not $o) { return $null }
    $hive = $o.SelectSingleNode('./win:hive', $script:nsm).'#text'
    $key  = $o.SelectSingleNode('./win:key',  $script:nsm).'#text'
    $name = $o.SelectSingleNode('./win:name', $script:nsm).'#text'
    # Map OVAL hive name to the PS registry drive prefix.
    $prefix = switch ($hive) {
        'HKEY_LOCAL_MACHINE' { 'HKLM:' }
        'HKEY_CURRENT_USER'  { 'HKCU:' }
        'HKEY_USERS'         { 'HKU:' }
        default              { 'HKLM:' }
    }
    @{ path = "$prefix\$key"; name = $name }
}

function Get-RegistryStateValue {
    param($Test)
    $stEl = $Test.SelectSingleNode('./win:state', $script:nsm)
    if (-not $stEl) { return @{ value=''; op='=' } }
    $s = $script:states[$stEl.state_ref]; if (-not $s) { return @{ value=''; op='=' } }
    # The 'value' child carries the expected data + operation; ignore the 'type' child.
    $val = $s.SelectSingleNode('./win:value', $script:nsm)
    if (-not $val) { return @{ value=''; op='=' } }
    @{ value = $val.'#text'; op = (Convert-Operation $val.operation) }
}

# Resolve one OVAL test to a concrete Registry check, or $null if it can't be one
# (non-registry type, pattern/cert-store path, or no literal expected value).
function Resolve-RegistryTestCheck {
    param($Test)
    if ($TYPE2METHOD[$Test.LocalName] -ne 'Registry') { return $null }
    $ra = Get-RegistryArgs $Test
    # Cert-store subkey enumerations and regex/pattern paths (e.g. smartcard readers,
    # DoD Root CA presence) have no single value name -- not auto-convertible.
    $isPattern = $ra -and ($ra.path -match '[\\^$.|?*+()\[\]]' -and $ra.path -notmatch '^HK[A-Z]+:\\[\w\\ .-]+$')
    if (-not ($ra -and $ra.name) -or $isPattern) { return $null }
    $sv = Get-RegistryStateValue $Test
    if (-not ("$($sv.value)".Trim())) { return $null }
    @{ args = $ra; op = $sv.op; rec = $sv.value }
}

# Does this definition (or any definition it extends) use OR logic in its criteria?
# 'A OR B' cannot be decomposed into independent all-must-pass findings.
function Test-DefUsesOrLogic {
    param([string]$DefId, [System.Collections.Generic.HashSet[string]]$Seen)
    if (-not $Seen) { $Seen = [System.Collections.Generic.HashSet[string]]::new() }
    if (-not $Seen.Add($DefId)) { return $false }
    $d = $script:defs[$DefId]; if (-not $d) { return $false }
    foreach ($crit in $d.SelectNodes('.//od:criteria', $script:nsm)) {
        if ("$($crit.operator)" -eq 'OR') { return $true }
    }
    foreach ($ext in $d.SelectNodes('.//od:criteria/od:extend_definition', $script:nsm)) {
        if (Test-DefUsesOrLogic -DefId $ext.definition_ref -Seen $Seen) { return $true }
    }
    return $false
}

# Build findings ----------------------------------------------------------------
$findings = New-Object System.Collections.Generic.List[object]
$idCounts = @{}
$stats = @{ Registry=0; auditpol=0; accountpolicy=0; accesschk=0; manual=0 }

$bench = $doc.SelectSingleNode('//xccdf:Benchmark', $nsm)
foreach ($r in $bench.SelectNodes('.//xccdf:Rule', $nsm)) {
    $sid = $r.SelectSingleNode('./xccdf:version', $nsm).'#text'
    $title = $r.SelectSingleNode('./xccdf:title', $nsm).'#text'
    $sev = switch ($r.severity) { 'high' {'High'} 'low' {'Low'} default {'Medium'} }
    $fix = $r.SelectSingleNode('./xccdf:fixtext', $nsm)
    $fixText = if ($fix) { $fix.'#text' } else { '' }

    # Unique id (STIG V-IDs/version can repeat across rules in some benchmarks)
    $rawId = $sid
    if ($idCounts.ContainsKey($rawId)) { $idCounts[$rawId]++; $uid = "$rawId-$($idCounts[$rawId])" }
    else { $idCounts[$rawId] = 1; $uid = $rawId }

    $chk = $r.SelectSingleNode('.//xccdf:check[@system="http://oval.mitre.org/XMLSchema/oval-definitions-5"]', $nsm)
    $method = 'manual'; $fargs = @{}; $op = 'manual'; $rec = ''
    $extraChecks = @()   # additional findings when a definition ANDs several registry tests
    $nameSuffix = ''
    if ($chk) {
        $ref = $chk.SelectSingleNode('./xccdf:check-content-ref', $nsm)
        $trefs = @(if ($ref) { Resolve-TestRefs -DefId $ref.name } else { @() })
        if (@($trefs).Count -eq 1 -and $script:tests[$trefs[0]]) {
            $t = $script:tests[$trefs[0]]
            $typ = $t.LocalName
            $m = $TYPE2METHOD[$typ]
            if ($m -eq 'Registry') {
                # Only a usable Registry finding if it resolves to a concrete single value;
                # cert-store/pattern checks and no-literal-value states stay manual so they
                # surface with their fixtext instead of as broken checks.
                $p = Resolve-RegistryTestCheck $t
                if ($p) { $method='Registry'; $fargs=$p.args; $op=$p.op; $rec=$p.rec }
                else { $fargs=@{ intendedMethod='Registry'; ovalType=$typ; note='cert-store, pattern, or no-literal-value check' } }
            }
            # Non-registry mappable types are emitted as manual for now (handler arg
            # extraction for audit/accountpolicy/accesschk from OVAL is a later stage),
            # but keep their intended method visible in the category.
            elseif ($m) {
                $method='manual'; $op='manual'
                $fargs=@{ intendedMethod = $m; ovalType = $typ }
            }
        }
        elseif (@($trefs).Count -gt 1) {
            # A definition with SEVERAL tests. Previously only the FIRST was emitted,
            # silently under-checking 'A AND B' rules: a machine failing only B was
            # reported compliant. AND-logic definitions whose tests ALL resolve to
            # concrete registry checks now emit ONE FINDING PER TEST; anything else
            # (OR logic, unresolvable sub-checks) honestly falls back to manual.
            $hasOr = Test-DefUsesOrLogic -DefId $ref.name
            $parts = @()
            $allOk = -not $hasOr
            if ($allOk) {
                foreach ($tr in $trefs) {
                    $t2 = $script:tests[$tr]
                    $p = if ($t2) { Resolve-RegistryTestCheck $t2 } else { $null }
                    if ($p) { $parts += , $p } else { $allOk = $false; break }
                }
            }
            if ($allOk -and $parts.Count -gt 0) {
                $method='Registry'; $fargs=$parts[0].args; $op=$parts[0].op; $rec=$parts[0].rec
                if ($parts.Count -gt 1) {
                    $extraChecks = $parts[1..($parts.Count - 1)]
                    $nameSuffix = " [check 1/$($parts.Count)]"
                }
            } else {
                $why = if ($hasOr) { 'OR logic' } else { 'not all sub-checks auto-convertible' }
                $fargs = @{ note = "multi-criterion OVAL check ($(@($trefs).Count) tests; $why); requires human verification" }
            }
        }
    }
    if ($method -eq 'Registry') { $stats.Registry++ } else { $stats.manual++ }

    $obj = [ordered]@{
        id = $uid; sourceId = $rawId; name = "$title$nameSuffix"
        category = "DoD STIG ($($r.severity))"; method = $method
        args = $fargs; operator = $op
        recommendedValue = "$rec"; defaultValue = ''
        severity = $sev; fixText = $fixText
    }
    $findings.Add([pscustomobject]$obj)

    # Sibling findings for the remaining AND'd sub-checks (same V-ID, suffixed ids).
    $k = 1
    foreach ($p in $extraChecks) {
        $k++
        $stats.Registry++
        $findings.Add([pscustomobject]([ordered]@{
            id = "$uid-t$k"; sourceId = $rawId; name = "$title [check $k/$(@($extraChecks).Count + 1)]"
            category = "DoD STIG ($($r.severity))"; method = 'Registry'
            args = $p.args; operator = $p.op
            recommendedValue = "$($p.rec)"; defaultValue = ''
            severity = $sev; fixText = $fixText
        }))
    }
}

$out = [ordered]@{
    listName = $ListName
    version  = (Get-Date -Format 'yyyy.MM.dd')
    source   = "Derived from authoritative DISA SCAP benchmark: $(Split-Path $ScapXml -Leaf)"
    findings = $findings
}
$safe = ($ListName -replace '[^\w\-]', '_')
$outPath = Join-Path $OutDir "$safe.json"
$out | ConvertTo-Json -Depth 8 | Set-Content -Path $outPath -Encoding UTF8

Write-Host "Wrote $($findings.Count) findings -> $outPath" -ForegroundColor Green
Write-Host "  Registry (auto): $($stats.Registry)   Manual/unsupported: $($stats.manual)" -ForegroundColor Cyan
Write-Host "  NOTE: non-registry STIG checks (audit/account/user-rights/WMI) are currently" -ForegroundColor DarkYellow
Write-Host "        emitted as 'manual' -- they carry the V-ID + fixtext but are reported Skipped." -ForegroundColor DarkYellow
