#Requires -Version 5.1
<#
.SYNOPSIS
    Validates an imported Microsoft baseline JSON by surfacing key findings across all
    three parser types (Registry / secedit / auditpol) so you can spot-check values
    against the SCT documentation spreadsheet.

.DESCRIPTION
    This does NOT contact any system. It only reads the generated JSON and prints the
    findings you'd want to verify by hand against Microsoft's baseline spreadsheet.
    It also runs sanity checks (counts, empty values, type sanity) that catch parser bugs.

.EXAMPLE
    ./Test-ImportedBaseline.ps1 -FindingList ./lists/microsoft/Microsoft_Windows_11_25H2_-_Machine.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $FindingList
)

if (-not (Test-Path $FindingList)) { throw "File not found: $FindingList" }

$list = Get-Content $FindingList -Raw | ConvertFrom-Json
$f = $list.findings

Write-Host ""
Write-Host "==== Imported baseline: $($list.listName) ====" -ForegroundColor Cyan
Write-Host "Total findings: $($f.Count)" -ForegroundColor Cyan
Write-Host ""

# ---- 1. Method breakdown ---------------------------------------------------
Write-Host "--- Method breakdown ---" -ForegroundColor Yellow
$f | Group-Object method | Sort-Object Count -Descending | ForEach-Object {
    Write-Host ("  {0,-12} {1}" -f $_.Name, $_.Count)
}
Write-Host ""

# ---- 2. Sanity checks (catch parser bugs) ----------------------------------
Write-Host "--- Sanity checks ---" -ForegroundColor Yellow
$issues = @()

$emptyVals = $f | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.recommendedValue) }
if ($emptyVals) { $issues += "[$($emptyVals.Count)] findings have EMPTY recommendedValue (possible parse miss)" }

$emptyNames = $f | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.name) }
if ($emptyNames) { $issues += "[$($emptyNames.Count)] findings have EMPTY name" }

# Registry findings should all have a path + name in args
$badReg = $f | Where-Object { $_.method -eq 'Registry' -and (-not $_.args.path -or -not $_.args.name) }
if ($badReg) { $issues += "[$($badReg.Count)] Registry findings missing args.path or args.name" }

# Are values suspiciously all identical? (would indicate a stuck parser)
$distinctVals = ($f | Where-Object method -eq 'Registry' | Select-Object -ExpandProperty recommendedValue | Sort-Object -Unique).Count
if ($distinctVals -le 1) { $issues += "All Registry values are identical (=$distinctVals distinct) — parser likely broken" }
else { Write-Host "  Registry recommendedValues span $distinctVals distinct values (good — not stuck)" -ForegroundColor Green }

# Type distribution
$types = $f | Where-Object method -eq 'Registry' | Group-Object { $_.args.type }
Write-Host "  Registry type spread: $(( $types | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', ')" -ForegroundColor Green

if ($issues) {
    Write-Host ""
    $issues | ForEach-Object { Write-Host "  ! $_" -ForegroundColor Red }
} else {
    Write-Host "  No structural issues found." -ForegroundColor Green
}
Write-Host ""

# ---- 3. Key settings to verify against the SCT spreadsheet -----------------
Write-Host "--- SPOT-CHECK THESE against the SCT Documentation spreadsheet ---" -ForegroundColor Yellow
Write-Host "    (open Documentation\*.xlsx in the unzipped baseline)" -ForegroundColor DarkGray
Write-Host ""

function Show-Match($label, $patterns) {
    Write-Host "  $label" -ForegroundColor Cyan
    $hits = $f | Where-Object {
        $name = $_.name
        $argstr = ($_.args.PSObject.Properties | ForEach-Object { $_.Value }) -join ' '
        $patterns | Where-Object { $name -match $_ -or $argstr -match $_ }
    }
    if (-not $hits) { Write-Host "    (none found)" -ForegroundColor DarkGray; return }
    foreach ($h in $hits) {
        $key = if ($h.method -eq 'auditpol') { $h.args.subcategory }
               elseif ($h.method -eq 'secedit') { $h.args.key }
               else { "$($h.args.name)" }
        Write-Host ("    [{0,-9}] {1,-45} = {2}" -f $h.method, $key, $h.recommendedValue)
    }
    Write-Host ""
}

# Account policy (secedit / GptTmpl.inf parser)
Show-Match "Password & lockout policy (expect e.g. 14, 365, 5):" `
    @('MinimumPasswordLength','MaximumPasswordAge','MinimumPasswordAge','PasswordComplexity','LockoutBadCount','LockoutDuration','PasswordHistorySize')

# Audit policy (auditpol / audit.csv parser)
Show-Match "Audit policy (expect e.g. 'Success and Failure'):" `
    @('Credential Validation','Logon','Logoff','Account Lockout','Security Group Management','Process Creation','Audit Policy Change')

# Well-known registry security settings
Show-Match "Key registry settings (verify values):" `
    @('EnableLUA','fDenyTSConnections','RestrictAnonymous','LmCompatibilityLevel','NoLMHash','EnableSmartScreen','DisableAutomaticRestartSignOn')

Write-Host "==== Done. Verify the above against the spreadsheet, then this list is trusted. ====" -ForegroundColor Cyan
