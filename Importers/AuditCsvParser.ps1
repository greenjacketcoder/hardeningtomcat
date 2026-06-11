#Requires -Version 5.1
<#
.SYNOPSIS
    Parses an audit.csv (advanced audit policy) from a GPO backup / SCT baseline.

.DESCRIPTION
    GPO backups store advanced audit policy as a CSV under
    <GPO>\DomainSysvol\GPO\Machine\microsoft\windows nt\Audit\audit.csv
    Columns include: 'Subcategory', 'Subcategory GUID', 'Inclusion Setting',
    'Exclusion Setting', 'Setting Value'. We map Subcategory + Inclusion Setting
    onto auditpol findings (the same shape the auditpol handler reads).
#>

function ConvertFrom-AuditCsv {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path)

    if (-not (Test-Path $Path)) { throw "audit.csv not found: $Path" }
    $rows = Import-Csv -Path $Path

    $records = New-Object System.Collections.Generic.List[object]
    foreach ($row in $rows) {
        $sub = $row.Subcategory
        if (-not $sub) { continue }
        $records.Add([pscustomobject]@{
            Subcategory = $sub.Trim()
            Setting     = $row.'Inclusion Setting'
        })
    }
    Write-Verbose "Parsed $($records.Count) audit subcategories."
    $records
}
