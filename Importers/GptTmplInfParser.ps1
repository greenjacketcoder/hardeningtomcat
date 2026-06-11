#Requires -Version 5.1
<#
.SYNOPSIS
    Parses a GptTmpl.inf security template (from a GPO backup / SCT baseline) into records.

.DESCRIPTION
    GptTmpl.inf is plain UTF-16 INI text. The sections HardeningTomcat cares about:
      [System Access]      -> password & lockout policy (MinimumPasswordLength, etc.)  -> secedit findings
      [Event Audit]        -> legacy audit categories (mostly superseded by auditpol)
      [Privilege Rights]   -> user-rights assignments (Se* privileges -> SID lists)     -> accesschk findings
      [Registry Values]    -> registry-backed security options                          -> Registry findings
    We emit a normalized record per setting; the mapper decides the final method.
#>

function ConvertFrom-GptTmplInf {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path)

    if (-not (Test-Path $Path)) { throw "GptTmpl.inf not found: $Path" }
    # INF files in GPO backups are typically UTF-16LE; fall back to default if not.
    $lines = Get-Content -Path $Path -Encoding Unicode -ErrorAction Stop

    $records = New-Object System.Collections.Generic.List[object]
    $section = $null
    foreach ($line in $lines) {
        $t = $line.Trim()
        if (-not $t -or $t.StartsWith(';')) { continue }
        if ($t -match '^\[(.+)\]$') { $section = $matches[1]; continue }
        if ($t -match '^(.+?)\s*=\s*(.*)$') {
            $records.Add([pscustomobject]@{
                Section = $section
                Key     = $matches[1].Trim()
                Value   = $matches[2].Trim()
            })
        }
    }
    Write-Verbose "Parsed $($records.Count) INF settings across sections."
    $records
}
