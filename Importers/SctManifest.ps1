#Requires -Version 5.1
<#
.SYNOPSIS
    Parses an SCT GPO-backup manifest.xml and resolves which GPO folders to import.

.DESCRIPTION
    Each baseline's GPOs\manifest.xml lists every GPO as a <BackupInst> with:
      <ID>             the GUID that names the folder ON DISK (e.g. {DAD42DA1-...})
      <GPODisplayName> the readable name (e.g. "MSFT Windows Server 2022 - Member Server")
    NOTE: the on-disk folder is named after <ID>, not <GPOGuid>. We map by <ID>.

    Server baselines bundle mutually-exclusive roles (Domain Controller vs Member Server)
    plus common layers (Defender, IE). Importing all of them into one list blends roles,
    which is wrong. This resolves a clean subset.
#>

function Get-SctGpoManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $GposPath)

    $manifestPath = Join-Path $GposPath 'manifest.xml'
    if (-not (Test-Path $manifestPath)) {
        # No manifest (e.g. a single-GPO folder pointed at directly) — signal caller to
        # fall back to "use everything under the path".
        return $null
    }

    [xml]$xml = Get-Content $manifestPath -Raw
    # Namespace-agnostic: grab all BackupInst regardless of default xmlns.
    $insts = $xml.GetElementsByTagName('BackupInst')
    $gpos = foreach ($inst in $insts) {
        $id   = ($inst.ID      | ForEach-Object { $_.'#cdata-section' }) -join ''
        $name = ($inst.GPODisplayName | ForEach-Object { $_.'#cdata-section' }) -join ''
        if (-not $id)   { $id   = "$($inst.ID)" }
        if (-not $name) { $name = "$($inst.GPODisplayName)" }
        [pscustomobject]@{
            Id          = $id.Trim()
            DisplayName = $name.Trim()
            FolderPath  = Join-Path $GposPath $id.Trim()
        }
    }
    $gpos | Where-Object { $_.Id }
}

function Resolve-SctGpoSelection {
    <#
      Returns the list of GPO folder paths to import, based on selection params.
      - If no manifest: returns @($GposPath) and caller recurses it wholesale (legacy behavior).
      - -IncludeGpo: wildcard patterns matched against DisplayName.
      - -Role: presets expanding to a pattern set (the role GPO + common layers).
      - No selection + manifest present: returns $null to signal "list and stop".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $GposPath,
        [string[]] $IncludeGpo,
        [ValidateSet('MemberServer','DomainController','Client')][string] $Role
    )

    $manifest = Get-SctGpoManifest -GposPath $GposPath
    if (-not $manifest) {
        return [pscustomobject]@{ Mode = 'WholePath'; Folders = @($GposPath); Manifest = $null }
    }

    # Role presets -> display-name patterns, verified against real SCT Server GPO names.
    # Shared layers (Domain Security, Defender, IE Computer) are included in BOTH server roles.
    # '*Member Server*' also matches 'Member Server Credential Guard'; '*Domain Controller*'
    # also matches 'Domain Controller Virtualization Based Security' — both intended.
    $rolePatterns = switch ($Role) {
        'MemberServer'     { @('*Member Server*','*Domain Security*','*Defender*','*Internet Explorer*Computer*') }
        'DomainController' { @('*Domain Controller*','*Domain Security*','*Defender*','*Internet Explorer*Computer*') }
        'Client'           { @('*- Computer*','*Credential Guard*','*Defender*','*BitLocker*','*Internet Explorer*Computer*') }
        default            { $null }
    }

    $patterns = if ($IncludeGpo) { $IncludeGpo } elseif ($rolePatterns) { $rolePatterns } else { $null }

    if (-not $patterns) {
        # No selection given — return manifest so caller can print options and stop.
        return [pscustomobject]@{ Mode = 'ListOnly'; Folders = @(); Manifest = $manifest }
    }

    $selected = foreach ($gpo in $manifest) {
        foreach ($p in $patterns) {
            if ($gpo.DisplayName -like $p) { $gpo; break }
        }
    }
    $selected = $selected | Sort-Object Id -Unique

    [pscustomobject]@{ Mode = 'Selected'; Folders = ($selected.FolderPath); Manifest = $manifest; Selected = $selected }
}
