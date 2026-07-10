# Regenerate-AllBaselines.ps1
# Regenerates every HardeningTomcat baseline list from the local SCT downloads in one pass.
# Run after importer changes (e.g. the accesschk handler) so all lists stay current & complete.
#
# Pass -BaseDir if your Microsoft Baselines folder lives elsewhere.

param(
    [string] $BaseDir = (Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads\Microsoft Baselines')
)
if (-not (Test-Path $BaseDir)) {
    throw "Microsoft Baselines folder not found: $BaseDir -- pass -BaseDir with the folder holding the unzipped SCT baselines."
}
$Importer = Join-Path $PSScriptRoot 'Import-MicrosoftBaseline.ps1'

# Client baselines (single role -> Client preset, machine scope)
$clients = @(
    @{ Path = "Windows 11 v23H2 Security Baseline";  Name = "Microsoft Windows 11 23H2 - Machine" }
    @{ Path = "Windows 11 v24H2 Security Baseline";  Name = "Microsoft Windows 11 24H2 - Machine" }
    @{ Path = "Windows 11 v25H2 Security Baseline";  Name = "Microsoft Windows 11 25H2 - Machine" }
)

# Server baselines (split per role)
$servers = @(
    @{ Path = "Windows Server-2022-Security-Baseline-FINAL";                          Tag = "Windows Server 2022" }
    @{ Path = "Windows Server 2025 Security Baseline - 2602";                         Tag = "Windows Server 2025" }
    @{ Path = "Windows 10 Version 1809 and Windows Server 2019 Security Baseline";    Tag = "Windows Server 2019" }
    @{ Path = "Windows-10-RS1-and-Server-2016-Security-Baseline";                     Tag = "Windows Server 2016" }
)

foreach ($c in $clients) {
    $gpos = Join-Path $BaseDir (Join-Path $c.Path 'GPOs')
    Write-Host "`n=== $($c.Name) ===" -ForegroundColor Cyan
    & $Importer -BaselinePath $gpos -Role Client -ListName $c.Name
}

foreach ($s in $servers) {
    $gpos = Join-Path $BaseDir (Join-Path $s.Path 'GPOs')
    foreach ($role in 'MemberServer','DomainController') {
        $roleLabel = if ($role -eq 'MemberServer') { 'Member Server' } else { 'Domain Controller' }
        $name = "Microsoft $($s.Tag) - $roleLabel"
        Write-Host "`n=== $name ===" -ForegroundColor Cyan
        & $Importer -BaselinePath $gpos -Role $role -ListName $name
    }
}

Write-Host "`nAll baselines regenerated. Lists are in lists/microsoft/." -ForegroundColor Green
