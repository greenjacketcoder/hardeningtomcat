# Update-ListManifest.ps1
# Generates/updates lists/manifest.sha256 -- a record of known-good SHA256 hashes for
# every finding list. Run this AFTER you've imported or edited lists you trust.
#
# The engine verifies a list against this manifest before use. Strike REFUSES a list
# whose hash doesn't match (or isn't listed); Recon warns but proceeds. This is the
# defense against a tampered finding list silently weakening a system.
#
# Treat manifest.sha256 as trusted: commit it, and review diffs to it in code review.

[CmdletBinding()]
param(
    [string] $ListsDir = (Join-Path (Split-Path $PSScriptRoot -Parent) 'lists'),
    [string] $ManifestPath
)

if (-not $ManifestPath) { $ManifestPath = Join-Path $ListsDir 'manifest.sha256' }
if (-not (Test-Path $ListsDir)) { throw "Lists directory not found: $ListsDir" }

$lists = Get-ChildItem -Path $ListsDir -Recurse -Filter '*.json' -ErrorAction SilentlyContinue
if (-not $lists) { Write-Warning "No .json lists found under $ListsDir"; return }

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# HardeningTomcat finding-list integrity manifest")
$lines.Add("# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  Format: <sha256>  <relative path>")
foreach ($l in ($lists | Sort-Object FullName)) {
    $hash = (Get-FileHash -Path $l.FullName -Algorithm SHA256).Hash.ToLower()
    # Store path relative to the lists dir, forward-slashed for cross-platform stability.
    $rel = $l.FullName.Substring($ListsDir.Length).TrimStart('\','/') -replace '\\','/'
    $lines.Add("$hash  $rel")
}
Set-Content -Path $ManifestPath -Value $lines -Encoding UTF8
Write-Host "Wrote $($lists.Count) hashes to $ManifestPath" -ForegroundColor Green
Write-Host "Commit this file. The engine verifies lists against it (Strike refuses mismatches)." -ForegroundColor Cyan
