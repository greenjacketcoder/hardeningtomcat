# Shared helpers available to all handlers (dot-sourced by the engine before handler load).

function Get-HtRegistryValue {
    <#
      Reads a single registry value. Returns @{ Found=$bool; Result=<value> }.
      Never throws on a missing key/value -- that's Found=$false, per the handler contract.

      Perf: a single Get-ItemProperty call. The catch handles a missing key OR value,
      so the old pre-check Test-Path (a second registry round-trip per finding) is gone.
      On a ~300-finding registry-heavy list that halves registry round-trips.
    #>
    param([string]$Path, [string]$Name)
    # Defensive: normalize any forward slashes in the registry path to backslashes.
    # Registry paths always use '\'; a '/' can only be corruption (e.g. an old list
    # generated on macOS/Linux where Split-Path mangled separators). Preserve 'HKLM:' etc.
    if ($Path -match '/') {
        $Path = $Path -replace '(?<!:)/', '\'
    }
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return @{ Found = $true; Result = $item.$Name }
    } catch {
        return @{ Found = $false; Result = $null }
    }
}
