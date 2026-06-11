# Shared helpers available to all handlers (dot-sourced by the engine before handler load).

function Get-HtRegistryValue {
    <#
      Reads a single registry value. Returns @{ Found=$bool; Result=<value> }.
      Never throws on a missing key/value — that's Found=$false, per the handler contract.
    #>
    param([string]$Path, [string]$Name)
    try {
        if (-not (Test-Path $Path)) { return @{ Found = $false; Result = $null } }
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return @{ Found = $true; Result = $item.$Name }
    } catch {
        return @{ Found = $false; Result = $null }
    }
}
