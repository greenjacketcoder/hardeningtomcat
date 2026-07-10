# Shared helpers available to all handlers (dot-sourced by the engine before handler load).

function Get-HtRegistryValue {
    <#
      Reads a single registry value. Returns @{ Found=$bool; Result=<value> }.
      Never throws on a missing key/value -- that's Found=$false, per the handler contract.
      Access DENIED, however, is a genuine error and is rethrown: conflating it with
      "value absent" would make the engine substitute defaultValue and report a confident
      Pass/Fail for a key it could not actually read. The contract says such findings
      must be Skipped, and the engine's Test wrapper does that on throw.

      Perf: a single Get-ItemProperty call. The generic catch handles a missing key OR
      value, so the old pre-check Test-Path (a second registry round-trip per finding)
      is gone. On a ~300-finding registry-heavy list that halves registry round-trips.
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
        # ONE generic catch with an explicit -is check, NOT typed catch blocks:
        # Windows PowerShell 5.1 mis-matches typed catch clauses once a hot function
        # gets JIT-compiled (~16 invocations), routing EVERY later exception into the
        # first typed handler -- observed as hundreds of missing-key reads reported
        # as access denied on a full-list run. Runtime -is checks are immune.
        $ex = $_.Exception
        if ($ex -is [System.Security.SecurityException] -or $ex -is [System.UnauthorizedAccessException]) {
            throw "Access denied reading $Path\$Name : $($ex.Message)"
        }
        return @{ Found = $false; Result = $null }
    }
}

function ConvertTo-HtObservedString {
    <#
      Normalizes a handler's observed Result into the engine's comparison string.
      Multi-string registry values (REG_MULTI_SZ) arrive as ARRAYS from Get-ItemProperty;
      finding lists store the expected value ';'-separated (e.g. 'netlogon;samr;lsarpc'),
      so arrays join on ';'. A space-join would make every multi-string finding
      false-fail forever -- and since elements can contain spaces ('Server
      Applications'), it would not even be reversible.
    #>
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [array]) { return (@($Value) -join ';') }
    return [string]$Value
}

function Resolve-HtApplyValue {
    <#
      Normalizes a recommendedValue into the literal value Strike writes. Shared by the
      apply path so audit (Test-HtOperator) and apply can never disagree on a value:
        - Strips a single pair of wrapping double-quotes (an INF/GptTmpl import
          artifact); XML/AppLocker payloads (starting '<') are left alone.
        - Resolves CIS "X or Y" prose to the FIRST listed value (CIS lists the primary
          acceptable value first); the '=or' operator accepts any of them on audit.
    #>
    param($Value)
    if ($Value -is [string] -and $Value.Length -ge 2 -and $Value[0] -eq '"' -and $Value[-1] -eq '"' -and $Value -notmatch '^"?<') {
        $Value = $Value.Substring(1, $Value.Length - 2)
    }
    if ($Value -is [string] -and $Value -match '^\s*([\w-]+)\s+or\s+') {
        $Value = $matches[1]
    }
    return $Value
}
