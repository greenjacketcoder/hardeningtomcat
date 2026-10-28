# Shared helpers available to all handlers (dot-sourced by the engine before handler load).

function Get-HtRegistryValue {
    <#
      Reads a single registry value. Returns @{ Found=$bool; Result=<value> }.
      Never throws on a missing key/value -- that's Found=$false, per the handler contract.
      Access DENIED, however, is a genuine error and is rethrown: conflating it with
      "value absent" would make the engine substitute defaultValue and report a confident
      Pass/Fail for a key it could not actually read. The contract says such findings
      must be Skipped, and the engine's Test wrapper does that on throw.

      Perf: the .NET registry API, not the provider. RegistryKey.OpenSubKey returns
      $null for a missing key instead of throwing; on a fresh machine MOST policy keys
      are absent, so the provider's exception path (ErrorRecord + script stack capture
      per miss) was the COMMON case on every Recon. Semantics are unchanged: literal
      path and value name, default RegistryView (the engine already refuses the WOW64
      view for Strike), REG_EXPAND_SZ expanded by GetValue, access denied rethrown.
      Paths on a drive the hive map does not know (a custom PSDrive) fall through to
      the provider.
    #>
    param([string]$Path, [string]$Name)
    # Defensive: normalize any forward slashes in the registry path to backslashes.
    # Registry paths always use '\'; a '/' can only be corruption (e.g. an old list
    # generated on macOS/Linux where Split-Path mangled separators). Preserve 'HKLM:' etc.
    if ($Path -match '/') {
        $Path = $Path -replace '(?<!:)/', '\'
    }
    try {
        if ($Path -match '^(?<hive>[A-Za-z_]+):?(?:\\(?<sub>.*))?$' -and $script:HtHiveMap.ContainsKey($matches.hive)) {
            $sub  = if ($matches.sub) { $matches.sub } else { '' }
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($script:HtHiveMap[$matches.hive], [Microsoft.Win32.RegistryView]::Default)
            try {
                $key = $base.OpenSubKey($sub, $false)
                if ($null -eq $key) { return @{ Found = $false; Result = $null } }
                try {
                    if ($key.GetValueNames() -contains $Name) {
                        return @{ Found = $true; Result = $key.GetValue($Name) }
                    }
                    return @{ Found = $false; Result = $null }
                } finally { $key.Dispose() }
            } finally { $base.Dispose() }
        }
        # Provider fallback (custom drive names). -LiteralPath, not -Path: args.path is
        # glob-expands *, ?, and [...], so a wildcard path would read (and, in the Apply
        # handler, WRITE) across every matching key -- turning one finding into a broad
        # blast radius. -LiteralPath binds the path exactly as written.
        #
        # The VALUE NAME must be literal too: the previous Get-ItemProperty -Name read
        # treated the name as a WILDCARD pattern, so names like '\\*\NETLOGON' (Hardened
        # UNC Paths) worked only by accident, a sibling value matching the pattern could
        # report Found=$true with a $null Result (grading against empty instead of
        # defaultValue), and names containing [ ] failed outright. GetValueNames() +
        # GetValue() bind the name literally -- and skip PSObject property wrapping
        # (~2-3x faster per read). GetValue's default options expand REG_EXPAND_SZ,
        # matching Get-ItemProperty's behavior, so observed values are unchanged.
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($key.GetValueNames() -contains $Name) {
            return @{ Found = $true; Result = $key.GetValue($Name) }
        }
        return @{ Found = $false; Result = $null }
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

# Provider drive names and long-form hive names -> RegistryHive, for the .NET read path.
$script:HtHiveMap = @{
    HKLM = [Microsoft.Win32.RegistryHive]::LocalMachine;  HKEY_LOCAL_MACHINE  = [Microsoft.Win32.RegistryHive]::LocalMachine
    HKCU = [Microsoft.Win32.RegistryHive]::CurrentUser;   HKEY_CURRENT_USER   = [Microsoft.Win32.RegistryHive]::CurrentUser
    HKCR = [Microsoft.Win32.RegistryHive]::ClassesRoot;   HKEY_CLASSES_ROOT   = [Microsoft.Win32.RegistryHive]::ClassesRoot
    HKU  = [Microsoft.Win32.RegistryHive]::Users;         HKEY_USERS          = [Microsoft.Win32.RegistryHive]::Users
    HKCC = [Microsoft.Win32.RegistryHive]::CurrentConfig; HKEY_CURRENT_CONFIG = [Microsoft.Win32.RegistryHive]::CurrentConfig
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

function Get-HtSeceditExport {
    <#
      Runs `secedit /export` ONCE and parses the INF into lookup tables. Shared by the
      secedit, accountpolicy, and accesschk handlers, which previously carried three
      near-identical spawn/parse/cleanup copies (differing only in /areas) plus an
      implicit cache-ordering coupling. One implementation = one place for the
      exit-code-2 (scesrv memory) diagnosis and the sensitive-temp-file cleanup.

      Memoized per run when -Cache is passed: the first caller pays for ONE full export
      (all areas -- it includes [System Access], [Privilege Rights], and the rest) and
      every later caller gets the parsed result from $Cache['secedit_export'].
      Previously each handler ran its own area-scoped export, and because Prefetch
      order follows hashtable key order, a CIS list paid two or three scesrv round
      trips per run. -Areas is ignored when -Cache is given (a shared export must be
      complete to be shareable).

      Returns @{
        Ok       = $bool     # export ran and produced content
        Flat     = @{}       # 'key = value' lines, section-agnostic, NON-EMPTY values
                             #   only (legacy secedit/accountpolicy lookup shape: an
                             #   empty value falls through to Found=$false/defaultValue)
        Sections = @{}       # '[Section]' -> @{ key = value }, EMPTY values KEPT (a
                             #   user right assigned to no one exports as 'SeXxx = ')
        Error    = <string>  # user-facing scesrv exit-2 message, else $null
      }
    #>
    param(
        [string] $Areas,   # e.g. 'SECURITYPOLICY' or 'USER_RIGHTS'; empty = full export
        $Context,          # engine context (for logging); optional
        $Cache             # engine per-run cache; when given, memoizes one FULL export
    )
    $log = { param($m, $l = 'Warn') if ($Context -and $Context.Log) { & $Context.Log $m $l } }
    if ($null -ne $Cache) {
        if ($Cache.ContainsKey('secedit_export')) { return $Cache['secedit_export'] }
        $Areas = ''
    }
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ht_secexp_{0:yyyyMMddHHmmssfff}.inf" -f (Get-Date))
    $ok = $false; $exitCode = $null; $err = $null
    try {
        if ($Areas) { & secedit.exe /export /areas $Areas /cfg $tmp /quiet 2>$null }
        else        { & secedit.exe /export /cfg $tmp /quiet 2>$null }
        $exitCode = $LASTEXITCODE
        if ($exitCode -eq 0 -and (Test-Path $tmp) -and (Get-Item $tmp).Length -gt 0) { $ok = $true }
    } catch {
        & $log "secedit export threw: $($_.Exception.Message)"
    }
    $flat = @{}; $sections = @{}
    if ($ok) {
        $current = ''
        foreach ($line in (Get-Content -Path $tmp -Encoding Unicode)) {
            $t = $line.Trim()
            if ($t -match '^\[(.+)\]$') {
                $current = $matches[1]
                if (-not $sections.ContainsKey($current)) { $sections[$current] = @{} }
                continue
            }
            if ($t -match '^([^=\[]+?)\s*=\s*(.*)$') {
                $k = $matches[1].Trim(); $v = $matches[2].Trim()
                if ($current) { $sections[$current][$k] = $v }
                if ($v) { $flat[$k] = $v }
            }
        }
    } elseif ($exitCode -eq 2) {
        # secedit exit 2 = "Not enough memory resources" -- a system/scesrv resource
        # condition, NOT a problem with any finding. Diagnosed here once for all callers.
        $err = 'secedit could not run: the system reported insufficient memory resources (scesrv). Free memory or reboot, then re-run. Policy findings were skipped, not failed.'
        & $log $err 'Error'
    } else {
        & $log "secedit export FAILED (exit $exitCode) -- dependent findings will be Skipped, not passed."
    }
    # Always remove the dump: it contains full security policy (user rights, SIDs).
    Remove-Item $tmp -Force -WhatIf:$false -ErrorAction SilentlyContinue
    $result = @{ Ok = $ok; Flat = $flat; Sections = $sections; Error = $err }
    if ($null -ne $Cache) { $Cache['secedit_export'] = $result }
    $result
}
