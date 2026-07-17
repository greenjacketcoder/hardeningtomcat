# accountpolicy handler -- password & lockout policy ([System Access] in secedit export).
# CIS finding names map to specific secedit keys. Reads via the SAME secedit export the
# secedit handler caches (or its own if run alone). Mostly the same source as 'secedit',
# but keyed by the CIS account-policy name rather than a raw key in args.

# Map CIS account-policy finding names -> secedit [System Access] keys.
$script:HtAccountPolicyMap = @{
    'Length of password history maintained' = 'PasswordHistorySize'
    'Maximum password age'                  = 'MaximumPasswordAge'
    'Minimum password age'                  = 'MinimumPasswordAge'
    'Minimum password length'               = 'MinimumPasswordLength'
    'Password must meet complexity requirements' = 'PasswordComplexity'
    'Store passwords using reversible encryption' = 'ClearTextPassword'
    'Account lockout duration'              = 'LockoutDuration'
    'Account lockout threshold'             = 'LockoutBadCount'
    'Reset account lockout counter after'   = 'ResetLockoutCount'
    'Allow Administrator account lockout'   = 'AllowAdministratorLockout'
}

@{
    Name = 'accountpolicy'
    RequiresAdmin = $true
    RequiresBinary = 'C:\Windows\System32\secedit.exe'

    Prefetch = {
        param($Findings, $Cache, $Context)
        # Reuse the secedit handler's cache if its prefetch already ran; otherwise run a
        # SECURITYPOLICY-scoped export via the shared helper (Private/_Helpers.ps1).
        if (-not $Cache.ContainsKey('secedit') -or -not $Cache['secedit_ok']) {
            $exp = Get-HtSeceditExport -Areas 'SECURITYPOLICY' -Context $Context
            if ($exp.Error) { $Cache['secedit_err'] = $exp.Error }
            $Cache['secedit'] = $exp.Flat; $Cache['secedit_ok'] = $exp.Ok
        }
        & $Context.Log "accountpolicy prefetch: using secedit export ($($Cache['secedit'].Count) keys)."
    }

    Test = {
        param($Finding, $Cache, $Context)
        if (-not $Cache['secedit_ok']) {
            if ($Cache['secedit_err']) { throw $Cache['secedit_err'] }
            throw "secedit export unavailable; cannot evaluate $($Finding.name)"
        }
        # Resolve the key: explicit args.key wins, else map by finding name.
        $key = if ($Finding.args.key) { $Finding.args.key } else { $script:HtAccountPolicyMap[$Finding.name] }
        if (-not $key) { throw "no account-policy key mapping for '$($Finding.name)'" }
        $table = $Cache['secedit']
        if ($table.ContainsKey($key)) {
            return [pscustomobject]@{ Result = $table[$key]; Found = $true }
        }
        [pscustomobject]@{ Result = $null; Found = $false }
    }

    # Account policy is applied the same way as secedit [System Access] -- write a minimal
    # INF and secedit /configure. Gated to read-only in beta until apply path is validated.
    Apply = $null
}
