# localaccount handler -- built-in account status & names (Guest/Administrator by RID).
# args.rid = the account's RID (500=Administrator, 501=Guest). MethodArgument in the
# CIS list carries that RID. Checks: enabled state (True/False) and the account name.
#
# The finding's intent is inferred from its name:
#   "...account status"  -> observe Enabled (True/False)
#   "Rename ... account"  -> observe the account Name
# Local accounts are looked up by SID suffix (RID) so renamed accounts are still found.

@{
    Name = 'localaccount'
    RequiresAdmin = $true

    Prefetch = {
        param($Findings, $Cache, $Context)
        $accounts = @{}
        try {
            # CIM is available on 5.1 and 7; filter to local accounts.
            $local = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction Stop
            foreach ($u in $local) {
                # SID looks like S-1-5-21-...-<RID>; key by the trailing RID.
                $rid = ($u.SID -split '-')[-1]
                $accounts[$rid] = [pscustomobject]@{ Name = $u.Name; Disabled = [bool]$u.Disabled }
            }
            $Cache['localaccounts_ok'] = $true
        } catch {
            $Cache['localaccounts_ok'] = $false
            & $Context.Log "localaccount: enumeration FAILED -- findings will Skip. $($_.Exception.Message)" 'Warn'
        }
        $Cache['localaccounts'] = $accounts
        & $Context.Log "localaccount prefetch: cached $($accounts.Count) local accounts."
    }

    Test = {
        param($Finding, $Cache, $Context)
        if (-not $Cache['localaccounts_ok']) { throw "local account enumeration unavailable; cannot evaluate $($Finding.name)" }
        $rid = "$($Finding.args.rid)"
        $acct = $Cache['localaccounts'][$rid]
        if (-not $acct) {
            # Built-in account genuinely absent (e.g. Guest removed). Found=false.
            return [pscustomobject]@{ Result = $null; Found = $false }
        }
        # Decide what to observe from the finding name.
        if ($Finding.name -match 'status') {
            # Enabled state as True/False (CIS phrases these as account status).
            $enabled = -not $acct.Disabled
            return [pscustomobject]@{ Result = "$enabled"; Found = $true }
        }
        else {
            # Rename checks -- observe the current account name.
            return [pscustomobject]@{ Result = $acct.Name; Found = $true }
        }
    }

    # Renaming/enabling/disabling built-in accounts is a sensitive change; gate Apply
    # to read-only in beta (a misfire here could lock you out). Build deliberately later.
    Apply = $null
}
