# accesschk handler -- user-rights assignments (the [Privilege Rights] section).
# args: { "privilege": "SeShutdownPrivilege" }
# recommendedValue: comma-separated SID list, e.g. "S-1-5-32-544,S-1-5-19"
# operator: 'set=' (order-independent set equality; names resolved to SIDs). The engine
#           rejects any other operator for this method at load time -- a plain '=' can
#           never match the export's '*S-1-5-...' form against a list's names.
#
# Reads user rights via `secedit /export` ONCE in Prefetch (batched), then each Test
# is an in-memory lookup -- same pattern as the secedit handler. No accesschk.exe needed.

@{
    Name = 'accesschk'
    RequiresAdmin = $true
    RequiresBinary = 'C:\Windows\System32\secedit.exe'

    Prefetch = {
        param($Findings, $Cache, $Context)
        # The shared, memoized full export (Private/_Helpers.ps1) -- one secedit spawn per
        # run, shared with secedit/accountpolicy. User rights live in the [Privilege Rights]
        # section; the helper keeps EMPTY values in Sections (a right assigned to no one
        # exports as 'SeXxx = ').
        $exp = Get-HtSeceditExport -Context $Context -Cache $Cache
        $rights = if ($exp.Sections.ContainsKey('Privilege Rights')) { $exp.Sections['Privilege Rights'] } else { @{} }
        $Cache['userrights']    = $rights
        $Cache['userrights_ok'] = $exp.Ok
        & $Context.Log "accesschk prefetch: export $(if($exp.Ok){'OK'}else{'FAILED'}), cached $($rights.Count) assignments."
    }

    Test = {
        param($Finding, $Cache, $Context)
        # If the export failed, we genuinely don't know the state -- do NOT claim compliant.
        if (-not $Cache['userrights_ok']) {
            throw "user-rights export unavailable; cannot evaluate $($Finding.args.privilege)"
        }
        $table = $Cache['userrights']
        $priv = $Finding.args.privilege
        if ($table.ContainsKey($priv)) {
            return [pscustomobject]@{ Result = $table[$priv]; Found = $true }
        }
        # Export succeeded AND privilege is absent = genuinely no accounts hold it (empty set).
        [pscustomobject]@{ Result = ''; Found = $true }
    }

    # Applying user rights means writing an INF with the [Privilege Rights] section and
    # running secedit /configure. Higher-risk; gated to read-only in beta like secedit.
    # Build deliberately after the audit path is validated on a VM.
    Apply = $null
}
