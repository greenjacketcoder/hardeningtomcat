# ProcessmitigationApplication handler -- per-application Exploit Protection settings
# (Windows Defender Exploit Guard / process mitigations), read via Get-ProcessMitigation.
#
# args.target = '<PROCESS>/<Category>/<Property>', e.g. 'ONEDRIVE.EXE/DEP/OverrideDEP'.
#   Category is one of: DEP, ASLR, Payload, ImageLoad, ChildProcess, SEHOP, etc.
#   Get-ProcessMitigation -Name <process> returns an object whose .<Category>.<Property>
#   holds the value (often an enum like ON/OFF/NOTSET or a bool-ish).
#
# Prefetch groups findings by process so Get-ProcessMitigation runs ONCE per process
# (not once per property) -- a process with ~30 properties becomes 1 call, not 30.

@{
    Name = 'ProcessmitigationApplication'
    RequiresAdmin = $true

    Prefetch = {
        param($Findings, $Cache, $Context)
        # Collect the distinct process names this run needs.
        $procs = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($f in $Findings) {
            $t = "$($f.args.target)"
            $p = ($t -split '/')[0]
            if ($p) { [void]$procs.Add($p) }
        }
        $byProc = @{}
        $ok = $true
        foreach ($p in $procs) {
            try {
                $byProc[$p] = Get-ProcessMitigation -Name $p -ErrorAction Stop
            } catch {
                # A process with no explicit mitigations, or cmdlet unavailable.
                $byProc[$p] = $null
                & $Context.Log "Processmitigation: Get-ProcessMitigation -Name $p failed: $($_.Exception.Message)" 'Warn'
            }
        }
        # If the cmdlet itself is missing (non-Windows / no Defender), mark not-ok so
        # findings Skip rather than silently report absent.
        if (-not (Get-Command Get-ProcessMitigation -ErrorAction SilentlyContinue)) {
            $ok = $false
            & $Context.Log "Processmitigation: Get-ProcessMitigation cmdlet not available -- findings will Skip." 'Warn'
        }
        $Cache['procmit'] = $byProc
        $Cache['procmit_ok'] = $ok
        & $Context.Log "ProcessmitigationApplication prefetch: queried $($procs.Count) process(es)."
    }

    Test = {
        param($Finding, $Cache, $Context)
        if (-not $Cache['procmit_ok']) { throw "Get-ProcessMitigation unavailable; cannot evaluate $($Finding.args.target)" }
        $parts = "$($Finding.args.target)" -split '/'
        if ($parts.Count -lt 3) { throw "malformed process-mitigation target '$($Finding.args.target)'" }
        $proc = $parts[0]; $category = $parts[1]; $property = $parts[2]

        $mit = $Cache['procmit'][$proc]
        # Distinguish "no data for this process at all" (app likely not installed) from
        # "process has mitigation data but this specific property is unset". Both are
        # genuine findings if the STIG expects a value -- we do NOT suppress them to a
        # pass -- but the Note makes the report interpretable rather than a bare blank.
        if (-not $mit) {
            return [pscustomobject]@{ Result = ''; Found = $false; Note = "no mitigation data for $proc (app may not be installed)" }
        }
        $catObj = $mit.$category
        if (-not $catObj) {
            return [pscustomobject]@{ Result = ''; Found = $false; Note = "$proc has no $category mitigations configured" }
        }
        $val = $catObj.$property
        if ($null -eq $val) {
            return [pscustomobject]@{ Result = ''; Found = $false; Note = "$proc $category/$property not set" }
        }
        # Normalize the mitigation enum/bool to a string the operators can compare.
        return [pscustomobject]@{ Result = "$val"; Found = $true }
    }

    # Applying exploit-protection settings uses Set-ProcessMitigation; high-impact and
    # easy to break app compatibility. Gated read-only in beta.
    Apply = $null
}
