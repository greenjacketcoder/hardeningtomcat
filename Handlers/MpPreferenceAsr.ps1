# MpPreferenceAsr handler -- Microsoft Defender Attack Surface Reduction (ASR) rules.
# args.ruleId = the ASR rule GUID (from MethodArgument). Observes that rule's action:
#   0 = Disabled (Not Configured), 1 = Block, 2 = Audit, 6 = Warn.
# Read once via Get-MpPreference, which exposes parallel arrays:
#   AttackSurfaceReductionRules_Ids  /  AttackSurfaceReductionRules_Actions

@{
    Name = 'MpPreferenceAsr'
    RequiresAdmin = $true

    Prefetch = {
        param($Findings, $Cache, $Context)
        $map = @{}
        try {
            $pref = Get-MpPreference -ErrorAction Stop
            $ids = @($pref.AttackSurfaceReductionRules_Ids)
            $act = @($pref.AttackSurfaceReductionRules_Actions)
            for ($i = 0; $i -lt $ids.Count; $i++) {
                if ($ids[$i]) { $map[("$($ids[$i])").ToLower()] = "$($act[$i])" }
            }
            $Cache['asr_ok'] = $true
        } catch {
            # Get-MpPreference missing (no Defender module) or access denied.
            $Cache['asr_ok'] = $false
            & $Context.Log "MpPreferenceAsr: Get-MpPreference FAILED -- ASR findings will Skip. $($_.Exception.Message)" 'Warn'
        }
        $Cache['asr'] = $map
        & $Context.Log "MpPreferenceAsr prefetch: cached $($map.Count) configured ASR rules."
    }

    Test = {
        param($Finding, $Cache, $Context)
        if (-not $Cache['asr_ok']) { throw "Get-MpPreference unavailable; cannot evaluate ASR rule $($Finding.args.ruleId)" }
        $id = "$($Finding.args.ruleId)".ToLower()
        $map = $Cache['asr']
        if ($map.ContainsKey($id)) {
            return [pscustomobject]@{ Result = $map[$id]; Found = $true }
        }
        # Rule not present in the configured set = action 0 (Not Configured / Disabled).
        [pscustomobject]@{ Result = '0'; Found = $true }
    }

    Apply = {
        param($Finding, $Cache, $Context)
        $id  = $Finding.args.ruleId
        $val = $Finding.recommendedValue
        if ($Context.WhatIf) {
            return @{ Changed = $false; Message = "WhatIf: would set ASR rule $id to action $val" }
        }
        try {
            # Map numeric action to the Set-MpPreference enum value.
            $action = switch ("$val") { '1' {'Enabled'} '2' {'AuditMode'} '6' {'Warn'} default {'Disabled'} }
            Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions $action -ErrorAction Stop
            if ($Cache.ContainsKey('asr')) { $Cache.Remove('asr') }   # invalidate cache
            return @{ Changed = $true; Message = "ASR rule $id set to $action" }
        } catch {
            # THROW so the engine counts this in ApplyFailed and surfaces a warning.
            # Returning Changed=$false here made a failed ASR apply invisible -- the
            # same green-summary bug class fixed for secedit/auditpol in 0.5.1/0.8.0.
            throw "ASR apply failed for $id : $($_.Exception.Message)"
        }
    }
}
