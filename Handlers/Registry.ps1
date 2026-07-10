# Registry handler
# args: { "path": "HKLM:\\...", "name": "ValueName", "type": "DWord" (optional) }
#
# If args.type is absent (the usual case for CIS/HardeningKitty lists, which don't
# carry a type column), the type is INFERRED from the value the same way HardeningKitty
# does at apply time: numeric -> DWord, a known multi-string item -> MultiString, a
# short list of named exceptions -> String, everything else -> String. Writing a value
# as the wrong type (e.g. a REG_SZ "1" where Windows expects a REG_DWORD) means the
# setting silently does not take effect, so this matters for correctness, not cosmetics.

@{
    Name = 'Registry'

    Test = {
        param($Finding, $Cache, $Context)
        $a = $Finding.args
        $v = Get-HtRegistryValue -Path $a.path -Name $a.name
        [pscustomobject]@{ Result = $v.Result; Found = $v.Found }
    }

    Apply = {
        param($Finding, $Cache, $Context)
        $a = $Finding.args
        $name = $a.name
        # Normalize the recommended value via the SHARED helper (Private/_Helpers.ps1):
        # strips INF-artifact wrapping quotes and resolves CIS "X or Y" prose to the
        # first listed value. Shared with the engine so audit and apply cannot drift.
        $val = Resolve-HtApplyValue $Finding.recommendedValue

        # --- Infer registry type (mirrors HardeningKitty's apply-time logic) -----
        $type = if ($a.type) { $a.type } else {
            $stringExceptions = @('MitigationOptions_FontBocking','Retention','AllocateDASD','ScRemoveOption','AutoAdminLogon')
            $multiStringItems = @('Machine','EccCurves','NullSessionPipes','NullSessionShares')
            if ($name -in $stringExceptions) { 'String' }
            elseif ($name -in $multiStringItems) { 'MultiString' }
            elseif ("$val" -match '^\d+$') { 'DWord' }
            else { 'String' }
        }
        # MultiString values are stored as ';'-separated; split for the registry.
        if ($type -eq 'MultiString' -and $val -is [string]) { $val = $val -split ';' }

        if ($Context.WhatIf) {
            return @{ Changed = $false; Message = "WhatIf: would set $($a.path)\$name = $val ($type)" }
        }
        if (-not (Test-Path $a.path)) { New-Item -Path $a.path -Force -WhatIf:$false | Out-Null }
        New-ItemProperty -Path $a.path -Name $name -Value $val -PropertyType $type -Force -WhatIf:$false | Out-Null
        @{ Changed = $true; Message = "Set $($a.path)\$name = $val ($type)" }
    }
}
