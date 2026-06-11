# Registry handler
# args: { "path": "HKLM:\\...", "name": "ValueName", "type": "DWord" }

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
        $type = if ($a.type) { $a.type } else { 'String' }
        $val  = $Finding.recommendedValue

        if ($Context.WhatIf) {
            return @{ Changed = $false; Message = "WhatIf: would set $($a.path)\$($a.name) = $val ($type)" }
        }
        if (-not (Test-Path $a.path)) { New-Item -Path $a.path -Force | Out-Null }
        New-ItemProperty -Path $a.path -Name $a.name -Value $val -PropertyType $type -Force | Out-Null
        @{ Changed = $true; Message = "Set $($a.path)\$($a.name) = $val ($type)" }
    }
}
