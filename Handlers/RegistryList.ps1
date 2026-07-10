# RegistryList handler -- checks whether a value APPEARS among all values under a key.
# Unlike Registry (one named value), CIS "list" keys (e.g. DenyDeviceClasses) hold an
# enumerated set: value "1" = <guid>, "2" = <guid>, ... The check passes if the
# recommendedValue appears as the DATA of ANY value under the key, order-independent.
#
# args: { path = 'HKLM:\...\DenyDeviceClasses', item = '<guid-or-string>' }
#   (item mirrors the recommendedValue; either may carry the expected content.)
# operator is typically '=' (present) or '!=' (absent).

@{
    Name = 'RegistryList'
    RequiresAdmin = $false   # HKLM list keys are readable without elevation

    Test = {
        param($Finding, $Cache, $Context)
        $path = $Finding.args.path
        if ($path -match '/') { $path = $path -replace '(?<!:)/', '\' }  # normalize stray slashes
        $needle = if ($Finding.args.item) { "$($Finding.args.item)" } else { "$($Finding.recommendedValue)" }

        # Read every value under the key; collect their data as strings.
        $values = @()
        try {
            # -LiteralPath: args.path is semi-trusted; -Path would glob-expand and read
            # across every matching key. Bind the path exactly as written.
            $props = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
                $values += "$($p.Value)"
            }
        } catch {
            # Key doesn't exist = empty list. Observed is empty; operators handle the verdict
            # (e.g. '=' vs a needle -> fail/absent; '!=' -> pass/absent), without throwing.
            return [pscustomobject]@{ Result = ''; Found = $false }
        }

        # Observed result = whether the needle is present among the list's values.
        # Return the matched value if present (so the report shows what matched), else empty.
        $match = $values | Where-Object { $_ -eq $needle }
        if ($match) {
            return [pscustomobject]@{ Result = $needle; Found = $true }
        }
        # Present the joined list as the observed value when nothing matched, for context.
        return [pscustomobject]@{ Result = ''; Found = $true }
    }

    # Applying a list entry means adding the value under the key with the next free name.
    # Sensitive (wrong entries can break device install policy); gated read-only in beta.
    Apply = $null
}
