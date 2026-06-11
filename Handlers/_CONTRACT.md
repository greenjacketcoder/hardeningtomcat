# Handler Contract

Every check method is a self-contained handler file in `Handlers/<Method>.ps1`.
A handler returns a hashtable with a known shape. The engine discovers handlers,
calls `Prefetch` once per run, then `Test` (and `Apply` in Strike) per finding.

This is the pattern that replaces the legacy 21-branch if/elseif ladder and the
duplicated audit/apply loops. Adding a new method = adding one file here. Nothing
in the engine changes.

## Shape

```powershell
@{
    # REQUIRED. Must match the 'method' value in finding lists.
    Name = 'Registry'

    # OPTIONAL. Runs ONCE before the finding loop. Use it to batch slow external
    # calls (auditpol /get /category:*, secedit /export) into a single spawn and
    # cache the parsed result. Receives the full finding list (so it can scope
    # what to prefetch) and a mutable [hashtable] $Cache to stash results in.
    # Return nothing; write into $Cache.
    Prefetch = {
        param($Findings, $Cache, $Context)
        # e.g. $Cache['auditpol'] = (parse auditpol once)
    }

    # REQUIRED. Evaluate ONE finding. Return a [pscustomobject]:
    #   @{ Result = <observed value as string>; Found = $true/$false }
    # The engine does the operator comparison; the handler only OBSERVES.
    # Never throw for "setting absent" — return Found=$false and let the engine
    # fall back to defaultValue. Throw only for genuine errors (missing binary,
    # access denied) so the engine can mark the finding skipped, not failed.
    Test = {
        param($Finding, $Cache, $Context)
        # return [pscustomobject]@{ Result = '1'; Found = $true }
    }

    # REQUIRED for Apply/Strike support. Set ONE finding to its recommendedValue.
    # Must honor $Context.WhatIf (do nothing but report) and return:
    #   @{ Changed = $true/$false; Message = '...' }
    # If a method cannot be applied (read-only, e.g. BitLockerVolume status),
    # set Apply = $null and the engine will report it as non-applicable.
    Apply = {
        param($Finding, $Cache, $Context)
        # if ($Context.WhatIf) { return @{ Changed=$false; Message='WhatIf: would set ...' } }
    }

    # OPTIONAL. $true if this method needs admin/elevation. The engine skips
    # these (with a clear message) when not elevated, instead of letting them
    # error out mid-run.
    RequiresAdmin = $true

    # OPTIONAL. External binary this handler needs. Engine checks existence once
    # and skips the method's findings with a clean message if absent.
    RequiresBinary = 'C:\Windows\System32\auditpol.exe'
}
```

## $Context

A read-only hashtable the engine passes to every scriptblock:

- `Mode`        : 'Recon' | 'Survey' | 'Strike'
- `IsAdmin`     : bool, whether the session is elevated
- `WhatIf`      : bool, set during a dry-run apply
- `PSVersion`   : the running PowerShell major version (5 or 7)
- `Log`         : a scriptblock { param($Text, $Level) } for unified logging

## Rules

1. Handlers OBSERVE in Test and MUTATE in Apply. Never mutate in Test.
2. Handlers never do their own operator comparison — return the raw result.
3. Handlers never write report files — they return data; the engine reports.
4. "Setting not present" is `Found=$false`, never an exception.
5. Keep each handler file independently signable (no cross-file dependencies
   beyond the shared private helpers the engine dot-sources first).
