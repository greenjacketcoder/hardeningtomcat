# HardeningTomcat unit tests (Pester 3.4-compatible -- the version that ships in-box
# on Windows PowerShell 5.1; syntax also parses on later Pester 3.x/4.x).
#
# Run from the repo root:  Invoke-Pester .\Tests
#
# These pin the pure logic that has ALREADY had bugs in the project's history:
# operator semantics (=or, numeric, set=), value normalization (multi-string join,
# quote stripping, 'X or Y' resolution), the list-integrity gate's fail-closed and
# content-swap behavior, and the registry.pol binary parser.

$here       = Split-Path -Parent $MyInvocation.MyCommand.Path
$moduleRoot = Split-Path -Parent $here

# Portability: fixtures use $env:TEMP, which macOS/Linux pwsh do not set. Fall back to
# the platform temp dir so the OS-independent Describes (integrity, auto-select, list
# validation) run on a dev Mac too -- only the registry-backed tests are Windows-only.
if (-not $env:TEMP) { $env:TEMP = [System.IO.Path]::GetTempPath() }

# Dot-source the standalone pieces under test.
. (Join-Path $moduleRoot 'Private\_Helpers.ps1')
. (Join-Path $moduleRoot 'Private\_Integrity.ps1')
. (Join-Path $moduleRoot 'Private\_OsDetect.ps1')
. (Join-Path $moduleRoot 'Importers\RegistryPolParser.ps1')

# Test-HtOperator is module-internal; import the module and call inside its scope.
$script:HtModule = Import-Module (Join-Path $moduleRoot 'HardeningTomcat.psd1') -Force -PassThru
function Test-Op {
    param([string]$Op, [string]$Obs, [string]$Rec)
    & $script:HtModule { param($o, $x, $r) Test-HtOperator -Operator $o -Observed $x -Recommended $r } $Op $Obs $Rec
}

Describe 'Test-HtOperator' {

    Context "'=' and '!='" {
        It 'passes on exact match' { (Test-Op '=' '1' '1') | Should Be $true }
        It 'fails on mismatch'     { (Test-Op '=' '2' '1') | Should Be $false }
        It '!= passes on mismatch' { (Test-Op '!=' '2' '1') | Should Be $true }
        It 'string comparison is case-insensitive by design (pinned)' {
            (Test-Op '=' 'Enterprise' 'ENTERPRISE') | Should Be $true
        }
    }

    Context "'=or' (CIS 'X or Y' values)" {
        It 'passes when observed matches the first option'  { (Test-Op '=or' '1' '1 or 2') | Should Be $true }
        It 'passes when observed matches the second option' { (Test-Op '=or' '2' '1 or 2') | Should Be $true }
        It 'passes on the 256 or 287 CIS case'              { (Test-Op '=or' '287' '256 or 287') | Should Be $true }
        It 'fails when observed matches no option'          { (Test-Op '=or' '3' '1 or 2') | Should Be $false }
    }

    Context 'numeric operators use int64 (values >= 2^31 are legitimate)' {
        It '<= passes within range'            { (Test-Op '<=' '5' '10') | Should Be $true }
        It '>= handles 4294967295 (max DWORD)' { (Test-Op '>=' '4294967295' '1') | Should Be $true }
        It '<= handles 4294967295 as bound'    { (Test-Op '<=' '4294967295' '4294967295') | Should Be $true }
        It 'non-numeric observed fails, not throws' { (Test-Op '<=' 'abc' '10') | Should Be $false }
        It '<=!0 rejects zero'                 { (Test-Op '<=!0' '0' '10') | Should Be $false }
        It '<=!0 passes nonzero within bound'  { (Test-Op '<=!0' '5' '10') | Should Be $true }
    }

    Context 'empty/absent observation must NOT coerce to 0 (LAPS false-pass regression)' {
        # Windows PowerShell 5.1: [int64]'' == 0 without throwing. An absent registry key is
        # graded with an empty Observed; before the guard, '' -> 0 made <=/>= a false PASS
        # (e.g. LAPS PasswordAgeDays <= 30 "passed" while unconfigured). Every numeric
        # operator must FAIL an empty/whitespace observation, never treat it as 0.
        It '<= fails on empty observed (was false-pass 0<=30)' { (Test-Op '<=' '' '30') | Should Be $false }
        It '>= fails on empty observed'                        { (Test-Op '>=' '' '0')  | Should Be $false }
        It '<  fails on empty observed'                        { (Test-Op '<'  '' '30') | Should Be $false }
        It '>  fails on empty observed'                        { (Test-Op '>'  '' '0')  | Should Be $false }
        It '<=!0 fails on empty observed'                      { (Test-Op '<=!0' '' '30') | Should Be $false }
        It '<= fails on whitespace-only observed'              { (Test-Op '<=' '   ' '30') | Should Be $false }
        It 'real zero still evaluates normally (0 <= 30 passes)' { (Test-Op '<=' '0' '30') | Should Be $true }
    }

    Context "'contains'" {
        It 'empty needle never passes (no unjustifiable pass)' { (Test-Op 'contains' 'anything' '') | Should Be $false }
        It 'passes on substring' { (Test-Op 'contains' 'abcdef' 'cde') | Should Be $true }
    }

    Context "'=|0' (match or empty)" {
        It 'passes on empty observed' { (Test-Op '=|0' '' '5') | Should Be $true }
        It 'passes on exact match'    { (Test-Op '=|0' '5' '5') | Should Be $true }
        It 'fails on other value'     { (Test-Op '=|0' '6' '5') | Should Be $false }
    }

    Context "'set=' (order-independent SID sets)" {
        It 'passes on reordered SID lists' {
            (Test-Op 'set=' 'S-1-5-32-544,S-1-1-0' 'S-1-1-0, S-1-5-32-544') | Should Be $true
        }
        It 'strips leading * from secedit-style entries' {
            (Test-Op 'set=' '*S-1-5-32-544' 'S-1-5-32-544') | Should Be $true
        }
        It 'both empty = equal sets (privilege held by no one)' {
            (Test-Op 'set=' '' '') | Should Be $true
        }
        It 'fails on different set sizes' {
            (Test-Op 'set=' 'S-1-5-32-544' 'S-1-5-32-544,S-1-1-0') | Should Be $false
        }
    }

    Context 'unknown operator' {
        It 'never passes' { (Test-Op 'bogus' '1' '1') | Should Be $false }
    }
}

Describe 'ConvertTo-HtObservedString (multi-string normalization)' {
    It 'joins arrays with ; to match the list convention' {
        ConvertTo-HtObservedString @('netlogon', 'samr', 'lsarpc') | Should Be 'netlogon;samr;lsarpc'
    }
    It 'joins elements containing spaces without mangling them' {
        ConvertTo-HtObservedString @('System\CCS\Control\ProductOptions', 'System\CCS\Control\Server Applications') |
            Should Be 'System\CCS\Control\ProductOptions;System\CCS\Control\Server Applications'
    }
    It 'passes plain strings through' { ConvertTo-HtObservedString 'plain' | Should Be 'plain' }
    It 'returns empty string for $null' { ConvertTo-HtObservedString $null | Should Be '' }
    It 'stringifies numbers' { ConvertTo-HtObservedString 5 | Should Be '5' }
}

Describe 'Resolve-HtApplyValue (apply-path value normalization)' {
    It 'strips a single pair of wrapping double-quotes' { Resolve-HtApplyValue '"1"' | Should Be '1' }
    It 'leaves XML/AppLocker payloads alone' {
        Resolve-HtApplyValue '"<RuleCollection/>"' | Should Be '"<RuleCollection/>"'
    }
    It "resolves 'X or Y' prose to the first value" { Resolve-HtApplyValue '1 or 2' | Should Be '1' }
    It "resolves '256 or 287' to 256" { Resolve-HtApplyValue '256 or 287' | Should Be '256' }
    It 'leaves plain values untouched' { Resolve-HtApplyValue '5' | Should Be '5' }
}

Describe 'Get-HtRegistryValue' {
    It 'reads an existing value (Found=true)' {
        $r = Get-HtRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentBuild'
        $r.Found | Should Be $true
        $r.Result | Should Match '^\d+$'
    }
    It 'reports a missing value as Found=false, not an error' {
        $r = Get-HtRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'HtNoSuchValue_12345'
        $r.Found | Should Be $false
    }
    It 'reports a missing key as Found=false, not an error' {
        $r = Get-HtRegistryValue -Path 'HKLM:\SOFTWARE\HtNoSuchKey_12345' -Name 'x'
        $r.Found | Should Be $false
    }
    It 'normalizes forward slashes in corrupted paths' {
        $r = Get-HtRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft/Windows NT/CurrentVersion' -Name 'CurrentBuild'
        $r.Found | Should Be $true
    }
    It 'reads value names containing wildcard characters LITERALLY (Hardened UNC Paths class)' {
        # Get-ItemProperty -Name treats the name as a wildcard pattern; the literal
        # GetValueNames()/GetValue() read must find the real '\\*\NETLOGON' value AND
        # must NOT report a pattern-only sibling match as Found.
        $p = 'HKCU:\Software\HtPesterLiteral'
        New-Item -Path $p -Force | Out-Null
        try {
            New-ItemProperty -Path $p -Name '\\*\NETLOGON' -Value 'RequireMutualAuthentication=1' -PropertyType String -Force | Out-Null
            $r = Get-HtRegistryValue -Path $p -Name '\\*\NETLOGON'
            $r.Found | Should Be $true
            $r.Result | Should Match 'RequireMutualAuthentication'
            # '\\*\SYSVOL' as a PATTERN would match the NETLOGON-adjacent name space;
            # as a LITERAL it matches nothing -- Found must be false.
            (Get-HtRegistryValue -Path $p -Name '\\*\SYSVOL').Found | Should Be $false
        } finally { Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Test-HtListIntegrity' {
    # Build a throwaway module-root fixture: <root>\lists\manifest.sha256 + a list file.
    $fixRoot = Join-Path $env:TEMP ("ht-pester-{0}" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    $listsDir = Join-Path $fixRoot 'lists\cis'
    New-Item -ItemType Directory -Path $listsDir -Force | Out-Null
    $listPath = Join-Path $listsDir 'Test_List.json'
    '{"listName":"t","findings":[]}' | Set-Content -Path $listPath -Encoding Ascii -NoNewline
    $hash = (Get-FileHash -Path $listPath -Algorithm SHA256).Hash.ToLower()
    $manifest = Join-Path $fixRoot 'lists\manifest.sha256'
    "# test manifest`r`n$hash  cis/Test_List.json" | Set-Content -Path $manifest -Encoding Ascii

    It 'verifies a list whose hash and name match the manifest' {
        $r = Test-HtListIntegrity -FindingList $listPath -ModuleRoot $fixRoot
        $r.Status | Should Be 'verified'
    }
    It 'reports CatalogPresent=false when no signed catalog ships' {
        $r = Test-HtListIntegrity -FindingList $listPath -ModuleRoot $fixRoot
        $r.CatalogPresent | Should Be $false
    }
    It 'flags an edited list as not-listed' {
        $edited = Join-Path $listsDir 'Test_List_Edited.json'
        '{"listName":"t","findings":[{"tampered":true}]}' | Set-Content -Path $edited -Encoding Ascii -NoNewline
        (Test-HtListIntegrity -FindingList $edited -ModuleRoot $fixRoot).Status | Should Be 'not-listed'
    }
    It 'refuses trusted content that appears under a DIFFERENT file name (content swap)' {
        $swapped = Join-Path $listsDir 'Some_Other_List.json'
        Copy-Item $listPath $swapped
        $r = Test-HtListIntegrity -FindingList $swapped -ModuleRoot $fixRoot
        $r.Status | Should Be 'not-listed'
        $r.Message | Should Match 'different path/name'
    }
    It 'reports no-manifest when the manifest is absent' {
        $bareRoot = Join-Path $env:TEMP ("ht-pester-{0}" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
        New-Item -ItemType Directory -Path (Join-Path $bareRoot 'lists') -Force | Out-Null
        try {
            (Test-HtListIntegrity -FindingList $listPath -ModuleRoot $bareRoot).Status | Should Be 'no-manifest'
        } finally { Remove-Item -Recurse -Force $bareRoot -ErrorAction SilentlyContinue }
    }

    # Cleanup after the Describe block's tests have run.
    It 'cleanup (fixture removal)' {
        Remove-Item -Recurse -Force $fixRoot -ErrorAction SilentlyContinue
        (Test-Path $fixRoot) | Should Be $false
    }
}

Describe 'ConvertFrom-RegistryPol' {
    $fixture = Join-Path $moduleRoot 'Importers\tests\sample_registry.pol'

    It 'parses the sample fixture into records' {
        $recs = @(ConvertFrom-RegistryPol -Path $fixture)
        $recs.Count | Should BeGreaterThan 0
        $recs[0].Key       | Should Not BeNullOrEmpty
        $recs[0].ValueName | Should Not BeNullOrEmpty
        $recs[0].TypeName  | Should Match '^REG_'
    }
    It 'rejects a file with a bad signature' {
        { ConvertFrom-RegistryPol -Bytes ([byte[]](1..64)) } | Should Throw
    }
    It 'rejects a truncated file' {
        { ConvertFrom-RegistryPol -Bytes ([byte[]](0x50, 0x52)) } | Should Throw
    }
}

Describe 'Finding-list data invariants' -Tag 'Data' {
    $listFiles = Get-ChildItem -Path (Join-Path $moduleRoot 'lists') -Recurse -Filter '*.json'

    It 'every shipped list parses as JSON with a findings array' {
        foreach ($f in $listFiles) {
            $d = Get-Content -Raw -Path $f.FullName | ConvertFrom-Json
            @($d.findings).Count | Should BeGreaterThan 0
        }
    }
    It "no '=or' finding exists outside the Registry method" {
        foreach ($f in $listFiles) {
            $d = Get-Content -Raw -Path $f.FullName | ConvertFrom-Json
            $bad = @($d.findings | Where-Object { $_.operator -eq '=or' -and $_.method -ne 'Registry' })
            $bad.Count | Should Be 0
        }
    }
    It "no 'X or Y' prose survives on '=' operator findings (the false-failure bug)" {
        foreach ($f in $listFiles) {
            $d = Get-Content -Raw -Path $f.FullName | ConvertFrom-Json
            $bad = @($d.findings | Where-Object {
                $_.operator -eq '=' -and "$($_.recommendedValue)" -match '^\s*[\w-]+\s+or\s+[\w-]+\s*$'
            })
            $bad.Count | Should Be 0
        }
    }
    It 'every Registry finding carries non-empty args.path and args.name' {
        foreach ($f in $listFiles) {
            $d = Get-Content -Raw -Path $f.FullName | ConvertFrom-Json
            $bad = @($d.findings | Where-Object {
                $_.method -eq 'Registry' -and ((-not $_.args) -or (-not $_.args.path) -or (-not $_.args.name))
            })
            $bad.Count | Should Be 0
        }
    }
    It 'no Registry/RegistryList finding carries wildcard characters in args.path' {
        # The engine also rejects these at load; enforcing here means a bad list fails
        # CI on push instead of failing the first user who runs it.
        foreach ($f in $listFiles) {
            $d = Get-Content -Raw -Path $f.FullName | ConvertFrom-Json
            $bad = @($d.findings | Where-Object {
                $_.method -in 'Registry','RegistryList' -and $_.args -and $_.args.path -match '[*?\[\]]'
            })
            $bad.Count | Should Be 0
        }
    }
}

Describe 'Resolve-HtDefaultList (auto-select)' {
    # Fixture module root with a lists/cis folder we control. Get-HtOsIdentity is
    # mocked so these tests run identically on any CI runner.
    $osdRoot = Join-Path $env:TEMP ("ht-pester-osd-{0}" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    $osdCis = Join-Path $osdRoot 'lists\cis'
    New-Item -ItemType Directory -Path $osdCis -Force | Out-Null
    '{"listName":"CIS Windows 11 25H2 L1","version":"1","findings":[{"id":"1"}]}' |
        Set-Content -Path (Join-Path $osdCis 'CIS_Windows_11_25H2_L1.json') -Encoding Ascii
    '{"listName":"CIS Intune Windows 11 L1","version":"1","autoSelect":false,"findings":[{"id":"1"}]}' |
        Set-Content -Path (Join-Path $osdCis 'CIS_Intune_Windows_11_L1.json') -Encoding Ascii

    Mock Get-HtOsIdentity { [pscustomobject]@{ Product = 'Windows 11'; Release = '25H2'; Build = 26200; Caption = 'Microsoft Windows 11 Enterprise' } }

    It 'selects the OS-matched list (release bonus wins)' {
        $r = Resolve-HtDefaultList -ModuleRoot $osdRoot
        $r.Path | Should Match 'CIS_Windows_11_25H2_L1\.json$'
    }
    It 'a list without the autoSelect field remains eligible (legacy lists unaffected)' {
        (Resolve-HtDefaultList -ModuleRoot $osdRoot).Path | Should Not Be $null
    }
    It 'never selects an autoSelect:false list, even as the only OS match' {
        $soloRoot = Join-Path $env:TEMP ("ht-pester-osd-{0}" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
        $soloCis = Join-Path $soloRoot 'lists\cis'
        New-Item -ItemType Directory -Path $soloCis -Force | Out-Null
        Copy-Item (Join-Path $osdCis 'CIS_Intune_Windows_11_L1.json') $soloCis
        try {
            (Resolve-HtDefaultList -ModuleRoot $soloRoot).Path | Should Be $null
        } finally { Remove-Item -Recurse -Force $soloRoot -ErrorAction SilentlyContinue }
    }
    It 'cleanup (fixture removal)' {
        Remove-Item -Recurse -Force $osdRoot -ErrorAction SilentlyContinue
        (Test-Path $osdRoot) | Should Be $false
    }
}

Describe 'Invoke-HardeningTomcat engine (Recon end-to-end)' {
    # The first test that exercises the unified loop rather than its pieces:
    # real registry fixtures under HKCU (no elevation needed) + a fixture list.
    $regRoot = 'HKCU:\Software\HtPesterTest'
    New-Item -Path $regRoot -Force | Out-Null
    New-ItemProperty -Path $regRoot -Name 'PassMe' -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $regRoot -Name 'FailMe' -Value 5 -PropertyType DWord -Force | Out-Null

    $e2eList = Join-Path $env:TEMP ("ht-pester-e2e-{0}.json" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    @'
{"listName":"Pester E2E","version":"1","findings":[
 {"id":"1","name":"passes on observed value","method":"Registry","args":{"path":"HKCU:\\Software\\HtPesterTest","name":"PassMe"},"operator":"=","recommendedValue":"1","severity":"Low"},
 {"id":"2","name":"fails on observed value","method":"Registry","args":{"path":"HKCU:\\Software\\HtPesterTest","name":"FailMe"},"operator":"=","recommendedValue":"1","severity":"Medium"},
 {"id":"3","name":"absent value grades against defaultValue","method":"Registry","args":{"path":"HKCU:\\Software\\HtPesterTest","name":"Missing"},"operator":"=","recommendedValue":"7","defaultValue":"7","severity":"Low"},
 {"id":"4","name":"manual is skipped with fixText","method":"manual","args":{},"operator":"manual","recommendedValue":"","severity":"Low","fixText":"do it by hand"}
]}
'@ | Set-Content -Path $e2eList -Encoding Ascii

    $run = Invoke-HardeningTomcat -Mode Recon -FindingList $e2eList -PassThru -WarningAction SilentlyContinue

    It 'grades pass / fail / default-pass / manual-skip correctly' {
        $run.Summary.Total   | Should Be 4
        $run.Summary.Passed  | Should Be 2   # id 1 (observed) + id 3 (defaultValue path)
        $run.Summary.Medium  | Should Be 1   # id 2
        $run.Summary.Skipped | Should Be 1   # id 4 (manual)
    }
    It 'reports the observed value it actually read' {
        ($run.Results | Where-Object ID -eq '2').Observed | Should Be '5'
    }
    It 'surfaces manual findings with their fixText' {
        ($run.Results | Where-Object ID -eq '4').Detail | Should Match 'do it by hand'
    }
    It 'cleanup (registry + fixture removal)' {
        Remove-Item -Path $regRoot -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item $e2eList -Force -ErrorAction SilentlyContinue
        (Test-Path $regRoot) | Should Be $false
    }
}

Describe 'Load-time list validation (fail-fast)' {
    $valDir = Join-Path $env:TEMP ("ht-pester-val-{0}" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    New-Item -ItemType Directory -Path $valDir -Force | Out-Null

    It 'rejects duplicate ids' {
        $p = Join-Path $valDir 'dup.json'
        '{"listName":"t","version":"1","findings":[{"id":"1","name":"a","method":"Registry","args":{"path":"HKCU:\\S","name":"x"},"operator":"=","recommendedValue":"1","severity":"Low"},{"id":"1","name":"b","method":"Registry","args":{"path":"HKCU:\\S","name":"y"},"operator":"=","recommendedValue":"1","severity":"Low"}]}' |
            Set-Content -Path $p -Encoding Ascii
        { Invoke-HardeningTomcat -Mode Recon -FindingList $p -WarningAction SilentlyContinue } | Should Throw 'duplicate id'
    }
    It 'rejects wildcard characters in Registry paths' {
        $p = Join-Path $valDir 'wild.json'
        '{"listName":"t","version":"1","findings":[{"id":"1","name":"a","method":"Registry","args":{"path":"HKLM:\\SOFTWARE\\Micro*soft","name":"x"},"operator":"=","recommendedValue":"1","severity":"Low"}]}' |
            Set-Content -Path $p -Encoding Ascii
        { Invoke-HardeningTomcat -Mode Recon -FindingList $p -WarningAction SilentlyContinue } | Should Throw 'wildcard'
    }
    It 'rejects unknown operators' {
        $p = Join-Path $valDir 'op.json'
        '{"listName":"t","version":"1","findings":[{"id":"1","name":"a","method":"Registry","args":{"path":"HKCU:\\S","name":"x"},"operator":"~=","recommendedValue":"1","severity":"Low"}]}' |
            Set-Content -Path $p -Encoding Ascii
        { Invoke-HardeningTomcat -Mode Recon -FindingList $p -WarningAction SilentlyContinue } | Should Throw 'invalid operator'
    }
    It "rejects '=or' outside the Registry method" {
        $p = Join-Path $valDir 'eqor.json'
        '{"listName":"t","version":"1","findings":[{"id":"1","name":"a","method":"service","args":{"name":"Spooler"},"operator":"=or","recommendedValue":"1 or 2","severity":"Low"}]}' |
            Set-Content -Path $p -Encoding Ascii
        { Invoke-HardeningTomcat -Mode Recon -FindingList $p -WarningAction SilentlyContinue } | Should Throw '=or'
    }
    It 'cleanup (fixture removal)' {
        Remove-Item -Recurse -Force $valDir -ErrorAction SilentlyContinue
        (Test-Path $valDir) | Should Be $false
    }
}
