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

# Dot-source the standalone pieces under test.
. (Join-Path $moduleRoot 'Private\_Helpers.ps1')
. (Join-Path $moduleRoot 'Private\_Integrity.ps1')
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
        $r.Message | Should Match 'different name'
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
}
