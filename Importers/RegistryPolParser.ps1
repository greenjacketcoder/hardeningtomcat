#Requires -Version 5.1
<#
.SYNOPSIS
    Parses a Windows registry.pol file (Group Policy registry policy) into structured records.

.DESCRIPTION
    registry.pol is the binary format Microsoft uses inside GPO backups (and that the
    Security Compliance Toolkit baselines ship). This parser reads it WITHOUT any external
    tools, so HardeningTomcat can ingest Microsoft baselines directly rather than relying
    on a third party's translation.

    FORMAT SPEC (documented by Microsoft, stable since Windows 2000):
    -----------------------------------------------------------------
      Offset 0 : signature  = 0x50526567  ("PReg" as little-endian bytes 50 52 65 67)
      Offset 4 : version    = 0x00000001  (4 bytes, little-endian)
      Then a sequence of records, each:
        '['  (0x5B 0x00 in UTF-16LE)
        Key       : null-terminated UTF-16LE string
        ';'       (0x3B 0x00)
        Value     : null-terminated UTF-16LE string
        ';'
        Type      : 4-byte little-endian DWORD (REG_SZ=1, REG_EXPAND_SZ=2,
                    REG_BINARY=3, REG_DWORD=4, REG_DWORD_BIG_ENDIAN=5,
                    REG_MULTI_SZ=7, REG_QWORD=11)
        ';'
        Size      : 4-byte little-endian DWORD  (size of Data in bytes)
        ';'
        Data      : <Size> bytes, interpreted per Type
        ']'  (0x5D 0x00)

    All strings/delimiters are UTF-16LE, so every "character" is 2 bytes and the
    null terminator is 0x00 0x00.

.OUTPUTS
    [pscustomobject] per record: Key, ValueName, Type, TypeName, Data, RawData
#>

function ConvertFrom-RegistryPol {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [string] $Path,

        [Parameter(Mandatory, ParameterSetName = 'Bytes')]
        [byte[]] $Bytes
    )

    if ($PSCmdlet.ParameterSetName -eq 'Path') {
        if (-not (Test-Path $Path)) { throw "registry.pol not found: $Path" }
        $Bytes = [System.IO.File]::ReadAllBytes($Path)
    }

    if ($Bytes.Length -lt 8) { throw "File too small to be a registry.pol ($($Bytes.Length) bytes)." }

    # --- header ---------------------------------------------------------------
    # Signature 'PReg' = 0x50 0x52 0x65 0x67
    if (-not ($Bytes[0] -eq 0x50 -and $Bytes[1] -eq 0x52 -and $Bytes[2] -eq 0x65 -and $Bytes[3] -eq 0x67)) {
        throw "Bad signature. Expected 'PReg' (50 52 65 67); got $($Bytes[0..3] | ForEach-Object { '{0:X2}' -f $_ })."
    }
    $version = [BitConverter]::ToUInt32($Bytes, 4)
    Write-Verbose "registry.pol version $version, $($Bytes.Length) bytes"

    $typeNames = @{
        1 = 'REG_SZ'; 2 = 'REG_EXPAND_SZ'; 3 = 'REG_BINARY'; 4 = 'REG_DWORD'
        5 = 'REG_DWORD_BIG_ENDIAN'; 7 = 'REG_MULTI_SZ'; 11 = 'REG_QWORD'
    }

    $records = New-Object System.Collections.Generic.List[object]
    $i = 8   # start after header

    # Helper: read a null-terminated UTF-16LE string starting at $i, advance $i past terminator.
    $readUtf16Z = {
        param([ref]$pos)
        $start = $pos.Value
        while ($pos.Value -lt $Bytes.Length - 1) {
            if ($Bytes[$pos.Value] -eq 0x00 -and $Bytes[$pos.Value + 1] -eq 0x00) { break }
            $pos.Value += 2
        }
        $strBytes = $Bytes[$start..($pos.Value - 1)]
        $pos.Value += 2   # skip the 00 00 terminator
        if ($strBytes.Length -eq 0) { return '' }
        [System.Text.Encoding]::Unicode.GetString($strBytes)
    }

    # Helper: expect a specific UTF-16LE char (e.g. '[' ';' ']') and advance.
    $expectChar = {
        param([ref]$pos, [char]$c)
        $expected = [System.Text.Encoding]::Unicode.GetBytes([string]$c)
        if ($Bytes[$pos.Value] -ne $expected[0] -or $Bytes[$pos.Value + 1] -ne $expected[1]) {
            throw "Parse error at offset $($pos.Value): expected '$c'."
        }
        $pos.Value += 2
    }

    while ($i -lt $Bytes.Length) {
        # Skip any stray padding/newlines between records
        if ($Bytes[$i] -eq 0x00) { $i += 1; continue }

        $ref = [ref]$i
        & $expectChar $ref '['
        $key = & $readUtf16Z $ref
        & $expectChar $ref ';'
        $valueName = & $readUtf16Z $ref
        & $expectChar $ref ';'
        $type = [BitConverter]::ToUInt32($Bytes, $ref.Value); $ref.Value += 4
        & $expectChar $ref ';'
        $size = [BitConverter]::ToUInt32($Bytes, $ref.Value); $ref.Value += 4
        & $expectChar $ref ';'

        # Bounds-check the attacker-influenced size field before slicing. A malformed/hostile
        # registry.pol can carry a bogus $size larger than the remaining buffer; slicing on it
        # would throw a confusing out-of-range error deep in the parse. Fail fast with a clear
        # message instead (the caller skips the file on a parse error).
        if ($size -gt ($Bytes.Length - $ref.Value)) {
            throw "registry.pol record has size $size exceeding remaining buffer $($Bytes.Length - $ref.Value) at offset $($ref.Value) -- file is malformed or truncated."
        }
        $rawData = if ($size -gt 0) { $Bytes[$ref.Value..($ref.Value + $size - 1)] } else { @() }
        $ref.Value += $size
        & $expectChar $ref ']'

        # Interpret data by type
        $data = switch ($type) {
            4  { if ($rawData.Length -ge 4) { [BitConverter]::ToUInt32($rawData, 0) } else { 0 } }       # DWORD
            5  { if ($rawData.Length -ge 4) { [System.BitConverter]::ToUInt32(($rawData[3..0]), 0) } else { 0 } } # DWORD big-endian
            11 { if ($rawData.Length -ge 8) { [BitConverter]::ToUInt64($rawData, 0) } else { 0 } }       # QWORD
            1  { ([System.Text.Encoding]::Unicode.GetString($rawData)).TrimEnd([char]0) }                # SZ
            2  { ([System.Text.Encoding]::Unicode.GetString($rawData)).TrimEnd([char]0) }                # EXPAND_SZ
            7  { (([System.Text.Encoding]::Unicode.GetString($rawData)).TrimEnd([char]0)) -split "`0" }  # MULTI_SZ
            default { $rawData }                                                                          # BINARY/unknown
        }

        $records.Add([pscustomobject]@{
            Key       = $key
            ValueName = $valueName
            Type      = $type
            TypeName  = if ($typeNames.ContainsKey([int]$type)) { $typeNames[[int]$type] } else { "UNKNOWN($type)" }
            Data      = $data
            RawData   = $rawData
        })
        $i = $ref.Value
    }

    Write-Verbose "Parsed $($records.Count) registry records."
    $records
}
