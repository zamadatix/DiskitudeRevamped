[CmdletBinding()]
param(
    [string]$NasmPath,
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

$sourcePath = Join-Path $PSScriptRoot 'DiskitudeRevamped.asm'
if (-not $OutputPath) {
    $OutputPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'DiskitudeRevamped.exe'
}
$OutputPath = [IO.Path]::GetFullPath($OutputPath)

if (-not $NasmPath) {
    $nasmCommand = Get-Command nasm.exe -CommandType Application -ErrorAction SilentlyContinue
    if ($nasmCommand) {
        $NasmPath = $nasmCommand.Source
    } else {
        $projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        $bundledNasmRoot = Join-Path $projectRoot 'tools\nasm-3.02'
        if (Test-Path -LiteralPath $bundledNasmRoot -PathType Container) {
            $NasmPath = Get-ChildItem -LiteralPath $bundledNasmRoot -Filter 'nasm.exe' -File -Recurse | Select-Object -First 1 -ExpandProperty FullName
        }
    }
}

if (-not $NasmPath -or -not (Test-Path -LiteralPath $NasmPath -PathType Leaf)) {
    throw 'NASM was not found. Install NASM and add nasm.exe to PATH, or pass -NasmPath.'
}

$outputDirectory = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
}

& $NasmPath '-f' 'bin' $sourcePath '-o' $OutputPath
if ($LASTEXITCODE -ne 0) {
    throw "NASM failed with exit code $LASTEXITCODE."
}

$bytes = [IO.File]::ReadAllBytes($OutputPath)
if ($bytes.Length -gt 8192) {
    throw "The executable is $($bytes.Length) bytes; the limit is 8,192 bytes."
}

$peOffset = [BitConverter]::ToUInt32($bytes,0x3C)
$machine = [BitConverter]::ToUInt16($bytes,$peOffset + 4)
$optionalHeader = $peOffset + 24
$magic = [BitConverter]::ToUInt16($bytes,$optionalHeader)
$subsystem = [BitConverter]::ToUInt16($bytes,$optionalHeader + 68)
if ($machine -ne 0x8664 -or $magic -ne 0x020B -or $subsystem -ne 2) {
    throw 'The output is not the expected AMD64 PE32+ Windows GUI executable.'
}

[pscustomobject]@{
    Output = $OutputPath
    Bytes = $bytes.Length
    SHA256 = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash
}
