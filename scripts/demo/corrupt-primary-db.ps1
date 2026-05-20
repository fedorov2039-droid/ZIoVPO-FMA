# Портит primary avdb.bin, переворачивая первый байт файла.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$DbPath = Join-Path $env:ProgramData 'AntivirusGui\bases\avdb.bin'
if (-not (Test-Path $DbPath)) {
    throw "Основная база не найдена: $DbPath"
}

$bytes = [System.IO.File]::ReadAllBytes($DbPath)
if ($bytes.Length -lt 1) {
    throw "Основная база пуста: $DbPath"
}

$bytes[0] = $bytes[0] -bxor 0xff
[System.IO.File]::WriteAllBytes($DbPath, $bytes)

Write-Host "Основная база повреждена: $DbPath"
