# Создаёт безопасные учебные файлы для проверки PE, PowerShell и clean scan.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TestDir = Join-Path $env:ProgramData 'AntivirusGuiScanTest'
New-Item -ItemType Directory -Force -Path $TestDir | Out-Null

$PePath = Join-Path $TestDir 'infected-pe.bin'
$PsPath = Join-Path $TestDir 'infected.ps1'
$CleanPath = Join-Path $TestDir 'clean.txt'

[System.IO.File]::WriteAllBytes($PePath, [System.Text.Encoding]::ASCII.GetBytes('MZAVGUI-PE-TEST'))
Set-Content -LiteralPath $PsPath -Value 'Write-Host "demo"; Invoke-AvGuiTest' -Encoding ascii
Set-Content -LiteralPath $CleanPath -Value 'Clean educational file without demo signatures.' -Encoding ascii

Write-Host "Тестовые файлы созданы в: $TestDir"
Get-ChildItem -LiteralPath $TestDir
