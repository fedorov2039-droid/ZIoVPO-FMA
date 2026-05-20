# Готовит демо-сервер для демонстрации активной лицензии.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$MockServerDir = Join-Path $env:ProgramData 'AntivirusGuiMockServer'
New-Item -ItemType Directory -Force -Path $MockServerDir | Out-Null

$LicenseStatusPath = Join-Path $MockServerDir 'license-status.txt'
Set-Content -LiteralPath $LicenseStatusPath -Value 'active' -Encoding ascii

Write-Host "Демо-статус лицензии записан: $LicenseStatusPath"
