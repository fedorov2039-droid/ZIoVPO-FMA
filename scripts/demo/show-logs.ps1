# Показывает service.log текущего запуска службы с первой строки.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$LogPath = Join-Path $env:ProgramData 'AntivirusGui\service.log'
if (-not (Test-Path $LogPath)) {
    Write-Host "Файл лога не найден: $LogPath"
    exit 0
}

Get-Content -LiteralPath $LogPath -Encoding UTF8
