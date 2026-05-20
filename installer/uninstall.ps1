# Удаляет учебную Windows-службу и установленные файлы приложения.
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'AntivirusGui')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName = 'AntivirusGuiService'
$serviceExe = Join-Path $InstallDir 'AntivirusService.exe'

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -ne $existing) {
    if ($existing.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
    }

    if (Test-Path $serviceExe) {
        & $serviceExe --uninstall
        if ($LASTEXITCODE -ne 0) {
            throw "Удаление службы завершилось с кодом $LASTEXITCODE."
        }
    }
}

if (Test-Path $InstallDir) {
    $resolvedInstallDir = (Resolve-Path $InstallDir).Path
    $programFiles = (Resolve-Path $env:ProgramFiles).Path
    if (-not $resolvedInstallDir.StartsWith($programFiles, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Отказ от удаления каталога вне Program Files: $resolvedInstallDir"
    }

    Remove-Item -LiteralPath $resolvedInstallDir -Recurse -Force
}

Write-Host "Удалено из $InstallDir"
