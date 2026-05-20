# Устанавливает учебный WinUI GUI и Windows-службу из Release-сборки.
param(
    [string]$SourceDir = (Join-Path $PSScriptRoot '..\build-local-winui-ui\Release'),
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'AntivirusGui'),
    [string]$WindowsAppRuntimeInstaller = (Join-Path $PSScriptRoot '..\out\installer\deps\windowsappruntimeinstall-x64.exe'),
    [switch]$StartService
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName = 'AntivirusGuiService'
$SourceDir = (Resolve-Path $SourceDir).Path

$RequiredFiles = @(
    'AntivirusWinUi.exe',
    'AntivirusService.exe',
    'Microsoft.WindowsAppRuntime.Bootstrap.dll'
)

foreach ($file in $RequiredFiles) {
    $path = Join-Path $SourceDir $file
    if (-not (Test-Path $path)) {
        throw "Не найден обязательный файл: $path"
    }
}

if (Test-Path $WindowsAppRuntimeInstaller) {
    & $WindowsAppRuntimeInstaller --quiet --force
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 3010) {
        throw "Установка Windows App Runtime завершилась с кодом $LASTEXITCODE."
    }
}

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -ne $existing -and $existing.Status -ne 'Stopped') {
    Stop-Service -Name $ServiceName -Force
    Start-Sleep -Seconds 2
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

foreach ($file in $RequiredFiles) {
    Copy-Item -LiteralPath (Join-Path $SourceDir $file) -Destination (Join-Path $InstallDir $file) -Force
}

$serviceExe = Join-Path $InstallDir 'AntivirusService.exe'
if ($null -ne $existing) {
    & $serviceExe --uninstall
    if ($LASTEXITCODE -ne 0) {
        throw "Удаление службы завершилось с кодом $LASTEXITCODE."
    }
}

& $serviceExe --install
if ($LASTEXITCODE -ne 0) {
    throw "Установка службы завершилась с кодом $LASTEXITCODE."
}

if ($StartService) {
    Start-Service -Name $ServiceName
}

Write-Host "Установлено в $InstallDir"
