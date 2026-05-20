# Собирает Release-версию проекта через CMake и выводит пути к готовым exe.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$BuildDir = Join-Path $ProjectRoot 'build-local-winui-ui'

if (-not (Test-Path (Join-Path $ProjectRoot 'CMakeLists.txt'))) {
    throw "Скрипт сборки нужно запускать из папки исходников проекта, а не из установленной папки приложения."
}

Push-Location $ProjectRoot
try {
    npx --yes @microsoft/winappcli restore
    cmake -S . -B $BuildDir -DCMAKE_BUILD_TYPE=Release
    cmake --build $BuildDir --config Release

    $GuiExe = Join-Path $BuildDir 'Release\AntivirusWinUi.exe'
    $ServiceExe = Join-Path $BuildDir 'Release\AntivirusService.exe'

    Write-Host "WinUI GUI: $GuiExe"
    Write-Host "Служба:    $ServiceExe"
} finally {
    Pop-Location
}
