# Готовит принудительное обновление: кладёт корректную базу в демо-сервер,
# портит манифест основной базы и показывает лог восстановления.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Corrupt-ManifestSignature {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 48) {
        throw "База слишком мала, чтобы содержать подпись манифеста: $Path"
    }

    $releaseDateLength = [System.BitConverter]::ToUInt32($bytes, 8)
    $manifestOffset = 4 + 4 + 4 + ([int]$releaseDateLength * 2) + 4
    if ($manifestOffset -ge $bytes.Length) {
        throw "Смещение манифеста находится вне файла базы: $manifestOffset"
    }

    $bytes[$manifestOffset] = $bytes[$manifestOffset] -bxor 0xff
    [System.IO.File]::WriteAllBytes($Path, $bytes)
}

function Wait-ServiceState {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,

        [Parameter(Mandatory = $true)]
        [System.ServiceProcess.ServiceControllerStatus] $Status,

        [int] $TimeoutSeconds = 20
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $service = Get-Service -Name $Name -ErrorAction Stop
        if ($service.Status -eq $Status) {
            return
        }

        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)

    throw "Служба $Name не перешла в состояние $Status за $TimeoutSeconds сек."
}

function Restart-AntivirusService {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name
    )

    $appDir = Resolve-Path (Join-Path $PSScriptRoot '..\..')
    $ctlPath = Join-Path $appDir 'AntivirusCtl.exe'

    if (Test-Path -LiteralPath $ctlPath) {
        & $ctlPath --request-stop | Out-Host
        Wait-ServiceState -Name $Name -Status ([System.ServiceProcess.ServiceControllerStatus]::Stopped)
    } else {
        Stop-Service -Name $Name -Force
        Wait-ServiceState -Name $Name -Status ([System.ServiceProcess.ServiceControllerStatus]::Stopped)
    }

    Stop-Process -Name AntivirusWinUi -Force -ErrorAction SilentlyContinue
    Stop-Process -Name AntivirusGui -Force -ErrorAction SilentlyContinue

    Start-Service -Name $Name
    Wait-ServiceState -Name $Name -Status ([System.ServiceProcess.ServiceControllerStatus]::Running)
}

$ServiceName = 'AntivirusGuiService'
$BaseDir = Join-Path $env:ProgramData 'AntivirusGui\bases'
$DbPath = Join-Path $BaseDir 'avdb.bin'
$BackupPath = Join-Path $BaseDir 'avdb.bak'
$MockServerDir = Join-Path $env:ProgramData 'AntivirusGuiMockServer'
$MockDbPath = Join-Path $MockServerDir 'avdb.bin'
$LogPath = Join-Path $env:ProgramData 'AntivirusGui\service.log'

if (-not (Test-Path $DbPath)) {
    throw "Основная база не найдена: $DbPath"
}

New-Item -ItemType Directory -Force -Path $MockServerDir | Out-Null

$ValidSourcePath = $DbPath
if (Test-Path -LiteralPath $BackupPath) {
    $ValidSourcePath = $BackupPath
} elseif (Test-Path -LiteralPath $MockDbPath) {
    $ValidSourcePath = $MockDbPath
}

$TempDbPath = Join-Path $env:TEMP 'AntivirusGui-valid-avdb.bin'
Copy-Item -LiteralPath $ValidSourcePath -Destination $TempDbPath -Force
Copy-Item -LiteralPath $TempDbPath -Destination $MockDbPath -Force
Copy-Item -LiteralPath $TempDbPath -Destination $DbPath -Force
Corrupt-ManifestSignature -Path $DbPath

Restart-AntivirusService -Name $ServiceName
Start-Sleep -Seconds 3

Write-Host "Демо-сервер обновлений подготовлен: $MockDbPath"
Write-Host "Основная база специально повреждена и должна восстановиться при запуске службы: $DbPath"
if (Test-Path $LogPath) {
    Get-Content -LiteralPath $LogPath -Encoding UTF8
}
