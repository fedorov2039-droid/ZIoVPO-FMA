# Готовит сценарий восстановления из avdb.bak:
# создаёт резервную копию, временно отключает демо-сервер обновлений,
# портит основную базу, перезапускает службу и показывает лог.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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
$MockDbPath = Join-Path $env:ProgramData 'AntivirusGuiMockServer\avdb.bin'
$DisabledMockDbPath = Join-Path $env:ProgramData 'AntivirusGuiMockServer\avdb.bin.disabled-for-backup-demo'
$LogPath = Join-Path $env:ProgramData 'AntivirusGui\service.log'

if (-not (Test-Path $DbPath)) {
    throw "Основная база не найдена: $DbPath"
}

Copy-Item -LiteralPath $DbPath -Destination $BackupPath -Force

if (Test-Path -LiteralPath $MockDbPath) {
    Move-Item -LiteralPath $MockDbPath -Destination $DisabledMockDbPath -Force
}

& (Join-Path $PSScriptRoot 'corrupt-primary-db.ps1')

Restart-AntivirusService -Name $ServiceName
Start-Sleep -Seconds 3

Write-Host "Резервная база подготовлена: $BackupPath"
Write-Host "Демо-сервер обновлений временно отключён для показа восстановления из backup."
if (Test-Path $LogPath) {
    Get-Content -LiteralPath $LogPath -Encoding UTF8
}
