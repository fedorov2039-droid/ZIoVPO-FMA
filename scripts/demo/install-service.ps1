# Переустанавливает Windows-службу из Release-сборки или из установленной папки,
# запускает её и показывает sc query.
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
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $service -and $Status -eq [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
            return
        }

        if ($null -ne $service -and $service.Status -eq $Status) {
            return
        }

        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)

    throw "Служба $Name не перешла в состояние $Status за $TimeoutSeconds сек."
}

function Stop-AntivirusService {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,

        [Parameter(Mandatory = $true)]
        [string] $CtlExe
    )

    if (Test-Path -LiteralPath $CtlExe) {
        & $CtlExe --request-stop | Out-Host
    } else {
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    }

    Wait-ServiceState -Name $Name -Status ([System.ServiceProcess.ServiceControllerStatus]::Stopped)
}

$ServiceName = 'AntivirusGuiService'
$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$BuildServiceExe = Join-Path $ProjectRoot 'build-local-winui-ui\Release\AntivirusService.exe'
$InstalledServiceExe = Join-Path $ProjectRoot 'AntivirusService.exe'

if (Test-Path -LiteralPath $BuildServiceExe) {
    $ServiceExe = $BuildServiceExe
} elseif (Test-Path -LiteralPath $InstalledServiceExe) {
    $ServiceExe = $InstalledServiceExe
} else {
    throw "Исполняемый файл службы не найден. Для исходников сначала запустите scripts/demo/build-release.ps1."
}

$CtlExe = Join-Path (Split-Path -Parent $ServiceExe) 'AntivirusCtl.exe'

Stop-Process -Name 'AntivirusWinUi' -Force -ErrorAction SilentlyContinue
Stop-Process -Name 'AntivirusGui' -Force -ErrorAction SilentlyContinue

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -ne $existing) {
    if ($existing.Status -ne 'Stopped') {
        Stop-AntivirusService -Name $ServiceName -CtlExe $CtlExe
    }

    & $ServiceExe --uninstall
    Start-Sleep -Seconds 2
}

& $ServiceExe --install
if ($LASTEXITCODE -ne 0) {
    throw "Установка службы завершилась с кодом $LASTEXITCODE."
}

Start-Service -Name $ServiceName
Wait-ServiceState -Name $ServiceName -Status ([System.ServiceProcess.ServiceControllerStatus]::Running)
sc.exe query $ServiceName
