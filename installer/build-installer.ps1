# Собирает единый EXE-инсталлер администратора со всеми обязательными зависимостями.
param(
    [string]$BuildDir = (Join-Path $PSScriptRoot '..\build-local-winui-clean'),
    [string]$OutputDir = (Join-Path $PSScriptRoot '..\out\installer')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Find-MakeNsis {
    $command = Get-Command makensis.exe -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }

    $candidates = @(
        "${env:ProgramFiles(x86)}\NSIS\makensis.exe",
        "${env:ProgramFiles(x86)}\NSIS\Bin\makensis.exe",
        "$env:ProgramFiles\NSIS\makensis.exe",
        "$env:ProgramFiles\NSIS\Bin\makensis.exe"
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

        throw "makensis.exe не найден. Установите NSIS 3.x или используйте сборку через GitHub Actions."
}

function Download-File {
    param(
        [string]$Uri,
        [string]$Destination,
        [string]$Sha256 = ''
    )

    if (-not (Test-Path $Destination)) {
        Invoke-WebRequest -Uri $Uri -OutFile $Destination
    }

    if ($Sha256.Length -gt 0) {
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Destination).Hash.ToLowerInvariant()
        if ($actual -ne $Sha256.ToLowerInvariant()) {
            throw "SHA256 не совпал для $Destination. Ожидалось $Sha256, получено $actual."
        }
    }
}

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$BuildDir = (Resolve-Path $BuildDir).Path
$OutputDirInfo = New-Item -ItemType Directory -Force -Path $OutputDir
$OutputDir = $OutputDirInfo.FullName
$DepsDirInfo = New-Item -ItemType Directory -Force -Path (Join-Path $OutputDir 'deps')
$DepsDir = $DepsDirInfo.FullName
$MakeNsis = Find-MakeNsis

$requiredBuildFiles = @(
    'AntivirusWinUi.exe',
    'AntivirusService.exe',
    'AntivirusCtl.exe',
    'Microsoft.WindowsAppRuntime.Bootstrap.dll'
)

foreach ($file in $requiredBuildFiles) {
    $path = Join-Path $BuildDir "Release\$file"
    if (-not (Test-Path $path)) {
        throw "Не найден обязательный артефакт сборки: $path"
    }
}

Download-File `
    -Uri 'https://aka.ms/vs/17/release/vc_redist.x64.exe' `
    -Destination (Join-Path $DepsDir 'vc_redist.x64.exe')

Download-File `
    -Uri 'https://aka.ms/windowsappsdk/2.0/2.0.1/windowsappruntimeinstall-x64.exe' `
    -Destination (Join-Path $DepsDir 'windowsappruntimeinstall-x64.exe') `
    -Sha256 '8b3164dacac14650a45ce7b1990a8a43ca4427a5a4751abc5611978e75df2810'

$OutputExe = Join-Path $OutputDir 'AntivirusGuiSetup.exe'
$ScriptPath = Join-Path $ProjectRoot 'installer\AntivirusGui.nsi'

& $MakeNsis `
    '/V2' `
    "/DPROJECT_ROOT=$ProjectRoot" `
    "/DBUILD_DIR=$BuildDir" `
    "/DDEPS_DIR=$DepsDir" `
    "/DOUTPUT_EXE=$OutputExe" `
    $ScriptPath

if ($LASTEXITCODE -ne 0) {
    throw "makensis завершился с кодом $LASTEXITCODE."
}

$readme = Join-Path $OutputDir 'README-INSTALLER.md'
@"
# Инсталлер Antivirus GUI

Запустите `AntivirusGuiSetup.exe` от имени администратора.

Инсталлер:

- устанавливает Microsoft Visual C++ Runtime;
- устанавливает и восстанавливает Windows App Runtime 2.0;
- копирует `AntivirusWinUi.exe`, `AntivirusService.exe`, `AntivirusCtl.exe`, `docx` и демо-скрипты в `C:\Program Files\AntivirusGui`;
- регистрирует службу `AntivirusGuiService` для автоматического запуска;
- запускает службу;
- создаёт ярлыки в меню Пуск;
- регистрирует uninstall.

Данные для демонстрации:

- логин: `demo`
- пароль: `demo`
- код активации: `DEMO-1234`

Для защиты откройте установленную папку `docx`: там есть чеклист, сценарий демонстрации и ответы на вопросы преподавателя.
"@ | Set-Content -Path $readme -Encoding UTF8

Write-Host "Инсталлер: $OutputExe"
