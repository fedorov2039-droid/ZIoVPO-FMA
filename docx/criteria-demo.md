# Показ по критериям: ПЗ 2.5 и дополнительные пункты

Этот файл открывать на защите, если преподаватель просит доказать конкретные критерии.
Команды для `C:\Program Files`, службы и `C:\ProgramData` выполнять в PowerShell от имени администратора.

## 0. Общая подготовка

Проверить права администратора:

```powershell
net session
Clear-Host
```

Подготовить переменные и helper для перезапуска службы через RPC:

```powershell
$AppDir = "C:\Program Files\AntivirusGui"
$BaseDir = Join-Path $env:ProgramData "AntivirusGui\bases"
$DbPath = Join-Path $BaseDir "avdb.bin"
$BakPath = Join-Path $BaseDir "avdb.bak"
$MockDir = Join-Path $env:ProgramData "AntivirusGuiMockServer"
$MockDbPath = Join-Path $MockDir "avdb.bin"
$LogPath = Join-Path $env:ProgramData "AntivirusGui\service.log"
$RepoDir = "C:\Users\13372\Desktop\учеба\ЗИоВПО\практика\antivirus-gui"

function Restart-AvService {
    Set-Location $AppDir
    .\AntivirusCtl.exe --request-stop
    Start-Sleep -Seconds 4

    if ((Get-Service AntivirusGuiService).Status -ne "Running") {
        Start-Service AntivirusGuiService
        Start-Sleep -Seconds 3
    }

    sc.exe query AntivirusGuiService
}

New-Item -ItemType Directory -Force -Path $BaseDir, $MockDir | Out-Null
```

Если установленный `prepare-license.ps1` сломан из-за кодировки, подготовить demo-лицензию вручную:

```powershell
New-Item -ItemType Directory -Force -Path $MockDir | Out-Null
Set-Content -LiteralPath (Join-Path $MockDir "license-status.txt") -Value "active" -Encoding ascii
Get-Content (Join-Path $MockDir "license-status.txt")
```

Ожидаемый вывод:

```text
active
```

## 1. ПЗ 2.5: базы на диске и recovery

### 1.1. Базы сохраняются на диске в бинарном компактном формате

Команды:

```powershell
Get-ChildItem $BaseDir
Format-Hex -Path $DbPath | Select-Object -First 8
```

Что говорить:

```text
Антивирусная база лежит на диске в C:\ProgramData\AntivirusGui\bases\avdb.bin.
Это бинарный файл. В начале виден magic 41 56 44 42, то есть AVDB.
Дальше идут version, release date, record count, подпись манифеста и бинарные записи.
```

Показать код формата:

```powershell
Set-Location $RepoDir
Select-String -Path .\src\service\scan\AvDatabaseStorage.cpp `
    -Pattern "kMagic|kVersion|writeDatabaseFile|writeRecord|signManifest|signAvRecord"
```

### 1.2. С продуктом поставляется база по умолчанию

Команды:

```powershell
Set-Location $AppDir

Copy-Item $DbPath "$DbPath.saved-before-default-demo" -Force -ErrorAction SilentlyContinue
Copy-Item $BakPath "$BakPath.saved-before-default-demo" -Force -ErrorAction SilentlyContinue

if (Test-Path $MockDbPath) {
    Move-Item $MockDbPath "$MockDbPath.disabled-default-demo" -Force
}

Remove-Item $DbPath -Force -ErrorAction SilentlyContinue
Remove-Item $BakPath -Force -ErrorAction SilentlyContinue

Restart-AvService

Get-ChildItem $BaseDir
Get-Content $LogPath -Encoding UTF8
```

Что говорить:

```text
Я удалил основную и резервную базу, а demo-сервер обновлений временно отключил.
При старте служба создала и загрузила базу по умолчанию.
Это доказывает, что продукт поставляется с default database.
```

Вернуть demo-сервер, если он был отключён:

```powershell
if (Test-Path "$MockDbPath.disabled-default-demo") {
    Move-Item "$MockDbPath.disabled-default-demo" $MockDbPath -Force
}
```

### 1.3. При запуске службы базы загружаются с диска

Команды:

```powershell
Restart-AvService
Get-Content $LogPath -Encoding UTF8
```

Что говорить:

```text
После рестарта в логе видно, что служба загрузила антивирусную базу с диска.
В коде это делает loadDatabaseFromDisk, который вызывает AvDatabaseStorage::loadOrRecover.
```

Показать код:

```powershell
Set-Location $RepoDir
Select-String -Path .\src\service\ServiceMain.cpp `
    -Pattern "loadDatabaseFromDisk|loadOrRecover|applyDatabaseLoadResult"
```

### 1.4. Проверка подписи манифеста

Команды портят подпись манифеста и показывают recovery из backup:

```powershell
Set-Location $AppDir

Copy-Item $DbPath $BakPath -Force

if (Test-Path $MockDbPath) {
    Move-Item $MockDbPath "$MockDbPath.disabled-manifest-demo" -Force
}

$bytes = [System.IO.File]::ReadAllBytes($DbPath)
$releaseDateLength = [System.BitConverter]::ToUInt32($bytes, 8)
$manifestOffset = 4 + 4 + 4 + ([int]$releaseDateLength * 2) + 4
$bytes[$manifestOffset] = $bytes[$manifestOffset] -bxor 0xff
[System.IO.File]::WriteAllBytes($DbPath, $bytes)

Restart-AvService

Get-ChildItem $BaseDir
Get-Content $LogPath -Encoding UTF8
```

Что говорить:

```text
Я изменил один байт подписи манифеста.
Служба при старте пересчитала подпись, обнаружила InvalidManifestSignature и не приняла повреждённый файл.
Так как backup есть, база восстановилась из avdb.bak.
```

Вернуть demo-сервер:

```powershell
if (Test-Path "$MockDbPath.disabled-manifest-demo") {
    Move-Item "$MockDbPath.disabled-manifest-demo" $MockDbPath -Force
}
```

Показать код проверки:

```powershell
Set-Location $RepoDir
Select-String -Path .\src\service\scan\AvDatabaseStorage.cpp `
    -Pattern "storedManifestSignature|expectedManifestSignature|InvalidManifestSignature|backupPath"
```

### 1.5. Проверка подписи записей и пропуск повреждённых записей

Подготовить валидную базу для demo-сервера:

```powershell
New-Item -ItemType Directory -Force -Path $MockDir | Out-Null
Copy-Item $DbPath $MockDbPath -Force
Copy-Item $DbPath $BakPath -Force
```

Испортить подпись первой записи:

```powershell
$bytes = [System.IO.File]::ReadAllBytes($DbPath)

$releaseDateLength = [System.BitConverter]::ToUInt32($bytes, 8)
$offset = 4 + 4 + 4 + ([int]$releaseDateLength * 2) + 4 + 32
$offset += 8 + 4 + 32 + 8 + 8 + 4

$threatNameLength = [System.BitConverter]::ToUInt32($bytes, $offset)
$offset += 4 + ([int]$threatNameLength * 2)

$bytes[$offset] = $bytes[$offset] -bxor 0xff
[System.IO.File]::WriteAllBytes($DbPath, $bytes)

Restart-AvService

Get-Content $LogPath -Encoding UTF8
```

Что говорить:

```text
Я испортил подпись одной записи базы.
При загрузке служба пересчитывает подпись каждой записи через signAvRecord.
Запись с некорректной подписью не добавляется в рабочий список: в коде для неё выполняется continue.
После этого служба запрашивает корректную замену с demo-сервера обновлений и переписывает основную базу.
```

Показать код:

```powershell
Set-Location $RepoDir
Select-String -Path .\src\service\scan\AvDatabaseStorage.cpp `
    -Pattern "expectedRecordSignature|InvalidRecordSignature|skippedRecordCount|corruptedRecords|continue|replaceCorruptedRecordsFromServer"
```

### 1.6. Принудительное обновление при повреждённом манифесте

Команды:

```powershell
New-Item -ItemType Directory -Force -Path $MockDir | Out-Null
Copy-Item $DbPath $MockDbPath -Force
Copy-Item $DbPath $BakPath -Force

$bytes = [System.IO.File]::ReadAllBytes($DbPath)
$releaseDateLength = [System.BitConverter]::ToUInt32($bytes, 8)
$manifestOffset = 4 + 4 + 4 + ([int]$releaseDateLength * 2) + 4
$bytes[$manifestOffset] = $bytes[$manifestOffset] -bxor 0xff
[System.IO.File]::WriteAllBytes($DbPath, $bytes)

Restart-AvService

Get-Content $LogPath -Encoding UTF8
```

Что говорить:

```text
При повреждённом манифесте служба сначала пытается принудительно получить базу с demo-сервера обновлений.
Если demo-сервер доступен, база восстанавливается через него.
Если demo-сервер недоступен, используется backup, а если backup нет, создаётся default database.
```

### 1.7. Автотесты для 2.5

Команды:

```powershell
Set-Location $RepoDir
cmake --build build-local-winui-ui --config Release
ctest --test-dir build-local-winui-ui -C Release --output-on-failure
```

Что говорить:

```text
Тест проверяет восстановление при повреждении подписи записи и при повреждении подписи манифеста.
Ожидаемый результат: AntivirusScanTests Passed.
```

## 2. Дополнительные критерии

### 2.1. Использование CMake при сборке приложения

Команды:

```powershell
Set-Location $RepoDir
Get-ChildItem .\CMakeLists.txt
cmake --build build-local-winui-ui --config Release
```

Что говорить:

```text
Проект собирается через CMake.
CMakeLists.txt описывает targets AntivirusService, AntivirusWinUi, AntivirusCtl и AntivirusScanTests.
```

### 2.2. Использование WinUI

Команды:

```powershell
Set-Location $RepoDir
Select-String -Path .\CMakeLists.txt -Pattern "ANTIVIRUS_BUILD_WINUI|AntivirusWinUi|Microsoft.UI|WindowsAppRuntime"
Select-String -Path .\src\winui\main.cpp -Pattern "Microsoft.UI.Xaml|AntivirusWinUi|makeButton|scanFixedDrives"
Start-Process "C:\Program Files\AntivirusGui\AntivirusWinUi.exe"
```

Что говорить:

```text
Основной GUI - AntivirusWinUi.exe.
Он собирается отдельным WinUI target и использует Microsoft UI Xaml / Windows App Runtime.
```

### 2.3. Подтверждение остановки службы на Secure Desktop

Показать код:

```powershell
Set-Location $RepoDir
Select-String -Path .\src\common\secure_stop_confirmation.cpp `
    -Pattern "CredUIPromptForWindowsCredentialsW|CREDUIWIN_SECURE_PROMPT|ERROR_SUCCESS"
```

Показать в GUI:

```text
Открыть AntivirusWinUi.exe.
Нажать Файл -> Выход или кнопку остановки службы.
Появится стандартный защищённый Windows prompt.
После подтверждения GUI отправляет RPC AvRequestServiceStop.
```

Показать лог:

```powershell
Get-Content $LogPath -Encoding UTF8 | Select-String "Secure Desktop|подтвердил|останов"
```

### 2.4. Защита процессов от завершения обычными пользователями и администраторами

Показать код DACL hardening:

```powershell
Set-Location $RepoDir
Select-String -Path .\src\common\process_hardening.cpp `
    -Pattern "PROCESS_TERMINATE|administrators|DENY_ACCESS|WRITE_DAC|WRITE_OWNER|protectFromAdministrators|SetSecurityInfo"

Select-String -Path .\src\service\main.cpp,.\src\winui\main.cpp,.\src\service\ProcessLauncher.cpp `
    -Pattern "hardenCurrentProcessForDemo|hardenProcessHandleForDemo"
```

Показать лог включения защиты:

```powershell
Get-Content $LogPath -Encoding UTF8 | Select-String "Защита процесса включена"
```

Проверка обычным пользователем:

```text
Открыть обычный PowerShell, не от администратора.
Выполнить команды ниже.
Ожидаемо: Access is denied, процесс остаётся запущенным.
```

```powershell
$svcPid = (Get-CimInstance Win32_Service -Filter "Name='AntivirusGuiService'").ProcessId
try {
    Stop-Process -Id $svcPid -Force -ErrorAction Stop
    "UNEXPECTED: process was stopped"
} catch {
    "Expected denial: $($_.Exception.Message)"
}
Get-Process -Id $svcPid
```

Проверка администратором:

```text
Эту команду запускать только если готов перезапустить службу после демонстрации.
Ожидаемый результат при включённой DACL-защите: Access is denied.
Не использовать PsExec/SYSTEM или утилиты с kernel driver, потому что это уже обход защиты ОС.
```

```powershell
$svcPid = (Get-CimInstance Win32_Service -Filter "Name='AntivirusGuiService'").ProcessId
try {
    Stop-Process -Id $svcPid -Force -ErrorAction Stop
    "UNEXPECTED: process was stopped"
} catch {
    "Expected denial: $($_.Exception.Message)"
}
sc.exe query AntivirusGuiService
```

Что говорить:

```text
DACL процесса запрещает опасные права PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_WRITE, WRITE_DAC, WRITE_OWNER и DELETE.
Для Administrators также включён deny при protectFromAdministrators=true.
Это учебная защита от штатного завершения процесса, а не rootkit и не обход Windows.
```

### 2.5. Сканирование всех несъёмных дисков

Команды:

```powershell
Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
    Select-Object DeviceID, VolumeName, Size, FreeSpace
```

Показать в GUI:

```text
Войти demo / demo, активировать DEMO-1234.
Нажать кнопку Все диски.
```

Показать код:

```powershell
Set-Location $RepoDir
Select-String -Path .\src\service\ServiceMain.cpp -Pattern "scanFixedDrives|GetLogicalDrives|DRIVE_FIXED"
```

### 2.6. Сканирование по расписанию

Подготовить demo-файлы:

```powershell
$DemoDir = Join-Path $env:ProgramData "AntivirusGuiScanTest"
New-Item -ItemType Directory -Force -Path $DemoDir | Out-Null
[System.IO.File]::WriteAllBytes((Join-Path $DemoDir "infected-pe.bin"), [System.Text.Encoding]::ASCII.GetBytes("MZAVGUI-PE-TEST"))
Set-Content -LiteralPath (Join-Path $DemoDir "infected.ps1") -Value 'Write-Host "demo"; Invoke-AvGuiTest' -Encoding ascii
Set-Content -LiteralPath (Join-Path $DemoDir "clean.txt") -Value "Clean educational file without demo signatures." -Encoding ascii
Get-ChildItem $DemoDir
```

Показать в GUI:

```text
В блоке Сканирование по расписанию поставить интервал 5.
Нажать Файл.
Выбрать C:\ProgramData\AntivirusGuiScanTest\infected-pe.bin.
Подождать 5-7 секунд.
Показать Последний запуск и результат.
```

Показать лог:

```powershell
Start-Sleep -Seconds 7
Get-Content $LogPath -Encoding UTF8 | Select-String "расписан|Результат|Demo.Test"
```

Показать код:

```powershell
Set-Location $RepoDir
Select-String -Path .\src\service\ServiceMain.cpp `
    -Pattern "startScanSchedule|scanScheduleLoop|runScheduledScan|AvStartScanSchedule"
```

### 2.7. Мониторинг директорий

Показать в GUI:

```text
В блоке Мониторинг нажать Запустить.
Выбрать C:\ProgramData\AntivirusGuiScanTest.
```

Изменить файл:

```powershell
$DemoDir = Join-Path $env:ProgramData "AntivirusGuiScanTest"
Set-Content -LiteralPath (Join-Path $DemoDir "monitor-trigger.ps1") `
    -Value 'Write-Host "demo"; Invoke-AvGuiTest' -Encoding ascii

Start-Sleep -Seconds 4

Get-Content $LogPath -Encoding UTF8 | Select-String "Мониторинг|monitor-trigger|Demo.Test"
```

Показать код:

```powershell
Set-Location $RepoDir
Select-String -Path .\src\service\scan\DirectoryMonitor.cpp `
    -Pattern "workerLoop|scanChangedFiles|last_write_time|file_size|callback"
Select-String -Path .\src\service\ServiceMain.cpp `
    -Pattern "startDirectoryMonitor|scanMonitoredFile|AvStartDirectoryMonitor"
```

### 2.8. Использование алгоритма Ахо-Корасика

Показать код:

```powershell
Set-Location $RepoDir
Select-String -Path .\src\service\scan\AhoCorasickScanner.cpp `
    -Pattern "buildFromDatabase|failure|outputs|scan|resultForPattern"
Select-String -Path .\src\service\scan\ScanEngine.cpp `
    -Pattern "AhoCorasickScanner|recordsByPrefix|fallback"
```

Показать тест:

```powershell
Set-Location $RepoDir
ctest --test-dir build-local-winui-ui -C Release --output-on-failure
```

Что говорить:

```text
Ахо-Корасик используется как быстрый multi-pattern scan по demo-сигнатурам.
Если автомат не построен, ScanEngine оставляет fallback через std::map по первым 8 байтам.
```

### 2.9. Периодическое обновление баз

Показать лог запуска планировщика:

```powershell
Restart-AvService
Get-Content $LogPath -Encoding UTF8 | Select-String "Планировщик обновления антивирусных баз запущен"
```

Показать код:

```powershell
Set-Location $RepoDir
Select-String -Path .\src\service\scan\AvUpdateScheduler.cpp `
    -Pattern "kUpdateInterval|workerLoop|wait_for|runUpdateNow"
Select-String -Path .\src\service\ServiceMain.cpp `
    -Pattern "startDatabaseUpdateScheduler|updateScheduler"
```

Что говорить:

```text
При запуске службы стартует AvUpdateScheduler.
Он периодически просыпается по wait_for и вызывает runUpdateNow.
```

### 2.10. Backup перед обновлением, загрузка после обновления и rollback

Показать код:

```powershell
Set-Location $RepoDir
Select-String -Path .\src\service\scan\AvUpdateScheduler.cpp `
    -Pattern "backupCurrentDatabase|writeDatabase|loadOrRecover|rolledBack|Антивирусная база обновлена"
Select-String -Path .\src\service\scan\AvDatabaseStorage.cpp `
    -Pattern "backupCurrentDatabase|copy_file|backupPath"
```

Показать наличие backup:

```powershell
Get-ChildItem $BaseDir
```

Что говорить:

```text
Перед update планировщик вызывает backupCurrentDatabase и создаёт avdb.bak.
После записи новой базы он вызывает loadOrRecover, то есть сразу загружает базу после обновления.
Если запись или загрузка обновления неуспешна, код копирует avdb.bak обратно в avdb.bin.
```

Если нужно показать recovery вручную:

```powershell
Copy-Item $DbPath $BakPath -Force

if (Test-Path $MockDbPath) {
    Move-Item $MockDbPath "$MockDbPath.disabled-backup-demo" -Force
}

$bytes = [System.IO.File]::ReadAllBytes($DbPath)
$bytes[0] = $bytes[0] -bxor 0xff
[System.IO.File]::WriteAllBytes($DbPath, $bytes)

Restart-AvService

Get-Content $LogPath -Encoding UTF8

if (Test-Path "$MockDbPath.disabled-backup-demo") {
    Move-Item "$MockDbPath.disabled-backup-demo" $MockDbPath -Force
}
```

### 2.11. Запрос повреждённых записей с сервера обновлений

Использовать сценарий из раздела 1.5.

Что говорить:

```text
При некорректной подписи записи база сначала пропускает повреждённую запись.
Потом loadOrRecover вызывает demo update client и replaceCorruptedRecordsFromServer.
Если сервер содержит корректную запись, она возвращается в базу, а avdb.bin переписывается.
```

### 2.12. Принудительное обновление баз при повреждённом манифесте

Использовать сценарий из раздела 1.6.

Что говорить:

```text
При InvalidManifestSignature служба явно пишет в events, что выполняется принудительное обновление с demo-сервера обновлений.
Это отдельный путь от обычного backup recovery.
```

## 3. Что не заявлять лишнего

```text
Для ПЗ 2.4 в текущей demo-версии реально распознаются PE и PowerShell.
NET, Java, Python и JS как отдельные ObjectType в коде не заведены.
Поэтому на защите лучше говорить: demo-типы PE и PowerShell, а модель записи содержит поле object type.
```
