# Команды PowerShell для демонстрации

Эти команды можно открывать прямо на защите. Если команда работает со службой, `C:\Program Files` или `C:\ProgramData`, запускайте PowerShell от имени администратора.

## Проверить, что PowerShell запущен от администратора

```powershell
net session
```

Если команда вернула ошибку доступа, закройте окно и откройте PowerShell через `Запуск от имени администратора`.

Очистить экран:

```powershell
Clear-Host
```

## Перейти в установленную папку приложения

```powershell
Set-Location "C:\Program Files\AntivirusGui"
```

Показать состав установленного приложения:

```powershell
Get-ChildItem
Get-ChildItem .\docx
Get-ChildItem .\scripts\demo
```

## Проверить службу

```powershell
sc.exe query AntivirusGuiService
Get-Service AntivirusGuiService
```

Запустить службу:

```powershell
Start-Service AntivirusGuiService
```

Перезапустить службу через helper приложения:

```powershell
Set-Location "C:\Program Files\AntivirusGui"
.\AntivirusCtl.exe --request-stop
Start-Sleep -Seconds 2
Start-Service AntivirusGuiService
Start-Sleep -Seconds 2
sc.exe query AntivirusGuiService
```

## Запустить GUI

```powershell
Start-Process "C:\Program Files\AntivirusGui\AntivirusWinUi.exe"
```

Данные для входа и активации:

```text
Логин: demo
Пароль: demo
Код активации: DEMO-1234
```

## Подготовить demo-лицензию

```powershell
Set-Location "C:\Program Files\AntivirusGui\scripts\demo"
.\prepare-license.ps1
```

## Создать demo-файлы для сканирования

Основной вариант, если PowerShell запущен от администратора:

```powershell
Set-Location "C:\Program Files\AntivirusGui\scripts\demo"
.\create-test-threats.ps1
```

После этого в GUI выбирайте:

```text
C:\ProgramData\AntivirusGuiScanTest
```

Если `C:\ProgramData\AntivirusGuiScanTest` уже создан с неправильными правами:

```powershell
takeown /F "C:\ProgramData\AntivirusGuiScanTest" /R /D Y
icacls "C:\ProgramData\AntivirusGuiScanTest" /grant "${env:USERNAME}:(OI)(CI)F" /T
Remove-Item "C:\ProgramData\AntivirusGuiScanTest" -Recurse -Force
.\create-test-threats.ps1
```

Вариант без прав администратора: создать demo-файлы на рабочем столе и выбрать эту папку в GUI.

```powershell
$DemoDir = Join-Path $env:USERPROFILE "Desktop\AntivirusGuiScanTest"
New-Item -ItemType Directory -Force -Path $DemoDir | Out-Null
[System.IO.File]::WriteAllBytes((Join-Path $DemoDir "infected-pe.bin"), [System.Text.Encoding]::ASCII.GetBytes("MZAVGUI-PE-TEST"))
Set-Content -LiteralPath (Join-Path $DemoDir "infected.ps1") -Value 'Write-Host "demo"; Invoke-AvGuiTest' -Encoding ascii
Set-Content -LiteralPath (Join-Path $DemoDir "clean.txt") -Value "Clean educational file without demo signatures." -Encoding ascii
Get-ChildItem $DemoDir
```

Путь для выбора в GUI:

```text
%USERPROFILE%\Desktop\AntivirusGuiScanTest
```

## Показать логи службы

```powershell
Set-Location "C:\Program Files\AntivirusGui\scripts\demo"
.\show-logs.ps1
```

Или напрямую:

```powershell
Get-Content "C:\ProgramData\AntivirusGui\service.log" -Encoding UTF8
```

## Показать восстановление базы из backup

```powershell
Set-Location "C:\Program Files\AntivirusGui\scripts\demo"
.\prepare-backup-recovery.ps1
```

## Показать принудительное обновление при повреждённом манифесте

```powershell
Set-Location "C:\Program Files\AntivirusGui\scripts\demo"
.\prepare-mock-update-recovery.ps1
```

## Показать файлы баз

```powershell
Get-ChildItem "C:\Program Files\AntivirusGui\bases"
```

## Остановить службу через helper

```powershell
Set-Location "C:\Program Files\AntivirusGui"
.\AntivirusCtl.exe --request-stop
```

## Удалить приложение

```powershell
Start-Process "C:\Program Files\AntivirusGui\Uninstall.exe" -Verb RunAs
```

Проверить, что служба удалена:

```powershell
sc.exe query AntivirusGuiService
```

## Собрать проект из исходников

Выполнять из папки репозитория:

```powershell
Set-Location "C:\Users\13372\Desktop\учеба\ЗИоВПО\практика\antivirus-gui"
npx --yes @microsoft/winappcli restore
cmake -S . -B build-local-winui-ui -DCMAKE_BUILD_TYPE=Release
cmake --build build-local-winui-ui --config Release
ctest --test-dir build-local-winui-ui -C Release --output-on-failure
```

## Собрать EXE-инсталлер из исходников

```powershell
Set-Location "C:\Users\13372\Desktop\учеба\ЗИоВПО\практика\antivirus-gui"
.\installer\build-installer.ps1 -BuildDir .\build-local-winui-ui -OutputDir .\out\installer
Get-FileHash .\out\installer\AntivirusGuiSetup.exe -Algorithm SHA256
```

Запустить собранный инсталлер:

```powershell
Start-Process ".\out\installer\AntivirusGuiSetup.exe" -Verb RunAs
```
