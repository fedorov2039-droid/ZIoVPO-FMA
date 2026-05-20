# Antivirus GUI

Учебный проект на C++20 для заданий 2.1-2.6: WinUI-интерфейс, Windows-служба, локальный RPC, авторизация, лицензия, антивирусная база, сканирование, обновления, мониторинг, расписание и EXE-инсталлер.

Проект безопасный и демонстрационный. Он не реализует вредоносное поведение, скрытие процессов, обход системной защиты или настоящий промышленный антивирус.

## Что закрыто

- Задание 2.1: GUI, трей, меню, запуск без окна, один экземпляр, CMake/MSBuild.
- Задание 2.2: Windows-служба, запуск GUI в пользовательских сессиях, RPC over ALPC, остановка через RPC.
- Задание 2.3: вход, выход, активация продукта, блокировка функций без лицензии.
- Задание 2.4: антивирусная база в памяти, сканирование файла, папки и всех несъёмных дисков, мониторинг директорий, расписание, Ахо-Корасик.
- Задание 2.5: хранение базы на диске, проверка целостности, backup, rollback, восстановление повреждённых записей, forced update при повреждённом manifest.
- Задание 2.6: EXE-инсталлер с зависимостями, установкой службы, ярлыками и uninstall.
- Дополнительные пункты: WinUI, CMake, Secure Desktop confirmation, DACL hardening, Ахо-Корасик, мониторинг, расписание, обновление баз и recovery.

## Документация для сдачи

Материалы, которые удобно открыть преподавателю, лежат в `docx`:

- `docx/checklist.md` - полный чеклист по заданиям 2.1-2.6 и дополнительным пунктам.
- `docx/demo.md` - порядок демонстрации приложения и инсталлера.
- `docx/answers.md` - короткие ответы на вероятные вопросы.

Данные для демонстрации:

- логин: `demo`
- пароль: `demo`
- код активации: `DEMO-1234`

## Сборка

Требования:

- Windows;
- Visual Studio 2022 или Visual Studio 2022 Build Tools;
- CMake 3.24+;
- Node.js/npm для восстановления WinUI-зависимостей через `@microsoft/winappcli`;
- NSIS 3.x для локальной сборки EXE-инсталлера.

```powershell
npx --yes @microsoft/winappcli restore
cmake -S . -B build-local-winui-ui -DCMAKE_BUILD_TYPE=Release
cmake --build build-local-winui-ui --config Release
ctest --test-dir build-local-winui-ui -C Release --output-on-failure
```

Старый Qt Widgets target по умолчанию отключён. Основной GUI в этой ветке - `AntivirusWinUi.exe`.

## Запуск без установки

Для демонстрационного запуска после сборки:

```powershell
.\build-local-winui-ui\Release\AntivirusService.exe --console
.\build-local-winui-ui\Release\AntivirusWinUi.exe --allow-standalone-debug --show
```

В нормальном установленном сценарии GUI запускается службой и общается с ней через Windows RPC.

## Инсталлер

Собрать локальный EXE-инсталлер:

```powershell
.\installer\build-installer.ps1 -BuildDir build-local-winui-ui -OutputDir out\installer
```

Запустить от администратора:

```powershell
.\out\installer\AntivirusGuiSetup.exe
```

Инсталлер ставит VC++ Runtime, устанавливает и восстанавливает Windows App Runtime 2.0, копирует приложение в `C:\Program Files\AntivirusGui`, регистрирует службу `AntivirusGuiService`, запускает её, создаёт ярлыки и добавляет uninstall.

## GitHub Actions

Windows workflow восстанавливает WinUI-зависимости, собирает Release, запускает тесты и публикует артефакты:

- `antivirus-gui-windows-release`;
- `antivirus-gui-installer` с файлом `AntivirusGuiSetup.exe`.
