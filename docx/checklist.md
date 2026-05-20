# Чеклист выполнения ТЗ

Дата проверки: 2026-05-15.

## Задание 2.1

| Пункт | Статус | Где реализовано | Как показать |
|---|---|---|---|
| Иконка в трее при запуске | Готово | `src/winui/main.cpp`, `Shell_NotifyIconW` | Запустить установленное приложение, показать иконку в трее. |
| Левый клик по трею открывает окно | Готово | обработка `WM_LBUTTONUP`, `NIN_SELECT` | Скрыть окно, нажать иконку левой кнопкой. |
| Правый клик открывает меню | Готово | Win32 popup menu | Нажать иконку правой кнопкой. |
| Меню содержит `Открыть` | Готово | `kTrayOpenCommand` | Выбрать `Открыть`. |
| Меню содержит `Выход` | Готово | `kTrayExitCommand` | Выбрать `Выход`, подтвердить остановку службы. |
| Восстановление иконки после пересоздания панели задач | Готово | сообщение `TaskbarCreated` | Перезапустить Explorer и показать возврат иконки. |
| Запуск без главного окна | Готово | `--service-child`, `--hidden` | Служба запускает GUI скрытым. |
| Закрытие окна оставляет приложение в фоне | Готово | обработчик `Closed` скрывает `AppWindow` | Нажать крестик, процесс остаётся живым. |
| Главное меню `Файл -> Выход` | Готово | native Win32 menu | Открыть меню в окне. |
| Один экземпляр на пользователя | Готово | `SingleInstanceGuard` | Запустить второй экземпляр, он открывает уже существующее окно. |
| CMake/MSBuild | Готово | `CMakeLists.txt` | `cmake --build build-local-winui-ui --config Release`. |
| Артефакты сборки | Готово | GitHub Actions | Artifact `antivirus-gui-windows-release`. |

## Задание 2.2

| Пункт | Статус | Где реализовано | Как показать |
|---|---|---|---|
| Windows-служба | Готово | `src/service/ServiceMain.cpp` | `AntivirusService.exe --install`, затем `sc query AntivirusGuiService`. |
| Запуск GUI во всех пользовательских сессиях | Готово | `SessionManager`, `ProcessLauncher` | Служба вызывает `CreateProcessAsUserW`. |
| GUI запускается от владельца сессии | Готово | `WTSQueryUserToken`, `DuplicateTokenEx` | Показать код запуска процесса. |
| Главное окно при запуске службой скрыто | Готово | `AntivirusWinUi.exe --service-child` | После старта видна только иконка в трее. |
| Обработка новых входов пользователя | Готово | `SERVICE_CONTROL_SESSIONCHANGE` | Показать обработчик события. |
| Stop/Shutdown SCM не останавливают службу напрямую | Готово | управляющий код не принимает прямой stop как рабочий сценарий | Остановка идёт через RPC. |
| RPC over local transport | Готово | `rpc/AntivirusRpc.idl`, `ncalrpc` | Показать IDL и `RpcServerUseProtseqEpW`. |
| RPC-команда остановки службы | Готово | `AvRequestServiceStop` | Нажать `Файл -> Выход` или `Остановить службу`. |
| Служба закрывает GUI при остановке | Готово | `SessionManager::stopAllGuiChildren` | Остановить службу через GUI. |
| Secure Desktop подтверждение | Доп. пункт готов | `secure_stop_confirmation.cpp` | При остановке появляется защищённый диалог. |
| DACL hardening процессов | Доп. пункт готов | `process_hardening.cpp` | Показать код и логи запуска. |

## Задание 2.3

| Пункт | Статус | Где реализовано | Как показать |
|---|---|---|---|
| Вход пользователя | Готово | `AuthManager`, `AvLogin` | Ввести `demo` / `demo`. |
| Выход пользователя | Готово | `AvLogout` | Нажать `Выйти`. |
| Активация продукта | Готово | `LicenseManager`, `AvActivateProduct` | Ввести `DEMO-1234`. |
| Блокировка функций без лицензии | Готово | `FeatureGate` | До входа/активации кнопки сканирования отключены. |
| Ошибки при неверных данных | Готово | `AuthManager`, `LicenseManager` | Ввести неверный пароль или код. |
| Информация о лицензии в GUI | Готово | `src/winui/main.cpp` | Показать срок действия лицензии. |

## Задание 2.4

| Пункт | Статус | Где реализовано | Как показать |
|---|---|---|---|
| База загружается после активации | Готово | `ServiceMain::activate`, `loadDatabaseFromDisk` | Активировать лицензию и показать блок баз. |
| Хранение базы в памяти | Готово | `AvDatabase` | Показать `std::map` с записями. |
| Красно-чёрное дерево | Готово | `std::map<std::uint64_t, ...>` | Объяснить, что стандартные реализации `std::map` обычно используют RB-tree. |
| Поля `AvRecord` | Готово | `AvDatabase.h` | Показать prefix, length, hash, offsets, type, signature, threat name. |
| PE / NET / Java / Python / JS / PowerShell type field | Готово для учебных demo-типов | `ObjectType`, `FileScanner` | В демо распознаются PE и PowerShell; остальные типы представлены enum-полем модели. |
| Алгоритм по первым 8 байтам | Готово | `ScanEngine.cpp` | Показать lookup по prefix в `recordsByPrefix`. |
| Проверка object type | Готово | `ScanEngine.cpp` | Тест wrong object type. |
| Проверка offset range | Готово | `ScanEngine.cpp` | Тест out-of-range. |
| Проверка hash/signature | Готово | `ScanEngine.cpp` | Тесты `AntivirusScanTests`. |
| Сканирование файла | Готово | `AvScanFile`, WinUI кнопка `Файл` | Выбрать файл. |
| Сканирование папки | Готово | `AvScanDirectory`, WinUI кнопка `Папка` | Выбрать папку. |
| Сканирование всех несъёмных дисков | Доп. пункт готов | `scanFixedDrives`, `DRIVE_FIXED` | Нажать `Все диски`. |
| Сканирование по расписанию | Доп. пункт готов | `AvStartScanSchedule`, WinUI блок расписания | Задать интервал, выбрать файл/папку/диски. |
| Мониторинг директорий | Доп. пункт готов | `DirectoryMonitor`, `AvStartDirectoryMonitor` | Запустить мониторинг папки и изменить файл. |
| Ахо-Корасик | Доп. пункт готов | `AhoCorasickScanner` | Показать быстрый multi-pattern scan и fallback через `std::map`. |

## Задание 2.5

| Пункт | Статус | Где реализовано | Как показать |
|---|---|---|---|
| База хранится на диске | Готово | `AvDatabaseStorage`, `avdb.bin` | Показать `C:\Program Files\AntivirusGui\bases`. |
| Бинарный компактный формат | Готово | `writeDatabaseFile`, `loadSingleFile` | Показать magic/version/манифест/records. |
| Целостность манифеста | Готово | `signManifest` | Скрипт `prepare-mock-update-recovery.ps1`. |
| Продукт поставляется с базой по умолчанию | Готово | `writeDefaultDatabase`, `makeDemoRecords` | Удалить базу и запустить службу. |
| Загрузка базы при запуске | Готово | `loadDatabaseFromDisk` | Показать `service.log`: `Антивирусная база загружена с диска`. |
| Backup перед update | Доп. пункт готов | `AvUpdateScheduler::runUpdateNow` | Показать `avdb.bak`. |
| Загрузка базы после update | Доп. пункт готов | `applyDatabaseLoadResult` | Показать запись в `service.log`: `Антивирусная база обновлена и перезагружена`. |
| Откат при неудачном update | Доп. пункт готов | `AvUpdateScheduler` | Показать copy из backup. |
| Запрос повреждённых записей с сервера | Доп. пункт готов | `replaceCorruptedRecordsFromServer` | Тест `Corrupted record recovery uses mock update server`. |
| Принудительное обновление при битом манифесте | Доп. пункт готов | `loadOrRecover`, `AvUpdateClient` | Скрипт `prepare-mock-update-recovery.ps1`. |
| Периодическое обновление баз | Доп. пункт готов | `AvUpdateScheduler` | Показать лог `Планировщик обновления антивирусных баз запущен`. |

## Задание 2.6

| Пункт | Статус | Где реализовано | Как показать |
|---|---|---|---|
| EXE-инсталлер | Готово | `installer/AntivirusGui.nsi` | Запустить `AntivirusGuiSetup.exe` от администратора. |
| Копирует EXE/DLL/resources/config | Готово | секция `Application` NSIS | Показать `C:\Program Files\AntivirusGui`. |
| Ставит зависимости | Готово | VC++ Runtime, Windows App Runtime 2.0 с восстановлением регистрации | Показать шаги в логе инсталлера. |
| Регистрирует службу | Готово | `AntivirusService.exe --install` | `sc query AntivirusGuiService`. |
| Удаляет файлы при uninstall | Готово | секция `Uninstall` | Запустить `Uninstall.exe`. |
| Останавливает и удаляет службу при uninstall | Готово | `sc stop`, `--uninstall` | Показать uninstall log. |
| Собирается в CI и публикуется artifact | Готово | `.github/workflows/windows.yml` | Artifact `antivirus-gui-installer`. |

## Команды проверки

```powershell
npx --yes @microsoft/winappcli restore
cmake -S . -B build-local-winui-ui -DCMAKE_BUILD_TYPE=Release
cmake --build build-local-winui-ui --config Release
ctest --test-dir build-local-winui-ui -C Release --output-on-failure
.\installer\build-installer.ps1 -BuildDir build-local-winui-ui -OutputDir out\installer
```
