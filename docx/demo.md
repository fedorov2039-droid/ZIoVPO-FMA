# Сценарий демонстрации преподавателю

## 1. Установка

Готовый набор команд PowerShell есть в `docx\powershell-commands.md`.
Для точечного показа ПЗ 2.5 и дополнительных критериев использовать `docx\criteria-demo.md`.

1. Открыть PowerShell или Explorer от администратора.
2. Запустить `AntivirusGuiSetup.exe`.
3. После установки открыть `C:\Program Files\AntivirusGui`.
4. Показать файлы:
   - `AntivirusWinUi.exe`;
   - `AntivirusService.exe`;
   - `AntivirusCtl.exe`;
   - `Microsoft.WindowsAppRuntime.Bootstrap.dll`;
   - `docx`;
   - `scripts\demo`.
5. Проверить службу:

```powershell
sc query AntivirusGuiService
```

## 2. GUI, трей и служба

1. Запустить `AntivirusWinUi.exe`.
2. Показать, что обычный запуск открывает service-owned окно, а не создаёт второй экземпляр.
3. Закрыть окно крестиком: приложение остаётся в трее.
4. Левой кнопкой по трею открыть окно.
5. Правой кнопкой показать меню `Открыть` и `Выход`.
6. В главном окне открыть меню `Файл -> Выход`.

## 3. Авторизация и лицензия

1. До входа показать, что scan/monitor/schedule кнопки заблокированы.
2. Ввести:

```text
Логин: demo
Пароль: demo
Код активации: DEMO-1234
```

3. После активации показать срок лицензии и количество записей базы.

## 4. Сканирование

1. Запустить `scripts\demo\create-test-threats.ps1`.
2. В GUI нажать `Файл` и выбрать demo PE файл.
3. Нажать `Папка` и выбрать `C:\ProgramData\AntivirusGuiScanTest`.
4. Нажать `Все диски`, если есть время.
5. Показать в журнале:
   - количество просканированных файлов;
   - количество угроз;
   - имя угрозы;
   - смещение.

## 5. Расписание

1. В поле интервала ввести `5`.
2. Нажать `Файл` в блоке `Сканирование по расписанию`.
3. Выбрать demo файл.
4. Через несколько секунд показать `Последний запуск`.
5. Нажать `Остановить`.

## 6. Мониторинг директории

1. Нажать `Запустить` в блоке `Мониторинг`.
2. Выбрать `C:\ProgramData\AntivirusGuiScanTest`.
3. Изменить или создать файл в этой папке.
4. Показать логи:

```powershell
.\scripts\demo\show-logs.ps1
```

## 7. Recovery баз

Показать восстановление из backup:

```powershell
.\scripts\demo\prepare-backup-recovery.ps1
```

Показать принудительное обновление при повреждённом манифесте:

```powershell
.\scripts\demo\prepare-mock-update-recovery.ps1
```

## 8. Инсталлер и удаление

1. Показать, что installer является `.exe`.
2. Запустить uninstall:

```powershell
C:\Program Files\AntivirusGui\Uninstall.exe
```

3. Проверить, что служба и файлы удалены.
