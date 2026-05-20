# Демо-скрипты

Для сценариев установки, перезапуска службы и проверки восстановления запускайте PowerShell от имени администратора.

Рекомендуемый порядок:

1. `.\scripts\demo\prepare-license.ps1`
2. `.\scripts\demo\create-test-threats.ps1`
3. Открыть установленный `C:\Program Files\AntivirusGui\AntivirusWinUi.exe`, войти как `demo` / `demo`, активировать кодом `DEMO-1234`, затем просканировать `C:\ProgramData\AntivirusGuiScanTest`.
4. Для ПЗ 2.4 запустить мониторинг папки из GUI, выполнить `C:\Program Files\AntivirusGui\PZ_2_4_DEMO\04_monitor\trigger-monitor-change.ps1` и затем `.\scripts\demo\show-logs.ps1`.
5. Для ПЗ 2.5 выполнить `.\scripts\demo\prepare-backup-recovery.ps1`.
6. Для ПЗ 2.5 выполнить `.\scripts\demo\prepare-mock-update-recovery.ps1`.
7. Выполнить `.\scripts\demo\show-logs.ps1`.

Заметки:

- `prepare-backup-recovery.ps1` копирует `avdb.bin` в `avdb.bak`, временно отключает демо-сервер обновлений, повреждает основную базу, перезапускает службу через `AntivirusCtl.exe` и показывает строки восстановления из резервной копии.
- `prepare-mock-update-recovery.ps1` копирует валидную базу в `C:\ProgramData\AntivirusGuiMockServer\avdb.bin`, повреждает подпись манифеста основной базы, перезапускает службу через `AntivirusCtl.exe` и показывает принудительное обновление через демо-сервер.
- Демо-сигнатуры безопасны: `MZAVGUI-PE-TEST` и `Invoke-AvGuiTest`.
