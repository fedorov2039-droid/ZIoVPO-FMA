# Task 2.1: Basic Graphical Application Functions

## Requirements

| # | Requirement | Implementation |
|---|-------------|----------------|
| 1 | Add an icon to the taskbar notification area on startup. | `TrayController` creates and shows a `QSystemTrayIcon`. |
| 2 | Left-clicking the tray icon shows the main window. | `QSystemTrayIcon::Trigger` calls `TrayController::showMainWindow()`. |
| 3 | Right-clicking the tray icon shows a context menu. | `QSystemTrayIcon` owns a `QMenu` context menu. |
| 4 | Context menu contains `Открыть`, which shows the main window. | Tray menu action calls `showMainWindow()`. |
| 5 | Context menu contains `Выход`, which terminates the app. | Tray menu action calls `AppLifecycle::quitApplication()`. |
| 6 | Tray icon is restored after taskbar recreation. | `TrayController` listens for the registered `TaskbarCreated` Windows message and shows the icon again. |
| 7 | App supports startup with hidden main window. | `--hidden` starts the app with tray icon only. |
| 8 | Closing the main window keeps the app running in background. | `MainWindow::closeEvent()` ignores close and hides the window. |
| 9 | Main menu contains `Файл -> Выход`, which terminates the app. | `MainWindow` creates the menu action and calls `AppLifecycle::quitApplication()`. |
| 10 | Single-instance mode prevents a second tray icon in the same user session. | `SingleInstanceGuard` uses `Local\\AntivirusGuiSingleton` before tray creation. |
| 11 | Build works through CMake/MSBuild on CI. | `.github/workflows/windows.yml` configures and builds Release with Qt installed. |
| 12 | Build artifacts are saved. | CI uploads `AntivirusGui.exe` and `AntivirusService.exe`. |

## Build

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

## Manual Verification

1. Run `AntivirusGui.exe`.
2. Verify the tray icon appears.
3. Close the main window with the window close button and verify the process stays alive.
4. Left-click the tray icon and verify the main window appears.
5. Right-click the tray icon and verify the context menu appears.
6. Click `Открыть` and verify the main window appears.
7. Click `Выход` and verify the process exits.
8. Run `AntivirusGui.exe --hidden` and verify the window does not appear while the tray icon exists.
9. Start a second `AntivirusGui.exe` instance and verify it exits quickly without adding another tray icon.
10. Restart `Explorer.exe` and verify the tray icon is restored.

## Artifacts

GitHub Actions uploads Release executables in the `antivirus-gui-windows-release` artifact:

- `AntivirusGui.exe`
- `AntivirusService.exe`

## Limitations

Task 2.1 intentionally does not start or stop the Windows service. Service lifecycle and RPC stop behavior are implemented in Task 2.2.
