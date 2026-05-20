# Testing

## Common Build Check

Run after each task:

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

## Task 2.1 Manual Checks

1. Start `AntivirusGui.exe`.
2. Verify a tray icon appears.
3. Close the main window and verify the process continues running.
4. Left-click the tray icon and verify the main window appears.
5. Right-click the tray icon and verify the context menu appears.
6. Use `Открыть` to show the window.
7. Use `Выход` to terminate the application.
8. Start `AntivirusGui.exe --hidden` and verify the window is hidden while the tray icon exists.
9. Start a second instance and verify it exits without creating another tray icon.
10. Restart Explorer and verify the tray icon is restored.

## Task 2.2 Manual Checks

1. Install the Windows service as administrator.
2. Start the service.
3. Verify the service launches GUI children in user sessions with hidden windows.
4. Verify new user logons trigger GUI launch.
5. Use GUI menu exit and tray exit to request service stop through local RPC.
6. Verify service stop closes owned GUI child processes.

## Task 2.3 Manual Checks

1. Start service and GUI in mock authentication mode.
2. Verify unauthenticated state shows login.
3. Verify failed login shows an error.
4. Verify successful login shows the user.
5. Verify missing license shows activation.
6. Verify failed activation shows an error.
7. Verify successful activation unlocks features and shows expiration.
8. Verify logout clears authentication and license state.

## Extra Points Manual Checks

1. Verify all targets build through CMake.
2. Verify service stop asks for secure confirmation where supported.
3. Verify process DACL hardening blocks non-admin termination attempts where Windows security allows it.
4. Verify limitations around administrators are documented honestly.

## Task 2.6 Manual Checks

1. Build the package target.
2. Install the generated MSI.
3. Verify files are installed under Program Files.
4. Verify the Windows service is registered for automatic startup.
5. Verify GUI and service launch.
6. Uninstall the application.
7. Verify service registration and installed files are removed.
