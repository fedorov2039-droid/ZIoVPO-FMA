# Task 2.2: Windows Service and GUI Interaction

## Requirements

| Area | Requirement | Implementation |
|------|-------------|----------------|
| Service | Launch GUI in all non-zero terminal sessions as the session owner with hidden main window. | `SessionManager` enumerates WTS sessions and `ProcessLauncher` uses `WTSQueryUserToken`, `DuplicateTokenEx`, `CreateEnvironmentBlock`, and `CreateProcessAsUserW` with `--hidden --service-child`. |
| Service | Track new user logons and launch GUI. | `ServiceMain` handles `SERVICE_CONTROL_SESSIONCHANGE` for logon/console/remote connect events. |
| Service | Keep controlled stop through RPC for coursework. | SCM stop/shutdown controls are not accepted while running; RPC stop sets the service stop event. |
| Service | Start Windows RPC server using `ncalrpc`. | `RpcServer` registers endpoint `AntivirusGuiRpc` over `ncalrpc`. Modern local RPC on Windows uses LPC/ALPC internally for local transport. |
| Service | Register RPC interface for stop requests. | `rpc/AntivirusRpc.idl` defines `AvPing`, `AvRequestServiceStop`, and `AvGetServiceStatus`; CMake runs MIDL and links generated server stubs. |
| Service | Stop all launched GUI children on service stop. | `SessionManager::stopAllGuiChildren()` waits for owned children and terminates only owned GUI processes after timeout. |
| GUI | Check Windows service state on startup. | `ServiceClient` queries SCM; if service is installed but stopped, GUI starts it, waits for `Running`, and exits. |
| GUI | Verify parent process is this project service. | `ParentProcessCheck` checks the parent image name and production mode requires `AntivirusService.exe`; `--allow-standalone-debug` bypasses this only for debugging. |
| GUI | `Файл -> Выход` stops service through RPC. | `AppLifecycle::quitApplication()` calls `RpcClient::requestServiceStop()`. |
| GUI | Tray `Выход` stops service through RPC. | Tray action uses the same `AppLifecycle` path. |
| CMake | Build generated RPC stubs. | `CMakeLists.txt` compiles `rpc/AntivirusRpc.idl` with MIDL and links generated client/server stubs into GUI/service targets. |

## Commands

Install service as administrator:

```powershell
.\AntivirusService.exe --install
```

Uninstall service as administrator:

```powershell
.\AntivirusService.exe --uninstall
```

Run as a real service through SCM:

```powershell
sc.exe start AntivirusGuiService
```

Run service logic in console for debugging:

```powershell
.\AntivirusService.exe --console
```

Run GUI in standalone debug mode:

```powershell
.\AntivirusGui.exe --allow-standalone-debug
```

Production GUI instances are launched by the service with:

```powershell
.\AntivirusGui.exe --hidden --service-child
```

## Manual Verification

1. Build Release binaries.
2. Install the service as administrator with `AntivirusService.exe --install`.
3. Start the service with `sc.exe start AntivirusGuiService`.
4. Verify the service launches hidden GUI/tray instances in active non-zero user sessions.
5. Left-click the tray icon and verify the main window opens.
6. Use `Файл -> Выход` and verify the GUI sends `AvRequestServiceStop` through RPC.
7. Start again and use tray `Выход`; verify it also stops the service through RPC.
8. Verify stopping the service closes owned GUI child processes.
9. Log on or connect to a new user session and verify session change handling launches a GUI child.

## Build Verification

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

## Limitations

- Installing, uninstalling, and starting the service requires administrator rights.
- `WTSQueryUserToken` requires the service to run as LocalSystem; console mode logs a warning when it lacks that context.
- The service does not hide processes, bypass UAC, or disable Windows protections.
- Local RPC is intentionally limited to `ncalrpc` and local clients.
