# Task 2.6: Installer Creation

## Requirements

| # | Requirement | Implementation |
|---|-------------|----------------|
| 1 | Include executable files, dynamic libraries, resources, and configuration files needed to run. | CPack NSIS package installs `AntivirusGui.exe`, `AntivirusService.exe`, Qt runtime files deployed by `windeployqt`, installer helper files, docs, and `config.example.json`. |
| 2 | Install necessary dependencies. | MSVC runtime is included through `InstallRequiredSystemLibraries`; Qt runtime/plugins are copied locally through `windeployqt`. |
| 3 | Register Windows service for automatic startup. | The installer runs `AntivirusService.exe --install`, which registers `AntivirusGuiService` as `SERVICE_AUTO_START`, then starts it. |
| 4 | Remove all application files on uninstall. | The NSIS uninstaller removes the installation directory after service cleanup. |
| 5 | Remove dependencies if not used elsewhere. | The package keeps app-local Qt/MSVC runtime copies under the installation root, so uninstall removes only this app's private dependency copies. |
| 6 | Stop and remove Windows service from SCM on uninstall. | The uninstaller terminates GUI/service processes, runs `AntivirusService.exe --uninstall`, and calls `sc.exe delete` as a cleanup fallback. |
| 7 | Build installer in CI and upload artifacts. | GitHub Actions builds Release, runs CPack `package`, and uploads the generated `.exe` installer as an artifact. |

## Build Locally

Prerequisites:

- Windows
- Visual Studio 2022 Build Tools
- CMake 3.24+
- Qt 6.7.3
- NSIS available in `PATH`

```powershell
cmake -S . -B build-installer -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="C:/Users/13372/QtCodex/6.7.3/msvc2019_64"
cmake --build build-installer --config Release
cmake --build build-installer --config Release --target package
```

Expected package:

```text
build-installer/AntivirusGuiInstaller-0.1.0-win64.exe
```

## Manual Verification

1. Build `AntivirusGuiInstaller-0.1.0-win64.exe`.
2. Run the installer as administrator.
3. Verify files exist under `C:\Program Files\Antivirus GUI`.
4. Verify `AntivirusGuiService` is registered.
5. Verify the service is set to automatic startup.
6. Verify the service starts after installation.
7. Verify GUI/tray starts through the service in a user session.
8. Uninstall through Windows installed applications or the generated uninstaller.
9. Verify the service is removed from Service Control Manager.
10. Verify installed files and private dependencies are removed.

## Verification Commands

```powershell
sc.exe qc antivirusguiservice
sc.exe query antivirusguiservice
tasklist | findstr /i "Antivirus"
```

After uninstall:

```powershell
sc.exe query antivirusguiservice
tasklist | findstr /i "Antivirus"
dir "C:\Program Files\Antivirus GUI"
```

Expected after uninstall:

- `sc.exe query antivirusguiservice` reports that the service does not exist.
- `tasklist` does not show `AntivirusGui.exe` or `AntivirusService.exe`.
- The installation directory is removed.

## Security Notes

- Installation requires administrator rights because service registration requires SCM write access.
- The installer performs transparent file copy, dependency deployment, service registration, and service cleanup only.
- The installer does not hide files, bypass UAC, disable Windows protections, or install drivers.
