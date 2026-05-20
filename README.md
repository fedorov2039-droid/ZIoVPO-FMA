# Antivirus GUI

Educational Windows C++20 project for antivirus GUI coursework. The project is intentionally limited to benign UI, service, IPC, authentication/licensing, and installer exercises. It does not implement malware behavior, process hiding, system protection bypasses, or real antivirus scanning.

## Covered Assignments

- Task 2.1: Qt Widgets GUI, tray lifecycle, hidden mode, single-instance behavior.
- Task 2.2: Windows service, session launch, and local RPC interaction.
- Task 2.3: account login, activation, and license-gated features.
- Extra points: CMake build, secure stop confirmation, and documented DACL hardening.
- Task 2.6: Windows installer packaging.

This initial scaffold provides the C++20/CMake structure, minimal GUI target, service target placeholder, documentation, and Windows CI.

## Build

Prerequisites:

- Windows with Visual Studio 2022 Build Tools or Visual Studio 2022.
- CMake 3.24 or newer.
- Qt 6 Widgets development package available to CMake.

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

## Run GUI

After building:

```powershell
.\build\Release\AntivirusGui.exe
```

At the scaffold stage the GUI shows a minimal Qt Widgets window only. Tray and lifecycle behavior are implemented in Task 2.1.

## Run Service

After building:

```powershell
.\build\Release\AntivirusService.exe --console
```

At the scaffold stage the service executable is a console placeholder. Native Windows service behavior is implemented in Task 2.2.

## CI Artifacts

The Windows workflow configures CMake, builds the Release targets, and uploads the built executables as artifacts.
