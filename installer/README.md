# Installer

This project ships a CPack NSIS installer package for Windows coursework demonstration.

## Build

Run these commands from the repository root:

    cmake -S . -B build-installer -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="C:/Users/13372/QtCodex/6.7.3/msvc2019_64"
    cmake --build build-installer --config Release
    cmake --build build-installer --config Release --target package

The generated package is named like:

    AntivirusGuiInstaller-0.1.0-win64.exe

## Install

Run the generated installer as administrator.

The installer copies files to C:\Program Files\Antivirus GUI, installs private Qt/MSVC runtime dependencies, registers AntivirusGuiService, configures service recovery, and starts the service.

## Uninstall

Use Windows installed applications or the generated uninstaller.

The uninstaller stops Antivirus GUI processes, removes AntivirusGuiService, and removes installed application files and private dependencies.
