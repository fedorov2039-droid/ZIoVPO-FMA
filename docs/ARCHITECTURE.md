# Architecture

## Component Overview

```text
User session
  AntivirusGui.exe
    - Qt Widgets main window
    - Tray icon and menu
    - Service/RPC client
    - Auth and activation dialogs

Session 0
  AntivirusService.exe
    - Windows Service entry point
    - Session manager
    - GUI process launcher
    - Local RPC server
    - Auth/license managers

Local IPC
  Windows RPC endpoint over ncalrpc
    - Local RPC transport on modern Windows uses LPC/ALPC internally

Packaging
  Installer
    - Copies binaries and runtime files
    - Registers/removes the Windows service
```

## Project Layout

- `src/common`: shared utilities for paths, logging, and Windows error formatting.
- `src/gui`: Qt Widgets GUI executable.
- `src/service`: Windows service executable.
- `rpc`: future RPC IDL and generated stubs.
- `installer`: future installer packaging files.
- `docs`: assignment documentation and manual verification notes.

## Safety Boundaries

This is an educational project. It does not implement hidden malicious activity, process hiding, UAC bypasses, anti-debugging, unauthorized persistence, or system protection disabling. Service/session behavior in later tasks is explicit and documented for coursework demonstration.

The GUI and service will use normal Windows APIs and transparent logs. Security-related hardening in later tasks is documented as best-effort DACL configuration, not malware-like self-defense.
