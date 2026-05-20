Unicode true
SetCompressor /SOLID lzma
RequestExecutionLevel admin

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"

!define APP_NAME "Antivirus GUI Coursework"
!define APP_VERSION "0.1.0"
!define APP_PUBLISHER "Antivirus Coursework"
!define SERVICE_NAME "AntivirusGuiService"

Name "${APP_NAME}"
OutFile "${OUTPUT_EXE}"
InstallDir "$PROGRAMFILES64\AntivirusGui"
InstallDirRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AntivirusGui" "InstallLocation"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "Russian"

Section "Prerequisites" SEC_PREREQ
    SetShellVarContext all
    SetOutPath "$TEMP\AntivirusGuiSetup"

    File /oname=vc_redist.x64.exe "${DEPS_DIR}\vc_redist.x64.exe"
    File /oname=windowsappruntimeinstall-x64.exe "${DEPS_DIR}\windowsappruntimeinstall-x64.exe"

    DetailPrint "Установка Microsoft Visual C++ Runtime..."
    ExecWait '"$TEMP\AntivirusGuiSetup\vc_redist.x64.exe" /install /quiet /norestart' $0
    ${If} $0 != 0
    ${AndIf} $0 != 3010
        MessageBox MB_ICONEXCLAMATION "Установщик Microsoft Visual C++ Runtime вернул код $0. Установка продолжится, но приложению может потребоваться эта зависимость."
    ${EndIf}

    DetailPrint "Установка и восстановление Windows App Runtime 2.0..."
    ExecWait '"$TEMP\AntivirusGuiSetup\windowsappruntimeinstall-x64.exe" --quiet --force' $0
    ${If} $0 != 0
    ${AndIf} $0 != 3010
        MessageBox MB_ICONEXCLAMATION "Установщик Windows App Runtime вернул код $0. Установка продолжится, но WinUI-интерфейсу может потребоваться эта зависимость."
    ${EndIf}
SectionEnd

Section "Application" SEC_APP
    SetShellVarContext all
    SetRegView 64

    SetOutPath "$TEMP\AntivirusGuiSetup"
    File /oname=AntivirusCtl.exe "${BUILD_DIR}\Release\AntivirusCtl.exe"

    DetailPrint "Запрос остановки существующей службы через RPC..."
    ExecWait '"$TEMP\AntivirusGuiSetup\AntivirusCtl.exe" --request-stop' $0
    Sleep 3000

    DetailPrint "Остановка старых процессов GUI, если они запущены..."
    nsExec::ExecToLog 'taskkill.exe /IM AntivirusWinUi.exe /F /T'
    nsExec::ExecToLog 'taskkill.exe /IM AntivirusGui.exe /F /T'
    Sleep 1000

    DetailPrint "Остановка существующей службы, если она установлена..."
    ExecWait 'sc.exe stop ${SERVICE_NAME}' $0
    Sleep 2000

    IfFileExists "$INSTDIR\AntivirusService.exe" 0 +3
        ExecWait '"$INSTDIR\AntivirusService.exe" --uninstall' $0
        Sleep 1000

    SetOutPath "$INSTDIR"
    File "${BUILD_DIR}\Release\AntivirusWinUi.exe"
    File "${BUILD_DIR}\Release\AntivirusService.exe"
    File "${BUILD_DIR}\Release\AntivirusCtl.exe"
    File "${BUILD_DIR}\Release\Microsoft.WindowsAppRuntime.Bootstrap.dll"

    SetOutPath "$INSTDIR\docx"
    File /oname=project-readme.md "${PROJECT_ROOT}\README.md"
    File "${PROJECT_ROOT}\docx\*.md"

    SetOutPath "$INSTDIR\scripts\demo"
    File "${PROJECT_ROOT}\scripts\demo\README.md"
    File "${PROJECT_ROOT}\scripts\demo\*.ps1"

    SetOutPath "$INSTDIR"
    WriteUninstaller "$INSTDIR\Uninstall.exe"

    DetailPrint "Регистрация Windows-службы..."
    ExecWait '"$INSTDIR\AntivirusService.exe" --install' $0
    ${If} $0 != 0
        MessageBox MB_ICONSTOP "Не удалось установить службу. Код ошибки: $0."
        Abort
    ${EndIf}

    DetailPrint "Запуск Windows-службы..."
    ExecWait 'sc.exe start ${SERVICE_NAME}' $0

    CreateDirectory "$SMPROGRAMS\Antivirus GUI"
    CreateShortCut "$SMPROGRAMS\Antivirus GUI\Antivirus GUI.lnk" "$INSTDIR\AntivirusWinUi.exe"
    CreateShortCut "$SMPROGRAMS\Antivirus GUI\Uninstall Antivirus GUI.lnk" "$INSTDIR\Uninstall.exe"

    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AntivirusGui" "DisplayName" "${APP_NAME}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AntivirusGui" "DisplayVersion" "${APP_VERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AntivirusGui" "Publisher" "${APP_PUBLISHER}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AntivirusGui" "InstallLocation" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AntivirusGui" "DisplayIcon" "$INSTDIR\AntivirusWinUi.exe"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AntivirusGui" "UninstallString" '"$INSTDIR\Uninstall.exe"'
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AntivirusGui" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AntivirusGui" "NoRepair" 1
SectionEnd

Section "Uninstall"
    SetShellVarContext all
    SetRegView 64

    DetailPrint "Остановка службы..."
    ExecWait 'sc.exe stop ${SERVICE_NAME}' $0
    Sleep 2000

    IfFileExists "$INSTDIR\AntivirusService.exe" 0 +2
        ExecWait '"$INSTDIR\AntivirusService.exe" --uninstall' $0

    Delete "$SMPROGRAMS\Antivirus GUI\Antivirus GUI.lnk"
    Delete "$SMPROGRAMS\Antivirus GUI\Uninstall Antivirus GUI.lnk"
    RMDir "$SMPROGRAMS\Antivirus GUI"

    Delete "$INSTDIR\AntivirusWinUi.exe"
    Delete "$INSTDIR\AntivirusService.exe"
    Delete "$INSTDIR\AntivirusCtl.exe"
    Delete "$INSTDIR\Microsoft.WindowsAppRuntime.Bootstrap.dll"
    Delete "$INSTDIR\Uninstall.exe"
    RMDir /r "$INSTDIR\docx"
    RMDir /r "$INSTDIR\docs"
    RMDir /r "$INSTDIR\scripts"
    RMDir "$INSTDIR"

    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AntivirusGui"
SectionEnd
