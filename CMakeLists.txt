cmake_minimum_required(VERSION 3.24)

project(
    AntivirusGuiProject
    VERSION 0.1.0
    DESCRIPTION "Учебное Windows-приложение Antivirus GUI"
    LANGUAGES C CXX
)

option(ANTIVIRUS_BUILD_GUI "Build the legacy Qt Widgets GUI application" OFF)
option(ANTIVIRUS_BUILD_WINUI "Build the WinUI GUI application" ON)
option(ANTIVIRUS_BUILD_SERVICE "Build the Windows service executable" ON)
option(ANTIVIRUS_BUILD_TESTS "Build antivirus test executables" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(WIN32)
    set(ANTIVIRUS_MIDL_SEARCH_PATHS)
    if(CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION)
        list(APPEND ANTIVIRUS_MIDL_SEARCH_PATHS
            "C:/Program Files (x86)/Windows Kits/10/bin/${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}/x64"
        )
    endif()
    file(GLOB ANTIVIRUS_WINDOWS_KIT_MIDL_PATHS "C:/Program Files (x86)/Windows Kits/10/bin/*/x64")
    list(APPEND ANTIVIRUS_MIDL_SEARCH_PATHS ${ANTIVIRUS_WINDOWS_KIT_MIDL_PATHS})
    find_program(MIDL_EXECUTABLE NAMES midl.exe PATHS ${ANTIVIRUS_MIDL_SEARCH_PATHS} REQUIRED)
    set(ANTIVIRUS_RPC_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/rpc")
    set(ANTIVIRUS_RPC_IDL "${CMAKE_CURRENT_SOURCE_DIR}/rpc/AntivirusRpc.idl")
    set(ANTIVIRUS_RPC_HEADER "${ANTIVIRUS_RPC_GENERATED_DIR}/AntivirusRpc.h")
    set(ANTIVIRUS_RPC_CLIENT "${ANTIVIRUS_RPC_GENERATED_DIR}/AntivirusRpc_c.c")
    set(ANTIVIRUS_RPC_SERVER "${ANTIVIRUS_RPC_GENERATED_DIR}/AntivirusRpc_s.c")

    add_custom_command(
        OUTPUT
            "${ANTIVIRUS_RPC_HEADER}"
            "${ANTIVIRUS_RPC_CLIENT}"
            "${ANTIVIRUS_RPC_SERVER}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${ANTIVIRUS_RPC_GENERATED_DIR}"
        COMMAND "${MIDL_EXECUTABLE}" /nologo /env x64 /char signed /out "${ANTIVIRUS_RPC_GENERATED_DIR}" "rpc/AntivirusRpc.idl"
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        DEPENDS "${ANTIVIRUS_RPC_IDL}"
        VERBATIM
    )

    add_custom_target(AntivirusRpcGenerated
        DEPENDS
            "${ANTIVIRUS_RPC_HEADER}"
            "${ANTIVIRUS_RPC_CLIENT}"
            "${ANTIVIRUS_RPC_SERVER}"
    )

    add_library(AntivirusRpcClient STATIC
        "${ANTIVIRUS_RPC_CLIENT}"
        src/common/rpc_memory.cpp
        src/common/rpc_memory.h
    )

    target_include_directories(AntivirusRpcClient
        PUBLIC
            "${ANTIVIRUS_RPC_GENERATED_DIR}"
            src
    )

    target_compile_definitions(AntivirusRpcClient
        PUBLIC
            WIN32_LEAN_AND_MEAN
            NOMINMAX
    )

    target_link_libraries(AntivirusRpcClient PUBLIC Rpcrt4)
    add_dependencies(AntivirusRpcClient AntivirusRpcGenerated)

    add_library(AntivirusRpcServer STATIC
        "${ANTIVIRUS_RPC_SERVER}"
        src/common/rpc_memory.cpp
        src/common/rpc_memory.h
    )

    target_include_directories(AntivirusRpcServer
        PUBLIC
            "${ANTIVIRUS_RPC_GENERATED_DIR}"
            src
    )

    target_compile_definitions(AntivirusRpcServer
        PUBLIC
            WIN32_LEAN_AND_MEAN
            NOMINMAX
    )

    target_link_libraries(AntivirusRpcServer PUBLIC Rpcrt4)
    add_dependencies(AntivirusRpcServer AntivirusRpcGenerated)
endif()

add_library(AntivirusCommon STATIC
    src/common/app_paths.cpp
    src/common/app_paths.h
    src/common/logging.cpp
    src/common/logging.h
    src/common/process_hardening.cpp
    src/common/process_hardening.h
    src/common/secure_stop_confirmation.cpp
    src/common/secure_stop_confirmation.h
    src/common/win_error.cpp
    src/common/win_error.h
)

target_include_directories(AntivirusCommon
    PUBLIC
        src
)

target_compile_definitions(AntivirusCommon
    PUBLIC
        UNICODE
        _UNICODE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
)

if(MSVC)
    target_compile_options(AntivirusCommon PRIVATE /W4 /permissive- /utf-8)
else()
    target_compile_options(AntivirusCommon PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(ANTIVIRUS_BUILD_GUI)
    find_package(Qt6 REQUIRED COMPONENTS Widgets)
    qt_standard_project_setup()

    qt_add_executable(AntivirusGui WIN32
        src/gui/AppLifecycle.cpp
        src/gui/AppLifecycle.h
        src/gui/MainWindow.cpp
        src/gui/MainWindow.h
        src/gui/AuthDialog.cpp
        src/gui/AuthDialog.h
        src/gui/ActivationDialog.cpp
        src/gui/ActivationDialog.h
        src/gui/ParentProcessCheck.cpp
        src/gui/ParentProcessCheck.h
        src/gui/RpcClient.cpp
        src/gui/RpcClient.h
        src/gui/SecureStopConfirmation.cpp
        src/gui/SecureStopConfirmation.h
        src/gui/ServiceClient.cpp
        src/gui/ServiceClient.h
        src/gui/SingleInstanceGuard.cpp
        src/gui/SingleInstanceGuard.h
        src/gui/TrayController.cpp
        src/gui/TrayController.h
        src/gui/main.cpp
    )

    target_link_libraries(AntivirusGui
        PRIVATE
            AntivirusCommon
            AntivirusRpcClient
            Qt6::Widgets
            Advapi32
            Credui
            Rpcrt4
    )

    target_compile_definitions(AntivirusGui PRIVATE ANTIVIRUS_APP_VERSION="${PROJECT_VERSION}")

    if(MSVC)
        target_compile_options(AntivirusGui PRIVATE /W4 /permissive- /utf-8)
    else()
        target_compile_options(AntivirusGui PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    install(TARGETS AntivirusGui RUNTIME DESTINATION bin)
endif()

if(WIN32 AND ANTIVIRUS_BUILD_WINUI)
    set(ANTIVIRUS_WINAPP_DIR "${CMAKE_CURRENT_SOURCE_DIR}/.winapp")
    set(ANTIVIRUS_WINAPP_INCLUDE_DIR "${ANTIVIRUS_WINAPP_DIR}/include")
    set(ANTIVIRUS_WINAPP_LIB_DIR "${ANTIVIRUS_WINAPP_DIR}/lib/x64")
    set(ANTIVIRUS_WINAPP_BIN_DIR "${ANTIVIRUS_WINAPP_DIR}/bin/x64")

    if(NOT EXISTS "${ANTIVIRUS_WINAPP_INCLUDE_DIR}/winrt/Microsoft.UI.Xaml.h")
        message(FATAL_ERROR "WinUI headers are missing. Run: npx --yes @microsoft/winappcli restore")
    endif()

    add_executable(AntivirusWinUi WIN32
        src/gui/ParentProcessCheck.cpp
        src/gui/ParentProcessCheck.h
        src/gui/ServiceClient.cpp
        src/gui/ServiceClient.h
        src/gui/SingleInstanceGuard.cpp
        src/gui/SingleInstanceGuard.h
        src/winui/main.cpp
        src/winui/RpcClientWin.cpp
        src/winui/RpcClientWin.h
    )

    set_target_properties(AntivirusWinUi PROPERTIES
        AUTOMOC OFF
        AUTORCC OFF
        AUTOUIC OFF
    )

    target_include_directories(AntivirusWinUi
        PRIVATE
            src
            "${ANTIVIRUS_WINAPP_INCLUDE_DIR}"
    )

    target_link_directories(AntivirusWinUi
        PRIVATE
            "${ANTIVIRUS_WINAPP_LIB_DIR}"
    )

    target_compile_definitions(AntivirusWinUi
        PRIVATE
            ANTIVIRUS_APP_VERSION="${PROJECT_VERSION}"
            UNICODE
            _UNICODE
            WIN32_LEAN_AND_MEAN
            NOMINMAX
    )

    target_link_libraries(AntivirusWinUi
        PRIVATE
            AntivirusCommon
            AntivirusRpcClient
            Microsoft.WindowsAppRuntime.Bootstrap
            Microsoft.WindowsAppRuntime
            Microsoft.UI.Dispatching
            DWriteCore
            WindowsApp
            RuntimeObject
            Advapi32
            Comctl32
            Comdlg32
            Credui
            Ole32
            Rpcrt4
            Shell32
    )

    if(MSVC)
        target_compile_options(AntivirusWinUi PRIVATE /W4 /permissive- /utf-8 /bigobj)
    else()
        target_compile_options(AntivirusWinUi PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_custom_command(TARGET AntivirusWinUi POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${ANTIVIRUS_WINAPP_BIN_DIR}/Microsoft.WindowsAppRuntime.Bootstrap.dll"
            "$<TARGET_FILE_DIR:AntivirusWinUi>"
        VERBATIM
    )

    install(TARGETS AntivirusWinUi RUNTIME DESTINATION bin)
    install(FILES
        "${ANTIVIRUS_WINAPP_BIN_DIR}/Microsoft.WindowsAppRuntime.Bootstrap.dll"
        DESTINATION bin
    )
endif()

if(WIN32)
    add_executable(AntivirusCtl
        src/tools/AntivirusCtl.cpp
        src/winui/RpcClientWin.cpp
        src/winui/RpcClientWin.h
    )

    target_include_directories(AntivirusCtl
        PRIVATE
            src
    )

    target_compile_definitions(AntivirusCtl
        PRIVATE
            UNICODE
            _UNICODE
            WIN32_LEAN_AND_MEAN
            NOMINMAX
    )

    target_link_libraries(AntivirusCtl
        PRIVATE
            AntivirusRpcClient
            Rpcrt4
    )

    if(MSVC)
        target_compile_options(AntivirusCtl PRIVATE /W4 /permissive- /utf-8)
    else()
        target_compile_options(AntivirusCtl PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    install(TARGETS AntivirusCtl RUNTIME DESTINATION bin)
endif()

if(ANTIVIRUS_BUILD_SERVICE)
    add_executable(AntivirusService
        src/service/ProcessLauncher.cpp
        src/service/ProcessLauncher.h
        src/service/AuthHttpClient.cpp
        src/service/AuthHttpClient.h
        src/service/AuthManager.cpp
        src/service/AuthManager.h
        src/service/FeatureGate.cpp
        src/service/FeatureGate.h
        src/service/LicenseManager.cpp
        src/service/LicenseManager.h
        src/service/RpcServer.cpp
        src/service/RpcServer.h
        src/service/ServiceMain.cpp
        src/service/ServiceMain.h
        src/service/SessionManager.cpp
        src/service/SessionManager.h
        src/service/scan/AvDatabase.cpp
        src/service/scan/AvDatabase.h
        src/service/scan/AvDatabaseStorage.cpp
        src/service/scan/AvDatabaseStorage.h
        src/service/scan/AvUpdateClient.cpp
        src/service/scan/AvUpdateClient.h
        src/service/scan/AhoCorasickScanner.cpp
        src/service/scan/AhoCorasickScanner.h
        src/service/scan/AvUpdateScheduler.cpp
        src/service/scan/AvUpdateScheduler.h
        src/service/scan/DirectoryMonitor.cpp
        src/service/scan/DirectoryMonitor.h
        src/service/scan/FileScanner.cpp
        src/service/scan/FileScanner.h
        src/service/scan/ScanEngine.cpp
        src/service/scan/ScanEngine.h
        src/service/main.cpp
    )

    target_link_libraries(AntivirusService
        PRIVATE
            AntivirusCommon
            AntivirusRpcServer
            Advapi32
            Rpcrt4
            Userenv
            Winhttp
            Wtsapi32
    )

    target_compile_definitions(AntivirusService PRIVATE ANTIVIRUS_APP_VERSION="${PROJECT_VERSION}")

    if(MSVC)
        target_compile_options(AntivirusService PRIVATE /W4 /permissive- /utf-8)
    else()
        target_compile_options(AntivirusService PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    install(TARGETS AntivirusService RUNTIME DESTINATION bin)
endif()

if(ANTIVIRUS_BUILD_TESTS)
    enable_testing()

    add_executable(AntivirusScanTests
        tests/ScanEngineTests.cpp
        src/common/logging.cpp
        src/common/logging.h
        src/service/scan/AvDatabase.cpp
        src/service/scan/AvDatabase.h
        src/service/scan/AvDatabaseStorage.cpp
        src/service/scan/AvDatabaseStorage.h
        src/service/scan/AvUpdateClient.cpp
        src/service/scan/AvUpdateClient.h
        src/service/scan/AhoCorasickScanner.cpp
        src/service/scan/AhoCorasickScanner.h
        src/service/scan/ScanEngine.cpp
        src/service/scan/ScanEngine.h
    )

    set_target_properties(AntivirusScanTests PROPERTIES
        AUTOMOC OFF
        AUTORCC OFF
        AUTOUIC OFF
    )

    target_include_directories(AntivirusScanTests
        PRIVATE
            src
    )

    target_compile_definitions(AntivirusScanTests
        PRIVATE
            UNICODE
            _UNICODE
            WIN32_LEAN_AND_MEAN
            NOMINMAX
    )

    if(MSVC)
        target_compile_options(AntivirusScanTests PRIVATE /W4 /permissive- /utf-8)
    else()
        target_compile_options(AntivirusScanTests PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(NAME AntivirusScanTests COMMAND AntivirusScanTests)
endif()

install(FILES README.md DESTINATION docx RENAME project-readme.md)
install(DIRECTORY docx/ DESTINATION docx)
install(DIRECTORY installer/ DESTINATION installer FILES_MATCHING PATTERN "*.ps1")
