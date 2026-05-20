cmake_minimum_required(VERSION 3.24)

project(
    AntivirusGuiProject
    VERSION 0.1.0
    DESCRIPTION "Educational Windows antivirus GUI scaffold"
    LANGUAGES CXX
)

option(ANTIVIRUS_BUILD_GUI "Build the Qt Widgets GUI application" ON)
option(ANTIVIRUS_BUILD_SERVICE "Build the Windows service executable" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(AntivirusCommon STATIC
    src/common/app_paths.cpp
    src/common/app_paths.h
    src/common/logging.cpp
    src/common/logging.h
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
    target_compile_options(AntivirusCommon PRIVATE /W4 /permissive-)
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
        src/gui/SingleInstanceGuard.cpp
        src/gui/SingleInstanceGuard.h
        src/gui/TrayController.cpp
        src/gui/TrayController.h
        src/gui/main.cpp
    )

    target_link_libraries(AntivirusGui
        PRIVATE
            AntivirusCommon
            Qt6::Widgets
    )

    target_compile_definitions(AntivirusGui PRIVATE ANTIVIRUS_APP_VERSION="${PROJECT_VERSION}")

    install(TARGETS AntivirusGui RUNTIME DESTINATION bin)
endif()

if(ANTIVIRUS_BUILD_SERVICE)
    add_executable(AntivirusService
        src/service/main.cpp
    )

    target_link_libraries(AntivirusService
        PRIVATE
            AntivirusCommon
    )

    target_compile_definitions(AntivirusService PRIVATE ANTIVIRUS_APP_VERSION="${PROJECT_VERSION}")

    if(MSVC)
        target_compile_options(AntivirusService PRIVATE /W4 /permissive-)
    else()
        target_compile_options(AntivirusService PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    install(TARGETS AntivirusService RUNTIME DESTINATION bin)
endif()

install(FILES README.md DESTINATION .)
install(DIRECTORY docs/ DESTINATION docs)
