#include "common/logging.h"

#include <windows.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>

namespace antivirus::common {
namespace {

std::mutex& log_mutex() {
    static std::mutex mutex;
    return mutex;
}

std::wstring_view level_name(LogLevel level) {
    switch (level) {
    case LogLevel::Info:
        return L"INFO";
    case LogLevel::Warning:
        return L"WARN";
    case LogLevel::Error:
        return L"ERROR";
    }

    return L"UNKNOWN";
}

std::filesystem::path log_directory() {
    wchar_t programData[MAX_PATH]{};

    const DWORD length = GetEnvironmentVariableW(
        L"ProgramData",
        programData,
        MAX_PATH
    );

    std::filesystem::path dir;

    if (length > 0 && length < MAX_PATH) {
        dir = std::filesystem::path(programData) / L"AntivirusGui";
    } else {
        dir = std::filesystem::temp_directory_path() / L"AntivirusGui";
    }

    std::error_code ec;
    std::filesystem::create_directories(dir, ec);

    return dir;
}

std::filesystem::path log_file_path() {
    return log_directory() / L"service.log";
}

std::wstring timestamp() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t tt = std::chrono::system_clock::to_time_t(now);

    std::tm localTime{};
    localtime_s(&localTime, &tt);

    std::wostringstream out;
    out << std::put_time(&localTime, L"%Y-%m-%d %H:%M:%S");

    return out.str();
}

void write_file_log(const std::wstring& line) {
    try {
        std::wofstream file(log_file_path(), std::ios::app);
        file << line;
    } catch (...) {
        // Logging must never crash the application or the service.
    }
}

} // namespace

void log_message(LogLevel level, std::wstring_view message) {
    const std::wstring line =
        L"[" + timestamp() + L"] "
        L"[AntivirusGui] ["
        + std::wstring(level_name(level))
        + L"] "
        + std::wstring(message)
        + L"\n";

    std::lock_guard<std::mutex> lock(log_mutex());

    OutputDebugStringW(line.c_str());
    std::wcerr << line;
    write_file_log(line);
}

void log_info(std::wstring_view message) {
    log_message(LogLevel::Info, message);
}

void log_warning(std::wstring_view message) {
    log_message(LogLevel::Warning, message);
}

void log_error(std::wstring_view message) {
    log_message(LogLevel::Error, message);
}

} // namespace antivirus::common