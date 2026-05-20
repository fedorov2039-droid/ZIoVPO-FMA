#include "common/logging.h"

#include <iostream>
#include <string>
#include <windows.h>

namespace antivirus::common {
namespace {

std::wstring_view level_name(LogLevel level)
{
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

} // namespace

void log_message(LogLevel level, std::wstring_view message)
{
    const std::wstring line = L"[AntivirusGui] [" + std::wstring(level_name(level)) + L"] " + std::wstring(message) + L"\n";
    OutputDebugStringW(line.c_str());
    std::wcerr << line;
}

void log_info(std::wstring_view message)
{
    log_message(LogLevel::Info, message);
}

void log_warning(std::wstring_view message)
{
    log_message(LogLevel::Warning, message);
}

void log_error(std::wstring_view message)
{
    log_message(LogLevel::Error, message);
}

} // namespace antivirus::common
