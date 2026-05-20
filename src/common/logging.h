#pragma once

#include <string_view>

namespace antivirus::common {

enum class LogLevel {
    Info,
    Warning,
    Error,
};

void log_message(LogLevel level, std::wstring_view message);
void log_info(std::wstring_view message);
void log_warning(std::wstring_view message);
void log_error(std::wstring_view message);
void start_new_log_session(std::wstring_view sessionName);

} // namespace antivirus::common
