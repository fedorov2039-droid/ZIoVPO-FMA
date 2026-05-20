#pragma once

#include <string>
#include <windows.h>

namespace antivirus::common {

std::string format_windows_error(DWORD error_code);
std::string format_last_error();

} // namespace antivirus::common
