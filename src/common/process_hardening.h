#pragma once

#include <Windows.h>

#include <string_view>

namespace antivirus::common {

bool hardenCurrentProcessForDemo(std::wstring_view componentName, bool protectFromAdministrators);

bool hardenProcessHandleForDemo(HANDLE processHandle, std::wstring_view componentName, bool protectFromAdministrators);

} // namespace antivirus::common