#include "common/win_error.h"

#include <string>
#include <stringapiset.h>

namespace antivirus::common {
namespace {

std::string narrow_from_wide(const std::wstring& value)
{
    if (value.empty()) {
        return {};
    }

    const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        return {};
    }

    std::string result(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size, nullptr, nullptr);
    return result;
}

} // namespace

std::string format_windows_error(DWORD error_code)
{
    wchar_t* buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD length = FormatMessageW(flags,
                                       nullptr,
                                       error_code,
                                       MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                       reinterpret_cast<wchar_t*>(&buffer),
                                       0,
                                       nullptr);

    if (length == 0 || buffer == nullptr) {
        return "Windows error " + std::to_string(error_code);
    }

    std::wstring message(buffer, length);
    LocalFree(buffer);

    while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n' || message.back() == L' ')) {
        message.pop_back();
    }

    return narrow_from_wide(message) + " (" + std::to_string(error_code) + ")";
}

std::string format_last_error()
{
    return format_windows_error(GetLastError());
}

} // namespace antivirus::common
