#include "common/app_paths.h"

#include "common/win_error.h"

#include <array>
#include <stdexcept>
#include <string>
#include <windows.h>

namespace antivirus::common {
namespace {

std::wstring read_executable_path()
{
    std::array<wchar_t, MAX_PATH> initial_buffer{};
    const DWORD initial_size = GetModuleFileNameW(nullptr, initial_buffer.data(), static_cast<DWORD>(initial_buffer.size()));

    if (initial_size == 0) {
        throw std::runtime_error("GetModuleFileNameW failed: " + format_last_error());
    }

    if (initial_size < initial_buffer.size()) {
        return std::wstring(initial_buffer.data(), initial_size);
    }

    std::wstring dynamic_buffer(initial_buffer.size() * 2, L'\0');
    for (;;) {
        const DWORD size = GetModuleFileNameW(nullptr, dynamic_buffer.data(), static_cast<DWORD>(dynamic_buffer.size()));
        if (size == 0) {
            throw std::runtime_error("GetModuleFileNameW failed: " + format_last_error());
        }

        if (size < dynamic_buffer.size()) {
            dynamic_buffer.resize(size);
            return dynamic_buffer;
        }

        dynamic_buffer.resize(dynamic_buffer.size() * 2);
    }
}

} // namespace

std::filesystem::path executable_path()
{
    return std::filesystem::path(read_executable_path());
}

std::filesystem::path executable_directory()
{
    return executable_path().parent_path();
}

} // namespace antivirus::common
