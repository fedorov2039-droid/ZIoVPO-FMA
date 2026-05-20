#include "gui/ParentProcessCheck.h"

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <string>
#include <windows.h>
#include <tlhelp32.h>

namespace antivirus::gui {
namespace {

DWORD parentProcessId()
{
    const DWORD currentProcessId = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    DWORD parent = 0;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID == currentProcessId) {
                parent = entry.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return parent;
}

std::wstring processImageName(DWORD processId)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (process == nullptr) {
        return {};
    }

    std::wstring buffer(MAX_PATH, L'\0');
    DWORD size = static_cast<DWORD>(buffer.size());
    if (!QueryFullProcessImageNameW(process, 0, buffer.data(), &size)) {
        CloseHandle(process);
        return {};
    }

    CloseHandle(process);
    buffer.resize(size);
    return std::filesystem::path(buffer).filename().wstring();
}

std::wstring lower(std::wstring value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return value;
}

} // namespace

bool isParentProjectService()
{
    const DWORD parent = parentProcessId();
    if (parent == 0) {
        return false;
    }

    return lower(processImageName(parent)) == L"antivirusservice.exe";
}

} // namespace antivirus::gui
