#include "gui/ParentProcessCheck.h"

#include "common/logging.h"
#include "common/win_error.h"

#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <string>
#include <string_view>

namespace antivirus::gui {
namespace {

constexpr wchar_t kServiceName[] = L"AntivirusGuiService";

std::wstring widenUtf8(std::string_view value) {
    if (value.empty()) {
        return {};
    }

    const int required = MultiByteToWideChar(
        CP_UTF8,
        0,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0
    );

    if (required <= 0) {
        return {};
    }

    std::wstring result(static_cast<std::size_t>(required), L'\0');

    const int written = MultiByteToWideChar(
        CP_UTF8,
        0,
        value.data(),
        static_cast<int>(value.size()),
        result.data(),
        required
    );

    if (written <= 0) {
        return {};
    }

    return result;
}

std::wstring windowsErrorMessage(DWORD errorCode) {
    std::wstring message = widenUtf8(antivirus::common::format_windows_error(errorCode));

    if (message.empty()) {
        message = L"Windows error " + std::to_wstring(errorCode);
    }

    return message;
}

void logWinApiFailure(std::wstring_view operation, DWORD errorCode) {
    antivirus::common::log_warning(
        std::wstring(operation) + L": " + windowsErrorMessage(errorCode)
    );
}

class SnapshotHandle final {
public:
    explicit SnapshotHandle(HANDLE handle = INVALID_HANDLE_VALUE) noexcept
        : handle_(handle) {
    }

    ~SnapshotHandle() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
    }

    SnapshotHandle(const SnapshotHandle&) = delete;
    SnapshotHandle& operator=(const SnapshotHandle&) = delete;

    [[nodiscard]] HANDLE get() const noexcept {
        return handle_;
    }

    [[nodiscard]] bool valid() const noexcept {
        return handle_ != INVALID_HANDLE_VALUE;
    }

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

class ServiceHandle final {
public:
    explicit ServiceHandle(SC_HANDLE handle = nullptr) noexcept
        : handle_(handle) {
    }

    ~ServiceHandle() {
        if (handle_ != nullptr) {
            CloseServiceHandle(handle_);
        }
    }

    ServiceHandle(const ServiceHandle&) = delete;
    ServiceHandle& operator=(const ServiceHandle&) = delete;

    [[nodiscard]] SC_HANDLE get() const noexcept {
        return handle_;
    }

    [[nodiscard]] bool valid() const noexcept {
        return handle_ != nullptr;
    }

private:
    SC_HANDLE handle_ = nullptr;
};

DWORD parentProcessId() {
    const DWORD currentProcessId = GetCurrentProcessId();

    SnapshotHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot.valid()) {
        logWinApiFailure(L"CreateToolhelp32Snapshot failed", GetLastError());
        return 0;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    DWORD parent = 0;

    if (Process32FirstW(snapshot.get(), &entry)) {
        do {
            if (entry.th32ProcessID == currentProcessId) {
                parent = entry.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snapshot.get(), &entry));
    } else {
        logWinApiFailure(L"Process32FirstW failed", GetLastError());
    }

    return parent;
}

DWORD serviceProcessIdFromScm() {
    ServiceHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.valid()) {
        logWinApiFailure(L"OpenSCManagerW failed in parent check", GetLastError());
        return 0;
    }

    ServiceHandle service(OpenServiceW(scm.get(), kServiceName, SERVICE_QUERY_STATUS));
    if (!service.valid()) {
        logWinApiFailure(L"OpenServiceW failed in parent check", GetLastError());
        return 0;
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD bytesNeeded = 0;

    if (!QueryServiceStatusEx(
            service.get(),
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status),
            sizeof(status),
            &bytesNeeded
        )) {
        logWinApiFailure(L"QueryServiceStatusEx failed in parent check", GetLastError());
        return 0;
    }

    if (status.dwCurrentState != SERVICE_RUNNING) {
        antivirus::common::log_warning(
            L"Parent check failed: service is not running, state="
            + std::to_wstring(status.dwCurrentState)
        );
        return 0;
    }

    return status.dwProcessId;
}

std::wstring processImageName(DWORD processId) {
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

std::wstring lower(std::wstring value) {
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](wchar_t ch) {
            return static_cast<wchar_t>(std::towlower(ch));
        }
    );

    return value;
}

bool fallbackParentNameCheck(DWORD parentPid) {
    if (parentPid == 0) {
        return false;
    }

    const std::wstring parentImage = lower(processImageName(parentPid));

    if (parentImage.empty()) {
        antivirus::common::log_warning(
            L"Parent name fallback failed: cannot query parent image"
        );
        return false;
    }

    const bool ok = parentImage == L"antivirusservice.exe";

    antivirus::common::log_warning(
        L"Parent name fallback result: parentPid="
        + std::to_wstring(parentPid)
        + L", image="
        + parentImage
        + L", ok="
        + std::wstring(ok ? L"true" : L"false")
    );

    return ok;
}

} // namespace

bool isParentProjectService() {
    const DWORD parentPid = parentProcessId();
    const DWORD servicePid = serviceProcessIdFromScm();

    antivirus::common::log_info(
        L"Parent process check: parentPid="
        + std::to_wstring(parentPid)
        + L", servicePid="
        + std::to_wstring(servicePid)
    );

    if (parentPid != 0 && servicePid != 0 && parentPid == servicePid) {
        antivirus::common::log_info(
            L"Parent process check passed by SCM service PID"
        );
        return true;
    }

    antivirus::common::log_warning(
        L"Parent process check by SCM PID failed"
    );

    return fallbackParentNameCheck(parentPid);
}

}