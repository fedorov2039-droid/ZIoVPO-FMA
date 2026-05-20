#include "service/ProcessLauncher.h"

#include "common/app_paths.h"
#include "common/logging.h"
#include "common/win_error.h"

#include <userenv.h>
#include <windows.h>
#include <wtsapi32.h>

#include <filesystem>
#include <string>
#include <string_view>

namespace {

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
        return L"";
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
        return L"";
    }

    return result;
}

std::wstring windowsErrorMessage(DWORD errorCode) {
    const std::string narrow = antivirus::common::format_windows_error(errorCode);
    std::wstring wide = widenUtf8(narrow);

    if (wide.empty()) {
        wide = L"Windows error " + std::to_wstring(errorCode);
    }

    return wide;
}

void logWinApiFailure(std::wstring_view operation, DWORD errorCode) {
    antivirus::common::log_warning(
        std::wstring(operation) + L": " + windowsErrorMessage(errorCode)
    );
}

class Handle final {
public:
    explicit Handle(HANDLE handle = nullptr) noexcept
        : handle_(handle) {
    }

    ~Handle() {
        reset();
    }

    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;

    Handle(Handle&& other) noexcept
        : handle_(other.release()) {
    }

    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    [[nodiscard]] HANDLE get() const noexcept {
        return handle_;
    }

    [[nodiscard]] bool valid() const noexcept {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

    HANDLE release() noexcept {
        HANDLE handle = handle_;
        handle_ = nullptr;
        return handle;
    }

    void reset(HANDLE handle = nullptr) noexcept {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
        handle_ = handle;
    }

private:
    HANDLE handle_ = nullptr;
};

class EnvironmentBlock final {
public:
    EnvironmentBlock() = default;

    ~EnvironmentBlock() {
        reset();
    }

    EnvironmentBlock(const EnvironmentBlock&) = delete;
    EnvironmentBlock& operator=(const EnvironmentBlock&) = delete;

    [[nodiscard]] void* get() const noexcept {
        return environment_;
    }

    [[nodiscard]] void** put() noexcept {
        reset();
        return &environment_;
    }

    void reset() noexcept {
        if (environment_ != nullptr) {
            DestroyEnvironmentBlock(environment_);
            environment_ = nullptr;
        }
    }

private:
    void* environment_ = nullptr;
};

std::wstring quotePath(const std::filesystem::path& path) {
    return L"\"" + path.wstring() + L"\"";
}

} // namespace

namespace antivirus::service {

bool ProcessLauncher::launchGuiInSession(DWORD sessionId, LaunchedProcess& launched) const {
    common::log_info(L"Preparing to launch GUI in session " + std::to_wstring(sessionId));

    HANDLE userTokenRaw = nullptr;
    if (!WTSQueryUserToken(sessionId, &userTokenRaw)) {
        const DWORD error = GetLastError();
        logWinApiFailure(
            L"WTSQueryUserToken failed for session " + std::to_wstring(sessionId),
            error
        );
        common::log_warning(
            L"WTSQueryUserToken requires the service process to run as LocalSystem"
        );
        return false;
    }

    Handle userToken(userTokenRaw);

    HANDLE primaryTokenRaw = nullptr;
    if (!DuplicateTokenEx(
            userToken.get(),
            TOKEN_ASSIGN_PRIMARY |
                TOKEN_DUPLICATE |
                TOKEN_QUERY |
                TOKEN_ADJUST_DEFAULT |
                TOKEN_ADJUST_SESSIONID,
            nullptr,
            SecurityImpersonation,
            TokenPrimary,
            &primaryTokenRaw
        )) {
        const DWORD error = GetLastError();
        logWinApiFailure(L"DuplicateTokenEx failed", error);
        return false;
    }

    Handle primaryToken(primaryTokenRaw);

    EnvironmentBlock environment;
    if (!CreateEnvironmentBlock(environment.put(), primaryToken.get(), FALSE)) {
        const DWORD error = GetLastError();
        logWinApiFailure(L"CreateEnvironmentBlock failed", error);
        return false;
    }

    const auto guiPath = common::executable_directory() / L"AntivirusGui.exe";
    const auto guiDir = guiPath.parent_path();

    common::log_info(L"GUI executable path: " + guiPath.wstring());
    common::log_info(L"GUI working directory: " + guiDir.wstring());

    std::error_code existsError;
    const bool guiExists = std::filesystem::exists(guiPath, existsError);

    if (!guiExists || existsError) {
        common::log_error(
            L"GUI executable does not exist or cannot be accessed: " + guiPath.wstring()
        );
        if (existsError) {
            common::log_error(
                L"std::filesystem::exists error: " + widenUtf8(existsError.message())
            );
        }
        return false;
    }

    std::wstring commandLine =
        quotePath(guiPath) + L" --hidden --service-child";

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

    PROCESS_INFORMATION processInfo{};

    common::log_info(L"CreateProcessAsUserW command line: " + commandLine);

    const BOOL created = CreateProcessAsUserW(
        primaryToken.get(),
        guiPath.c_str(),
        commandLine.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_UNICODE_ENVIRONMENT,
        environment.get(),
        guiDir.c_str(),
        &startup,
        &processInfo
    );

    if (!created) {
        const DWORD error = GetLastError();
        logWinApiFailure(L"CreateProcessAsUserW failed for GUI child", error);
        return false;
    }

    Handle threadHandle(processInfo.hThread);

    launched.processHandle = processInfo.hProcess;
    launched.processId = processInfo.dwProcessId;

    common::log_info(
        L"GUI child started successfully, pid=" + std::to_wstring(launched.processId)
    );

    return true;
}

} // namespace antivirus::service