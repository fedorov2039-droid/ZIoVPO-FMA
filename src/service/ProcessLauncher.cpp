#include "service/ProcessLauncher.h"

#include "common/app_paths.h"
#include "common/logging.h"

#include <string>
#include <userenv.h>
#include <wtsapi32.h>

namespace antivirus::service {
namespace {

class Handle final {
public:
    explicit Handle(HANDLE handle = nullptr)
        : handle_(handle)
    {
    }

    ~Handle()
    {
        if (handle_ != nullptr) {
            CloseHandle(handle_);
        }
    }

    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;

    [[nodiscard]] HANDLE get() const
    {
        return handle_;
    }

    HANDLE release()
    {
        HANDLE handle = handle_;
        handle_ = nullptr;
        return handle;
    }

private:
    HANDLE handle_ = nullptr;
};

} // namespace

bool ProcessLauncher::launchGuiInSession(DWORD sessionId, LaunchedProcess& launched) const
{
    HANDLE userTokenRaw = nullptr;
    if (!WTSQueryUserToken(sessionId, &userTokenRaw)) {
        antivirus::common::log_warning(L"WTSQueryUserToken failed; service must run as LocalSystem");
        return false;
    }
    Handle userToken(userTokenRaw);

    HANDLE primaryTokenRaw = nullptr;
    if (!DuplicateTokenEx(userToken.get(),
                          TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
                          nullptr,
                          SecurityImpersonation,
                          TokenPrimary,
                          &primaryTokenRaw)) {
        antivirus::common::log_warning(L"DuplicateTokenEx failed");
        return false;
    }
    Handle primaryToken(primaryTokenRaw);

    void* environment = nullptr;
    if (!CreateEnvironmentBlock(&environment, primaryToken.get(), FALSE)) {
        antivirus::common::log_warning(L"CreateEnvironmentBlock failed");
        return false;
    }

    const auto guiPath = antivirus::common::executable_directory() / L"AntivirusGui.exe";
    std::wstring commandLine = L"\"" + guiPath.wstring() + L"\" --hidden --service-child";

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.lpDesktop = const_cast<wchar_t*>(L"winsta0\\default");

    PROCESS_INFORMATION processInfo{};
    const BOOL created = CreateProcessAsUserW(primaryToken.get(),
                                              guiPath.c_str(),
                                              commandLine.data(),
                                              nullptr,
                                              nullptr,
                                              FALSE,
                                              CREATE_UNICODE_ENVIRONMENT,
                                              environment,
                                              guiPath.parent_path().c_str(),
                                              &startup,
                                              &processInfo);
    DestroyEnvironmentBlock(environment);

    if (!created) {
        antivirus::common::log_warning(L"CreateProcessAsUserW failed for GUI child");
        return false;
    }

    CloseHandle(processInfo.hThread);
    launched.processHandle = processInfo.hProcess;
    launched.processId = processInfo.dwProcessId;
    return true;
}

} // namespace antivirus::service
