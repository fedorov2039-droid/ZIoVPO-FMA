#include "gui/ServiceClient.h"

#include "common/logging.h"

#include <windows.h>
#include <winsvc.h>

namespace antivirus::gui {
namespace {

constexpr wchar_t kServiceName[] = L"AntivirusGuiService";

class ScmHandle final {
public:
    explicit ScmHandle(SC_HANDLE handle)
        : handle_(handle)
    {
    }

    ~ScmHandle()
    {
        if (handle_ != nullptr) {
            CloseServiceHandle(handle_);
        }
    }

    ScmHandle(const ScmHandle&) = delete;
    ScmHandle& operator=(const ScmHandle&) = delete;

    [[nodiscard]] SC_HANDLE get() const
    {
        return handle_;
    }

private:
    SC_HANDLE handle_ = nullptr;
};

bool queryServiceStatus(DWORD& state)
{
    ScmHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (scm.get() == nullptr) {
        return false;
    }

    ScmHandle service(OpenServiceW(scm.get(), kServiceName, SERVICE_QUERY_STATUS));
    if (service.get() == nullptr) {
        return false;
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD bytesNeeded = 0;
    if (!QueryServiceStatusEx(service.get(),
                              SC_STATUS_PROCESS_INFO,
                              reinterpret_cast<LPBYTE>(&status),
                              sizeof(status),
                              &bytesNeeded)) {
        return false;
    }

    state = status.dwCurrentState;
    return true;
}

} // namespace

bool ServiceClient::isInstalled() const
{
    ScmHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (scm.get() == nullptr) {
        return false;
    }

    ScmHandle service(OpenServiceW(scm.get(), kServiceName, SERVICE_QUERY_STATUS));
    return service.get() != nullptr;
}

bool ServiceClient::isRunning() const
{
    DWORD state = 0;
    return queryServiceStatus(state) && state == SERVICE_RUNNING;
}

bool ServiceClient::startService() const
{
    ScmHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (scm.get() == nullptr) {
        antivirus::common::log_error(L"OpenSCManagerW failed; administrator rights may be required");
        return false;
    }

    ScmHandle service(OpenServiceW(scm.get(), kServiceName, SERVICE_START | SERVICE_QUERY_STATUS));
    if (service.get() == nullptr) {
        antivirus::common::log_error(L"OpenServiceW failed for AntivirusGuiService");
        return false;
    }

    if (!StartServiceW(service.get(), 0, nullptr)) {
        const DWORD error = GetLastError();
        if (error != ERROR_SERVICE_ALREADY_RUNNING) {
            antivirus::common::log_error(L"StartServiceW failed for AntivirusGuiService");
            return false;
        }
    }

    return true;
}

bool ServiceClient::waitUntilRunning(unsigned timeoutMilliseconds) const
{
    const DWORD started = GetTickCount();
    for (;;) {
        DWORD state = 0;
        if (queryServiceStatus(state) && state == SERVICE_RUNNING) {
            return true;
        }

        if (GetTickCount() - started >= timeoutMilliseconds) {
            return false;
        }

        Sleep(250);
    }
}

} // namespace antivirus::gui
