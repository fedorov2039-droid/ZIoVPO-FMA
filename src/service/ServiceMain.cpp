#include "service/ServiceMain.h"

#include "common/app_paths.h"
#include "common/logging.h"
#include "service/RpcServer.h"
#include "service/SessionManager.h"

#include <string>
#include <windows.h>
#include <winsvc.h>
#include <wtsapi32.h>

namespace antivirus::service {
namespace {

constexpr wchar_t kServiceName[] = L"AntivirusGuiService";
constexpr wchar_t kServiceDisplayName[] = L"Antivirus GUI Service";

class ServiceRuntime;
ServiceRuntime* g_runtime = nullptr;

class ServiceHandle final {
public:
    explicit ServiceHandle(SC_HANDLE handle = nullptr)
        : handle_(handle)
    {
    }

    ~ServiceHandle()
    {
        if (handle_ != nullptr) {
            CloseServiceHandle(handle_);
        }
    }

    ServiceHandle(const ServiceHandle&) = delete;
    ServiceHandle& operator=(const ServiceHandle&) = delete;

    [[nodiscard]] SC_HANDLE get() const
    {
        return handle_;
    }

private:
    SC_HANDLE handle_ = nullptr;
};

class ServiceRuntime final {
public:
    int run(bool serviceMode)
    {
        serviceMode_ = serviceMode;
        stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (stopEvent_ == nullptr) {
            return 1;
        }

        g_runtime = this;

        setStatus(SERVICE_START_PENDING);

        if (!rpcServer_.start()) {
            setStatus(SERVICE_STOPPED);
            CloseHandle(stopEvent_);
            stopEvent_ = nullptr;
            g_runtime = nullptr;
            return 1;
        }

        setStatus(SERVICE_RUNNING);
        sessionManager_.launchGuiForExistingSessions();
        WaitForSingleObject(stopEvent_, INFINITE);

        setStatus(SERVICE_STOP_PENDING);
        sessionManager_.stopAllGuiChildren();
        rpcServer_.stop();
        setStatus(SERVICE_STOPPED);

        CloseHandle(stopEvent_);
        stopEvent_ = nullptr;
        g_runtime = nullptr;
        return 0;
    }

    void requestStop()
    {
        if (stopEvent_ != nullptr) {
            SetEvent(stopEvent_);
        }
    }

    long currentState() const
    {
        return static_cast<long>(status_.dwCurrentState);
    }

    void setStatusHandle(SERVICE_STATUS_HANDLE statusHandle)
    {
        statusHandle_ = statusHandle;
    }

    DWORD control(DWORD controlCode, DWORD eventType, void* eventData)
    {
        if (controlCode == SERVICE_CONTROL_SESSIONCHANGE) {
            if (eventType == WTS_SESSION_LOGON || eventType == WTS_CONSOLE_CONNECT || eventType == WTS_REMOTE_CONNECT) {
                const auto* notification = static_cast<WTSSESSION_NOTIFICATION*>(eventData);
                if (notification != nullptr) {
                    sessionManager_.launchGuiForSession(notification->dwSessionId);
                }
            }
            return NO_ERROR;
        }

        return NO_ERROR;
    }

private:
    void setStatus(DWORD state)
    {
        status_.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        status_.dwCurrentState = state;
        status_.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_SESSIONCHANGE : 0;
        status_.dwWin32ExitCode = NO_ERROR;
        status_.dwServiceSpecificExitCode = 0;
        status_.dwCheckPoint = 0;
        status_.dwWaitHint = 0;

        if (serviceMode_ && statusHandle_ != nullptr) {
            SetServiceStatus(statusHandle_, &status_);
        }
    }

    bool serviceMode_ = false;
    SERVICE_STATUS_HANDLE statusHandle_ = nullptr;
    SERVICE_STATUS status_{};
    HANDLE stopEvent_ = nullptr;
    RpcServer rpcServer_;
    SessionManager sessionManager_;
};

DWORD WINAPI serviceControlHandler(DWORD controlCode, DWORD eventType, void* eventData, void*)
{
    if (g_runtime == nullptr) {
        return NO_ERROR;
    }

    return g_runtime->control(controlCode, eventType, eventData);
}

void WINAPI serviceMain(DWORD, LPWSTR*)
{
    ServiceRuntime runtime;
    const SERVICE_STATUS_HANDLE statusHandle = RegisterServiceCtrlHandlerExW(kServiceName, serviceControlHandler, nullptr);
    if (statusHandle == nullptr) {
        return;
    }

    runtime.setStatusHandle(statusHandle);
    runtime.run(true);
}

} // namespace

void requestServiceStopFromRpc()
{
    if (g_runtime != nullptr) {
        g_runtime->requestStop();
    }
}

long queryServiceStateFromRpc()
{
    if (g_runtime == nullptr) {
        return SERVICE_STOPPED;
    }

    return g_runtime->currentState();
}

int installService()
{
    ServiceHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE));
    if (scm.get() == nullptr) {
        antivirus::common::log_error(L"OpenSCManagerW failed; run as administrator");
        return 1;
    }

    const auto servicePath = antivirus::common::executable_path();
    const std::wstring command = L"\"" + servicePath.wstring() + L"\" --run-service";

    ServiceHandle service(CreateServiceW(scm.get(),
                                         kServiceName,
                                         kServiceDisplayName,
                                         SERVICE_ALL_ACCESS,
                                         SERVICE_WIN32_OWN_PROCESS,
                                         SERVICE_AUTO_START,
                                         SERVICE_ERROR_NORMAL,
                                         command.c_str(),
                                         nullptr,
                                         nullptr,
                                         nullptr,
                                         nullptr,
                                         nullptr));
    if (service.get() == nullptr) {
        antivirus::common::log_error(L"CreateServiceW failed");
        return 1;
    }

    return 0;
}

int uninstallService()
{
    ServiceHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (scm.get() == nullptr) {
        antivirus::common::log_error(L"OpenSCManagerW failed; run as administrator");
        return 1;
    }

    ServiceHandle service(OpenServiceW(scm.get(), kServiceName, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS));
    if (service.get() == nullptr) {
        antivirus::common::log_error(L"OpenServiceW failed");
        return 1;
    }

    SERVICE_STATUS status{};
    ControlService(service.get(), SERVICE_CONTROL_STOP, &status);

    if (!DeleteService(service.get())) {
        antivirus::common::log_error(L"DeleteService failed");
        return 1;
    }

    return 0;
}

int runService()
{
    SERVICE_TABLE_ENTRYW table[] = {
        {const_cast<wchar_t*>(kServiceName), serviceMain},
        {nullptr, nullptr},
    };

    if (!StartServiceCtrlDispatcherW(table)) {
        antivirus::common::log_error(L"StartServiceCtrlDispatcherW failed");
        return 1;
    }

    return 0;
}

int runConsole()
{
    ServiceRuntime runtime;
    return runtime.run(false);
}

} // namespace antivirus::service
