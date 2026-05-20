#include "service/ServiceMain.h"

#include "common/app_paths.h"
#include "common/logging.h"
#include "service/AuthManager.h"
#include "service/FeatureGate.h"
#include "service/LicenseManager.h"
#include "service/RpcServer.h"
#include "service/SessionManager.h"
#include "service/scan/AvDatabase.h"
#include "service/scan/FileScanner.h"

#include <sstream>
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

std::wstring pathOrEmpty(const wchar_t* path)
{
    return path != nullptr ? path : L"";
}

std::wstring buildFileScanDetails(const scan::FileScanReport& report)
{
    std::wstringstream stream;

    if (!report.result.error.empty()) {
        stream << L"Ошибка: " << report.result.error;
        return stream.str();
    }

    stream << L"Файл: " << report.path.wstring() << L"\n";
    stream << L"Тип объекта: " << report.result.objectType << L"\n";

    if (report.result.malicious) {
        stream << L"Результат: обнаружена угроза\n";
        stream << L"Угроза: " << report.result.threatName << L"\n";
        stream << L"Смещение: " << report.result.detectionOffset;
    } else {
        stream << L"Результат: угроз не обнаружено";
    }

    return stream.str();
}

std::wstring buildDirectoryScanDetails(const scan::DirectoryScanReport& report)
{
    std::wstringstream stream;

    if (!report.error.empty()) {
        stream << L"Ошибка: " << report.error;
        return stream.str();
    }

    stream << L"Просканировано файлов: " << report.scannedFiles << L"\n";
    stream << L"Обнаружено угроз: " << report.maliciousFiles;

    std::size_t shown = 0;
    for (const scan::FileScanReport& detection : report.detections) {
        if (shown >= 20) {
            stream << L"\n... список обнаружений сокращен";
            break;
        }

        stream << L"\n\nФайл: " << detection.path.wstring();
        stream << L"\nУгроза: " << detection.result.threatName;
        stream << L"\nСмещение: " << detection.result.detectionOffset;
        ++shown;
    }

    return stream.str();
}

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

    AuthState authState() const
    {
        return authManager_.state();
    }

    AuthState login(const wchar_t* login, const wchar_t* password)
    {
        return authManager_.login(login != nullptr ? login : L"", password != nullptr ? password : L"");
    }

    AuthState logout()
    {
        const AuthState state = authManager_.logout();
        licenseManager_.clear();
        database_.clear();
        return state;
    }

    LicenseState licenseState() const
    {
        return licenseManager_.state(authManager_.state().authenticated);
    }

    LicenseState activate(const wchar_t* activationCode)
    {
        LicenseState state = licenseManager_.activate(authManager_.state().authenticated, activationCode != nullptr ? activationCode : L"");
        if (state.active) {
            database_.loadDemoDatabase();
            antivirus::common::log_info(L"Antivirus database loaded after successful activation");
        }

        return state;
    }

    FeatureState featureState() const
    {
        const AuthState auth = authManager_.state();
        return computeFeatureState(auth, licenseManager_.state(auth.authenticated));
    }

    DatabaseInfo databaseInfo() const
    {
        DatabaseInfo info;
        info.loaded = database_.loaded();
        info.releaseDate = database_.releaseDate();
        info.recordCount = database_.recordCount();

        if (!info.loaded) {
            info.lastError = L"Antivirus database is not loaded";
        }

        return info;
    }

    RpcScanResult scanFile(const wchar_t* path)
    {
        RpcScanResult result;
        result.scannedPath = pathOrEmpty(path);

        const FeatureState feature = featureState();
        if (!feature.enabled) {
            result.lastError = feature.blockedReason.empty() ? L"Feature is blocked" : feature.blockedReason;
            result.details = result.lastError;
            return result;
        }

        if (!database_.loaded()) {
            result.lastError = L"Antivirus database is not loaded";
            result.details = result.lastError;
            return result;
        }

        const scan::FileScanReport report = scanner_.scanFile(result.scannedPath, database_);

        result.scanned = report.result.scanned;
        result.malicious = report.result.malicious;
        result.scannedPath = report.path.wstring();
        result.threatName = report.result.threatName;
        result.objectType = report.result.objectType;
        result.detectionOffset = report.result.detectionOffset;
        result.details = buildFileScanDetails(report);
        result.lastError = report.result.error;

        return result;
    }

    RpcScanResult scanDirectory(const wchar_t* path)
    {
        RpcScanResult result;
        result.scannedPath = pathOrEmpty(path);

        const FeatureState feature = featureState();
        if (!feature.enabled) {
            result.lastError = feature.blockedReason.empty() ? L"Feature is blocked" : feature.blockedReason;
            result.details = result.lastError;
            return result;
        }

        if (!database_.loaded()) {
            result.lastError = L"Antivirus database is not loaded";
            result.details = result.lastError;
            return result;
        }

        const scan::DirectoryScanReport report = scanner_.scanDirectory(result.scannedPath, database_);

        result.scanned = report.error.empty();
        result.malicious = report.maliciousFiles > 0;
        result.scannedFiles = report.scannedFiles;
        result.maliciousFiles = report.maliciousFiles;
        result.details = buildDirectoryScanDetails(report);
        result.lastError = report.error;

        if (!report.detections.empty()) {
            const scan::FileScanReport& firstDetection = report.detections.front();
            result.scannedPath = firstDetection.path.wstring();
            result.threatName = firstDetection.result.threatName;
            result.objectType = firstDetection.result.objectType;
            result.detectionOffset = firstDetection.result.detectionOffset;
        }

        return result;
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
    AuthManager authManager_;
    LicenseManager licenseManager_;
    scan::AvDatabase database_;
    scan::FileScanner scanner_;
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

AuthState queryAuthStateFromRpc()
{
    if (g_runtime == nullptr) {
        return AuthState{.lastError = L"Service runtime unavailable"};
    }

    return g_runtime->authState();
}

AuthState loginFromRpc(const wchar_t* login, const wchar_t* password)
{
    if (g_runtime == nullptr) {
        return AuthState{.lastError = L"Service runtime unavailable"};
    }

    return g_runtime->login(login, password);
}

AuthState logoutFromRpc()
{
    if (g_runtime == nullptr) {
        return AuthState{.lastError = L"Service runtime unavailable"};
    }

    return g_runtime->logout();
}

LicenseState queryLicenseStateFromRpc()
{
    if (g_runtime == nullptr) {
        return LicenseState{.lastError = L"Service runtime unavailable"};
    }

    return g_runtime->licenseState();
}

LicenseState activateFromRpc(const wchar_t* activationCode)
{
    if (g_runtime == nullptr) {
        return LicenseState{.lastError = L"Service runtime unavailable"};
    }

    return g_runtime->activate(activationCode);
}

FeatureState queryFeatureStateFromRpc()
{
    if (g_runtime == nullptr) {
        return FeatureState{.enabled = false, .blockedReason = L"Service runtime unavailable"};
    }

    return g_runtime->featureState();
}

DatabaseInfo queryDatabaseInfoFromRpc()
{
    if (g_runtime == nullptr) {
        return DatabaseInfo{.lastError = L"Service runtime unavailable"};
    }

    return g_runtime->databaseInfo();
}

RpcScanResult scanFileFromRpc(const wchar_t* path)
{
    if (g_runtime == nullptr) {
        return RpcScanResult{.scannedPath = pathOrEmpty(path), .lastError = L"Service runtime unavailable"};
    }

    return g_runtime->scanFile(path);
}

RpcScanResult scanDirectoryFromRpc(const wchar_t* path)
{
    if (g_runtime == nullptr) {
        return RpcScanResult{.scannedPath = pathOrEmpty(path), .lastError = L"Service runtime unavailable"};
    }

    return g_runtime->scanDirectory(path);
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
