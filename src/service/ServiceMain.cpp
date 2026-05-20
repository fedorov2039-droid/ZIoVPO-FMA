#include "service/ServiceMain.h"

#include "common/app_paths.h"
#include "common/logging.h"
#include "service/AuthManager.h"
#include "service/FeatureGate.h"
#include "service/LicenseManager.h"
#include "service/RpcServer.h"
#include "service/SessionManager.h"
#include "service/scan/AvDatabaseStorage.h"
#include "service/scan/AvUpdateScheduler.h"
#include "service/scan/DirectoryMonitor.h"
#include "service/scan/FileScanner.h"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <windows.h>
#include <winsvc.h>
#include <wtsapi32.h>

namespace antivirus::service {
namespace {

constexpr wchar_t kServiceName[] = L"AntivirusGuiService";
constexpr wchar_t kServiceDisplayName[] = L"Antivirus GUI Service";
constexpr long kScheduleTargetFile = 1;
constexpr long kScheduleTargetDirectory = 2;
constexpr long kScheduleTargetFixedDrives = 3;
constexpr std::uint32_t kMinScheduleIntervalSeconds = 5;
constexpr std::uint32_t kMaxScheduleIntervalSeconds = 24 * 60 * 60;

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

std::uint32_t normalizeScheduleInterval(std::uint32_t intervalSeconds)
{
    if (intervalSeconds < kMinScheduleIntervalSeconds) {
        return kMinScheduleIntervalSeconds;
    }

    if (intervalSeconds > kMaxScheduleIntervalSeconds) {
        return kMaxScheduleIntervalSeconds;
    }

    return intervalSeconds;
}

std::wstring nowText()
{
    SYSTEMTIME time{};
    GetLocalTime(&time);

    wchar_t buffer[64]{};
    swprintf_s(buffer,
               L"%04u-%02u-%02u %02u:%02u:%02u",
               time.wYear,
               time.wMonth,
               time.wDay,
               time.wHour,
               time.wMinute,
               time.wSecond);
    return buffer;
}

std::wstring scheduleTargetName(long targetType)
{
    switch (targetType) {
    case kScheduleTargetFile:
        return L"файл";
    case kScheduleTargetDirectory:
        return L"папка";
    case kScheduleTargetFixedDrives:
        return L"все несъёмные диски";
    default:
        return L"неизвестная цель";
    }
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
            stream << L"\n... список обнаружений сокращён";
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

        loadDatabaseFromDisk();
        startDatabaseUpdateScheduler();

        if (!rpcServer_.start()) {
            updateScheduler_.stop();
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
        stopScanSchedule();
        directoryMonitor_.stop();
        updateScheduler_.stop();
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
        stopScanSchedule();
        directoryMonitor_.stop();

        {
            std::lock_guard lock(databaseMutex_);
            database_.clear();
        }

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
            loadDatabaseFromDisk();
            antivirus::common::log_info(L"Антивирусная база загружена после успешной активации");
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
        std::lock_guard lock(databaseMutex_);

        DatabaseInfo info;
        info.loaded = database_.loaded();
        info.releaseDate = database_.releaseDate();
        info.recordCount = database_.recordCount();

        if (!info.loaded) {
            info.lastError = L"Антивирусная база не загружена";
        }

        return info;
    }

    RpcScanResult scanFile(const wchar_t* path)
    {
        RpcScanResult result;
        result.scannedPath = pathOrEmpty(path);

        const FeatureState feature = featureState();
        if (!feature.enabled) {
            result.lastError = feature.blockedReason.empty() ? L"Функция заблокирована" : feature.blockedReason;
            result.details = result.lastError;
            return result;
        }

        std::lock_guard lock(databaseMutex_);

        if (!database_.loaded()) {
            result.lastError = L"Антивирусная база не загружена";
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
            result.lastError = feature.blockedReason.empty() ? L"Функция заблокирована" : feature.blockedReason;
            result.details = result.lastError;
            return result;
        }

        std::lock_guard lock(databaseMutex_);

        if (!database_.loaded()) {
            result.lastError = L"Антивирусная база не загружена";
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

    RpcScanResult scanFixedDrives()
    {
        RpcScanResult result;
        result.scannedPath = L"Все несъёмные диски";

        const FeatureState feature = featureState();
        if (!feature.enabled) {
            result.lastError = feature.blockedReason.empty() ? L"Функция заблокирована" : feature.blockedReason;
            result.details = result.lastError;
            return result;
        }

        std::lock_guard lock(databaseMutex_);

        if (!database_.loaded()) {
            result.lastError = L"Антивирусная база не загружена";
            result.details = result.lastError;
            return result;
        }

        const DWORD driveMask = GetLogicalDrives();
        if (driveMask == 0) {
            result.lastError = L"Не удалось перечислить логические диски";
            result.details = result.lastError;
            return result;
        }

        std::wstringstream stream;
        stream << L"Цель сканирования: все несъёмные диски";

        bool scannedAnyDrive = false;
        bool firstDetectionCaptured = false;

        for (wchar_t letter = L'A'; letter <= L'Z'; ++letter) {
            const DWORD bit = 1u << (letter - L'A');
            if ((driveMask & bit) == 0) {
                continue;
            }

            wchar_t root[] = {letter, L':', L'\\', L'\0'};
            if (GetDriveTypeW(root) != DRIVE_FIXED) {
                continue;
            }

            scannedAnyDrive = true;
            stream << L"\n\nДиск: " << root;

            const scan::DirectoryScanReport report = scanner_.scanDirectory(root, database_);

            if (!report.error.empty()) {
                stream << L"\nОшибка: " << report.error;
                continue;
            }

            result.scannedFiles += report.scannedFiles;
            result.maliciousFiles += report.maliciousFiles;

            stream << L"\nПросканировано файлов: " << report.scannedFiles;
            stream << L"\nОбнаружено угроз: " << report.maliciousFiles;

            if (!report.detections.empty() && !firstDetectionCaptured) {
                const scan::FileScanReport& firstDetection = report.detections.front();
                result.scannedPath = firstDetection.path.wstring();
                result.threatName = firstDetection.result.threatName;
                result.objectType = firstDetection.result.objectType;
                result.detectionOffset = firstDetection.result.detectionOffset;
                firstDetectionCaptured = true;
            }

            std::size_t shown = 0;
            for (const scan::FileScanReport& detection : report.detections) {
                if (shown >= 20) {
                    stream << L"\n... список обнаружений сокращён";
                    break;
                }

                stream << L"\nУгроза: " << detection.result.threatName;
                stream << L"\nФайл: " << detection.path.wstring();
                stream << L"\nСмещение: " << detection.result.detectionOffset;
                ++shown;
            }
        }

        if (!scannedAnyDrive) {
            result.lastError = L"Несъёмные диски не найдены";
            result.details = result.lastError;
            return result;
        }

        result.scanned = true;
        result.malicious = result.maliciousFiles > 0;
        result.details = stream.str();

        return result;
    }

    DirectoryMonitorInfo startDirectoryMonitor(const wchar_t* path)
    {
        DirectoryMonitorInfo info;
        info.path = pathOrEmpty(path);

        const FeatureState feature = featureState();
        if (!feature.enabled) {
            directoryMonitor_.stop();
            info.lastError = feature.blockedReason.empty() ? L"Функция заблокирована" : feature.blockedReason;
            return info;
        }

        {
            std::lock_guard lock(databaseMutex_);
            if (!database_.loaded()) {
                info.lastError = L"Антивирусная база не загружена";
                return info;
            }
        }

        const std::filesystem::path monitorPath(info.path);
        const bool started = directoryMonitor_.start(monitorPath, [this](const std::filesystem::path& changedPath) {
            scanMonitoredFile(changedPath);
        });

        if (started) {
            antivirus::common::log_info(L"Мониторинг директории запущен: " + monitorPath.wstring());
        }

        return monitorInfo();
    }

    DirectoryMonitorInfo stopDirectoryMonitor()
    {
        const scan::DirectoryMonitorStatus beforeStop = directoryMonitor_.status();
        directoryMonitor_.stop();
        if (beforeStop.running) {
            antivirus::common::log_info(L"Мониторинг директории остановлен");
        }
        return monitorInfo();
    }

    DirectoryMonitorInfo monitorInfo() const
    {
        const scan::DirectoryMonitorStatus status = directoryMonitor_.status();
        return DirectoryMonitorInfo{
            .running = status.running,
            .path = status.path.wstring(),
            .lastError = status.lastError,
        };
    }

    ScanScheduleInfo startScanSchedule(long targetType, const wchar_t* path, std::uint32_t intervalSeconds)
    {
        ScanScheduleInfo info;
        info.targetType = targetType;
        info.path = pathOrEmpty(path);
        info.intervalSeconds = normalizeScheduleInterval(intervalSeconds);

        const FeatureState feature = featureState();
        if (!feature.enabled) {
            info.lastError = feature.blockedReason.empty() ? L"Функция заблокирована" : feature.blockedReason;
            return info;
        }

        if ((targetType == kScheduleTargetFile || targetType == kScheduleTargetDirectory) && info.path.empty()) {
            info.lastError = L"Для расписания нужно выбрать путь";
            return info;
        }

        if (targetType != kScheduleTargetFile
            && targetType != kScheduleTargetDirectory
            && targetType != kScheduleTargetFixedDrives) {
            info.lastError = L"Неизвестный тип расписания сканирования";
            return info;
        }

        {
            std::lock_guard lock(databaseMutex_);
            if (!database_.loaded()) {
                info.lastError = L"Антивирусная база не загружена";
                return info;
            }
        }

        {
            std::lock_guard controlLock(scheduleControlMutex_);
            stopScanScheduleUnlocked();

            {
                std::lock_guard lock(scheduleMutex_);
                scheduleStopRequested_ = false;
                lastScheduleLogText_.clear();
                scheduleInfo_ = info;
                scheduleInfo_.running = true;
                scheduleInfo_.lastError.clear();
                scheduleInfo_.lastDetails = L"Ожидание первого запуска по расписанию";
            }

            scheduleThread_ = std::thread(
                &ServiceRuntime::scanScheduleLoop,
                this,
                targetType,
                info.path,
                info.intervalSeconds);
        }

        antivirus::common::log_info(
            L"Запущено сканирование по расписанию: " + scheduleTargetName(targetType)
            + L", интервал " + std::to_wstring(info.intervalSeconds) + L" сек.");
        return scanScheduleInfo();
    }

    ScanScheduleInfo stopScanSchedule()
    {
        std::lock_guard controlLock(scheduleControlMutex_);
        return stopScanScheduleUnlocked();
    }

    ScanScheduleInfo scanScheduleInfo() const
    {
        std::lock_guard lock(scheduleMutex_);
        return scheduleInfo_;
    }

private:
    ScanScheduleInfo stopScanScheduleUnlocked()
    {
        {
            std::lock_guard lock(scheduleMutex_);
            scheduleStopRequested_ = true;
        }
        scheduleCv_.notify_all();

        if (scheduleThread_.joinable()) {
            scheduleThread_.join();
        }

        std::lock_guard lock(scheduleMutex_);
        scheduleInfo_.running = false;
        return scheduleInfo_;
    }
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

    void loadDatabaseFromDisk()
    {
        const scan::AvDatabaseLoadResult loadResult = databaseStorage_.loadOrRecover();
        applyDatabaseLoadResult(loadResult);

        for (const std::wstring& event : loadResult.events) {
            antivirus::common::log_info(event);
        }

        bool messageAlreadyLogged = false;
        for (const std::wstring& event : loadResult.events) {
            if (event == loadResult.message) {
                messageAlreadyLogged = true;
                break;
            }
        }

        if (loadResult.loaded) {
            if (!loadResult.message.empty() && !messageAlreadyLogged) {
                antivirus::common::log_info(loadResult.message);
            }
        } else {
            antivirus::common::log_error(L"Не удалось загрузить антивирусную базу с диска");
            if (!loadResult.message.empty() && !messageAlreadyLogged) {
                antivirus::common::log_error(loadResult.message);
            }
        }
    }

    void applyDatabaseLoadResult(const scan::AvDatabaseLoadResult& loadResult)
    {
        std::lock_guard lock(databaseMutex_);

        if (loadResult.loaded) {
            database_.loadRecords(loadResult.releaseDate, loadResult.records);
            return;
        }

        database_.loadDemoDatabase();
    }

    void startDatabaseUpdateScheduler()
    {
        updateScheduler_.start([this](const scan::AvUpdateResult& result) {
            for (const std::wstring& event : result.loadResult.events) {
                antivirus::common::log_info(event);
            }

            if (result.loadResult.loaded) {
                applyDatabaseLoadResult(result.loadResult);
                antivirus::common::log_info(result.message);
                if (result.loadResult.message != result.message) {
                    antivirus::common::log_info(result.loadResult.message);
                }
            } else {
                antivirus::common::log_error(result.message);
                if (result.loadResult.message != result.message) {
                    antivirus::common::log_error(result.loadResult.message);
                }
            }
        });

        antivirus::common::log_info(L"Планировщик обновления антивирусных баз запущен");
    }

    void scanMonitoredFile(const std::filesystem::path& path)
    {
        const FeatureState feature = featureState();
        if (!feature.enabled) {
            antivirus::common::log_warning(L"Мониторинг пропустил сканирование: функции антивируса заблокированы");
            return;
        }

        std::lock_guard lock(databaseMutex_);
        if (!database_.loaded()) {
            antivirus::common::log_warning(L"Мониторинг пропустил сканирование: антивирусная база не загружена");
            return;
        }

        const scan::FileScanReport report = scanner_.scanFile(path, database_);

        std::wstringstream stream;
        stream << L"Мониторинг директории просканировал файл: " << path.wstring() << L"\n";
        stream << buildFileScanDetails(report);

        if (report.result.malicious) {
            antivirus::common::log_warning(stream.str());
        } else if (!report.result.error.empty()) {
            antivirus::common::log_warning(stream.str());
        } else {
            antivirus::common::log_info(stream.str());
        }
    }

    RpcScanResult runScheduledScan(long targetType, const std::wstring& path)
    {
        switch (targetType) {
        case kScheduleTargetFile:
            return scanFile(path.c_str());
        case kScheduleTargetDirectory:
            return scanDirectory(path.c_str());
        case kScheduleTargetFixedDrives:
            return scanFixedDrives();
        default:
            return RpcScanResult{.lastError = L"Неизвестный тип расписания сканирования"};
        }
    }

    void scanScheduleLoop(long targetType, std::wstring path, std::uint32_t intervalSeconds)
    {
        for (;;) {
            {
                std::lock_guard lock(scheduleMutex_);
                if (scheduleStopRequested_) {
                    scheduleInfo_.running = false;
                    return;
                }
            }

            const RpcScanResult result = runScheduledScan(targetType, path);

            {
                std::lock_guard lock(scheduleMutex_);
                scheduleInfo_.running = true;
                scheduleInfo_.lastRunAt = nowText();
                scheduleInfo_.lastDetails = result.details.empty() ? result.lastError : result.details;
                scheduleInfo_.lastError = result.lastError;
            }

            const std::wstring logText =
                L"Результат сканирования по расписанию (" + scheduleTargetName(targetType) + L"):\n"
                + (result.details.empty() ? result.lastError : result.details);

            if (logText != lastScheduleLogText_) {
                lastScheduleLogText_ = logText;
                if (result.malicious || !result.lastError.empty()) {
                    antivirus::common::log_warning(logText);
                } else {
                    antivirus::common::log_info(logText);
                }
            }

            std::unique_lock lock(scheduleMutex_);
            if (scheduleCv_.wait_for(lock, std::chrono::seconds(intervalSeconds), [this]() {
                    return scheduleStopRequested_;
                })) {
                scheduleInfo_.running = false;
                return;
            }
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

    mutable std::mutex databaseMutex_;
    scan::AvDatabase database_;
    scan::AvDatabaseStorage databaseStorage_;
    scan::AvUpdateScheduler updateScheduler_;
    scan::DirectoryMonitor directoryMonitor_;
    scan::FileScanner scanner_;

    mutable std::mutex scheduleControlMutex_;
    mutable std::mutex scheduleMutex_;
    std::condition_variable scheduleCv_;
    std::thread scheduleThread_;
    bool scheduleStopRequested_ = false;
    std::wstring lastScheduleLogText_;
    ScanScheduleInfo scheduleInfo_;
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
        return AuthState{.lastError = L"Служба недоступна"};
    }

    return g_runtime->authState();
}

AuthState loginFromRpc(const wchar_t* login, const wchar_t* password)
{
    if (g_runtime == nullptr) {
        return AuthState{.lastError = L"Служба недоступна"};
    }

    return g_runtime->login(login, password);
}

AuthState logoutFromRpc()
{
    if (g_runtime == nullptr) {
        return AuthState{.lastError = L"Служба недоступна"};
    }

    return g_runtime->logout();
}

LicenseState queryLicenseStateFromRpc()
{
    if (g_runtime == nullptr) {
        return LicenseState{.lastError = L"Служба недоступна"};
    }

    return g_runtime->licenseState();
}

LicenseState activateFromRpc(const wchar_t* activationCode)
{
    if (g_runtime == nullptr) {
        return LicenseState{.lastError = L"Служба недоступна"};
    }

    return g_runtime->activate(activationCode);
}

FeatureState queryFeatureStateFromRpc()
{
    if (g_runtime == nullptr) {
        return FeatureState{.enabled = false, .blockedReason = L"Служба недоступна"};
    }

    return g_runtime->featureState();
}

DatabaseInfo queryDatabaseInfoFromRpc()
{
    if (g_runtime == nullptr) {
        return DatabaseInfo{.lastError = L"Служба недоступна"};
    }

    return g_runtime->databaseInfo();
}

RpcScanResult scanFileFromRpc(const wchar_t* path)
{
    if (g_runtime == nullptr) {
        return RpcScanResult{.scannedPath = pathOrEmpty(path), .lastError = L"Служба недоступна"};
    }

    return g_runtime->scanFile(path);
}

RpcScanResult scanDirectoryFromRpc(const wchar_t* path)
{
    if (g_runtime == nullptr) {
        return RpcScanResult{.scannedPath = pathOrEmpty(path), .lastError = L"Служба недоступна"};
    }

    return g_runtime->scanDirectory(path);
}

RpcScanResult scanFixedDrivesFromRpc()
{
    if (g_runtime == nullptr) {
        return RpcScanResult{.scannedPath = L"Все несъёмные диски", .lastError = L"Служба недоступна"};
    }

    return g_runtime->scanFixedDrives();
}

DirectoryMonitorInfo startDirectoryMonitorFromRpc(const wchar_t* path)
{
    if (g_runtime == nullptr) {
        return DirectoryMonitorInfo{.path = pathOrEmpty(path), .lastError = L"Служба недоступна"};
    }

    return g_runtime->startDirectoryMonitor(path);
}

DirectoryMonitorInfo stopDirectoryMonitorFromRpc()
{
    if (g_runtime == nullptr) {
        return DirectoryMonitorInfo{.lastError = L"Служба недоступна"};
    }

    return g_runtime->stopDirectoryMonitor();
}

DirectoryMonitorInfo queryDirectoryMonitorStatusFromRpc()
{
    if (g_runtime == nullptr) {
        return DirectoryMonitorInfo{.lastError = L"Служба недоступна"};
    }

    return g_runtime->monitorInfo();
}

ScanScheduleInfo startScanScheduleFromRpc(long targetType, const wchar_t* path, std::uint32_t intervalSeconds)
{
    if (g_runtime == nullptr) {
        return ScanScheduleInfo{
            .targetType = targetType,
            .path = pathOrEmpty(path),
            .intervalSeconds = intervalSeconds,
            .lastError = L"Служба недоступна",
        };
    }

    return g_runtime->startScanSchedule(targetType, path, intervalSeconds);
}

ScanScheduleInfo stopScanScheduleFromRpc()
{
    if (g_runtime == nullptr) {
        return ScanScheduleInfo{.lastError = L"Служба недоступна"};
    }

    return g_runtime->stopScanSchedule();
}

ScanScheduleInfo queryScanScheduleStatusFromRpc()
{
    if (g_runtime == nullptr) {
        return ScanScheduleInfo{.lastError = L"Служба недоступна"};
    }

    return g_runtime->scanScheduleInfo();
}

int installService()
{
    ServiceHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE));
    if (scm.get() == nullptr) {
        antivirus::common::log_error(L"OpenSCManagerW не выполнен; запустите от имени администратора");
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
        antivirus::common::log_error(L"CreateServiceW завершился ошибкой");
        return 1;
    }

    return 0;
}

int uninstallService()
{
    ServiceHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (scm.get() == nullptr) {
        antivirus::common::log_error(L"OpenSCManagerW не выполнен; запустите от имени администратора");
        return 1;
    }

    ServiceHandle service(OpenServiceW(scm.get(), kServiceName, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS));
    if (service.get() == nullptr) {
        antivirus::common::log_error(L"OpenServiceW завершился ошибкой");
        return 1;
    }

    SERVICE_STATUS status{};
    ControlService(service.get(), SERVICE_CONTROL_STOP, &status);

    if (!DeleteService(service.get())) {
        antivirus::common::log_error(L"DeleteService завершился ошибкой");
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
        antivirus::common::log_error(L"StartServiceCtrlDispatcherW завершился ошибкой");
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
