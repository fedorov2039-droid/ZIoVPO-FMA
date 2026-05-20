#include "winui/RpcClientWin.h"

#include "AntivirusRpc.h"

#include <rpc.h>

namespace antivirus::winui {
namespace {

constexpr wchar_t kRpcProtocol[] = L"ncalrpc";
constexpr wchar_t kRpcEndpoint[] = L"AntivirusGuiRpc";
constexpr unsigned long kRpcOk = RPC_S_OK;

std::wstring rpcUnavailableMessage()
{
    return L"RPC недоступен: служба не запущена или endpoint не зарегистрирован";
}

std::wstring rpcExceptionMessage(unsigned long code)
{
    return L"RPC недоступен, код ошибки: " + std::to_wstring(code);
}

class RpcBinding final {
public:
    RpcBinding()
    {
        RPC_WSTR stringBinding = nullptr;
        RPC_STATUS status = RpcStringBindingComposeW(nullptr,
                                                    reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcProtocol)),
                                                    nullptr,
                                                    reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)),
                                                    nullptr,
                                                    &stringBinding);
        if (status != RPC_S_OK) {
            return;
        }

        status = RpcBindingFromStringBindingW(stringBinding, &binding_);
        RpcStringFreeW(&stringBinding);
        if (status != RPC_S_OK) {
            binding_ = nullptr;
        }
    }

    ~RpcBinding()
    {
        if (binding_ != nullptr) {
            RpcBindingFree(&binding_);
        }
    }

    RpcBinding(const RpcBinding&) = delete;
    RpcBinding& operator=(const RpcBinding&) = delete;

    [[nodiscard]] handle_t get() const
    {
        return binding_;
    }

private:
    handle_t binding_ = nullptr;
};

bool callPing(handle_t binding, long& result, unsigned long& exceptionCode)
{
    exceptionCode = kRpcOk;
    RpcTryExcept
    {
        AvPing(binding, &result);
    }
    RpcExcept(1)
    {
        exceptionCode = RpcExceptionCode();
    }
    RpcEndExcept

    return exceptionCode == kRpcOk;
}

bool callRequestServiceStop(handle_t binding, long& result, unsigned long& exceptionCode)
{
    exceptionCode = kRpcOk;
    RpcTryExcept
    {
        AvRequestServiceStop(binding, &result);
    }
    RpcExcept(1)
    {
        exceptionCode = RpcExceptionCode();
    }
    RpcEndExcept

    return exceptionCode == kRpcOk;
}

bool callGetServiceStatus(handle_t binding, long& status, unsigned long& exceptionCode)
{
    exceptionCode = kRpcOk;
    RpcTryExcept
    {
        AvGetServiceStatus(binding, &status);
    }
    RpcExcept(1)
    {
        exceptionCode = RpcExceptionCode();
    }
    RpcEndExcept

    return exceptionCode == kRpcOk;
}

bool callGetAuthState(handle_t binding, AvAuthState& state, unsigned long& exceptionCode)
{
    exceptionCode = kRpcOk;
    RpcTryExcept
    {
        AvGetAuthState(binding, &state);
    }
    RpcExcept(1)
    {
        exceptionCode = RpcExceptionCode();
    }
    RpcEndExcept

    return exceptionCode == kRpcOk;
}

bool callLogin(handle_t binding,
               const wchar_t* login,
               const wchar_t* password,
               AvAuthState& state,
               unsigned long& exceptionCode)
{
    exceptionCode = kRpcOk;
    RpcTryExcept
    {
        AvLogin(binding, login, password, &state);
    }
    RpcExcept(1)
    {
        exceptionCode = RpcExceptionCode();
    }
    RpcEndExcept

    return exceptionCode == kRpcOk;
}

bool callLogout(handle_t binding, AvAuthState& state, unsigned long& exceptionCode)
{
    exceptionCode = kRpcOk;
    RpcTryExcept
    {
        AvLogout(binding, &state);
    }
    RpcExcept(1)
    {
        exceptionCode = RpcExceptionCode();
    }
    RpcEndExcept

    return exceptionCode == kRpcOk;
}

bool callGetLicenseState(handle_t binding, AvLicenseState& state, unsigned long& exceptionCode)
{
    exceptionCode = kRpcOk;
    RpcTryExcept
    {
        AvGetLicenseState(binding, &state);
    }
    RpcExcept(1)
    {
        exceptionCode = RpcExceptionCode();
    }
    RpcEndExcept

    return exceptionCode == kRpcOk;
}

bool callActivateProduct(handle_t binding,
                         const wchar_t* activationCode,
                         AvLicenseState& state,
                         unsigned long& exceptionCode)
{
    exceptionCode = kRpcOk;
    RpcTryExcept
    {
        AvActivateProduct(binding, activationCode, &state);
    }
    RpcExcept(1)
    {
        exceptionCode = RpcExceptionCode();
    }
    RpcEndExcept

    return exceptionCode == kRpcOk;
}

bool callGetFeatureState(handle_t binding, AvFeatureState& state, unsigned long& exceptionCode)
{
    exceptionCode = kRpcOk;
    RpcTryExcept
    {
        AvGetFeatureState(binding, &state);
    }
    RpcExcept(1)
    {
        exceptionCode = RpcExceptionCode();
    }
    RpcEndExcept

    return exceptionCode == kRpcOk;
}

bool callGetDatabaseInfo(handle_t binding, AvDatabaseInfo& info, unsigned long& exceptionCode)
{
    exceptionCode = kRpcOk;
    RpcTryExcept
    {
        AvGetDatabaseInfo(binding, &info);
    }
    RpcExcept(1)
    {
        exceptionCode = RpcExceptionCode();
    }
    RpcEndExcept

    return exceptionCode == kRpcOk;
}

bool callScanFile(handle_t binding,
                  const wchar_t* path,
                  AvScanResult& result,
                  unsigned long& exceptionCode)
{
    exceptionCode = kRpcOk;
    RpcTryExcept
    {
        AvScanFile(binding, path, &result);
    }
    RpcExcept(1)
    {
        exceptionCode = RpcExceptionCode();
    }
    RpcEndExcept

    return exceptionCode == kRpcOk;
}

bool callScanDirectory(handle_t binding,
                       const wchar_t* path,
                       AvScanResult& result,
                       unsigned long& exceptionCode)
{
    exceptionCode = kRpcOk;
    RpcTryExcept
    {
        AvScanDirectory(binding, path, &result);
    }
    RpcExcept(1)
    {
        exceptionCode = RpcExceptionCode();
    }
    RpcEndExcept

    return exceptionCode == kRpcOk;
}

bool callScanFixedDrives(handle_t binding, AvScanResult& result, unsigned long& exceptionCode)
{
    exceptionCode = kRpcOk;
    RpcTryExcept
    {
        AvScanFixedDrives(binding, &result);
    }
    RpcExcept(1)
    {
        exceptionCode = RpcExceptionCode();
    }
    RpcEndExcept

    return exceptionCode == kRpcOk;
}

bool callStartDirectoryMonitor(handle_t binding,
                               const wchar_t* path,
                               AvDirectoryMonitorStatus& status,
                               unsigned long& exceptionCode)
{
    exceptionCode = kRpcOk;
    RpcTryExcept
    {
        AvStartDirectoryMonitor(binding, path, &status);
    }
    RpcExcept(1)
    {
        exceptionCode = RpcExceptionCode();
    }
    RpcEndExcept

    return exceptionCode == kRpcOk;
}

bool callStopDirectoryMonitor(handle_t binding,
                              AvDirectoryMonitorStatus& status,
                              unsigned long& exceptionCode)
{
    exceptionCode = kRpcOk;
    RpcTryExcept
    {
        AvStopDirectoryMonitor(binding, &status);
    }
    RpcExcept(1)
    {
        exceptionCode = RpcExceptionCode();
    }
    RpcEndExcept

    return exceptionCode == kRpcOk;
}

bool callGetDirectoryMonitorStatus(handle_t binding,
                                   AvDirectoryMonitorStatus& status,
                                   unsigned long& exceptionCode)
{
    exceptionCode = kRpcOk;
    RpcTryExcept
    {
        AvGetDirectoryMonitorStatus(binding, &status);
    }
    RpcExcept(1)
    {
        exceptionCode = RpcExceptionCode();
    }
    RpcEndExcept

    return exceptionCode == kRpcOk;
}

bool callStartScanSchedule(handle_t binding,
                           long targetType,
                           const wchar_t* path,
                           unsigned long intervalSeconds,
                           AvScanScheduleStatus& status,
                           unsigned long& exceptionCode)
{
    exceptionCode = kRpcOk;
    RpcTryExcept
    {
        AvStartScanSchedule(binding, targetType, path, intervalSeconds, &status);
    }
    RpcExcept(1)
    {
        exceptionCode = RpcExceptionCode();
    }
    RpcEndExcept

    return exceptionCode == kRpcOk;
}

bool callStopScanSchedule(handle_t binding, AvScanScheduleStatus& status, unsigned long& exceptionCode)
{
    exceptionCode = kRpcOk;
    RpcTryExcept
    {
        AvStopScanSchedule(binding, &status);
    }
    RpcExcept(1)
    {
        exceptionCode = RpcExceptionCode();
    }
    RpcEndExcept

    return exceptionCode == kRpcOk;
}

bool callGetScanScheduleStatus(handle_t binding, AvScanScheduleStatus& status, unsigned long& exceptionCode)
{
    exceptionCode = kRpcOk;
    RpcTryExcept
    {
        AvGetScanScheduleStatus(binding, &status);
    }
    RpcExcept(1)
    {
        exceptionCode = RpcExceptionCode();
    }
    RpcEndExcept

    return exceptionCode == kRpcOk;
}

AuthState convertAuthState(const AvAuthState& state)
{
    return AuthState{
        .authenticated = state.authenticated != 0,
        .displayName = state.displayName,
        .login = state.login,
        .lastError = state.lastError,
    };
}

LicenseState convertLicenseState(const AvLicenseState& state)
{
    return LicenseState{
        .licenseActive = state.licenseActive != 0,
        .licenseExpiresAt = state.licenseExpiresAt,
        .activationRequired = state.activationRequired != 0,
        .featureBlockedReason = state.featureBlockedReason,
        .lastError = state.lastError,
    };
}

FeatureState convertFeatureState(const AvFeatureState& state)
{
    return FeatureState{
        .functionalityEnabled = state.functionalityEnabled != 0,
        .blockedReason = state.blockedReason,
    };
}

DatabaseInfo convertDatabaseInfo(const AvDatabaseInfo& info)
{
    return DatabaseInfo{
        .loaded = info.databaseLoaded != 0,
        .releaseDate = info.releaseDate,
        .recordCount = info.recordCount,
        .lastError = info.lastError,
    };
}

ScanResult convertScanResult(const AvScanResult& result)
{
    return ScanResult{
        .scanned = result.scanned != 0,
        .malicious = result.malicious != 0,
        .scannedPath = result.scannedPath,
        .threatName = result.threatName,
        .objectType = result.objectType,
        .detectionOffset = result.detectionOffset,
        .scannedFiles = result.scannedFiles,
        .maliciousFiles = result.maliciousFiles,
        .details = result.details,
        .lastError = result.lastError,
    };
}

DirectoryMonitorStatus convertDirectoryMonitorStatus(const AvDirectoryMonitorStatus& status)
{
    return DirectoryMonitorStatus{
        .running = status.running != 0,
        .path = status.path,
        .lastError = status.lastError,
    };
}

ScanScheduleStatus convertScanScheduleStatus(const AvScanScheduleStatus& status)
{
    return ScanScheduleStatus{
        .running = status.running != 0,
        .targetType = status.targetType,
        .path = status.path,
        .intervalSeconds = status.intervalSeconds,
        .lastRunAt = status.lastRunAt,
        .lastDetails = status.lastDetails,
        .lastError = status.lastError,
    };
}

} // namespace

bool RpcClientWin::ping() const
{
    RpcBinding binding;
    if (binding.get() == nullptr) {
        return false;
    }

    long result = 0;
    unsigned long exceptionCode = kRpcOk;
    return callPing(binding.get(), result, exceptionCode) && result == 1;
}

bool RpcClientWin::requestServiceStop() const
{
    RpcBinding binding;
    if (binding.get() == nullptr) {
        return false;
    }

    long result = 0;
    unsigned long exceptionCode = kRpcOk;
    return callRequestServiceStop(binding.get(), result, exceptionCode) && result == 1;
}

long RpcClientWin::serviceStatus() const
{
    RpcBinding binding;
    if (binding.get() == nullptr) {
        return 0;
    }

    long status = 0;
    unsigned long exceptionCode = kRpcOk;
    if (!callGetServiceStatus(binding.get(), status, exceptionCode)) {
        return 0;
    }

    return status;
}

AuthState RpcClientWin::authState() const
{
    RpcBinding binding;
    AvAuthState state{};
    if (binding.get() == nullptr) {
        return AuthState{.lastError = rpcUnavailableMessage()};
    }

    unsigned long exceptionCode = kRpcOk;
    if (!callGetAuthState(binding.get(), state, exceptionCode)) {
        return AuthState{.lastError = rpcExceptionMessage(exceptionCode)};
    }

    return convertAuthState(state);
}

AuthState RpcClientWin::login(const std::wstring& login, const std::wstring& password) const
{
    RpcBinding binding;
    AvAuthState state{};
    if (binding.get() == nullptr) {
        return AuthState{.lastError = rpcUnavailableMessage()};
    }

    unsigned long exceptionCode = kRpcOk;
    if (!callLogin(binding.get(), login.c_str(), password.c_str(), state, exceptionCode)) {
        return AuthState{.lastError = rpcExceptionMessage(exceptionCode)};
    }

    return convertAuthState(state);
}

AuthState RpcClientWin::logout() const
{
    RpcBinding binding;
    AvAuthState state{};
    if (binding.get() == nullptr) {
        return AuthState{.lastError = rpcUnavailableMessage()};
    }

    unsigned long exceptionCode = kRpcOk;
    if (!callLogout(binding.get(), state, exceptionCode)) {
        return AuthState{.lastError = rpcExceptionMessage(exceptionCode)};
    }

    return convertAuthState(state);
}

LicenseState RpcClientWin::licenseState() const
{
    RpcBinding binding;
    AvLicenseState state{};
    if (binding.get() == nullptr) {
        return LicenseState{.lastError = rpcUnavailableMessage()};
    }

    unsigned long exceptionCode = kRpcOk;
    if (!callGetLicenseState(binding.get(), state, exceptionCode)) {
        return LicenseState{.lastError = rpcExceptionMessage(exceptionCode)};
    }

    return convertLicenseState(state);
}

LicenseState RpcClientWin::activateProduct(const std::wstring& activationCode) const
{
    RpcBinding binding;
    AvLicenseState state{};
    if (binding.get() == nullptr) {
        return LicenseState{.lastError = rpcUnavailableMessage()};
    }

    unsigned long exceptionCode = kRpcOk;
    if (!callActivateProduct(binding.get(), activationCode.c_str(), state, exceptionCode)) {
        return LicenseState{.lastError = rpcExceptionMessage(exceptionCode)};
    }

    return convertLicenseState(state);
}

FeatureState RpcClientWin::featureState() const
{
    RpcBinding binding;
    AvFeatureState state{};
    if (binding.get() == nullptr) {
        return FeatureState{.blockedReason = rpcUnavailableMessage()};
    }

    unsigned long exceptionCode = kRpcOk;
    if (!callGetFeatureState(binding.get(), state, exceptionCode)) {
        return FeatureState{.blockedReason = rpcExceptionMessage(exceptionCode)};
    }

    return convertFeatureState(state);
}

DatabaseInfo RpcClientWin::databaseInfo() const
{
    RpcBinding binding;
    AvDatabaseInfo info{};
    if (binding.get() == nullptr) {
        return DatabaseInfo{.lastError = rpcUnavailableMessage()};
    }

    unsigned long exceptionCode = kRpcOk;
    if (!callGetDatabaseInfo(binding.get(), info, exceptionCode)) {
        return DatabaseInfo{.lastError = rpcExceptionMessage(exceptionCode)};
    }

    return convertDatabaseInfo(info);
}

ScanResult RpcClientWin::scanFile(const std::wstring& path) const
{
    RpcBinding binding;
    AvScanResult result{};
    if (binding.get() == nullptr) {
        return ScanResult{.scannedPath = path, .lastError = rpcUnavailableMessage()};
    }

    unsigned long exceptionCode = kRpcOk;
    if (!callScanFile(binding.get(), path.c_str(), result, exceptionCode)) {
        return ScanResult{.scannedPath = path, .lastError = rpcExceptionMessage(exceptionCode)};
    }

    return convertScanResult(result);
}

ScanResult RpcClientWin::scanDirectory(const std::wstring& path) const
{
    RpcBinding binding;
    AvScanResult result{};
    if (binding.get() == nullptr) {
        return ScanResult{.scannedPath = path, .lastError = rpcUnavailableMessage()};
    }

    unsigned long exceptionCode = kRpcOk;
    if (!callScanDirectory(binding.get(), path.c_str(), result, exceptionCode)) {
        return ScanResult{.scannedPath = path, .lastError = rpcExceptionMessage(exceptionCode)};
    }

    return convertScanResult(result);
}

ScanResult RpcClientWin::scanFixedDrives() const
{
    RpcBinding binding;
    AvScanResult result{};
    if (binding.get() == nullptr) {
        return ScanResult{.scannedPath = L"Все несъёмные диски", .lastError = rpcUnavailableMessage()};
    }

    unsigned long exceptionCode = kRpcOk;
    if (!callScanFixedDrives(binding.get(), result, exceptionCode)) {
        return ScanResult{.scannedPath = L"Все несъёмные диски", .lastError = rpcExceptionMessage(exceptionCode)};
    }

    return convertScanResult(result);
}

DirectoryMonitorStatus RpcClientWin::startDirectoryMonitor(const std::wstring& path) const
{
    RpcBinding binding;
    AvDirectoryMonitorStatus status{};
    if (binding.get() == nullptr) {
        return DirectoryMonitorStatus{.path = path, .lastError = rpcUnavailableMessage()};
    }

    unsigned long exceptionCode = kRpcOk;
    if (!callStartDirectoryMonitor(binding.get(), path.c_str(), status, exceptionCode)) {
        return DirectoryMonitorStatus{.path = path, .lastError = rpcExceptionMessage(exceptionCode)};
    }

    return convertDirectoryMonitorStatus(status);
}

DirectoryMonitorStatus RpcClientWin::stopDirectoryMonitor() const
{
    RpcBinding binding;
    AvDirectoryMonitorStatus status{};
    if (binding.get() == nullptr) {
        return DirectoryMonitorStatus{.lastError = rpcUnavailableMessage()};
    }

    unsigned long exceptionCode = kRpcOk;
    if (!callStopDirectoryMonitor(binding.get(), status, exceptionCode)) {
        return DirectoryMonitorStatus{.lastError = rpcExceptionMessage(exceptionCode)};
    }

    return convertDirectoryMonitorStatus(status);
}

DirectoryMonitorStatus RpcClientWin::directoryMonitorStatus() const
{
    RpcBinding binding;
    AvDirectoryMonitorStatus status{};
    if (binding.get() == nullptr) {
        return DirectoryMonitorStatus{.lastError = rpcUnavailableMessage()};
    }

    unsigned long exceptionCode = kRpcOk;
    if (!callGetDirectoryMonitorStatus(binding.get(), status, exceptionCode)) {
        return DirectoryMonitorStatus{.lastError = rpcExceptionMessage(exceptionCode)};
    }

    return convertDirectoryMonitorStatus(status);
}

ScanScheduleStatus RpcClientWin::startScanSchedule(long targetType, const std::wstring& path, unsigned long intervalSeconds) const
{
    RpcBinding binding;
    AvScanScheduleStatus status{};
    if (binding.get() == nullptr) {
        return ScanScheduleStatus{
            .targetType = targetType,
            .path = path,
            .intervalSeconds = intervalSeconds,
            .lastError = rpcUnavailableMessage(),
        };
    }

    unsigned long exceptionCode = kRpcOk;
    if (!callStartScanSchedule(binding.get(), targetType, path.c_str(), intervalSeconds, status, exceptionCode)) {
        return ScanScheduleStatus{
            .targetType = targetType,
            .path = path,
            .intervalSeconds = intervalSeconds,
            .lastError = rpcExceptionMessage(exceptionCode),
        };
    }

    return convertScanScheduleStatus(status);
}

ScanScheduleStatus RpcClientWin::stopScanSchedule() const
{
    RpcBinding binding;
    AvScanScheduleStatus status{};
    if (binding.get() == nullptr) {
        return ScanScheduleStatus{.lastError = rpcUnavailableMessage()};
    }

    unsigned long exceptionCode = kRpcOk;
    if (!callStopScanSchedule(binding.get(), status, exceptionCode)) {
        return ScanScheduleStatus{.lastError = rpcExceptionMessage(exceptionCode)};
    }

    return convertScanScheduleStatus(status);
}

ScanScheduleStatus RpcClientWin::scanScheduleStatus() const
{
    RpcBinding binding;
    AvScanScheduleStatus status{};
    if (binding.get() == nullptr) {
        return ScanScheduleStatus{.lastError = rpcUnavailableMessage()};
    }

    unsigned long exceptionCode = kRpcOk;
    if (!callGetScanScheduleStatus(binding.get(), status, exceptionCode)) {
        return ScanScheduleStatus{.lastError = rpcExceptionMessage(exceptionCode)};
    }

    return convertScanScheduleStatus(status);
}

} // namespace antivirus::winui
