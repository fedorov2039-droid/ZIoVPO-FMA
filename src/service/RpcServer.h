#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace antivirus::service {

struct AuthState;
struct LicenseState;
struct FeatureState;

struct DatabaseInfo {
    bool loaded = false;
    std::wstring releaseDate;
    std::size_t recordCount = 0;
    std::wstring lastError;
};

struct DirectoryMonitorInfo {
    bool running = false;
    std::wstring path;
    std::wstring lastError;
};

struct ScanScheduleInfo {
    bool running = false;
    long targetType = 0;
    std::wstring path;
    std::uint32_t intervalSeconds = 0;
    std::wstring lastRunAt;
    std::wstring lastDetails;
    std::wstring lastError;
};

struct RpcScanResult {
    bool scanned = false;
    bool malicious = false;
    std::wstring scannedPath;
    std::wstring threatName;
    std::wstring objectType;
    std::uint64_t detectionOffset = 0;
    std::size_t scannedFiles = 0;
    std::size_t maliciousFiles = 0;
    std::wstring details;
    std::wstring lastError;
};

class RpcServer final {
public:
    bool start();
    void stop();

private:
    bool started_ = false;
};

void requestServiceStopFromRpc();
long queryServiceStateFromRpc();
AuthState queryAuthStateFromRpc();
AuthState loginFromRpc(const wchar_t* login, const wchar_t* password);
AuthState logoutFromRpc();
LicenseState queryLicenseStateFromRpc();
LicenseState activateFromRpc(const wchar_t* activationCode);
FeatureState queryFeatureStateFromRpc();

DatabaseInfo queryDatabaseInfoFromRpc();
RpcScanResult scanFileFromRpc(const wchar_t* path);
RpcScanResult scanDirectoryFromRpc(const wchar_t* path);
RpcScanResult scanFixedDrivesFromRpc();
DirectoryMonitorInfo startDirectoryMonitorFromRpc(const wchar_t* path);
DirectoryMonitorInfo stopDirectoryMonitorFromRpc();
DirectoryMonitorInfo queryDirectoryMonitorStatusFromRpc();
ScanScheduleInfo startScanScheduleFromRpc(long targetType, const wchar_t* path, std::uint32_t intervalSeconds);
ScanScheduleInfo stopScanScheduleFromRpc();
ScanScheduleInfo queryScanScheduleStatusFromRpc();

} // namespace antivirus::service
