#pragma once

#include <string>

namespace antivirus::winui {

constexpr long kScanScheduleFile = 1;
constexpr long kScanScheduleDirectory = 2;
constexpr long kScanScheduleFixedDrives = 3;

struct AuthState {
    bool authenticated = false;
    std::wstring displayName;
    std::wstring login;
    std::wstring lastError;
};

struct LicenseState {
    bool licenseActive = false;
    std::wstring licenseExpiresAt;
    bool activationRequired = true;
    std::wstring featureBlockedReason;
    std::wstring lastError;
};

struct FeatureState {
    bool functionalityEnabled = false;
    std::wstring blockedReason;
};

struct DatabaseInfo {
    bool loaded = false;
    std::wstring releaseDate;
    unsigned long recordCount = 0;
    std::wstring lastError;
};

struct ScanResult {
    bool scanned = false;
    bool malicious = false;
    std::wstring scannedPath;
    std::wstring threatName;
    std::wstring objectType;
    unsigned long detectionOffset = 0;
    unsigned long scannedFiles = 0;
    unsigned long maliciousFiles = 0;
    std::wstring details;
    std::wstring lastError;
};

struct DirectoryMonitorStatus {
    bool running = false;
    std::wstring path;
    std::wstring lastError;
};

struct ScanScheduleStatus {
    bool running = false;
    long targetType = 0;
    std::wstring path;
    unsigned long intervalSeconds = 0;
    std::wstring lastRunAt;
    std::wstring lastDetails;
    std::wstring lastError;
};

class RpcClientWin final {
public:
    bool ping() const;
    bool requestServiceStop() const;
    long serviceStatus() const;
    AuthState authState() const;
    AuthState login(const std::wstring& login, const std::wstring& password) const;
    AuthState logout() const;
    LicenseState licenseState() const;
    LicenseState activateProduct(const std::wstring& activationCode) const;
    FeatureState featureState() const;

    DatabaseInfo databaseInfo() const;
    ScanResult scanFile(const std::wstring& path) const;
    ScanResult scanDirectory(const std::wstring& path) const;
    ScanResult scanFixedDrives() const;
    DirectoryMonitorStatus startDirectoryMonitor(const std::wstring& path) const;
    DirectoryMonitorStatus stopDirectoryMonitor() const;
    DirectoryMonitorStatus directoryMonitorStatus() const;
    ScanScheduleStatus startScanSchedule(long targetType, const std::wstring& path, unsigned long intervalSeconds) const;
    ScanScheduleStatus stopScanSchedule() const;
    ScanScheduleStatus scanScheduleStatus() const;
};

} // namespace antivirus::winui
