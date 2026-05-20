#pragma once

#include <QString>

namespace antivirus::gui {

struct AuthState {
    bool authenticated = false;
    QString displayName;
    QString login;
    QString lastError;
};

struct LicenseState {
    bool licenseActive = false;
    QString licenseExpiresAt;
    bool activationRequired = true;
    QString featureBlockedReason;
    QString lastError;
};

struct FeatureState {
    bool functionalityEnabled = false;
    QString blockedReason;
};

struct DatabaseInfo {
    bool loaded = false;
    QString releaseDate;
    unsigned long recordCount = 0;
    QString lastError;
};

struct ScanResult {
    bool scanned = false;
    bool malicious = false;
    QString scannedPath;
    QString threatName;
    QString objectType;
    unsigned long detectionOffset = 0;
    unsigned long scannedFiles = 0;
    unsigned long maliciousFiles = 0;
    QString details;
    QString lastError;
};

class RpcClient final {
public:
    bool ping() const;
    bool requestServiceStop() const;
    long serviceStatus() const;
    AuthState authState() const;
    AuthState login(const QString& login, const QString& password) const;
    AuthState logout() const;
    LicenseState licenseState() const;
    LicenseState activateProduct(const QString& activationCode) const;
    FeatureState featureState() const;

    DatabaseInfo databaseInfo() const;
    ScanResult scanFile(const QString& path) const;
    ScanResult scanDirectory(const QString& path) const;
};

} // namespace antivirus::gui
