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
};

} // namespace antivirus::gui
