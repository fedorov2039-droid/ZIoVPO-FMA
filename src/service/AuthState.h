#pragma once

#include <string>

namespace antivirus::service {

struct AuthState {
    bool authenticated = false;
    std::wstring displayName;
    std::wstring login;
    std::wstring lastError;
};

struct LicenseState {
    bool active = false;
    std::wstring expiresAt;
    bool activationRequired = true;
    std::wstring blockedReason = L"Требуется вход и активация";
    std::wstring lastError;
};

struct FeatureState {
    bool enabled = false;
    std::wstring blockedReason = L"Требуется вход и активация";
};

} // namespace antivirus::service
