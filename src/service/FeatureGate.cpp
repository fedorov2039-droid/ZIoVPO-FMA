#include "service/FeatureGate.h"

namespace antivirus::service {

FeatureState computeFeatureState(const AuthState& authState, const LicenseState& licenseState)
{
    if (!authState.authenticated) {
        return FeatureState{.enabled = false, .blockedReason = L"Требуется вход в аккаунт"};
    }

    if (!licenseState.active) {
        return FeatureState{.enabled = false, .blockedReason = L"Требуется активная лицензия"};
    }

    return FeatureState{.enabled = true, .blockedReason = L""};
}

} // namespace antivirus::service
