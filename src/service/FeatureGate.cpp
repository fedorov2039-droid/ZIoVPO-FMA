#include "service/FeatureGate.h"

namespace antivirus::service {

FeatureState computeFeatureState(const AuthState& authState, const LicenseState& licenseState)
{
    if (!authState.authenticated) {
        return FeatureState{.enabled = false, .blockedReason = L"Требуется вход в аккаунт"};
    }

    if (!licenseState.active) {
        const std::wstring reason = licenseState.blockedReason.empty()
                                        ? L"Требуется активная лицензия"
                                        : licenseState.blockedReason;

        return FeatureState{.enabled = false, .blockedReason = reason};
    }

    return FeatureState{.enabled = true, .blockedReason = L""};
}

} // namespace antivirus::service