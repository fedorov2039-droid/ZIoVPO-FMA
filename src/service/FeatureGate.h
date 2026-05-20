#pragma once

#include "service/AuthState.h"

namespace antivirus::service {

FeatureState computeFeatureState(const AuthState& authState, const LicenseState& licenseState);

} // namespace antivirus::service
