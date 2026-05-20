#pragma once

#include "service/AuthState.h"

#include <mutex>
#include <string>

namespace antivirus::service {

class LicenseManager final {
public:
    LicenseState state(bool authenticated) const;
    LicenseState activate(bool authenticated, std::wstring activationCode);
    void clear();

private:
    mutable std::mutex mutex_;
    LicenseState state_;
    std::wstring licenseProof_;
};

} // namespace antivirus::service
