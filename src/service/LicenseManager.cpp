#include "service/LicenseManager.h"

namespace antivirus::service {

LicenseState LicenseManager::state(bool authenticated) const
{
    std::lock_guard lock(mutex_);
    LicenseState result = state_;
    if (!authenticated) {
        result.active = false;
        result.activationRequired = true;
        result.blockedReason = L"Требуется вход в аккаунт";
    }
    return result;
}

LicenseState LicenseManager::activate(bool authenticated, std::wstring activationCode)
{
    std::lock_guard lock(mutex_);

    if (!authenticated) {
        state_.active = false;
        state_.activationRequired = true;
        state_.blockedReason = L"Сначала выполните вход";
        state_.lastError = L"Пользователь не аутентифицирован";
        return state_;
    }

    if (activationCode != L"DEMO-1234") {
        state_.active = false;
        state_.activationRequired = true;
        state_.blockedReason = L"Требуется активация";
        state_.lastError = L"Неверный код активации";
        licenseProof_.clear();
        return state_;
    }

    state_.active = true;
    state_.activationRequired = false;
    state_.expiresAt = L"2027-01-01";
    state_.blockedReason.clear();
    state_.lastError.clear();
    licenseProof_ = L"in-memory-license-proof";
    return state_;
}

void LicenseManager::clear()
{
    std::lock_guard lock(mutex_);
    state_ = LicenseState{};
    licenseProof_.clear();
}

} // namespace antivirus::service
