#include "service/LicenseManager.h"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

namespace antivirus::service {
namespace {

constexpr wchar_t kValidActivationCode[] = L"DEMO-1234";
constexpr wchar_t kActiveLicenseExpiresAt[] = L"2027-01-01";
constexpr wchar_t kExpiredLicenseDate[] = L"2024-01-01";

std::filesystem::path mockServerLicenseStatusPath()
{
    wchar_t* programDataRaw = nullptr;
    std::size_t programDataLength = 0;
    _wdupenv_s(&programDataRaw, &programDataLength, L"ProgramData");

    std::filesystem::path programData = L"C:\\ProgramData";
    if (programDataRaw != nullptr && programDataLength > 0) {
        programData = programDataRaw;
    }

    std::free(programDataRaw);

    return programData / L"AntivirusGuiMockServer" / L"license-status.txt";
}

std::string normalizeServerStatus(std::string value)
{
    value.erase(std::remove(value.begin(), value.end(), '\r'), value.end());
    value.erase(std::remove(value.begin(), value.end(), '\n'), value.end());
    value.erase(std::remove(value.begin(), value.end(), ' '), value.end());
    value.erase(std::remove(value.begin(), value.end(), '\t'), value.end());

    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });

    return value;
}

std::string readMockServerLicenseStatus()
{
    const std::filesystem::path path = mockServerLicenseStatusPath();

    std::ifstream file(path);
    if (!file.is_open()) {
        return "active";
    }

    std::string value;
    std::getline(file, value);

    value = normalizeServerStatus(value);
    if (value.empty()) {
        return "active";
    }

    return value;
}

LicenseState applyMockServerState(const LicenseState& source)
{
    LicenseState result = source;

    if (!result.active) {
        return result;
    }

    const std::string serverStatus = readMockServerLicenseStatus();

    if (serverStatus == "expired") {
        result.active = false;
        result.activationRequired = false;
        result.expiresAt = kExpiredLicenseDate;
        result.blockedReason = L"Лицензия истекла";
        result.lastError.clear();
        return result;
    }

    if (serverStatus == "revoked" || serverStatus == "blocked") {
        result.active = false;
        result.activationRequired = true;
        result.blockedReason = L"Лицензия отозвана сервером";
        result.lastError.clear();
        return result;
    }

    result.active = true;
    result.activationRequired = false;
    result.expiresAt = kActiveLicenseExpiresAt;
    result.blockedReason.clear();
    result.lastError.clear();

    return result;
}

} // namespace

LicenseState LicenseManager::state(bool authenticated) const
{
    std::lock_guard lock(mutex_);

    LicenseState result = state_;

    if (!authenticated) {
        result.active = false;
        result.activationRequired = true;
        result.blockedReason = L"Требуется вход в аккаунт";
        return result;
    }

    return applyMockServerState(result);
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

    if (activationCode != kValidActivationCode) {
        state_.active = false;
        state_.activationRequired = true;
        state_.blockedReason = L"Требуется активация";
        state_.lastError = L"Неверный код активации";
        licenseProof_.clear();
        return state_;
    }

    state_.active = true;
    state_.activationRequired = false;
    state_.expiresAt = kActiveLicenseExpiresAt;
    state_.blockedReason.clear();
    state_.lastError.clear();

    licenseProof_ = L"in-memory-license-proof";

    return applyMockServerState(state_);
}

void LicenseManager::clear()
{
    std::lock_guard lock(mutex_);
    state_ = LicenseState{};
    licenseProof_.clear();
}

} // namespace antivirus::service