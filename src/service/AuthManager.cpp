#include "service/AuthManager.h"

#include "common/logging.h"

namespace antivirus::service {
namespace {

constexpr wchar_t kDemoLogin[] = L"demo";
constexpr wchar_t kDemoPassword[] = L"demo";

} // namespace

AuthManager::AuthManager()
    : httpClient_(L"https://auth.example.invalid")
{
}

AuthState AuthManager::state() const
{
    std::lock_guard lock(mutex_);
    return state_;
}

AuthState AuthManager::login(std::wstring login, std::wstring password)
{
    std::lock_guard lock(mutex_);

    if (!httpClient_.isConfiguredForHttps()) {
        state_.authenticated = false;
        state_.displayName.clear();
        state_.login.clear();
        state_.lastError = L"Backend URL must use HTTPS";
        sessionProof_.clear();
        renewalProof_.clear();
        return state_;
    }

    if (login != kDemoLogin || password != kDemoPassword) {
        state_.authenticated = false;
        state_.displayName.clear();
        state_.login.clear();
        state_.lastError = L"Неверный логин или пароль";
        sessionProof_.clear();
        renewalProof_.clear();
        antivirus::common::log_warning(L"Authentication failed; credentials rejected by mock HTTPS backend");
        return state_;
    }

    state_.authenticated = true;
    state_.login = std::move(login);
    state_.displayName = L"Demo User";
    state_.lastError.clear();

    sessionProof_ = L"in-memory-session-proof";
    renewalProof_ = L"in-memory-renewal-proof";

    antivirus::common::log_info(L"User authenticated; sensitive auth material kept in RAM only");
    return state_;
}

AuthState AuthManager::logout()
{
    std::lock_guard lock(mutex_);
    state_ = AuthState{};
    sessionProof_.clear();
    renewalProof_.clear();
    return state_;
}

} // namespace antivirus::service