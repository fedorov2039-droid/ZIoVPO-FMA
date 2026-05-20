#pragma once

#include "service/AuthHttpClient.h"
#include "service/AuthState.h"

#include <mutex>
#include <string>

namespace antivirus::service {

class AuthManager final {
public:
    AuthManager();

    AuthState state() const;
    AuthState login(std::wstring login, std::wstring password);
    AuthState logout();

private:
    mutable std::mutex mutex_;
    AuthHttpClient httpClient_;
    AuthState state_;
    std::wstring sessionProof_;
    std::wstring renewalProof_;
};

} // namespace antivirus::service
