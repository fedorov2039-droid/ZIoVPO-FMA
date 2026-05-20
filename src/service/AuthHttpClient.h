#pragma once

#include "service/AuthState.h"

#include <string>

namespace antivirus::service {

class AuthHttpClient final {
public:
    explicit AuthHttpClient(std::wstring baseUrl);

    [[nodiscard]] bool isConfiguredForHttps() const;
    [[nodiscard]] const std::wstring& baseUrl() const;

private:
    std::wstring baseUrl_;
};

} // namespace antivirus::service
