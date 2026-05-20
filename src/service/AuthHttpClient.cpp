#include "service/AuthHttpClient.h"

#include <algorithm>
#include <cwctype>
#include <windows.h>
#include <winhttp.h>

namespace antivirus::service {
namespace {

std::wstring lower(std::wstring value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return value;
}

} // namespace

AuthHttpClient::AuthHttpClient(std::wstring baseUrl)
    : baseUrl_(std::move(baseUrl))
{
}

bool AuthHttpClient::isConfiguredForHttps() const
{
    return lower(baseUrl_).starts_with(L"https://");
}

const std::wstring& AuthHttpClient::baseUrl() const
{
    return baseUrl_;
}

} // namespace antivirus::service
