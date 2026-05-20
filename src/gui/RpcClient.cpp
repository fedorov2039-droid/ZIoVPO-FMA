#include "gui/RpcClient.h"

#include "AntivirusRpc.h"
#include "common/logging.h"

#include <rpc.h>

namespace antivirus::gui {
namespace {

constexpr wchar_t kRpcProtocol[] = L"ncalrpc";
constexpr wchar_t kRpcEndpoint[] = L"AntivirusGuiRpc";

class RpcBinding final {
public:
    RpcBinding()
    {
        RPC_WSTR stringBinding = nullptr;
        RPC_STATUS status = RpcStringBindingComposeW(nullptr,
                                                    reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcProtocol)),
                                                    nullptr,
                                                    reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)),
                                                    nullptr,
                                                    &stringBinding);
        if (status != RPC_S_OK) {
            return;
        }

        status = RpcBindingFromStringBindingW(stringBinding, &binding_);
        RpcStringFreeW(&stringBinding);
        if (status != RPC_S_OK) {
            binding_ = nullptr;
        }
    }

    ~RpcBinding()
    {
        if (binding_ != nullptr) {
            RpcBindingFree(&binding_);
        }
    }

    RpcBinding(const RpcBinding&) = delete;
    RpcBinding& operator=(const RpcBinding&) = delete;

    [[nodiscard]] handle_t get() const
    {
        return binding_;
    }

private:
    handle_t binding_ = nullptr;
};

AuthState convertAuthState(const AvAuthState& state)
{
    return AuthState{
        .authenticated = state.authenticated != 0,
        .displayName = QString::fromWCharArray(state.displayName),
        .login = QString::fromWCharArray(state.login),
        .lastError = QString::fromWCharArray(state.lastError),
    };
}

LicenseState convertLicenseState(const AvLicenseState& state)
{
    return LicenseState{
        .licenseActive = state.licenseActive != 0,
        .licenseExpiresAt = QString::fromWCharArray(state.licenseExpiresAt),
        .activationRequired = state.activationRequired != 0,
        .featureBlockedReason = QString::fromWCharArray(state.featureBlockedReason),
        .lastError = QString::fromWCharArray(state.lastError),
    };
}

FeatureState convertFeatureState(const AvFeatureState& state)
{
    return FeatureState{
        .functionalityEnabled = state.functionalityEnabled != 0,
        .blockedReason = QString::fromWCharArray(state.blockedReason),
    };
}

} // namespace

bool RpcClient::ping() const
{
    RpcBinding binding;
    if (binding.get() == nullptr) {
        return false;
    }

    long result = 0;
    AvPing(binding.get(), &result);

    return result == 1;
}

bool RpcClient::requestServiceStop() const
{
    RpcBinding binding;
    if (binding.get() == nullptr) {
        antivirus::common::log_warning(L"RPC binding unavailable for service stop request");
        return false;
    }

    long result = 0;
    AvRequestServiceStop(binding.get(), &result);

    return result == 1;
}

long RpcClient::serviceStatus() const
{
    RpcBinding binding;
    if (binding.get() == nullptr) {
        return 0;
    }

    long status = 0;
    AvGetServiceStatus(binding.get(), &status);

    return status;
}

AuthState RpcClient::authState() const
{
    RpcBinding binding;
    AvAuthState state{};
    if (binding.get() == nullptr) {
        state.lastError[0] = L'\0';
        return convertAuthState(state);
    }

    AvGetAuthState(binding.get(), &state);
    return convertAuthState(state);
}

AuthState RpcClient::login(const QString& login, const QString& password) const
{
    RpcBinding binding;
    AvAuthState state{};
    if (binding.get() == nullptr) {
        return convertAuthState(state);
    }

    AvLogin(binding.get(),
            reinterpret_cast<const wchar_t*>(login.utf16()),
            reinterpret_cast<const wchar_t*>(password.utf16()),
            &state);
    return convertAuthState(state);
}

AuthState RpcClient::logout() const
{
    RpcBinding binding;
    AvAuthState state{};
    if (binding.get() == nullptr) {
        return convertAuthState(state);
    }

    AvLogout(binding.get(), &state);
    return convertAuthState(state);
}

LicenseState RpcClient::licenseState() const
{
    RpcBinding binding;
    AvLicenseState state{};
    if (binding.get() == nullptr) {
        return convertLicenseState(state);
    }

    AvGetLicenseState(binding.get(), &state);
    return convertLicenseState(state);
}

LicenseState RpcClient::activateProduct(const QString& activationCode) const
{
    RpcBinding binding;
    AvLicenseState state{};
    if (binding.get() == nullptr) {
        return convertLicenseState(state);
    }

    AvActivateProduct(binding.get(), reinterpret_cast<const wchar_t*>(activationCode.utf16()), &state);
    return convertLicenseState(state);
}

FeatureState RpcClient::featureState() const
{
    RpcBinding binding;
    AvFeatureState state{};
    if (binding.get() == nullptr) {
        return convertFeatureState(state);
    }

    AvGetFeatureState(binding.get(), &state);
    return convertFeatureState(state);
}

} // namespace antivirus::gui
