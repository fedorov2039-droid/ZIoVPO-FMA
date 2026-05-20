#include "service/RpcServer.h"

#include "AntivirusRpc.h"
#include "common/logging.h"
#include "service/AuthState.h"

#include <rpc.h>
#include <windows.h>

namespace antivirus::service {
namespace {

constexpr wchar_t kRpcProtocol[] = L"ncalrpc";
constexpr wchar_t kRpcEndpoint[] = L"AntivirusGuiRpc";

template <std::size_t Size>
void copyString(wchar_t (&destination)[Size], const std::wstring& source)
{
    wcsncpy_s(destination, source.c_str(), _TRUNCATE);
}

void copyAuthState(const AuthState& source, AvAuthState* destination)
{
    if (destination == nullptr) {
        return;
    }

    destination->authenticated = source.authenticated ? 1 : 0;
    copyString(destination->displayName, source.displayName);
    copyString(destination->login, source.login);
    copyString(destination->lastError, source.lastError);
}

void copyLicenseState(const LicenseState& source, AvLicenseState* destination)
{
    if (destination == nullptr) {
        return;
    }

    destination->licenseActive = source.active ? 1 : 0;
    copyString(destination->licenseExpiresAt, source.expiresAt);
    destination->activationRequired = source.activationRequired ? 1 : 0;
    copyString(destination->featureBlockedReason, source.blockedReason);
    copyString(destination->lastError, source.lastError);
}

void copyFeatureState(const FeatureState& source, AvFeatureState* destination)
{
    if (destination == nullptr) {
        return;
    }

    destination->functionalityEnabled = source.enabled ? 1 : 0;
    copyString(destination->blockedReason, source.blockedReason);
}

} // namespace

bool RpcServer::start()
{
    RPC_STATUS status = RpcServerUseProtseqEpW(reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcProtocol)),
                                              RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
                                              reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)),
                                              nullptr);
    if (status != RPC_S_OK && status != RPC_S_DUPLICATE_ENDPOINT) {
        antivirus::common::log_error(L"RpcServerUseProtseqEpW failed");
        return false;
    }

    status = RpcServerRegisterIf2(AntivirusRpc_v1_0_s_ifspec,
                                  nullptr,
                                  nullptr,
                                  RPC_IF_ALLOW_LOCAL_ONLY,
                                  RPC_C_LISTEN_MAX_CALLS_DEFAULT,
                                  static_cast<unsigned>(-1),
                                  nullptr);
    if (status != RPC_S_OK) {
        antivirus::common::log_error(L"RpcServerRegisterIf2 failed");
        return false;
    }

    status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
    if (status != RPC_S_OK) {
        antivirus::common::log_error(L"RpcServerListen failed");
        RpcServerUnregisterIf(AntivirusRpc_v1_0_s_ifspec, nullptr, FALSE);
        return false;
    }

    started_ = true;
    return true;
}

void RpcServer::stop()
{
    if (!started_) {
        return;
    }

    RpcMgmtStopServerListening(nullptr);
    RpcServerUnregisterIf(AntivirusRpc_v1_0_s_ifspec, nullptr, FALSE);
    started_ = false;
}

} // namespace antivirus::service

void AvPing(handle_t, long* result)
{
    if (result != nullptr) {
        *result = 1;
    }
}

void AvRequestServiceStop(handle_t, long* result)
{
    antivirus::service::requestServiceStopFromRpc();
    if (result != nullptr) {
        *result = 1;
    }
}

void AvGetServiceStatus(handle_t, long* status)
{
    if (status != nullptr) {
        *status = antivirus::service::queryServiceStateFromRpc();
    }
}

void AvGetAuthState(handle_t, AvAuthState* state)
{
    antivirus::service::copyAuthState(antivirus::service::queryAuthStateFromRpc(), state);
}

void AvLogin(handle_t, const wchar_t* login, const wchar_t* password, AvAuthState* state)
{
    antivirus::service::copyAuthState(antivirus::service::loginFromRpc(login, password), state);
}

void AvLogout(handle_t, AvAuthState* state)
{
    antivirus::service::copyAuthState(antivirus::service::logoutFromRpc(), state);
}

void AvGetLicenseState(handle_t, AvLicenseState* state)
{
    antivirus::service::copyLicenseState(antivirus::service::queryLicenseStateFromRpc(), state);
}

void AvActivateProduct(handle_t, const wchar_t* activationCode, AvLicenseState* state)
{
    antivirus::service::copyLicenseState(antivirus::service::activateFromRpc(activationCode), state);
}

void AvGetFeatureState(handle_t, AvFeatureState* state)
{
    antivirus::service::copyFeatureState(antivirus::service::queryFeatureStateFromRpc(), state);
}
