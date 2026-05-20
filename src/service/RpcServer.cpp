#include "service/RpcServer.h"

#include "AntivirusRpc.h"
#include "common/logging.h"

#include <rpc.h>
#include <windows.h>

namespace antivirus::service {
namespace {

constexpr wchar_t kRpcProtocol[] = L"ncalrpc";
constexpr wchar_t kRpcEndpoint[] = L"AntivirusGuiRpc";

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
