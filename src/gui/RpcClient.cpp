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

} // namespace antivirus::gui
