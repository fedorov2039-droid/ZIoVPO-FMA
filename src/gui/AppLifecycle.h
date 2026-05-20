#pragma once

namespace antivirus::gui {

class TrayController;
class RpcClient;

class AppLifecycle final {
public:
    void setTrayController(TrayController* trayController);
    void setRpcClient(RpcClient* rpcClient);
    void quitApplication();

private:
    TrayController* trayController_ = nullptr;
    RpcClient* rpcClient_ = nullptr;
};

} // namespace antivirus::gui
