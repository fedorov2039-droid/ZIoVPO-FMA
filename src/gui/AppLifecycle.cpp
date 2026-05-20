#include "gui/AppLifecycle.h"

#include "common/logging.h"
#include "gui/RpcClient.h"
#include "gui/TrayController.h"

#include <QCoreApplication>

namespace antivirus::gui {

void AppLifecycle::setTrayController(TrayController* trayController)
{
    trayController_ = trayController;
}

void AppLifecycle::setRpcClient(RpcClient* rpcClient)
{
    rpcClient_ = rpcClient;
}

void AppLifecycle::quitApplication()
{
    if (rpcClient_ != nullptr && !rpcClient_->requestServiceStop()) {
        antivirus::common::log_warning(L"Service stop RPC request failed; quitting GUI locally");
    }

    if (trayController_ != nullptr) {
        trayController_->hide();
    }

    QCoreApplication::quit();
}

} // namespace antivirus::gui
