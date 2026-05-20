#include "gui/AppLifecycle.h"

#include "common/logging.h"
#include "gui/RpcClient.h"
#include "gui/SecureStopConfirmation.h"
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
    if (!confirmServiceStopOnSecureDesktop()) {
        antivirus::common::log_info(L"Остановка службы отменена пользователем");
        return;
    }

    if (rpcClient_ != nullptr && !rpcClient_->requestServiceStop()) {
        antivirus::common::log_warning(L"RPC-запрос остановки службы не выполнен; GUI завершается локально");
    }

    if (trayController_ != nullptr) {
        trayController_->hide();
    }

    QCoreApplication::quit();
}

} // namespace antivirus::gui
