#include "gui/AppLifecycle.h"

#include "gui/TrayController.h"

#include <QCoreApplication>

namespace antivirus::gui {

void AppLifecycle::setTrayController(TrayController* trayController)
{
    trayController_ = trayController;
}

void AppLifecycle::quitApplication()
{
    if (trayController_ != nullptr) {
        trayController_->hide();
    }

    QCoreApplication::quit();
}

} // namespace antivirus::gui
