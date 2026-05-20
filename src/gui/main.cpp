#include "common/logging.h"
#include "gui/AppLifecycle.h"
#include "gui/MainWindow.h"
#include "gui/ParentProcessCheck.h"
#include "gui/RpcClient.h"
#include "gui/ServiceClient.h"
#include "gui/SingleInstanceGuard.h"
#include "gui/TrayController.h"

#include <QApplication>

#include <iostream>
#include <string_view>

namespace {

bool hasArgument(int argc, char* argv[], std::string_view expected)
{
    for (int i = 1; i < argc; ++i) {
        if (argv[i] == expected) {
            return true;
        }
    }

    return false;
}

} // namespace

int main(int argc, char* argv[])
{
    if (hasArgument(argc, argv, "--version")) {
        std::cout << "AntivirusGui " << ANTIVIRUS_APP_VERSION << "\n";
        return 0;
    }

    const bool allowStandaloneDebug = hasArgument(argc, argv, "--allow-standalone-debug");
    const bool serviceChild = hasArgument(argc, argv, "--service-child");

    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("Antivirus GUI"));
    QApplication::setApplicationVersion(QStringLiteral(ANTIVIRUS_APP_VERSION));
    QApplication::setOrganizationName(QStringLiteral("Antivirus Coursework"));
    QApplication::setQuitOnLastWindowClosed(false);

    if (!allowStandaloneDebug) {
        antivirus::gui::ServiceClient serviceClient;
        if (!serviceClient.isRunning()) {
            if (!serviceClient.isInstalled()) {
                antivirus::common::log_error(L"AntivirusGuiService is not installed");
                return 1;
            }

            antivirus::common::log_info(L"Service is not running; attempting to start it and exit");
            if (!serviceClient.startService() || !serviceClient.waitUntilRunning(15000)) {
                antivirus::common::log_error(L"Unable to start AntivirusGuiService");
                return 1;
            }

            return 0;
        }

        if (!serviceChild || !antivirus::gui::isParentProjectService()) {
            antivirus::common::log_error(L"GUI must be launched by AntivirusService.exe in production mode");
            return 1;
        }
    }

    antivirus::gui::SingleInstanceGuard singleInstance;
    if (!singleInstance.isPrimaryInstance()) {
        antivirus::common::log_info(L"Second GUI instance exits before creating tray icon");
        return 0;
    }

    antivirus::common::log_info(L"Starting GUI");

    antivirus::gui::AppLifecycle lifecycle;
    antivirus::gui::RpcClient rpcClient;
    lifecycle.setRpcClient(&rpcClient);

    antivirus::gui::MainWindow window(lifecycle, rpcClient);
    antivirus::gui::TrayController trayController(window, lifecycle);
    lifecycle.setTrayController(&trayController);

    trayController.show();

    const bool hidden = hasArgument(argc, argv, "--hidden");
    const bool show = hasArgument(argc, argv, "--show");
    if (show || !hidden) {
        window.show();
    }

    return QApplication::exec();
}
