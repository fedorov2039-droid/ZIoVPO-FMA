#include "common/logging.h"
#include "common/process_hardening.h"
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
                antivirus::common::log_error(L"AntivirusGuiService не установлена");
                return 1;
            }

            antivirus::common::log_info(L"Служба не запущена; пробуем запустить её и выйти");
            if (!serviceClient.startService() || !serviceClient.waitUntilRunning(15000)) {
                antivirus::common::log_error(L"Не удалось запустить AntivirusGuiService");
                return 1;
            }

            return 0;
        }

        if (!serviceChild || !antivirus::gui::isParentProjectService()) {
            antivirus::common::log_error(L"В рабочем режиме GUI должен запускаться службой AntivirusService.exe");
            return 1;
        }
    }

    antivirus::gui::SingleInstanceGuard singleInstance;
    if (!singleInstance.isPrimaryInstance()) {
        antivirus::common::log_info(L"Второй экземпляр GUI завершается до создания иконки в трее");
        return 0;
    }

    antivirus::common::hardenCurrentProcessForDemo(L"AntivirusGui.exe", true);
    antivirus::common::log_info(L"Запуск GUI");

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
