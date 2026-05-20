#include "common/logging.h"
#include "gui/AppLifecycle.h"
#include "gui/MainWindow.h"
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

    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("Antivirus GUI"));
    QApplication::setApplicationVersion(QStringLiteral(ANTIVIRUS_APP_VERSION));
    QApplication::setOrganizationName(QStringLiteral("Antivirus Coursework"));
    QApplication::setQuitOnLastWindowClosed(false);

    antivirus::gui::SingleInstanceGuard singleInstance;
    if (!singleInstance.isPrimaryInstance()) {
        antivirus::common::log_info(L"Second GUI instance exits before creating tray icon");
        return 0;
    }

    antivirus::common::log_info(L"Starting GUI");

    antivirus::gui::AppLifecycle lifecycle;
    antivirus::gui::MainWindow window(lifecycle);
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
