#include "gui/TrayController.h"

#include "gui/AppLifecycle.h"

#include <QAction>
#include <QApplication>
#include <QMenu>
#include <QPainter>
#include <QPixmap>
#include <QTimer>
#include <QWidget>

namespace antivirus::gui {

TrayController::TrayController(QWidget& mainWindow, AppLifecycle& lifecycle, QObject* parent)
    : QObject(parent)
    , mainWindow_(mainWindow)
    , lifecycle_(lifecycle)
    , trayIcon_(this)
    , taskbarCreatedMessage_(RegisterWindowMessageW(L"TaskbarCreated"))
{
    trayIcon_.setIcon(createTrayIcon());
    trayIcon_.setToolTip(QStringLiteral("Антивирус GUI"));

    trayMenu_ = new QMenu(&mainWindow_);
    auto* openAction = trayMenu_->addAction(QStringLiteral("Открыть"));
    auto* exitAction = trayMenu_->addAction(QStringLiteral("Выход"));
    trayIcon_.setContextMenu(trayMenu_);

    connect(openAction, &QAction::triggered, this, [this]() {
        showMainWindow();
    });
    connect(exitAction, &QAction::triggered, this, [this]() {
        lifecycle_.quitApplication();
    });
    connect(&trayIcon_, &QSystemTrayIcon::activated, this, [this](QSystemTrayIcon::ActivationReason reason) {
        if (reason == QSystemTrayIcon::Trigger || reason == QSystemTrayIcon::DoubleClick) {
            showMainWindow();
        }
    });

    qApp->installNativeEventFilter(this);
}

TrayController::~TrayController()
{
    qApp->removeNativeEventFilter(this);
    hide();
}

void TrayController::show()
{
    trayIcon_.show();
}

void TrayController::hide()
{
    trayIcon_.hide();
}

void TrayController::showMainWindow()
{
    mainWindow_.show();
    mainWindow_.raise();
    mainWindow_.activateWindow();
}

bool TrayController::nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result)
{
    if (eventType != "windows_generic_MSG" && eventType != "windows_dispatcher_MSG") {
        return false;
    }

    const auto* msg = static_cast<MSG*>(message);
    if (msg == nullptr || msg->message != taskbarCreatedMessage_) {
        return false;
    }

    restoreAfterTaskbarRecreated();
    if (result != nullptr) {
        *result = 0;
    }

    return false;
}

QIcon TrayController::createTrayIcon()
{
    QPixmap pixmap(32, 32);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setBrush(QColor(20, 116, 73));
    painter.setPen(Qt::NoPen);
    painter.drawEllipse(2, 2, 28, 28);
    painter.setPen(QPen(Qt::white, 3));
    painter.drawLine(10, 17, 15, 22);
    painter.drawLine(15, 22, 23, 10);

    return QIcon(pixmap);
}

void TrayController::restoreAfterTaskbarRecreated()
{
    trayIcon_.hide();
    QTimer::singleShot(250, this, [this]() {
        trayIcon_.show();
    });
}

} // namespace antivirus::gui
