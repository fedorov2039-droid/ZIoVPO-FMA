#pragma once

#include <QAbstractNativeEventFilter>
#include <QIcon>
#include <QObject>
#include <QSystemTrayIcon>

#include <windows.h>

class QAction;
class QMenu;
class QWidget;

namespace antivirus::gui {

class AppLifecycle;

class TrayController final : public QObject, public QAbstractNativeEventFilter {
public:
    TrayController(QWidget& mainWindow, AppLifecycle& lifecycle, QObject* parent = nullptr);
    ~TrayController() override;

    void show();
    void hide();
    void showMainWindow();

    bool nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result) override;

private:
    static QIcon createTrayIcon();

    void restoreAfterTaskbarRecreated();

    QWidget& mainWindow_;
    AppLifecycle& lifecycle_;
    QSystemTrayIcon trayIcon_;
    QMenu* trayMenu_ = nullptr;
    UINT taskbarCreatedMessage_ = 0;
};

} // namespace antivirus::gui
