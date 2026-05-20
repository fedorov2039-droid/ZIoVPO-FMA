#pragma once

#include <QMainWindow>

class QLabel;

namespace antivirus::gui {

class AppLifecycle;
class RpcClient;

class MainWindow final : public QMainWindow {
public:
    MainWindow(AppLifecycle& lifecycle, RpcClient& rpcClient, QWidget* parent = nullptr);

protected:
    void closeEvent(QCloseEvent* event) override;

private:
    void updateAccountState();
    void showLoginFlow();
    void showActivationFlow();
    void logout();

    AppLifecycle& lifecycle_;
    RpcClient& rpcClient_;
    QLabel* accountLabel_ = nullptr;
    QLabel* licenseLabel_ = nullptr;
    QLabel* featureLabel_ = nullptr;
};

} // namespace antivirus::gui
