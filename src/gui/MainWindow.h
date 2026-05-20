#pragma once

#include <QMainWindow>

class QLabel;
class QPushButton;
class QTextEdit;

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
    void updateDatabaseState();
    void showLoginFlow();
    void showActivationFlow();
    void logout();
    void scanFile();
    void scanDirectory();

    AppLifecycle& lifecycle_;
    RpcClient& rpcClient_;
    QLabel* accountLabel_ = nullptr;
    QLabel* licenseLabel_ = nullptr;
    QLabel* featureLabel_ = nullptr;
    QLabel* databaseLabel_ = nullptr;
    QPushButton* scanFileButton_ = nullptr;
    QPushButton* scanDirectoryButton_ = nullptr;
    QTextEdit* scanResultEdit_ = nullptr;
};

} // namespace antivirus::gui
