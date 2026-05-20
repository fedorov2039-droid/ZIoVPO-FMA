#pragma once

#include <QDialog>

class QLineEdit;
class QLabel;

namespace antivirus::gui {

class RpcClient;

class AuthDialog final : public QDialog {
public:
    explicit AuthDialog(RpcClient& rpcClient, QWidget* parent = nullptr);

private:
    void submit();

    RpcClient& rpcClient_;
    QLineEdit* loginEdit_ = nullptr;
    QLineEdit* passwordEdit_ = nullptr;
    QLabel* errorLabel_ = nullptr;
};

} // namespace antivirus::gui
