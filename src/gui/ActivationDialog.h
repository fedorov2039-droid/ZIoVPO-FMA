#pragma once

#include <QDialog>

class QLabel;
class QLineEdit;

namespace antivirus::gui {

class RpcClient;

class ActivationDialog final : public QDialog {
public:
    explicit ActivationDialog(RpcClient& rpcClient, QWidget* parent = nullptr);

private:
    void submit();

    RpcClient& rpcClient_;
    QLineEdit* codeEdit_ = nullptr;
    QLabel* errorLabel_ = nullptr;
};

} // namespace antivirus::gui
