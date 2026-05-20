#include "gui/AuthDialog.h"

#include "gui/RpcClient.h"

#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>

namespace antivirus::gui {

AuthDialog::AuthDialog(RpcClient& rpcClient, QWidget* parent)
    : QDialog(parent)
    , rpcClient_(rpcClient)
{
    setWindowTitle(QStringLiteral("Вход в аккаунт"));

    auto* layout = new QFormLayout(this);
    loginEdit_ = new QLineEdit(this);
    passwordEdit_ = new QLineEdit(this);
    passwordEdit_->setEchoMode(QLineEdit::Password);
    errorLabel_ = new QLabel(this);
    errorLabel_->setStyleSheet(QStringLiteral("color: #b00020"));
    errorLabel_->setWordWrap(true);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    buttons->button(QDialogButtonBox::Ok)->setText(QStringLiteral("Войти"));
    buttons->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("Отмена"));

    layout->addRow(QStringLiteral("Логин"), loginEdit_);
    layout->addRow(QStringLiteral("Пароль"), passwordEdit_);
    layout->addRow(errorLabel_);
    layout->addRow(buttons);

    connect(buttons, &QDialogButtonBox::accepted, this, [this]() {
        submit();
    });
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
}

void AuthDialog::submit()
{
    const auto state = rpcClient_.login(loginEdit_->text(), passwordEdit_->text());
    if (!state.authenticated) {
        errorLabel_->setText(state.lastError.isEmpty() ? QStringLiteral("Не удалось выполнить вход") : state.lastError);
        return;
    }

    accept();
}

} // namespace antivirus::gui
