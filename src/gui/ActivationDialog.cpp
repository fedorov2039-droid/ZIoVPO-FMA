#include "gui/ActivationDialog.h"

#include "gui/RpcClient.h"

#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>

namespace antivirus::gui {

ActivationDialog::ActivationDialog(RpcClient& rpcClient, QWidget* parent)
    : QDialog(parent)
    , rpcClient_(rpcClient)
{
    setWindowTitle(QStringLiteral("Активация продукта"));

    auto* layout = new QFormLayout(this);
    codeEdit_ = new QLineEdit(this);
    errorLabel_ = new QLabel(this);
    errorLabel_->setStyleSheet(QStringLiteral("color: #b00020"));
    errorLabel_->setWordWrap(true);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    buttons->button(QDialogButtonBox::Ok)->setText(QStringLiteral("Активировать"));
    buttons->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("Отмена"));

    layout->addRow(QStringLiteral("Код активации"), codeEdit_);
    layout->addRow(errorLabel_);
    layout->addRow(buttons);

    connect(buttons, &QDialogButtonBox::accepted, this, [this]() {
        submit();
    });
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
}

void ActivationDialog::submit()
{
    const auto state = rpcClient_.activateProduct(codeEdit_->text());
    if (!state.licenseActive) {
        errorLabel_->setText(state.lastError.isEmpty() ? QStringLiteral("Активация не выполнена") : state.lastError);
        return;
    }

    accept();
}

} // namespace antivirus::gui
