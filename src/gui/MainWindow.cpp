#include "gui/MainWindow.h"

#include "gui/ActivationDialog.h"
#include "gui/AppLifecycle.h"
#include "gui/AuthDialog.h"
#include "gui/RpcClient.h"

#include <QAction>
#include <QCloseEvent>
#include <QFont>
#include <QLabel>
#include <QMenu>
#include <QMenuBar>
#include <QPushButton>
#include <QStatusBar>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

namespace antivirus::gui {

MainWindow::MainWindow(AppLifecycle& lifecycle, RpcClient& rpcClient, QWidget* parent)
    : QMainWindow(parent)
    , lifecycle_(lifecycle)
    , rpcClient_(rpcClient)
{
    setWindowTitle(QStringLiteral("Антивирус GUI"));
    resize(720, 480);

    auto* fileMenu = menuBar()->addMenu(QStringLiteral("Файл"));
    auto* exitAction = fileMenu->addAction(QStringLiteral("Выход"));
    connect(exitAction, &QAction::triggered, this, [this]() {
        lifecycle_.quitApplication();
    });

    auto* accountMenu = menuBar()->addMenu(QStringLiteral("Аккаунт"));
    auto* loginAction = accountMenu->addAction(QStringLiteral("Войти"));
    auto* logoutAction = accountMenu->addAction(QStringLiteral("Выйти из аккаунта"));
    connect(loginAction, &QAction::triggered, this, [this]() {
        showLoginFlow();
    });
    connect(logoutAction, &QAction::triggered, this, [this]() {
        logout();
    });

    auto* central = new QWidget(this);
    auto* layout = new QVBoxLayout(central);

    auto* title = new QLabel(QStringLiteral("Антивирус GUI"), central);
    QFont titleFont = title->font();
    titleFont.setPointSize(18);
    titleFont.setBold(true);
    title->setFont(titleFont);

    accountLabel_ = new QLabel(QStringLiteral("Аккаунт: не проверен"), central);
    accountLabel_->setWordWrap(true);

    licenseLabel_ = new QLabel(QStringLiteral("Лицензия: не проверена"), central);
    licenseLabel_->setWordWrap(true);

    featureLabel_ = new QLabel(QStringLiteral("Функции: заблокированы"), central);
    featureLabel_->setWordWrap(true);

    auto* note = new QLabel(QStringLiteral("Закрытие окна скрывает интерфейс, приложение продолжает работать в фоне."), central);
    note->setWordWrap(true);

    auto* exitButton = new QPushButton(QStringLiteral("Выход"), central);
    connect(exitButton, &QPushButton::clicked, this, [this]() {
        lifecycle_.quitApplication();
    });

    layout->addWidget(title);
    layout->addWidget(accountLabel_);
    layout->addWidget(licenseLabel_);
    layout->addWidget(featureLabel_);
    layout->addWidget(note);
    layout->addStretch(1);
    layout->addWidget(exitButton);

    setCentralWidget(central);
    statusBar()->showMessage(QStringLiteral("Учебный C++20 / Qt 6 проект"));

    QTimer::singleShot(0, this, [this]() {
        updateAccountState();
    });

    auto* pollingTimer = new QTimer(this);
    pollingTimer->setInterval(7000);
    connect(pollingTimer, &QTimer::timeout, this, [this]() {
        updateAccountState();
    });
    pollingTimer->start();
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    event->ignore();
    hide();
}

void MainWindow::updateAccountState()
{
    const auto auth = rpcClient_.authState();
    const auto license = rpcClient_.licenseState();
    const auto feature = rpcClient_.featureState();

    if (auth.authenticated) {
        accountLabel_->setText(QStringLiteral("Аккаунт: %1 (%2)").arg(auth.displayName, auth.login));
    } else {
        accountLabel_->setText(QStringLiteral("Аккаунт: требуется вход"));
    }

    if (license.licenseActive) {
        licenseLabel_->setText(QStringLiteral("Лицензия: активна до %1").arg(license.licenseExpiresAt));
    } else if (license.featureBlockedReason.contains(QStringLiteral("истек"), Qt::CaseInsensitive)) {
        licenseLabel_->setText(QStringLiteral("Лицензия: истекла %1").arg(license.licenseExpiresAt));
    } else if (!license.featureBlockedReason.isEmpty()) {
        licenseLabel_->setText(QStringLiteral("Лицензия: %1").arg(license.featureBlockedReason));
    } else {
        licenseLabel_->setText(QStringLiteral("Лицензия: требуется активация"));
    }

    featureLabel_->setText(feature.functionalityEnabled
                               ? QStringLiteral("Функции: доступны")
                               : QStringLiteral("Функции: заблокированы (%1)").arg(feature.blockedReason));

    if (!auth.authenticated) {
        showLoginFlow();
        return;
    }

    if (!license.licenseActive && license.activationRequired) {
        showActivationFlow();
    }
}

void MainWindow::showLoginFlow()
{
    AuthDialog dialog(rpcClient_, this);
    if (dialog.exec() == QDialog::Accepted) {
        updateAccountState();
    }
}

void MainWindow::showActivationFlow()
{
    ActivationDialog dialog(rpcClient_, this);
    if (dialog.exec() == QDialog::Accepted) {
        updateAccountState();
    }
}

void MainWindow::logout()
{
    rpcClient_.logout();
    updateAccountState();
}

} // namespace antivirus::gui