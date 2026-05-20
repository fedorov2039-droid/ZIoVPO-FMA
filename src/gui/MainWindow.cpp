#include "gui/MainWindow.h"

#include "gui/ActivationDialog.h"
#include "gui/AppLifecycle.h"
#include "gui/AuthDialog.h"
#include "gui/RpcClient.h"

#include <QAction>
#include <QCloseEvent>
#include <QFileDialog>
#include <QFont>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QMenuBar>
#include <QPushButton>
#include <QStatusBar>
#include <QTextEdit>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

namespace antivirus::gui {
namespace {

QString formatScanResult(const ScanResult& result)
{
    QString text;

    if (!result.lastError.isEmpty()) {
        text += QStringLiteral("Ошибка: %1\n\n").arg(result.lastError);
    }

    if (!result.details.isEmpty()) {
        text += result.details;
    } else {
        text += result.malicious
            ? QStringLiteral("Результат: обнаружена угроза")
            : QStringLiteral("Результат: угроз не обнаружено");
    }

    return text;
}

} // namespace

MainWindow::MainWindow(AppLifecycle& lifecycle, RpcClient& rpcClient, QWidget* parent)
    : QMainWindow(parent)
    , lifecycle_(lifecycle)
    , rpcClient_(rpcClient)
{
    setWindowTitle(QStringLiteral("Антивирус GUI"));
    resize(820, 620);

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

    databaseLabel_ = new QLabel(QStringLiteral("Антивирусные базы: не загружены"), central);
    databaseLabel_->setWordWrap(true);

    directoryMonitorLabel_ = new QLabel(QStringLiteral("Мониторинг: выключен"), central);
    directoryMonitorLabel_->setWordWrap(true);

    auto* note = new QLabel(QStringLiteral("Закрытие окна скрывает интерфейс, приложение продолжает работать в фоне."), central);
    note->setWordWrap(true);

    auto* scanButtonsLayout = new QHBoxLayout();
    scanFileButton_ = new QPushButton(QStringLiteral("Сканировать файл"), central);
    scanDirectoryButton_ = new QPushButton(QStringLiteral("Сканировать папку"), central);
    scanFixedDrivesButton_ = new QPushButton(QStringLiteral("Сканировать все несъёмные диски"), central);

    scanButtonsLayout->addWidget(scanFileButton_);
    scanButtonsLayout->addWidget(scanDirectoryButton_);
    scanButtonsLayout->addWidget(scanFixedDrivesButton_);

    auto* monitorButtonsLayout = new QHBoxLayout();
    startDirectoryMonitorButton_ = new QPushButton(QStringLiteral("Запустить мониторинг папки"), central);
    stopDirectoryMonitorButton_ = new QPushButton(QStringLiteral("Остановить мониторинг"), central);
    monitorButtonsLayout->addWidget(startDirectoryMonitorButton_);
    monitorButtonsLayout->addWidget(stopDirectoryMonitorButton_);

    connect(scanFileButton_, &QPushButton::clicked, this, [this]() {
        scanFile();
    });
    connect(scanDirectoryButton_, &QPushButton::clicked, this, [this]() {
        scanDirectory();
    });
    connect(scanFixedDrivesButton_, &QPushButton::clicked, this, [this]() {
        scanFixedDrives();
    });
    connect(startDirectoryMonitorButton_, &QPushButton::clicked, this, [this]() {
        startDirectoryMonitor();
    });
    connect(stopDirectoryMonitorButton_, &QPushButton::clicked, this, [this]() {
        stopDirectoryMonitor();
    });


    scanResultEdit_ = new QTextEdit(central);
    scanResultEdit_->setReadOnly(true);
    scanResultEdit_->setPlaceholderText(QStringLiteral("Здесь будут отображаться результаты сканирования."));

    auto* exitButton = new QPushButton(QStringLiteral("Выход"), central);
    connect(exitButton, &QPushButton::clicked, this, [this]() {
        lifecycle_.quitApplication();
    });

    layout->addWidget(title);
    layout->addWidget(accountLabel_);
    layout->addWidget(licenseLabel_);
    layout->addWidget(featureLabel_);
    layout->addWidget(databaseLabel_);
    layout->addWidget(directoryMonitorLabel_);
    layout->addWidget(note);
    layout->addLayout(scanButtonsLayout);
    layout->addLayout(monitorButtonsLayout);
    layout->addWidget(scanResultEdit_, 1);
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

    scanFileButton_->setEnabled(feature.functionalityEnabled);
    scanDirectoryButton_->setEnabled(feature.functionalityEnabled);
    scanFixedDrivesButton_->setEnabled(feature.functionalityEnabled);
    startDirectoryMonitorButton_->setEnabled(feature.functionalityEnabled);

    updateDatabaseState();
    updateDirectoryMonitorState();

    if (!auth.authenticated) {
        showLoginFlow();
        return;
    }

    if (!license.licenseActive && license.activationRequired) {
        showActivationFlow();
    }
}

void MainWindow::updateDatabaseState()
{
    const auto database = rpcClient_.databaseInfo();

    if (database.loaded) {
        databaseLabel_->setText(QStringLiteral("Антивирусные базы: загружены, дата выпуска: %1, записей: %2")
                                    .arg(database.releaseDate)
                                    .arg(database.recordCount));
    } else if (!database.lastError.isEmpty()) {
        databaseLabel_->setText(QStringLiteral("Антивирусные базы: %1").arg(database.lastError));
    } else {
        databaseLabel_->setText(QStringLiteral("Антивирусные базы: не загружены"));
    }
}

void MainWindow::updateDirectoryMonitorState()
{
    const DirectoryMonitorStatus status = rpcClient_.directoryMonitorStatus();

    if (status.running) {
        directoryMonitorLabel_->setText(QStringLiteral("Мониторинг: включён, папка: %1").arg(status.path));
        stopDirectoryMonitorButton_->setEnabled(true);
        return;
    }

    stopDirectoryMonitorButton_->setEnabled(false);
    if (!status.lastError.isEmpty()) {
        directoryMonitorLabel_->setText(QStringLiteral("Мониторинг: ошибка: %1").arg(status.lastError));
    } else {
        directoryMonitorLabel_->setText(QStringLiteral("Мониторинг: выключен"));
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

void MainWindow::scanFile()
{
    const QString path = QFileDialog::getOpenFileName(this, QStringLiteral("Выберите файл для сканирования"));
    if (path.isEmpty()) {
        return;
    }

    scanResultEdit_->setPlainText(QStringLiteral("Сканирование файла...\n%1").arg(path));
    const ScanResult result = rpcClient_.scanFile(path);
    scanResultEdit_->setPlainText(formatScanResult(result));
    updateDatabaseState();
}

void MainWindow::scanDirectory()
{
    const QString path = QFileDialog::getExistingDirectory(this, QStringLiteral("Выберите папку для сканирования"));
    if (path.isEmpty()) {
        return;
    }

    scanResultEdit_->setPlainText(QStringLiteral("Сканирование папки...\n%1").arg(path));
    const ScanResult result = rpcClient_.scanDirectory(path);
    scanResultEdit_->setPlainText(formatScanResult(result));
    updateDatabaseState();
}

void MainWindow::scanFixedDrives()
{
    scanResultEdit_->setPlainText(QStringLiteral("Сканирование всех несъёмных дисков..."));
    const ScanResult result = rpcClient_.scanFixedDrives();
    scanResultEdit_->setPlainText(formatScanResult(result));
    updateDatabaseState();
}

void MainWindow::startDirectoryMonitor()
{
    const QString path = QFileDialog::getExistingDirectory(this, QStringLiteral("Выберите папку для мониторинга"));
    if (path.isEmpty()) {
        return;
    }

    const DirectoryMonitorStatus status = rpcClient_.startDirectoryMonitor(path);
    updateDirectoryMonitorState();

    if (!status.lastError.isEmpty()) {
        scanResultEdit_->setPlainText(QStringLiteral("Мониторинг не запущен: %1").arg(status.lastError));
    } else {
        scanResultEdit_->setPlainText(QStringLiteral("Мониторинг папки запущен:\n%1").arg(status.path));
    }
}

void MainWindow::stopDirectoryMonitor()
{
    const DirectoryMonitorStatus status = rpcClient_.stopDirectoryMonitor();
    updateDirectoryMonitorState();

    if (!status.lastError.isEmpty()) {
        scanResultEdit_->setPlainText(QStringLiteral("Мониторинг остановлен с предупреждением: %1").arg(status.lastError));
    } else {
        scanResultEdit_->setPlainText(QStringLiteral("Мониторинг папки остановлен."));
    }
}

} // namespace antivirus::gui
