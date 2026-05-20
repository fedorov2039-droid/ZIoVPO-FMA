#include "gui/MainWindow.h"

#include "gui/AppLifecycle.h"

#include <QAction>
#include <QCloseEvent>
#include <QFont>
#include <QLabel>
#include <QMenu>
#include <QMenuBar>
#include <QPushButton>
#include <QStatusBar>
#include <QVBoxLayout>
#include <QWidget>

namespace antivirus::gui {

MainWindow::MainWindow(AppLifecycle& lifecycle, QWidget* parent)
    : QMainWindow(parent)
    , lifecycle_(lifecycle)
{
    setWindowTitle(QStringLiteral("Антивирус GUI"));
    resize(720, 480);

    auto* fileMenu = menuBar()->addMenu(QStringLiteral("Файл"));
    auto* exitAction = fileMenu->addAction(QStringLiteral("Выход"));
    connect(exitAction, &QAction::triggered, this, [this]() {
        lifecycle_.quitApplication();
    });

    auto* central = new QWidget(this);
    auto* layout = new QVBoxLayout(central);

    auto* title = new QLabel(QStringLiteral("Антивирус GUI"), central);
    QFont titleFont = title->font();
    titleFont.setPointSize(18);
    titleFont.setBold(true);
    title->setFont(titleFont);

    auto* state = new QLabel(QStringLiteral("Состояние: работает"), central);
    state->setWordWrap(true);

    auto* note = new QLabel(QStringLiteral("Закрытие окна скрывает интерфейс, приложение продолжает работать в фоне."), central);
    note->setWordWrap(true);

    auto* exitButton = new QPushButton(QStringLiteral("Выход"), central);
    connect(exitButton, &QPushButton::clicked, this, [this]() {
        lifecycle_.quitApplication();
    });

    layout->addWidget(title);
    layout->addWidget(state);
    layout->addWidget(note);
    layout->addStretch(1);
    layout->addWidget(exitButton);

    setCentralWidget(central);
    statusBar()->showMessage(QStringLiteral("Учебный C++20 / Qt 6 проект"));
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    event->ignore();
    hide();
}

} // namespace antivirus::gui
