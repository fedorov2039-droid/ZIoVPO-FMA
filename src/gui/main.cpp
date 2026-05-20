#include "common/logging.h"

#include <QApplication>
#include <QFont>
#include <QLabel>
#include <QMainWindow>
#include <QStatusBar>
#include <QVBoxLayout>
#include <QWidget>

namespace {

class MainWindow final : public QMainWindow {
public:
    MainWindow()
    {
        setWindowTitle(QStringLiteral("Antivirus GUI"));
        resize(640, 420);

        auto* central = new QWidget(this);
        auto* layout = new QVBoxLayout(central);

        auto* title = new QLabel(QStringLiteral("Антивирус GUI"), central);
        QFont title_font = title->font();
        title_font.setPointSize(18);
        title_font.setBold(true);
        title->setFont(title_font);

        auto* state = new QLabel(QStringLiteral("Состояние: scaffold готов к развитию"), central);
        state->setWordWrap(true);

        layout->addWidget(title);
        layout->addWidget(state);
        layout->addStretch(1);

        setCentralWidget(central);
        statusBar()->showMessage(QStringLiteral("Учебный C++20 / Qt 6 проект"));
    }
};

} // namespace

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("Antivirus GUI"));
    QApplication::setApplicationVersion(QStringLiteral(ANTIVIRUS_APP_VERSION));
    QApplication::setOrganizationName(QStringLiteral("Antivirus Coursework"));

    antivirus::common::log_info(L"Starting GUI scaffold");

    MainWindow window;
    window.show();

    return QApplication::exec();
}
