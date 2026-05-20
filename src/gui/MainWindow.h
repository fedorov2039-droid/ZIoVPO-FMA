#pragma once

#include <QMainWindow>

namespace antivirus::gui {

class AppLifecycle;

class MainWindow final : public QMainWindow {
public:
    explicit MainWindow(AppLifecycle& lifecycle, QWidget* parent = nullptr);

protected:
    void closeEvent(QCloseEvent* event) override;

private:
    AppLifecycle& lifecycle_;
};

} // namespace antivirus::gui
