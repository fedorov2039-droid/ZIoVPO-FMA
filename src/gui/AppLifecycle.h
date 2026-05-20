#pragma once

namespace antivirus::gui {

class TrayController;

class AppLifecycle final {
public:
    void setTrayController(TrayController* trayController);
    void quitApplication();

private:
    TrayController* trayController_ = nullptr;
};

} // namespace antivirus::gui
