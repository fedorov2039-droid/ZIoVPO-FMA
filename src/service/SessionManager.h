#pragma once

#include "service/ProcessLauncher.h"

#include <map>
#include <windows.h>

namespace antivirus::service {

struct GuiChildProcess {
    DWORD sessionId = 0;
    HANDLE processHandle = nullptr;
    DWORD processId = 0;
    ULONGLONG startedTick = 0;
};

class SessionManager final {
public:
    ~SessionManager();

    void launchGuiForExistingSessions();
    void launchGuiForSession(DWORD sessionId);
    void stopAllGuiChildren();

private:
    ProcessLauncher processLauncher_;
    std::map<DWORD, GuiChildProcess> children_;
};

} // namespace antivirus::service
