#pragma once

#include <windows.h>

namespace antivirus::service {

struct LaunchedProcess {
    HANDLE processHandle = nullptr;
    DWORD processId = 0;
};

class ProcessLauncher final {
public:
    bool launchGuiInSession(DWORD sessionId, LaunchedProcess& launched) const;
};

} // namespace antivirus::service
