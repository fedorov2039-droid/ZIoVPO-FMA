#include "service/SessionManager.h"

#include "common/logging.h"

#include <wtsapi32.h>

namespace antivirus::service {

SessionManager::~SessionManager()
{
    stopAllGuiChildren();
}

void SessionManager::launchGuiForExistingSessions()
{
    WTS_SESSION_INFOW* sessions = nullptr;
    DWORD count = 0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) {
        antivirus::common::log_warning(L"WTSEnumerateSessionsW failed");
        return;
    }

    for (DWORD i = 0; i < count; ++i) {
        if (sessions[i].SessionId == 0) {
            continue;
        }

        if (sessions[i].State == WTSActive || sessions[i].State == WTSConnected) {
            launchGuiForSession(sessions[i].SessionId);
        }
    }

    WTSFreeMemory(sessions);
}

void SessionManager::launchGuiForSession(DWORD sessionId)
{
    if (sessionId == 0 || children_.contains(sessionId)) {
        return;
    }

    LaunchedProcess launched{};
    if (!processLauncher_.launchGuiInSession(sessionId, launched)) {
        return;
    }

    children_[sessionId] = GuiChildProcess{
        .sessionId = sessionId,
        .processHandle = launched.processHandle,
        .processId = launched.processId,
        .startedTick = GetTickCount64(),
    };
}

void SessionManager::stopAllGuiChildren()
{
    for (auto& [sessionId, child] : children_) {
        if (child.processHandle == nullptr) {
            continue;
        }

        const DWORD waitResult = WaitForSingleObject(child.processHandle, 3000);
        if (waitResult == WAIT_TIMEOUT) {
            TerminateProcess(child.processHandle, 0);
            WaitForSingleObject(child.processHandle, 2000);
        }

        CloseHandle(child.processHandle);
        child.processHandle = nullptr;
    }

    children_.clear();
}

} // namespace antivirus::service
