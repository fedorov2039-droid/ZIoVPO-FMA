#include "gui/SingleInstanceGuard.h"

#include "common/logging.h"
#include "common/win_error.h"

#include <string>

namespace antivirus::gui {

SingleInstanceGuard::SingleInstanceGuard()
{
    mutex_ = CreateMutexW(nullptr, TRUE, L"Local\\AntivirusGuiSingleton");
    if (mutex_ == nullptr) {
        antivirus::common::log_error(L"CreateMutexW failed for single-instance guard");
        primaryInstance_ = false;
        return;
    }

    const DWORD error = GetLastError();
    primaryInstance_ = error != ERROR_ALREADY_EXISTS;
    if (!primaryInstance_) {
        antivirus::common::log_info(L"Another GUI instance is already running in this user session");
    }
}

SingleInstanceGuard::~SingleInstanceGuard()
{
    if (mutex_ != nullptr) {
        if (primaryInstance_) {
            ReleaseMutex(mutex_);
        }
        CloseHandle(mutex_);
    }
}

SingleInstanceGuard::SingleInstanceGuard(SingleInstanceGuard&& other) noexcept
    : mutex_(other.mutex_)
    , primaryInstance_(other.primaryInstance_)
{
    other.mutex_ = nullptr;
    other.primaryInstance_ = false;
}

SingleInstanceGuard& SingleInstanceGuard::operator=(SingleInstanceGuard&& other) noexcept
{
    if (this == &other) {
        return *this;
    }

    if (mutex_ != nullptr) {
        if (primaryInstance_) {
            ReleaseMutex(mutex_);
        }
        CloseHandle(mutex_);
    }

    mutex_ = other.mutex_;
    primaryInstance_ = other.primaryInstance_;
    other.mutex_ = nullptr;
    other.primaryInstance_ = false;
    return *this;
}

bool SingleInstanceGuard::isPrimaryInstance() const
{
    return primaryInstance_;
}

} // namespace antivirus::gui
