#pragma once

#include <windows.h>

namespace antivirus::gui {

class SingleInstanceGuard final {
public:
    SingleInstanceGuard();
    ~SingleInstanceGuard();

    SingleInstanceGuard(const SingleInstanceGuard&) = delete;
    SingleInstanceGuard& operator=(const SingleInstanceGuard&) = delete;

    SingleInstanceGuard(SingleInstanceGuard&& other) noexcept;
    SingleInstanceGuard& operator=(SingleInstanceGuard&& other) noexcept;

    [[nodiscard]] bool isPrimaryInstance() const;

private:
    HANDLE mutex_ = nullptr;
    bool primaryInstance_ = false;
};

} // namespace antivirus::gui
