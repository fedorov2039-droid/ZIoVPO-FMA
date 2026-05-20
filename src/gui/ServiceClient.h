#pragma once

namespace antivirus::gui {

class ServiceClient final {
public:
    bool isInstalled() const;
    bool isRunning() const;
    bool startService() const;
    bool waitUntilRunning(unsigned timeoutMilliseconds) const;
};

} // namespace antivirus::gui
