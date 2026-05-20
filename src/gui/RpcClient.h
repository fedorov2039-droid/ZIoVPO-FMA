#pragma once

namespace antivirus::gui {

class RpcClient final {
public:
    bool ping() const;
    bool requestServiceStop() const;
    long serviceStatus() const;
};

} // namespace antivirus::gui
