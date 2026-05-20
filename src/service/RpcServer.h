#pragma once

namespace antivirus::service {

class RpcServer final {
public:
    bool start();
    void stop();

private:
    bool started_ = false;
};

void requestServiceStopFromRpc();
long queryServiceStateFromRpc();

} // namespace antivirus::service
