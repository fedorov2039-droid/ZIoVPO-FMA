#pragma once

namespace antivirus::service {

struct AuthState;
struct LicenseState;
struct FeatureState;

class RpcServer final {
public:
    bool start();
    void stop();

private:
    bool started_ = false;
};

void requestServiceStopFromRpc();
long queryServiceStateFromRpc();
AuthState queryAuthStateFromRpc();
AuthState loginFromRpc(const wchar_t* login, const wchar_t* password);
AuthState logoutFromRpc();
LicenseState queryLicenseStateFromRpc();
LicenseState activateFromRpc(const wchar_t* activationCode);
FeatureState queryFeatureStateFromRpc();

} // namespace antivirus::service
