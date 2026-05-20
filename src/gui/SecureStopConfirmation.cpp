#include "gui/SecureStopConfirmation.h"

#include "common/secure_stop_confirmation.h"

namespace antivirus::gui {

bool confirmServiceStopOnSecureDesktop()
{
    return antivirus::common::confirmServiceStopOnSecureDesktop();
}

} // namespace antivirus::gui
