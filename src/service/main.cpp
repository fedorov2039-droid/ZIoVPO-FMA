#include "common/logging.h"
#include "service/ServiceMain.h"

#include <iostream>
#include <string_view>
#include <vector>

namespace {

bool has_argument(const std::vector<std::wstring_view>& args, std::wstring_view expected)
{
    for (const std::wstring_view arg : args) {
        if (arg == expected) {
            return true;
        }
    }

    return false;
}

} // namespace

int wmain(int argc, wchar_t* argv[])
{
    std::vector<std::wstring_view> args;
    args.reserve(static_cast<std::size_t>(argc));
    for (int i = 0; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }

    if (has_argument(args, L"--version")) {
        std::wcout << L"AntivirusService " << ANTIVIRUS_APP_VERSION << L"\n";
        return 0;
    }

    antivirus::common::log_info(L"Starting service");

    if (has_argument(args, L"--install")) {
        return antivirus::service::installService();
    }

    if (has_argument(args, L"--uninstall")) {
        return antivirus::service::uninstallService();
    }

    if (has_argument(args, L"--run-service")) {
        return antivirus::service::runService();
    }

    if (has_argument(args, L"--console")) {
        return antivirus::service::runConsole();
    }

    std::wcout << L"Usage: AntivirusService.exe --install | --uninstall | --run-service | --console | --version\n";
    return 0;
}
