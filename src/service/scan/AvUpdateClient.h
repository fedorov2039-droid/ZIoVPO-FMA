#pragma once

#include "service/scan/AvDatabaseStorage.h"

#include <filesystem>

namespace antivirus::service::scan {

class AvUpdateClient final {
public:
    AvUpdateClient();

    [[nodiscard]] std::filesystem::path serverDirectory() const;
    [[nodiscard]] std::filesystem::path serverDatabasePath() const;
    [[nodiscard]] AvDatabaseLoadResult fetchDatabase() const;

private:
    std::filesystem::path serverDirectory_;
};

} // namespace antivirus::service::scan
