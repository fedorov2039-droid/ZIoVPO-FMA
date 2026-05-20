#pragma once

#include "service/scan/AvDatabase.h"

#include <cstdint>
#include <istream>
#include <string>

namespace antivirus::service::scan {

struct ScanResult {
    bool scanned = false;
    bool malicious = false;
    std::wstring threatName;
    std::wstring objectType;
    std::uint64_t detectionOffset = 0;
    std::wstring error;
};

class ScanEngine final {
public:
    [[nodiscard]] ScanResult scan(std::istream& input, ObjectType objectType, const AvDatabase& database) const;
};

} // namespace antivirus::service::scan
