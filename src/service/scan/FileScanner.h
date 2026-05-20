#pragma once

#include "service/scan/AvDatabase.h"
#include "service/scan/ScanEngine.h"

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace antivirus::service::scan {

struct FileScanReport {
    std::filesystem::path path;
    ScanResult result;
};

struct DirectoryScanReport {
    std::size_t scannedFiles = 0;
    std::size_t maliciousFiles = 0;
    std::vector<FileScanReport> detections;
    std::wstring error;
};

class FileScanner final {
public:
    [[nodiscard]] FileScanReport scanFile(const std::filesystem::path& path, const AvDatabase& database) const;
    [[nodiscard]] DirectoryScanReport scanDirectory(const std::filesystem::path& path, const AvDatabase& database) const;

private:
    [[nodiscard]] ObjectType detectObjectType(const std::filesystem::path& path) const;
};

} // namespace antivirus::service::scan
