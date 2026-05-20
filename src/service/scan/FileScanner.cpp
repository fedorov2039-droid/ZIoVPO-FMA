#include "service/scan/FileScanner.h"

#include <fstream>

namespace antivirus::service::scan {
namespace {

bool isPowerShellExtension(const std::filesystem::path& path)
{
    const std::wstring extension = path.extension().wstring();
    return extension == L".ps1" || extension == L".psm1" || extension == L".psd1";
}

bool hasMzHeader(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        return false;
    }

    char magic[2] = {};
    input.read(magic, sizeof(magic));

    return input.gcount() == sizeof(magic) && magic[0] == 'M' && magic[1] == 'Z';
}

} // namespace

FileScanReport FileScanner::scanFile(const std::filesystem::path& path, const AvDatabase& database) const
{
    FileScanReport report;
    report.path = path;

    std::error_code errorCode;
    if (!std::filesystem::exists(path, errorCode) || !std::filesystem::is_regular_file(path, errorCode)) {
        report.result.scanned = false;
        report.result.error = L"File does not exist or is not a regular file";
        return report;
    }

    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        report.result.scanned = false;
        report.result.error = L"Failed to open file";
        return report;
    }

    const ObjectType objectType = detectObjectType(path);
    const ScanEngine engine;
    report.result = engine.scan(input, objectType, database);

    return report;
}

DirectoryScanReport FileScanner::scanDirectory(const std::filesystem::path& path, const AvDatabase& database) const
{
    DirectoryScanReport report;

    std::error_code errorCode;
    if (!std::filesystem::exists(path, errorCode) || !std::filesystem::is_directory(path, errorCode)) {
        report.error = L"Directory does not exist";
        return report;
    }

    const std::filesystem::directory_options options = std::filesystem::directory_options::skip_permission_denied;

    for (std::filesystem::recursive_directory_iterator iterator(path, options, errorCode), end;
         iterator != end;
         iterator.increment(errorCode)) {
        if (errorCode) {
            errorCode.clear();
            continue;
        }

        if (!iterator->is_regular_file(errorCode)) {
            errorCode.clear();
            continue;
        }

        FileScanReport fileReport = scanFile(iterator->path(), database);
        if (fileReport.result.scanned) {
            ++report.scannedFiles;
        }

        if (fileReport.result.malicious) {
            ++report.maliciousFiles;
            report.detections.push_back(std::move(fileReport));
        }
    }

    return report;
}

ObjectType FileScanner::detectObjectType(const std::filesystem::path& path) const
{
    if (isPowerShellExtension(path)) {
        return ObjectType::PowerShellScript;
    }

    if (hasMzHeader(path)) {
        return ObjectType::PeFile;
    }

    return ObjectType::Unknown;
}

} // namespace antivirus::service::scan
