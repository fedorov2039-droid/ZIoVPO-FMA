#pragma once

#include "service/scan/AvDatabase.h"

#include <filesystem>
#include <string>
#include <vector>

namespace antivirus::service::scan {

struct AvDatabaseLoadResult {
    bool loaded = false;
    bool recoveredFromBackup = false;
    bool usedDefaultDatabase = false;
    std::wstring releaseDate;
    std::vector<AvRecord> records;
    std::wstring message;
};

class AvDatabaseStorage final {
public:
    AvDatabaseStorage();

    [[nodiscard]] std::filesystem::path databasePath() const;
    [[nodiscard]] std::filesystem::path backupPath() const;
    [[nodiscard]] std::filesystem::path baseDirectory() const;

    [[nodiscard]] AvDatabaseLoadResult loadOrRecover() const;
    [[nodiscard]] bool writeDefaultDatabase() const;
    [[nodiscard]] bool backupCurrentDatabase() const;
    [[nodiscard]] bool writeDatabase(const std::wstring& releaseDate, const std::vector<AvRecord>& records) const;

private:
    [[nodiscard]] AvDatabaseLoadResult loadSingleFile(const std::filesystem::path& path) const;
    [[nodiscard]] bool writeDatabaseFile(const std::filesystem::path& path,
                                         const std::wstring& releaseDate,
                                         const std::vector<AvRecord>& records) const;

    std::filesystem::path baseDirectory_;
};

} // namespace antivirus::service::scan
