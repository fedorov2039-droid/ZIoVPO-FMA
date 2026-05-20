#pragma once

#include "service/scan/AvDatabase.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace antivirus::service::scan {

enum class AvDatabaseLoadError {
    None = 0,
    FileNotFound,
    InvalidMagic,
    InvalidVersion,
    InvalidReleaseDate,
    InvalidRecordCount,
    InvalidManifestSignature,
    InvalidRecordSignature,
    RecordReadFailed,
};

struct AvDatabaseLoadResult {
    bool loaded = false;
    bool recoveredFromBackup = false;
    bool usedDefaultDatabase = false;
    bool repairedFromMockUpdateServer = false;
    bool mockUpdateServerUnavailable = false;
    std::uint32_t skippedRecordCount = 0;
    AvDatabaseLoadError error = AvDatabaseLoadError::None;
    AvDatabaseLoadError primaryError = AvDatabaseLoadError::None;
    std::wstring releaseDate;
    std::vector<AvRecord> records;
    std::vector<AvRecord> corruptedRecords;
    std::wstring message;
    std::vector<std::wstring> events;
};

class AvDatabaseStorage final {
public:
    AvDatabaseStorage();
    explicit AvDatabaseStorage(std::filesystem::path baseDirectory);

    [[nodiscard]] std::filesystem::path databasePath() const;
    [[nodiscard]] std::filesystem::path backupPath() const;
    [[nodiscard]] std::filesystem::path baseDirectory() const;

    [[nodiscard]] AvDatabaseLoadResult loadOrRecover() const;
    [[nodiscard]] AvDatabaseLoadResult loadDatabaseFile(const std::filesystem::path& path) const;
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
