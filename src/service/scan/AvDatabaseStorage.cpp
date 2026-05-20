#include "service/scan/AvDatabaseStorage.h"

#include <array>
#include <fstream>
#include <limits>
#include <system_error>
#include <windows.h>

namespace antivirus::service::scan {
namespace {

constexpr std::array<char, 4> kMagic = {'A', 'V', 'D', 'B'};
constexpr std::uint32_t kVersion = 1;
constexpr std::uint32_t kMaxReleaseDateChars = 256;
constexpr std::uint32_t kMaxThreatNameChars = 256;
constexpr std::uint32_t kMaxRecordCount = 100000;

std::filesystem::path programDataDirectory()
{
    std::array<wchar_t, MAX_PATH> buffer{};
    const DWORD length = GetEnvironmentVariableW(L"ProgramData", buffer.data(), static_cast<DWORD>(buffer.size()));

    if (length > 0 && length < buffer.size()) {
        return std::filesystem::path(buffer.data());
    }

    return std::filesystem::path(L"C:\\ProgramData");
}

void writeUint32(std::ofstream& output, std::uint32_t value)
{
    output.write(reinterpret_cast<const char*>(&value), sizeof(value));
}

void writeUint64(std::ofstream& output, std::uint64_t value)
{
    output.write(reinterpret_cast<const char*>(&value), sizeof(value));
}

void writeBytes(std::ofstream& output, const std::array<std::uint8_t, 32>& bytes)
{
    output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

void writeWideString(std::ofstream& output, const std::wstring& value)
{
    writeUint32(output, static_cast<std::uint32_t>(value.size()));

    for (const wchar_t ch : value) {
        const auto codeUnit = static_cast<std::uint16_t>(ch);
        output.write(reinterpret_cast<const char*>(&codeUnit), sizeof(codeUnit));
    }
}

bool readUint32(std::ifstream& input, std::uint32_t& value)
{
    input.read(reinterpret_cast<char*>(&value), sizeof(value));
    return input.gcount() == sizeof(value);
}

bool readUint64(std::ifstream& input, std::uint64_t& value)
{
    input.read(reinterpret_cast<char*>(&value), sizeof(value));
    return input.gcount() == sizeof(value);
}

bool readBytes(std::ifstream& input, std::array<std::uint8_t, 32>& bytes)
{
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return input.gcount() == static_cast<std::streamsize>(bytes.size());
}

bool readWideString(std::ifstream& input, std::uint32_t maxChars, std::wstring& value)
{
    std::uint32_t length = 0;
    if (!readUint32(input, length)) {
        return false;
    }

    if (length > maxChars) {
        return false;
    }

    value.clear();
    value.reserve(length);

    for (std::uint32_t index = 0; index < length; ++index) {
        std::uint16_t codeUnit = 0;
        input.read(reinterpret_cast<char*>(&codeUnit), sizeof(codeUnit));
        if (input.gcount() != sizeof(codeUnit)) {
            return false;
        }

        value.push_back(static_cast<wchar_t>(codeUnit));
    }

    return true;
}

void writeRecord(std::ofstream& output, AvRecord record)
{
    record.avRecordSignature = signAvRecord(record);

    writeUint64(output, record.objectSignaturePrefix);
    writeUint32(output, record.objectSignatureLength);
    writeBytes(output, record.objectSignature);
    writeUint64(output, record.offsetBegin);
    writeUint64(output, record.offsetEnd);
    writeUint32(output, static_cast<std::uint32_t>(record.objectType));
    writeWideString(output, record.threatName);
    writeBytes(output, record.avRecordSignature);
}

bool readRecord(std::ifstream& input, AvRecord& record)
{
    std::uint32_t objectTypeValue = 0;

    if (!readUint64(input, record.objectSignaturePrefix)) {
        return false;
    }

    if (!readUint32(input, record.objectSignatureLength)) {
        return false;
    }

    if (!readBytes(input, record.objectSignature)) {
        return false;
    }

    if (!readUint64(input, record.offsetBegin)) {
        return false;
    }

    if (!readUint64(input, record.offsetEnd)) {
        return false;
    }

    if (!readUint32(input, objectTypeValue)) {
        return false;
    }

    record.objectType = static_cast<ObjectType>(objectTypeValue);

    if (!readWideString(input, kMaxThreatNameChars, record.threatName)) {
        return false;
    }

    if (!readBytes(input, record.avRecordSignature)) {
        return false;
    }

    return true;
}

} // namespace

AvDatabaseStorage::AvDatabaseStorage()
    : baseDirectory_(programDataDirectory() / L"AntivirusGui" / L"bases")
{
}

std::filesystem::path AvDatabaseStorage::databasePath() const
{
    return baseDirectory_ / L"avdb.bin";
}

std::filesystem::path AvDatabaseStorage::backupPath() const
{
    return baseDirectory_ / L"avdb.bak";
}

std::filesystem::path AvDatabaseStorage::baseDirectory() const
{
    return baseDirectory_;
}

AvDatabaseLoadResult AvDatabaseStorage::loadOrRecover() const
{
    std::error_code errorCode;
    std::filesystem::create_directories(baseDirectory_, errorCode);

    AvDatabaseLoadResult primary = loadSingleFile(databasePath());
    if (primary.loaded) {
        return primary;
    }

    AvDatabaseLoadResult backup = loadSingleFile(backupPath());
    if (backup.loaded) {
        backup.recoveredFromBackup = true;
        backup.message = L"Primary antivirus database is invalid; recovered from backup";

        std::filesystem::copy_file(backupPath(),
                                   databasePath(),
                                   std::filesystem::copy_options::overwrite_existing,
                                   errorCode);
        return backup;
    }

    writeDefaultDatabase();

    AvDatabaseLoadResult fallback = loadSingleFile(databasePath());
    fallback.usedDefaultDatabase = true;

    if (fallback.loaded) {
        fallback.message = L"Primary and backup antivirus databases are invalid; loaded default database";
    } else {
        fallback.message = L"Failed to load primary, backup, and default antivirus databases";
    }

    return fallback;
}

bool AvDatabaseStorage::writeDefaultDatabase() const
{
    return writeDatabaseFile(databasePath(), L"2026-05-08 default", makeDemoRecords());
}

bool AvDatabaseStorage::backupCurrentDatabase() const
{
    std::error_code errorCode;
    std::filesystem::create_directories(baseDirectory_, errorCode);

    if (!std::filesystem::exists(databasePath(), errorCode)) {
        return false;
    }

    return std::filesystem::copy_file(databasePath(),
                                      backupPath(),
                                      std::filesystem::copy_options::overwrite_existing,
                                      errorCode);
}

bool AvDatabaseStorage::writeDatabase(const std::wstring& releaseDate, const std::vector<AvRecord>& records) const
{
    return writeDatabaseFile(databasePath(), releaseDate, records);
}

bool AvDatabaseStorage::writeDatabaseFile(const std::filesystem::path& path,
                                          const std::wstring& releaseDate,
                                          const std::vector<AvRecord>& records) const
{
    std::error_code errorCode;
    std::filesystem::create_directories(path.parent_path(), errorCode);

    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output.is_open()) {
        return false;
    }

    output.write(kMagic.data(), static_cast<std::streamsize>(kMagic.size()));
    writeUint32(output, kVersion);
    writeWideString(output, releaseDate);
    writeUint32(output, static_cast<std::uint32_t>(records.size()));

    const std::array<std::uint8_t, 32> manifestSignature = signManifest(releaseDate, records.size());
    writeBytes(output, manifestSignature);

    for (const AvRecord& record : records) {
        writeRecord(output, record);
    }

    return output.good();
}

AvDatabaseLoadResult AvDatabaseStorage::loadSingleFile(const std::filesystem::path& path) const
{
    AvDatabaseLoadResult result;

    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        result.message = L"Antivirus database file is not available";
        return result;
    }

    std::array<char, 4> magic{};
    input.read(magic.data(), static_cast<std::streamsize>(magic.size()));
    if (input.gcount() != static_cast<std::streamsize>(magic.size()) || magic != kMagic) {
        result.message = L"Invalid antivirus database magic";
        return result;
    }

    std::uint32_t version = 0;
    if (!readUint32(input, version) || version != kVersion) {
        result.message = L"Unsupported antivirus database version";
        return result;
    }

    if (!readWideString(input, kMaxReleaseDateChars, result.releaseDate)) {
        result.message = L"Invalid antivirus database release date";
        return result;
    }

    std::uint32_t declaredRecordCount = 0;
    if (!readUint32(input, declaredRecordCount) || declaredRecordCount > kMaxRecordCount) {
        result.message = L"Invalid antivirus database record count";
        return result;
    }

    std::array<std::uint8_t, 32> storedManifestSignature{};
    if (!readBytes(input, storedManifestSignature)) {
        result.message = L"Invalid antivirus database manifest signature";
        return result;
    }

    const std::array<std::uint8_t, 32> expectedManifestSignature = signManifest(result.releaseDate, declaredRecordCount);
    if (storedManifestSignature != expectedManifestSignature) {
        result.message = L"Antivirus database manifest signature verification failed";
        return result;
    }

    for (std::uint32_t index = 0; index < declaredRecordCount; ++index) {
        AvRecord record;
        if (!readRecord(input, record)) {
            result.message = L"Antivirus database record read failed";
            return result;
        }

        const std::array<std::uint8_t, 32> expectedRecordSignature = signAvRecord(record);
        if (record.avRecordSignature != expectedRecordSignature) {
            continue;
        }

        result.records.push_back(record);
    }

    result.loaded = true;
    result.message = L"Antivirus database loaded from disk";
    return result;
}

} // namespace antivirus::service::scan
