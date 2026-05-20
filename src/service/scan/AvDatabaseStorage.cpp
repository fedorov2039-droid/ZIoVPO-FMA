#include "service/scan/AvDatabaseStorage.h"

#include "service/scan/AvUpdateClient.h"

#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
#include <system_error>
#include <utility>
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

bool sameRecordIdentity(const AvRecord& left, const AvRecord& right)
{
    return left.objectSignaturePrefix == right.objectSignaturePrefix
        && left.objectSignatureLength == right.objectSignatureLength
        && left.objectSignature == right.objectSignature
        && left.offsetBegin == right.offsetBegin
        && left.offsetEnd == right.offsetEnd
        && left.objectType == right.objectType
        && left.threatName == right.threatName;
}

std::vector<AvRecord> replaceCorruptedRecordsFromServer(const AvDatabaseLoadResult& primary,
                                                        const AvDatabaseLoadResult& server,
                                                        std::uint32_t& repairedCount)
{
    std::vector<AvRecord> repairedRecords = primary.records;
    repairedCount = 0;

    for (const AvRecord& corruptedRecord : primary.corruptedRecords) {
        const auto found = std::find_if(server.records.begin(), server.records.end(), [&](const AvRecord& serverRecord) {
            return sameRecordIdentity(corruptedRecord, serverRecord);
        });

        if (found == server.records.end()) {
            continue;
        }

        repairedRecords.push_back(*found);
        ++repairedCount;
    }

    return repairedRecords;
}

} // namespace

AvDatabaseStorage::AvDatabaseStorage()
    : baseDirectory_(programDataDirectory() / L"AntivirusGui" / L"bases")
{
}

AvDatabaseStorage::AvDatabaseStorage(std::filesystem::path baseDirectory)
    : baseDirectory_(std::move(baseDirectory))
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
    (void)std::filesystem::create_directories(baseDirectory_, errorCode);

    AvDatabaseLoadResult primary = loadSingleFile(databasePath());
    if (primary.loaded && primary.skippedRecordCount == 0) {
        return primary;
    }

    std::vector<std::wstring> events;
    events.push_back(L"Основная база повреждена");

    if (primary.error == AvDatabaseLoadError::InvalidManifestSignature) {
        events.push_back(L"Подпись манифеста неверна; выполняется принудительное обновление с демо-сервера обновлений");
    }

    if (primary.loaded && primary.skippedRecordCount > 0) {
        events.push_back(L"Найдены повреждённые записи базы; запрошены замены с демо-сервера обновлений");
    }

    events.push_back(L"Попытка восстановить базу через демо-сервер обновлений");

    const AvUpdateClient updateClient;
    AvDatabaseLoadResult server = updateClient.fetchDatabase();
    if (server.loaded) {
        if (primary.loaded && primary.skippedRecordCount > 0) {
            std::uint32_t repairedCount = 0;
            std::vector<AvRecord> repairedRecords = replaceCorruptedRecordsFromServer(primary, server, repairedCount);

            if (repairedCount == primary.skippedRecordCount) {
                AvDatabaseLoadResult repaired = primary;
                repaired.loaded = true;
                repaired.repairedFromMockUpdateServer = true;
                repaired.primaryError = primary.error;
                repaired.skippedRecordCount = 0;
                repaired.error = AvDatabaseLoadError::None;
                repaired.records = std::move(repairedRecords);
                repaired.corruptedRecords.clear();
                repaired.events = events;
                repaired.events.push_back(L"Повреждённые записи восстановлены через демо-сервер обновлений");
                repaired.message = L"Повреждённые записи базы запрошены и восстановлены через демо-сервер обновлений";

                if (!writeDatabase(repaired.releaseDate, repaired.records)) {
                    repaired.events.push_back(L"Не удалось записать восстановленную базу в основной файл");
                }

                return repaired;
            }

            events.push_back(L"Демо-сервер обновлений не содержит все записи для замены; база заменяется целиком");
        }

        server.repairedFromMockUpdateServer = true;
        server.primaryError = primary.error;
        server.events = events;
        server.events.push_back(L"База восстановлена через демо-сервер обновлений");
        server.message = L"База восстановлена через демо-сервер обновлений";

        if (!writeDatabase(server.releaseDate, server.records)) {
            server.events.push_back(L"Не удалось записать восстановленную базу в основной файл");
        }

        return server;
    }

    events.push_back(server.mockUpdateServerUnavailable ? L"Демо-сервер обновлений недоступен"
                                                        : L"База демо-сервера обновлений повреждена");

    AvDatabaseLoadResult backup = loadSingleFile(backupPath());
    if (backup.loaded) {
        backup.recoveredFromBackup = true;
        backup.primaryError = primary.error;
        backup.events = events;
        backup.events.push_back(L"Восстановлено из резервной копии");
        backup.message = L"Основная антивирусная база повреждена; выполнено восстановление из резервной копии";

        (void)std::filesystem::copy_file(backupPath(),
                                         databasePath(),
                                         std::filesystem::copy_options::overwrite_existing,
                                         errorCode);
        return backup;
    }

    (void)writeDefaultDatabase();

    AvDatabaseLoadResult fallback = loadSingleFile(databasePath());
    fallback.usedDefaultDatabase = true;
    fallback.primaryError = primary.error;
    fallback.events = events;

    if (fallback.loaded) {
        fallback.events.push_back(L"Загружена база по умолчанию");
        fallback.message = L"Основная и резервная базы повреждены; загружена база по умолчанию";
    } else {
        fallback.message = L"Не удалось загрузить основную, резервную базу и базу по умолчанию";
    }

    return fallback;
}

AvDatabaseLoadResult AvDatabaseStorage::loadDatabaseFile(const std::filesystem::path& path) const
{
    return loadSingleFile(path);
}

bool AvDatabaseStorage::writeDefaultDatabase() const
{
    return writeDatabaseFile(databasePath(), L"2026-05-08 база по умолчанию", makeDemoRecords());
}

bool AvDatabaseStorage::backupCurrentDatabase() const
{
    std::error_code errorCode;
    (void)std::filesystem::create_directories(baseDirectory_, errorCode);

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
    (void)std::filesystem::create_directories(path.parent_path(), errorCode);

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
        result.error = AvDatabaseLoadError::FileNotFound;
        result.message = L"Файл антивирусной базы недоступен";
        return result;
    }

    std::array<char, 4> magic{};
    input.read(magic.data(), static_cast<std::streamsize>(magic.size()));
    if (input.gcount() != static_cast<std::streamsize>(magic.size()) || magic != kMagic) {
        result.error = AvDatabaseLoadError::InvalidMagic;
        result.message = L"Некорректный magic антивирусной базы";
        return result;
    }

    std::uint32_t version = 0;
    if (!readUint32(input, version) || version != kVersion) {
        result.error = AvDatabaseLoadError::InvalidVersion;
        result.message = L"Неподдерживаемая версия антивирусной базы";
        return result;
    }

    if (!readWideString(input, kMaxReleaseDateChars, result.releaseDate)) {
        result.error = AvDatabaseLoadError::InvalidReleaseDate;
        result.message = L"Некорректная дата выпуска антивирусной базы";
        return result;
    }

    std::uint32_t declaredRecordCount = 0;
    if (!readUint32(input, declaredRecordCount) || declaredRecordCount > kMaxRecordCount) {
        result.error = AvDatabaseLoadError::InvalidRecordCount;
        result.message = L"Некорректное количество записей антивирусной базы";
        return result;
    }

    std::array<std::uint8_t, 32> storedManifestSignature{};
    if (!readBytes(input, storedManifestSignature)) {
        result.error = AvDatabaseLoadError::InvalidManifestSignature;
        result.message = L"Некорректная подпись манифеста антивирусной базы";
        return result;
    }

    const std::array<std::uint8_t, 32> expectedManifestSignature = signManifest(result.releaseDate, declaredRecordCount);
    if (storedManifestSignature != expectedManifestSignature) {
        result.error = AvDatabaseLoadError::InvalidManifestSignature;
        result.message = L"Проверка подписи манифеста антивирусной базы не пройдена";
        return result;
    }

    for (std::uint32_t index = 0; index < declaredRecordCount; ++index) {
        AvRecord record;
        if (!readRecord(input, record)) {
            result.error = AvDatabaseLoadError::RecordReadFailed;
            result.message = L"Не удалось прочитать запись антивирусной базы";
            return result;
        }

        const std::array<std::uint8_t, 32> expectedRecordSignature = signAvRecord(record);
        if (record.avRecordSignature != expectedRecordSignature) {
            result.error = AvDatabaseLoadError::InvalidRecordSignature;
            ++result.skippedRecordCount;
            result.corruptedRecords.push_back(record);
            continue;
        }

        result.records.push_back(record);
    }

    result.loaded = true;
    if (result.skippedRecordCount > 0) {
        result.message = L"Антивирусная база загружена с диска, повреждённые записи пропущены";
    } else {
        result.error = AvDatabaseLoadError::None;
        result.message = L"Антивирусная база загружена с диска";
    }
    return result;
}

} // namespace antivirus::service::scan
