#include "service/scan/ScanEngine.h"

#include "service/scan/AhoCorasickScanner.h"

#include <array>
#include <optional>
#include <vector>

namespace antivirus::service::scan {
namespace {

bool readExactly(std::istream& input, std::streamoff offset, std::uint8_t* buffer, std::size_t size)
{
    input.clear();
    input.seekg(offset, std::ios::beg);
    if (!input.good()) {
        return false;
    }

    input.read(reinterpret_cast<char*>(buffer), static_cast<std::streamsize>(size));
    return static_cast<std::size_t>(input.gcount()) == size;
}

bool offsetMatches(std::uint64_t position, const AvRecord& record)
{
    return position >= record.offsetBegin && position <= record.offsetEnd;
}

} // namespace

ScanResult ScanEngine::scan(std::istream& input, ObjectType objectType, const AvDatabase& database) const
{
    ScanResult result;
    result.scanned = true;
    result.objectType = objectTypeToString(objectType);

    if (!database.loaded()) {
        result.error = L"Антивирусная база не загружена";
        return result;
    }

    if (objectType == ObjectType::Unknown) {
        result.error = L"Неподдерживаемый тип объекта";
        return result;
    }

    input.clear();
    input.seekg(0, std::ios::end);
    const std::streamoff fileSize = input.tellg();
    if (fileSize < 8) {
        return result;
    }

    AhoCorasickScanner ahoScanner;
    ahoScanner.buildFromDatabase(database);
    if (!ahoScanner.empty()) {
        std::optional<ScanResult> ahoResult = ahoScanner.scan(input, objectType);
        if (ahoResult.has_value()) {
            return ahoResult.value();
        }
    }

    // Поиск через std::map оставлен как fallback и как выполнение требования 2.4
    // про красно-чёрное дерево по префиксу сигнатуры.
    for (std::streamoff position = 0; position <= fileSize - 8; ++position) {
        std::array<std::uint8_t, 8> prefixBytes{};
        if (!readExactly(input, position, prefixBytes.data(), prefixBytes.size())) {
            break;
        }

        const std::uint64_t prefix = prefixFromBytes(prefixBytes);
        const auto found = database.recordsByPrefix().find(prefix);
        if (found == database.recordsByPrefix().end()) {
            continue;
        }

        for (const AvRecord& record : found->second) {
            if (record.objectType != objectType) {
                continue;
            }

            if (!offsetMatches(static_cast<std::uint64_t>(position), record)) {
                continue;
            }

            if (record.objectSignatureLength < 8) {
                continue;
            }

            const std::size_t tailLength = static_cast<std::size_t>(record.objectSignatureLength - 8);
            if (position + static_cast<std::streamoff>(record.objectSignatureLength) > fileSize) {
                continue;
            }

            std::vector<std::uint8_t> candidate;
            candidate.reserve(record.objectSignatureLength);
            candidate.insert(candidate.end(), prefixBytes.begin(), prefixBytes.end());

            if (tailLength > 0) {
                std::vector<std::uint8_t> tail(tailLength);
                if (!readExactly(input, position + 8, tail.data(), tail.size())) {
                    continue;
                }

                candidate.insert(candidate.end(), tail.begin(), tail.end());
            }

            if (demoHash32(candidate) != record.objectSignature) {
                continue;
            }

            result.malicious = true;
            result.threatName = record.threatName;
            result.detectionOffset = static_cast<std::uint64_t>(position);
            return result;
        }
    }

    return result;
}

} // namespace antivirus::service::scan
