#include "service/scan/AvDatabase.h"

#include <algorithm>
#include <cstring>

namespace antivirus::service::scan {
namespace {

std::array<std::uint8_t, 8> firstEightBytes(const std::vector<std::uint8_t>& signature)
{
    std::array<std::uint8_t, 8> result{};
    for (std::size_t index = 0; index < result.size() && index < signature.size(); ++index) {
        result[index] = signature[index];
    }
    return result;
}

void appendUint64(std::vector<std::uint8_t>& bytes, std::uint64_t value)
{
    for (int shift = 56; shift >= 0; shift -= 8) {
        bytes.push_back(static_cast<std::uint8_t>((value >> shift) & 0xff));
    }
}

void appendUint32(std::vector<std::uint8_t>& bytes, std::uint32_t value)
{
    for (int shift = 24; shift >= 0; shift -= 8) {
        bytes.push_back(static_cast<std::uint8_t>((value >> shift) & 0xff));
    }
}

std::vector<std::uint8_t> asciiBytes(const char* text)
{
    std::vector<std::uint8_t> result;
    while (*text != '\0') {
        result.push_back(static_cast<std::uint8_t>(*text));
        ++text;
    }
    return result;
}

std::array<std::uint8_t, 32> signRecordFields(const AvRecord& record)
{
    std::vector<std::uint8_t> bytes;
    appendUint64(bytes, record.objectSignaturePrefix);
    appendUint32(bytes, record.objectSignatureLength);

    bytes.insert(bytes.end(), record.objectSignature.begin(), record.objectSignature.end());

    appendUint64(bytes, record.offsetBegin);
    appendUint64(bytes, record.offsetEnd);
    appendUint32(bytes, static_cast<std::uint32_t>(record.objectType));

    return demoHash32(bytes);
}

AvRecord makeRecord(const char* signatureText,
                    std::uint64_t offsetBegin,
                    std::uint64_t offsetEnd,
                    ObjectType objectType,
                    std::wstring threatName)
{
    const std::vector<std::uint8_t> signature = asciiBytes(signatureText);
    const std::array<std::uint8_t, 8> prefixBytes = firstEightBytes(signature);

    AvRecord record;
    record.objectSignaturePrefix = prefixFromBytes(prefixBytes);
    record.objectSignatureLength = static_cast<std::uint32_t>(signature.size());
    record.objectSignature = demoHash32(signature);
    record.offsetBegin = offsetBegin;
    record.offsetEnd = offsetEnd;
    record.objectType = objectType;
    record.threatName = std::move(threatName);
    record.avRecordSignature = signRecordFields(record);

    return record;
}

} // namespace

std::uint64_t prefixFromBytes(const std::array<std::uint8_t, 8>& bytes)
{
    std::uint64_t result = 0;
    for (const std::uint8_t byte : bytes) {
        result <<= 8;
        result |= byte;
    }
    return result;
}

std::array<std::uint8_t, 32> demoHash32(const std::vector<std::uint8_t>& bytes)
{
    std::array<std::uint8_t, 32> result{};

    std::uint64_t hash = 14695981039346656037ull;
    for (const std::uint8_t byte : bytes) {
        hash ^= byte;
        hash *= 1099511628211ull;
    }

    for (std::size_t block = 0; block < 4; ++block) {
        std::uint64_t mixed = hash ^ (0x9e3779b97f4a7c15ull * static_cast<std::uint64_t>(block + 1));
        mixed ^= static_cast<std::uint64_t>(bytes.size()) << ((block * 7) % 24);

        for (std::size_t index = 0; index < 8; ++index) {
            result[block * 8 + index] = static_cast<std::uint8_t>((mixed >> (56 - index * 8)) & 0xff);
        }
    }

    return result;
}

std::wstring objectTypeToString(ObjectType type)
{
    switch (type) {
    case ObjectType::PeFile:
        return L"PE file";
    case ObjectType::PowerShellScript:
        return L"PowerShell script";
    default:
        return L"Unknown";
    }
}

void AvDatabase::loadDemoDatabase()
{
    recordsByPrefix_.clear();

    const AvRecord peRecord = makeRecord(
        "MZAVGUI-PE-TEST",
        0,
        512,
        ObjectType::PeFile,
        L"Demo.Test.PE.Signature"
    );

    const AvRecord powerShellRecord = makeRecord(
        "Invoke-AvGuiTest",
        0,
        4096,
        ObjectType::PowerShellScript,
        L"Demo.Test.PowerShell.Signature"
    );

    recordsByPrefix_[peRecord.objectSignaturePrefix].push_back(peRecord);
    recordsByPrefix_[powerShellRecord.objectSignaturePrefix].push_back(powerShellRecord);

    releaseDate_ = L"2026-05-08";
    loaded_ = true;
}

void AvDatabase::clear()
{
    recordsByPrefix_.clear();
    releaseDate_.clear();
    loaded_ = false;
}

bool AvDatabase::loaded() const
{
    return loaded_;
}

std::wstring AvDatabase::releaseDate() const
{
    return releaseDate_;
}

std::size_t AvDatabase::recordCount() const
{
    std::size_t total = 0;
    for (const auto& [prefix, records] : recordsByPrefix_) {
        (void)prefix;
        total += records.size();
    }
    return total;
}

const std::map<std::uint64_t, std::vector<AvRecord>>& AvDatabase::recordsByPrefix() const
{
    return recordsByPrefix_;
}

} // namespace antivirus::service::scan
