#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace antivirus::service::scan {

enum class ObjectType : std::uint32_t {
    Unknown = 0,
    PeFile = 1,
    PowerShellScript = 2,
};

struct AvRecord {
    std::uint64_t objectSignaturePrefix = 0;
    std::uint32_t objectSignatureLength = 0;
    std::array<std::uint8_t, 32> objectSignature{};
    std::uint64_t offsetBegin = 0;
    std::uint64_t offsetEnd = 0;
    ObjectType objectType = ObjectType::Unknown;
    std::array<std::uint8_t, 32> avRecordSignature{};
    std::wstring threatName;
};

class AvDatabase final {
public:
    void loadDemoDatabase();
    void clear();

    [[nodiscard]] bool loaded() const;
    [[nodiscard]] std::wstring releaseDate() const;
    [[nodiscard]] std::size_t recordCount() const;

    [[nodiscard]] const std::map<std::uint64_t, std::vector<AvRecord>>& recordsByPrefix() const;

private:
    bool loaded_ = false;
    std::wstring releaseDate_;
    std::map<std::uint64_t, std::vector<AvRecord>> recordsByPrefix_;
};

std::uint64_t prefixFromBytes(const std::array<std::uint8_t, 8>& bytes);
std::array<std::uint8_t, 32> demoHash32(const std::vector<std::uint8_t>& bytes);
std::wstring objectTypeToString(ObjectType type);

} // namespace antivirus::service::scan
