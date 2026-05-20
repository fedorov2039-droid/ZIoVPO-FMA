#pragma once

#include "service/scan/AvDatabase.h"
#include "service/scan/ScanEngine.h"

#include <array>
#include <cstdint>
#include <istream>
#include <optional>
#include <vector>

namespace antivirus::service::scan {

struct AhoCorasickPattern {
    std::vector<std::uint8_t> bytes;
    AvRecord record;
};

class AhoCorasickScanner final {
public:
    void build(const std::vector<AhoCorasickPattern>& patterns);
    void buildFromDatabase(const AvDatabase& database);
    [[nodiscard]] bool empty() const;

    [[nodiscard]] std::optional<ScanResult> scan(std::istream& input, ObjectType objectType) const;

private:
    struct Node {
        std::array<int, 256> next{};
        int failure = 0;
        std::vector<std::size_t> outputs;

        Node();
    };

    [[nodiscard]] std::optional<ScanResult> resultForPattern(std::size_t patternIndex,
                                                             ObjectType objectType,
                                                             std::uint64_t matchEndOffset) const;

    std::vector<Node> nodes_;
    std::vector<AhoCorasickPattern> patterns_;
};

} // namespace antivirus::service::scan
