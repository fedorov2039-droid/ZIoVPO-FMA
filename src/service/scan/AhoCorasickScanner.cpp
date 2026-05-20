#include "service/scan/AhoCorasickScanner.h"

#include <queue>

namespace antivirus::service::scan {
namespace {

constexpr int kMissingTransition = -1;
constexpr std::size_t kAlphabetSize = 256;

bool offsetMatches(std::uint64_t position, const AvRecord& record)
{
    return position >= record.offsetBegin && position <= record.offsetEnd;
}

bool prefixMatches(const std::vector<std::uint8_t>& bytes, const AvRecord& record)
{
    if (bytes.size() < 8) {
        return false;
    }

    std::array<std::uint8_t, 8> prefixBytes{};
    for (std::size_t index = 0; index < prefixBytes.size(); ++index) {
        prefixBytes[index] = bytes[index];
    }

    return prefixFromBytes(prefixBytes) == record.objectSignaturePrefix;
}

} // namespace

AhoCorasickScanner::Node::Node()
{
    next.fill(kMissingTransition);
}

void AhoCorasickScanner::build(const std::vector<AhoCorasickPattern>& patterns)
{
    nodes_.clear();
    patterns_.clear();
    nodes_.emplace_back();

    for (const AhoCorasickPattern& pattern : patterns) {
        if (pattern.bytes.empty()) {
            continue;
        }

        const std::size_t patternIndex = patterns_.size();
        patterns_.push_back(pattern);

        int state = 0;
        for (const std::uint8_t byte : pattern.bytes) {
            int nextState = nodes_[static_cast<std::size_t>(state)].next[byte];
            if (nextState == kMissingTransition) {
                nextState = static_cast<int>(nodes_.size());
                nodes_[static_cast<std::size_t>(state)].next[byte] = nextState;
                nodes_.emplace_back();
            }

            state = nextState;
        }

        nodes_[static_cast<std::size_t>(state)].outputs.push_back(patternIndex);
    }

    // Рёбра trie соответствуют байтам сигнатур. Failure-ссылки позволяют автомату
    // переиспользовать уже найденный длинный суффикс вместо полного перезапуска поиска.
    std::queue<int> queue;
    for (std::size_t byte = 0; byte < kAlphabetSize; ++byte) {
        const int child = nodes_[0].next[byte];
        if (child == kMissingTransition) {
            continue;
        }

        nodes_[static_cast<std::size_t>(child)].failure = 0;
        queue.push(child);
    }

    while (!queue.empty()) {
        const int state = queue.front();
        queue.pop();

        for (std::size_t byte = 0; byte < kAlphabetSize; ++byte) {
            const int child = nodes_[static_cast<std::size_t>(state)].next[byte];
            if (child == kMissingTransition) {
                continue;
            }

            int fallback = nodes_[static_cast<std::size_t>(state)].failure;
            while (fallback != 0 && nodes_[static_cast<std::size_t>(fallback)].next[byte] == kMissingTransition) {
                fallback = nodes_[static_cast<std::size_t>(fallback)].failure;
            }

            const int fallbackTransition = nodes_[static_cast<std::size_t>(fallback)].next[byte];
            nodes_[static_cast<std::size_t>(child)].failure =
                fallbackTransition == kMissingTransition ? 0 : fallbackTransition;

            const std::vector<std::size_t>& inheritedOutputs =
                nodes_[static_cast<std::size_t>(nodes_[static_cast<std::size_t>(child)].failure)].outputs;
            nodes_[static_cast<std::size_t>(child)].outputs.insert(nodes_[static_cast<std::size_t>(child)].outputs.end(),
                                                                   inheritedOutputs.begin(),
                                                                   inheritedOutputs.end());

            queue.push(child);
        }
    }
}

void AhoCorasickScanner::buildFromDatabase(const AvDatabase& database)
{
    std::vector<AhoCorasickPattern> patterns;

    for (const AvRecord& record : database.allRecords()) {
        std::optional<std::vector<std::uint8_t>> rawSignature = demoRawSignatureForRecord(record);
        if (!rawSignature.has_value()) {
            continue;
        }

        patterns.push_back(AhoCorasickPattern{
            .bytes = std::move(rawSignature.value()),
            .record = record,
        });
    }

    build(patterns);
}

bool AhoCorasickScanner::empty() const
{
    return patterns_.empty();
}

std::optional<ScanResult> AhoCorasickScanner::scan(std::istream& input, ObjectType objectType) const
{
    if (empty()) {
        return std::nullopt;
    }

    input.clear();
    input.seekg(0, std::ios::beg);
    if (!input.good()) {
        return std::nullopt;
    }

    int state = 0;
    std::uint64_t offset = 0;
    char ch = '\0';

    while (input.get(ch)) {
        const auto byte = static_cast<std::uint8_t>(ch);

        while (state != 0 && nodes_[static_cast<std::size_t>(state)].next[byte] == kMissingTransition) {
            state = nodes_[static_cast<std::size_t>(state)].failure;
        }

        const int nextState = nodes_[static_cast<std::size_t>(state)].next[byte];
        state = nextState == kMissingTransition ? 0 : nextState;

        for (const std::size_t patternIndex : nodes_[static_cast<std::size_t>(state)].outputs) {
            std::optional<ScanResult> result = resultForPattern(patternIndex, objectType, offset);
            if (result.has_value()) {
                return result;
            }
        }

        ++offset;
    }

    return std::nullopt;
}

std::optional<ScanResult> AhoCorasickScanner::resultForPattern(std::size_t patternIndex,
                                                               ObjectType objectType,
                                                               std::uint64_t matchEndOffset) const
{
    if (patternIndex >= patterns_.size()) {
        return std::nullopt;
    }

    const AhoCorasickPattern& pattern = patterns_[patternIndex];
    const AvRecord& record = pattern.record;

    if (record.objectType != objectType) {
        return std::nullopt;
    }

    if (pattern.bytes.size() != record.objectSignatureLength || pattern.bytes.size() < 8) {
        return std::nullopt;
    }

    const std::uint64_t detectionOffset = matchEndOffset + 1 - static_cast<std::uint64_t>(pattern.bytes.size());
    if (!offsetMatches(detectionOffset, record)) {
        return std::nullopt;
    }

    if (!prefixMatches(pattern.bytes, record) || demoHash32(pattern.bytes) != record.objectSignature) {
        return std::nullopt;
    }

    ScanResult result;
    result.scanned = true;
    result.malicious = true;
    result.threatName = record.threatName;
    result.objectType = objectTypeToString(objectType);
    result.detectionOffset = detectionOffset;
    return result;
}

} // namespace antivirus::service::scan
