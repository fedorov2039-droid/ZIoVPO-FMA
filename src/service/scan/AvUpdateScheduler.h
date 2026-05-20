#pragma once

#include "service/scan/AvDatabaseStorage.h"

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

namespace antivirus::service::scan {

struct AvUpdateResult {
    bool updated = false;
    bool backupCreated = false;
    bool rolledBack = false;
    AvDatabaseLoadResult loadResult;
    std::wstring message;
};

using AvUpdateCallback = std::function<void(const AvUpdateResult&)>;

class AvUpdateScheduler final {
public:
    AvUpdateScheduler() = default;
    ~AvUpdateScheduler();

    AvUpdateScheduler(const AvUpdateScheduler&) = delete;
    AvUpdateScheduler& operator=(const AvUpdateScheduler&) = delete;

    void start(AvUpdateCallback callback);
    void stop();

    [[nodiscard]] AvUpdateResult runUpdateNow();

private:
    void workerLoop();
    [[nodiscard]] std::wstring scheduledReleaseDate() const;

    std::atomic_bool stopRequested_ = false;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::thread worker_;
    AvUpdateCallback callback_;
    AvDatabaseStorage storage_;
};

} // namespace antivirus::service::scan
