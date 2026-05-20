#pragma once

#include <condition_variable>
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>

namespace antivirus::service::scan {

struct DirectoryMonitorStatus {
    bool running = false;
    std::filesystem::path path;
    std::wstring lastError;
};

using DirectoryMonitorCallback = std::function<void(const std::filesystem::path&)>;

class DirectoryMonitor final {
public:
    DirectoryMonitor() = default;
    ~DirectoryMonitor();

    DirectoryMonitor(const DirectoryMonitor&) = delete;
    DirectoryMonitor& operator=(const DirectoryMonitor&) = delete;

    [[nodiscard]] bool start(const std::filesystem::path& path, DirectoryMonitorCallback callback);
    void stop();
    [[nodiscard]] DirectoryMonitorStatus status() const;

private:
    struct FileSnapshot {
        std::filesystem::file_time_type lastWriteTime{};
        std::uintmax_t size = 0;
    };

    void workerLoop(std::filesystem::path path, DirectoryMonitorCallback callback);
    void scanChangedFiles(const std::filesystem::path& path,
                          DirectoryMonitorCallback& callback,
                          std::map<std::filesystem::path, FileSnapshot>& knownFiles);
    void setLastError(std::wstring error);
    [[nodiscard]] bool stopRequested() const;

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::thread worker_;
    bool stopRequested_ = false;
    bool running_ = false;
    std::filesystem::path path_;
    std::wstring lastError_;
};

} // namespace antivirus::service::scan
