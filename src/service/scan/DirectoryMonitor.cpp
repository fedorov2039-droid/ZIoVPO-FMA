#include "service/scan/DirectoryMonitor.h"

#include <chrono>
#include <exception>

namespace antivirus::service::scan {
namespace {

constexpr auto kPollingInterval = std::chrono::seconds(2);

std::wstring exceptionText()
{
    try {
        throw;
    } catch (const std::exception& ex) {
        return std::wstring(ex.what(), ex.what() + std::char_traits<char>::length(ex.what()));
    } catch (...) {
        return L"Неизвестная ошибка мониторинга директории";
    }
}

} // namespace

DirectoryMonitor::~DirectoryMonitor()
{
    stop();
}

bool DirectoryMonitor::start(const std::filesystem::path& path, DirectoryMonitorCallback callback)
{
    if (!callback) {
        std::lock_guard lock(mutex_);
        lastError_ = L"Callback мониторинга директории не настроен";
        return false;
    }

    std::error_code errorCode;
    if (!std::filesystem::exists(path, errorCode) || !std::filesystem::is_directory(path, errorCode)) {
        std::lock_guard lock(mutex_);
        lastError_ = L"Директория не существует";
        return false;
    }

    std::lock_guard lock(mutex_);
    if (worker_.joinable()) {
        lastError_ = L"Мониторинг директории уже запущен";
        return false;
    }

    path_ = path;
    lastError_.clear();
    stopRequested_ = false;
    running_ = true;
    worker_ = std::thread(&DirectoryMonitor::workerLoop, this, path, std::move(callback));
    return true;
}

void DirectoryMonitor::stop()
{
    {
        std::lock_guard lock(mutex_);
        stopRequested_ = true;
    }

    cv_.notify_all();

    if (worker_.joinable()) {
        worker_.join();
    }

    std::lock_guard lock(mutex_);
    running_ = false;
    path_.clear();
}

DirectoryMonitorStatus DirectoryMonitor::status() const
{
    std::lock_guard lock(mutex_);
    return DirectoryMonitorStatus{
        .running = running_,
        .path = path_,
        .lastError = lastError_,
    };
}

void DirectoryMonitor::workerLoop(std::filesystem::path path, DirectoryMonitorCallback callback)
{
    std::map<std::filesystem::path, FileSnapshot> knownFiles;

    try {
        while (!stopRequested()) {
            scanChangedFiles(path, callback, knownFiles);

            std::unique_lock lock(mutex_);
            cv_.wait_for(lock, kPollingInterval, [this]() {
                return stopRequested_;
            });
        }
    } catch (...) {
        setLastError(exceptionText());
    }

    std::lock_guard lock(mutex_);
    running_ = false;
}

void DirectoryMonitor::scanChangedFiles(const std::filesystem::path& path,
                                        DirectoryMonitorCallback& callback,
                                        std::map<std::filesystem::path, FileSnapshot>& knownFiles)
{
    std::error_code errorCode;
    const std::filesystem::directory_options options = std::filesystem::directory_options::skip_permission_denied;

    for (std::filesystem::recursive_directory_iterator iterator(path, options, errorCode), end;
         iterator != end;
         iterator.increment(errorCode)) {
        if (errorCode) {
            errorCode.clear();
            continue;
        }

        if (!iterator->is_regular_file(errorCode)) {
            errorCode.clear();
            continue;
        }

        const std::filesystem::path filePath = iterator->path();
        const auto lastWriteTime = iterator->last_write_time(errorCode);
        if (errorCode) {
            errorCode.clear();
            continue;
        }

        const std::uintmax_t size = iterator->file_size(errorCode);
        if (errorCode) {
            errorCode.clear();
            continue;
        }

        const FileSnapshot snapshot{
            .lastWriteTime = lastWriteTime,
            .size = size,
        };

        const auto found = knownFiles.find(filePath);
        if (found == knownFiles.end() || found->second.lastWriteTime != snapshot.lastWriteTime || found->second.size != snapshot.size) {
            knownFiles[filePath] = snapshot;
            callback(filePath);
        }
    }
}

void DirectoryMonitor::setLastError(std::wstring error)
{
    std::lock_guard lock(mutex_);
    lastError_ = std::move(error);
}

bool DirectoryMonitor::stopRequested() const
{
    std::lock_guard lock(mutex_);
    return stopRequested_;
}

} // namespace antivirus::service::scan
