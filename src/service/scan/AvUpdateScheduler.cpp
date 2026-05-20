#include "service/scan/AvUpdateScheduler.h"

#include <chrono>
#include <filesystem>
#include <windows.h>

namespace antivirus::service::scan {
namespace {

constexpr auto kUpdateInterval = std::chrono::minutes(30);

} // namespace

AvUpdateScheduler::~AvUpdateScheduler()
{
    stop();
}

void AvUpdateScheduler::start(AvUpdateCallback callback)
{
    std::lock_guard lock(mutex_);

    if (worker_.joinable()) {
        return;
    }

    callback_ = std::move(callback);
    stopRequested_ = false;
    worker_ = std::thread(&AvUpdateScheduler::workerLoop, this);
}

void AvUpdateScheduler::stop()
{
    {
        std::lock_guard lock(mutex_);
        stopRequested_ = true;
    }

    cv_.notify_all();

    if (worker_.joinable()) {
        worker_.join();
    }
}

AvUpdateResult AvUpdateScheduler::runUpdateNow()
{
    AvUpdateResult result;

    result.backupCreated = storage_.backupCurrentDatabase();

    const std::vector<AvRecord> records = makeDemoRecords();
    const std::wstring releaseDate = scheduledReleaseDate();

    if (!storage_.writeDatabase(releaseDate, records)) {
        result.message = L"Antivirus database update write failed";

        if (result.backupCreated) {
            std::error_code errorCode;
            std::filesystem::copy_file(storage_.backupPath(),
                                       storage_.databasePath(),
                                       std::filesystem::copy_options::overwrite_existing,
                                       errorCode);
            result.rolledBack = !errorCode;
        }

        result.loadResult = storage_.loadOrRecover();
        return result;
    }

    result.loadResult = storage_.loadOrRecover();
    result.updated = result.loadResult.loaded && !result.loadResult.usedDefaultDatabase;
    result.rolledBack = result.loadResult.recoveredFromBackup;

    if (result.updated) {
        result.message = L"Antivirus database updated and reloaded";
    } else if (result.rolledBack) {
        result.message = L"Antivirus database update failed; rolled back from backup";
    } else {
        result.message = L"Antivirus database update failed; fallback database loaded";
    }

    return result;
}

void AvUpdateScheduler::workerLoop()
{
    while (true) {
        std::unique_lock lock(mutex_);

        const bool stopped = cv_.wait_for(lock, kUpdateInterval, [this]() {
            return stopRequested_.load();
        });

        if (stopped || stopRequested_.load()) {
            break;
        }

        AvUpdateCallback callback = callback_;
        lock.unlock();

        const AvUpdateResult result = runUpdateNow();

        if (callback) {
            callback(result);
        }
    }
}

std::wstring AvUpdateScheduler::scheduledReleaseDate() const
{
    SYSTEMTIME time{};
    GetLocalTime(&time);

    wchar_t buffer[128] = {};
    swprintf_s(buffer,
               L"%04u-%02u-%02u scheduled update %02u:%02u:%02u",
               static_cast<unsigned>(time.wYear),
               static_cast<unsigned>(time.wMonth),
               static_cast<unsigned>(time.wDay),
               static_cast<unsigned>(time.wHour),
               static_cast<unsigned>(time.wMinute),
               static_cast<unsigned>(time.wSecond));

    return buffer;
}

} // namespace antivirus::service::scan
