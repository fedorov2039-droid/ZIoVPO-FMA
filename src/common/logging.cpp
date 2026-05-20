#include "common/logging.h"

#include <windows.h>

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>

namespace antivirus::common {
namespace {

std::mutex& log_mutex() {
    static std::mutex mutex;
    return mutex;
}

std::wstring_view level_name(LogLevel level) {
    switch (level) {
    case LogLevel::Info:
        return L"ИНФО";
    case LogLevel::Warning:
        return L"ПРЕДУПРЕЖДЕНИЕ";
    case LogLevel::Error:
        return L"ОШИБКА";
    }

    return L"НЕИЗВЕСТНО";
}

std::filesystem::path log_directory() {
    wchar_t programData[MAX_PATH]{};

    const DWORD length = GetEnvironmentVariableW(
        L"ProgramData",
        programData,
        MAX_PATH
    );

    std::filesystem::path dir;

    if (length > 0 && length < MAX_PATH) {
        dir = std::filesystem::path(programData) / L"AntivirusGui";
    } else {
        dir = std::filesystem::temp_directory_path() / L"AntivirusGui";
    }

    std::error_code ec;
    std::filesystem::create_directories(dir, ec);

    return dir;
}

std::filesystem::path log_file_path() {
    return log_directory() / L"service.log";
}

bool is_log_space(wchar_t ch) {
    return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n';
}

std::wstring trim_log_message(std::wstring text) {
    std::size_t begin = 0;
    while (begin < text.size() && is_log_space(text[begin])) {
        ++begin;
    }

    std::size_t end = text.size();
    while (end > begin && is_log_space(text[end - 1])) {
        --end;
    }

    return text.substr(begin, end - begin);
}

std::wstring normalize_log_message(std::wstring_view message) {
    std::wstring text = trim_log_message(std::wstring(message));
    std::wstring normalized;
    normalized.reserve(text.size());

    bool pendingSeparator = false;
    for (const wchar_t ch : text) {
        if (ch == L'\r' || ch == L'\n') {
            pendingSeparator = !normalized.empty();
            continue;
        }

        if (pendingSeparator && !is_log_space(ch)) {
            normalized += L" | ";
        }
        pendingSeparator = false;
        normalized.push_back(ch);
    }

    return trim_log_message(std::move(normalized));
}

bool replace_prefix(std::wstring& text, std::wstring_view prefix, std::wstring_view replacement) {
    if (!std::wstring_view(text).starts_with(prefix)) {
        return false;
    }

    text.replace(0, prefix.size(), replacement.data(), replacement.size());
    return true;
}

void replace_all(std::wstring& text, std::wstring_view from, std::wstring_view to) {
    if (from.empty()) {
        return;
    }

    std::size_t position = 0;
    while ((position = text.find(from, position)) != std::wstring::npos) {
        text.replace(position, from.size(), to.data(), to.size());
        position += to.size();
    }
}

std::wstring legacy_bool_text(std::wstring_view value) {
    if (value == L"true") {
        return L"да";
    }

    if (value == L"false") {
        return L"нет";
    }

    return std::wstring(value);
}

std::wstring legacy_scan_target_name(std::wstring_view value) {
    if (value == L"file") {
        return L"файл";
    }

    if (value == L"directory") {
        return L"папка";
    }

    if (value == L"fixed drives" || value == L"all fixed drives") {
        return L"все несъёмные диски";
    }

    return std::wstring(value);
}

bool localize_legacy_process_hardening_message(std::wstring& text) {
    constexpr std::wstring_view prefix = L"Process hardening enabled for ";
    constexpr std::wstring_view option = L"; protectFromAdministrators=";

    if (!std::wstring_view(text).starts_with(prefix)) {
        return false;
    }

    std::wstring details = text.substr(prefix.size());
    const std::size_t optionPosition = details.find(option);
    if (optionPosition == std::wstring::npos) {
        return false;
    }

    std::wstring component = details.substr(0, optionPosition);
    if (std::wstring_view(component).ends_with(L" child")) {
        component.resize(component.size() - 6);
        component += L" (дочерний процесс)";
    }

    const std::wstring protectFromAdministrators =
        legacy_bool_text(std::wstring_view(details).substr(optionPosition + option.size()));

    text = L"Защита процесса включена для "
        + component
        + L"; защита от администраторов="
        + protectFromAdministrators;
    return true;
}

bool localize_legacy_scheduled_scan_start(std::wstring& text) {
    constexpr std::wstring_view prefix = L"Scheduled scan started: ";
    constexpr std::wstring_view interval = L", interval ";

    if (!std::wstring_view(text).starts_with(prefix)) {
        return false;
    }

    std::wstring details = text.substr(prefix.size());
    const std::size_t intervalPosition = details.find(interval);
    if (intervalPosition == std::wstring::npos) {
        return false;
    }

    std::wstring seconds = details.substr(intervalPosition + interval.size());
    replace_all(seconds, L" sec.", L" сек.");
    replace_all(seconds, L" sec", L" сек.");

    text = L"Запущено сканирование по расписанию: "
        + legacy_scan_target_name(std::wstring_view(details).substr(0, intervalPosition))
        + L", интервал "
        + seconds;
    return true;
}

bool localize_legacy_scheduled_scan_result(std::wstring& text) {
    constexpr std::wstring_view prefix = L"Scheduled scan result (";
    constexpr std::wstring_view separator = L"): ";

    if (!std::wstring_view(text).starts_with(prefix)) {
        return false;
    }

    const std::size_t separatorPosition = text.find(separator, prefix.size());
    if (separatorPosition == std::wstring::npos) {
        return false;
    }

    const std::wstring target =
        legacy_scan_target_name(std::wstring_view(text).substr(
            prefix.size(),
            separatorPosition - prefix.size()));
    const std::wstring details = text.substr(separatorPosition + separator.size());
    text = L"Результат сканирования по расписанию (" + target + L"): " + details;
    return true;
}

std::wstring localize_known_english_log_message(std::wstring text) {
    struct Translation {
        std::wstring_view from;
        std::wstring_view to;
    };

    static constexpr Translation exactTranslations[] = {
        {L"Starting service", L"Запуск службы"},
        {L"Installing service", L"Установка службы"},
        {L"Removing service", L"Удаление службы"},
        {L"Starting service in console mode", L"Запуск службы в консольном режиме"},
        {L"Antivirus database loaded from disk", L"Антивирусная база загружена с диска"},
        {L"Antivirus database loaded after successful activation", L"Антивирусная база загружена после успешной активации"},
        {L"Antivirus database update scheduler started", L"Планировщик обновления антивирусных баз запущен"},
        {L"Antivirus database updated and reloaded", L"Антивирусная база обновлена и перезагружена"},
        {L"Primary database invalid", L"Основная база повреждена"},
        {L"Manifest signature is invalid; forcing update from mock update server", L"Подпись манифеста неверна; выполняется принудительное обновление с демо-сервера обновлений"},
        {L"Trying to repair database from mock update server", L"Попытка восстановить базу через демо-сервер обновлений"},
        {L"Mock update server unavailable", L"Демо-сервер обновлений недоступен"},
        {L"Mock update server database is invalid", L"База демо-сервера обновлений повреждена"},
        {L"Loaded default database", L"Загружена база по умолчанию"},
        {L"Primary and backup antivirus databases are invalid; loaded default database", L"Основная и резервная базы повреждены; загружена база по умолчанию"},
        {L"Service is not running; attempting to start it and exit", L"Служба не запущена; пробуем запустить её и выйти"},
        {L"User logged in; sensitive authentication data is stored only in memory", L"Пользователь вошёл; чувствительные данные авторизации хранятся только в оперативной памяти"},
        {L"WTSQueryUserToken requires the service process to run as LocalSystem", L"Для WTSQueryUserToken служба должна работать от имени LocalSystem"},
    };

    for (const Translation translation : exactTranslations) {
        if (text == translation.from) {
            return std::wstring(translation.to);
        }
    }

    const bool dynamicTranslationApplied =
        localize_legacy_process_hardening_message(text)
        || localize_legacy_scheduled_scan_start(text)
        || localize_legacy_scheduled_scan_result(text);

    if (!dynamicTranslationApplied) {
        (void)(replace_prefix(text, L"Preparing to launch GUI in session ", L"Подготовка запуска GUI в сеансе ")
               || replace_prefix(text, L"GUI executable path: ", L"Путь к GUI: ")
               || replace_prefix(text, L"GUI working directory: ", L"Рабочая папка GUI: ")
               || replace_prefix(text, L"CreateProcessAsUserW command line: ", L"Командная строка CreateProcessAsUserW: ")
               || replace_prefix(text, L"GUI child started successfully, pid=", L"Дочерний GUI запущен, идентификатор процесса=")
               || replace_prefix(text, L"Directory monitoring started: ", L"Мониторинг директории запущен: ")
               || replace_prefix(text, L"Directory monitoring scanned file: ", L"Мониторинг директории просканировал файл: ")
               || replace_prefix(text, L"WTSQueryUserToken failed for session ", L"WTSQueryUserToken не выполнен для сеанса "));
    }

    replace_all(text, L"[INFO]", L"[ИНФО]");
    replace_all(text, L"[WARN]", L"[ПРЕДУПРЕЖДЕНИЕ]");
    replace_all(text, L"[ERROR]", L"[ОШИБКА]");
    replace_all(text, L"WTSQueryUserToken requires the service process to run as LocalSystem", L"Для WTSQueryUserToken служба должна работать от имени LocalSystem");
    replace_all(text, L"File: ", L"Файл: ");
    replace_all(text, L"Object type: ", L"Тип объекта: ");
    replace_all(text, L"Result: threat detected", L"Результат: обнаружена угроза");
    replace_all(text, L"Result: no threats detected", L"Результат: угроз не обнаружено");
    replace_all(text, L"Threat: ", L"Угроза: ");
    replace_all(text, L"Offset: ", L"Смещение: ");
    replace_all(text, L"Error: ", L"Ошибка: ");
    replace_all(text, L"Unsupported object type", L"Неподдерживаемый тип объекта");

    return text;
}

std::wstring timestamp() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t tt = std::chrono::system_clock::to_time_t(now);

    std::tm localTime{};
    localtime_s(&localTime, &tt);

    std::wostringstream out;
    out << std::put_time(&localTime, L"%Y-%m-%d %H:%M:%S");

    return out.str();
}

void write_file_log(const std::wstring& line) {
    try {
        const std::filesystem::path path = log_file_path();
        std::error_code ec;
        const bool exists = std::filesystem::exists(path, ec);
        const auto fileSize = exists && !ec ? std::filesystem::file_size(path, ec) : 0;
        const bool writeBom = !exists || ec || fileSize == 0;

        const int required = WideCharToMultiByte(
            CP_UTF8,
            0,
            line.c_str(),
            static_cast<int>(line.size()),
            nullptr,
            0,
            nullptr,
            nullptr);
        if (required <= 0) {
            return;
        }

        std::string utf8Line(static_cast<std::size_t>(required), '\0');
        const int written = WideCharToMultiByte(
            CP_UTF8,
            0,
            line.c_str(),
            static_cast<int>(line.size()),
            utf8Line.data(),
            required,
            nullptr,
            nullptr);
        if (written <= 0) {
            return;
        }

        std::ofstream file(path, std::ios::binary | std::ios::app);
        if (writeBom) {
            const unsigned char bom[] = {0xef, 0xbb, 0xbf};
            file.write(reinterpret_cast<const char*>(bom), sizeof(bom));
        }

        file.write(utf8Line.data(), static_cast<std::streamsize>(utf8Line.size()));
    } catch (...) {
        // Логирование не должно ронять приложение или службу.
    }
}

std::string to_utf8(const std::wstring& text)
{
    const int required = WideCharToMultiByte(
        CP_UTF8,
        0,
        text.c_str(),
        static_cast<int>(text.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (required <= 0) {
        return {};
    }

    std::string utf8Text(static_cast<std::size_t>(required), '\0');
    const int written = WideCharToMultiByte(
        CP_UTF8,
        0,
        text.c_str(),
        static_cast<int>(text.size()),
        utf8Text.data(),
        required,
        nullptr,
        nullptr);
    if (written <= 0) {
        return {};
    }

    return utf8Text;
}

} // namespace

void start_new_log_session(std::wstring_view sessionName)
{
    const std::wstring normalizedSessionName = normalize_log_message(sessionName);
    const std::wstring line =
        L"[" + timestamp() + L"] "
        L"[AntivirusGui] [ИНФО] "
        L"Начат новый сеанс логирования: "
        + (normalizedSessionName.empty() ? L"без имени" : normalizedSessionName)
        + L"\n";

    std::lock_guard<std::mutex> lock(log_mutex());

    OutputDebugStringW(line.c_str());
    std::wcerr << line;

    try {
        const std::filesystem::path path = log_file_path();
        const std::string utf8Line = to_utf8(line);
        if (utf8Line.empty()) {
            return;
        }

        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        const unsigned char bom[] = {0xef, 0xbb, 0xbf};
        file.write(reinterpret_cast<const char*>(bom), sizeof(bom));
        file.write(utf8Line.data(), static_cast<std::streamsize>(utf8Line.size()));
    } catch (...) {
        // Логирование не должно ронять приложение или службу.
    }
}

void log_message(LogLevel level, std::wstring_view message) {
    const std::wstring normalizedMessage = localize_known_english_log_message(normalize_log_message(message));
    if (normalizedMessage.empty()) {
        return;
    }

    const std::wstring line =
        L"[" + timestamp() + L"] "
        L"[AntivirusGui] ["
        + std::wstring(level_name(level))
        + L"] "
        + normalizedMessage
        + L"\n";

    std::lock_guard<std::mutex> lock(log_mutex());

    OutputDebugStringW(line.c_str());
    std::wcerr << line;
    write_file_log(line);
}

void log_info(std::wstring_view message) {
    log_message(LogLevel::Info, message);
}

void log_warning(std::wstring_view message) {
    log_message(LogLevel::Warning, message);
}

void log_error(std::wstring_view message) {
    log_message(LogLevel::Error, message);
}

} // namespace antivirus::common
