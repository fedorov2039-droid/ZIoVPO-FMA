#include "common/logging.h"
#include "common/process_hardening.h"
#include "common/secure_stop_confirmation.h"
#include "gui/ParentProcessCheck.h"
#include "gui/ServiceClient.h"
#include "gui/SingleInstanceGuard.h"
#include "winui/RpcClientWin.h"

#include <windows.h>
#undef GetCurrentTime

#include <algorithm>
#include <commdlg.h>
#include <commctrl.h>
#include <microsoft.ui.xaml.window.h>
#include <shellapi.h>
#include <shlobj.h>

#include <winrt/base.h>
#include <WindowsAppSDK-VersionInfo.h>
#include <MddBootstrap.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Graphics.h>
#include <winrt/Windows.UI.Xaml.Interop.h>
#include <winrt/Microsoft.UI.Dispatching.h>
#include <winrt/Microsoft.UI.Windowing.h>
#include <winrt/Microsoft.UI.Xaml.Controls.Primitives.h>
#include <winrt/Microsoft.UI.Xaml.Controls.h>
#include <winrt/Microsoft.UI.Xaml.Markup.h>
#include <winrt/Microsoft.UI.Xaml.Media.h>
#include <winrt/Microsoft.UI.Xaml.XamlTypeInfo.h>
#include <winrt/Microsoft.UI.Xaml.h>
#include <winrt/Windows.UI.Text.h>
#include <winrt/Windows.UI.h>

#include <atomic>
#include <cmath>
#include <cstdio>
#include <cwchar>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace mux = winrt::Microsoft::UI::Xaml;
namespace controls = winrt::Microsoft::UI::Xaml::Controls;
namespace dispatching = winrt::Microsoft::UI::Dispatching;
namespace markup = winrt::Microsoft::UI::Xaml::Markup;
namespace media = winrt::Microsoft::UI::Xaml::Media;
namespace windowing = winrt::Microsoft::UI::Windowing;
namespace xamltype = winrt::Microsoft::UI::Xaml::XamlTypeInfo;

namespace {

constexpr UINT kTrayMessage = WM_APP + 42;
constexpr UINT kTrayIconId = 1;
constexpr UINT kTrayOpenCommand = 1001;
constexpr UINT kTrayExitCommand = 1002;
constexpr UINT kShowMainWindowMessage = WM_APP + 43;
constexpr wchar_t kMainWindowTitle[] = L"Антивирус GUI - WinUI";

unsigned int iconPixel(unsigned char alpha, unsigned char red, unsigned char green, unsigned char blue)
{
    return (static_cast<unsigned int>(alpha) << 24)
        | (static_cast<unsigned int>(red) << 16)
        | (static_cast<unsigned int>(green) << 8)
        | static_cast<unsigned int>(blue);
}

double distanceToSegment(double px, double py, double ax, double ay, double bx, double by)
{
    const double vx = bx - ax;
    const double vy = by - ay;
    const double wx = px - ax;
    const double wy = py - ay;
    const double lengthSquared = vx * vx + vy * vy;
    if (lengthSquared <= 0.0) {
        const double dx = px - ax;
        const double dy = py - ay;
        return std::sqrt(dx * dx + dy * dy);
    }

    const double t = std::clamp((wx * vx + wy * vy) / lengthSquared, 0.0, 1.0);
    const double cx = ax + t * vx;
    const double cy = ay + t * vy;
    const double dx = px - cx;
    const double dy = py - cy;
    return std::sqrt(dx * dx + dy * dy);
}

bool isInIconBadge(double nx, double ny)
{
    const double dx = nx - 0.50;
    const double dy = ny - 0.50;
    return std::sqrt(dx * dx + dy * dy) <= 0.43;
}

bool isNearIconBadgeBorder(double nx, double ny)
{
    const double dx = nx - 0.50;
    const double dy = ny - 0.50;
    const double radius = std::sqrt(dx * dx + dy * dy);
    return radius > 0.37 && radius <= 0.43;
}

HICON createAppIcon(int requestedSize)
{
    const int size = std::max(16, requestedSize);
    std::vector<unsigned int> pixels(static_cast<size_t>(size) * static_cast<size_t>(size), 0);

    for (int y = 0; y < size; ++y) {
        for (int x = 0; x < size; ++x) {
            const double nx = (static_cast<double>(x) + 0.5) / static_cast<double>(size);
            const double ny = (static_cast<double>(y) + 0.5) / static_cast<double>(size);
            if (!isInIconBadge(nx, ny)) {
                continue;
            }

            const double shade = std::clamp((ny - 0.08) / 0.84, 0.0, 1.0);
            unsigned char red = static_cast<unsigned char>(22 + shade * 2);
            unsigned char green = static_cast<unsigned char>(163 - shade * 47);
            unsigned char blue = static_cast<unsigned char>(74 - shade * 1);
            if (isNearIconBadgeBorder(nx, ny)) {
                red = 15;
                green = 118;
                blue = 73;
            }

            pixels[static_cast<size_t>(y) * static_cast<size_t>(size) + static_cast<size_t>(x)] =
                iconPixel(255, red, green, blue);
        }
    }

    for (int y = 0; y < size; ++y) {
        for (int x = 0; x < size; ++x) {
            const double nx = (static_cast<double>(x) + 0.5) / static_cast<double>(size);
            const double ny = (static_cast<double>(y) + 0.5) / static_cast<double>(size);
            const double checkDistance = std::min(
                distanceToSegment(nx, ny, 0.30, 0.53, 0.45, 0.68),
                distanceToSegment(nx, ny, 0.45, 0.68, 0.72, 0.37));
            if (checkDistance < 0.050 && isInIconBadge(nx, ny)) {
                pixels[static_cast<size_t>(y) * static_cast<size_t>(size) + static_cast<size_t>(x)] =
                    iconPixel(255, 255, 255, 255);
            } else if (checkDistance < 0.070 && isInIconBadge(nx, ny)) {
                pixels[static_cast<size_t>(y) * static_cast<size_t>(size) + static_cast<size_t>(x)] =
                    iconPixel(255, 220, 252, 231);
            }
        }
    }

    BITMAPV5HEADER bitmapHeader{};
    bitmapHeader.bV5Size = sizeof(bitmapHeader);
    bitmapHeader.bV5Width = size;
    bitmapHeader.bV5Height = -size;
    bitmapHeader.bV5Planes = 1;
    bitmapHeader.bV5BitCount = 32;
    bitmapHeader.bV5Compression = BI_BITFIELDS;
    bitmapHeader.bV5RedMask = 0x00FF0000;
    bitmapHeader.bV5GreenMask = 0x0000FF00;
    bitmapHeader.bV5BlueMask = 0x000000FF;
    bitmapHeader.bV5AlphaMask = 0xFF000000;

    void* bits = nullptr;
    HDC screenDc = GetDC(nullptr);
    HBITMAP colorBitmap = CreateDIBSection(
        screenDc,
        reinterpret_cast<BITMAPINFO*>(&bitmapHeader),
        DIB_RGB_COLORS,
        &bits,
        nullptr,
        0);
    ReleaseDC(nullptr, screenDc);

    if (colorBitmap == nullptr || bits == nullptr) {
        if (colorBitmap != nullptr) {
            DeleteObject(colorBitmap);
        }
        return nullptr;
    }

    std::copy(pixels.begin(), pixels.end(), static_cast<unsigned int*>(bits));
    HBITMAP maskBitmap = CreateBitmap(size, size, 1, 1, nullptr);
    if (maskBitmap == nullptr) {
        DeleteObject(colorBitmap);
        return nullptr;
    }

    ICONINFO iconInfo{};
    iconInfo.fIcon = TRUE;
    iconInfo.hbmMask = maskBitmap;
    iconInfo.hbmColor = colorBitmap;
    HICON icon = CreateIconIndirect(&iconInfo);
    DeleteObject(maskBitmap);
    DeleteObject(colorBitmap);

    return icon;
}

winrt::Windows::UI::Color color(unsigned char red, unsigned char green, unsigned char blue)
{
    return winrt::Windows::UI::Color{255, red, green, blue};
}

media::SolidColorBrush brush(unsigned char red, unsigned char green, unsigned char blue)
{
    return media::SolidColorBrush(color(red, green, blue));
}

std::wstring formatHresult(winrt::hresult code)
{
    wchar_t buffer[16]{};
    swprintf_s(buffer, L"0x%08X", static_cast<unsigned int>(code.value));
    return buffer;
}

std::wstring widenAscii(std::string_view text)
{
    std::wstring result;
    result.reserve(text.size());
    for (const char ch : text) {
        result.push_back(static_cast<unsigned char>(ch));
    }
    return result;
}

void showStartupError(const std::wstring& message)
{
    MessageBoxW(nullptr, message.c_str(), L"Antivirus GUI", MB_OK | MB_ICONERROR);
}

void reportStartupError(const std::wstring& message, bool serviceChild)
{
    antivirus::common::log_error(message);
    if (!serviceChild) {
        showStartupError(message);
    }
}

controls::TextBlock makeTextBlock(const wchar_t* text, double fontSize = 14.0)
{
    controls::TextBlock block;
    block.Text(text);
    block.FontSize(fontSize);
    block.TextWrapping(mux::TextWrapping::Wrap);
    return block;
}

controls::TextBlock makeStatusText(const wchar_t* text)
{
    controls::TextBlock block = makeTextBlock(text, 14);
    block.Foreground(brush(51, 65, 85));
    block.LineHeight(21);
    return block;
}

controls::TextBlock makeSmallCaps(const wchar_t* text)
{
    controls::TextBlock block = makeTextBlock(text, 12);
    block.Foreground(brush(100, 116, 139));
    block.FontWeight(winrt::Windows::UI::Text::FontWeights::SemiBold());
    return block;
}

controls::FontIcon makeIcon(const wchar_t* glyph)
{
    controls::FontIcon icon;
    icon.Glyph(glyph);
    icon.FontFamily(media::FontFamily(L"Segoe Fluent Icons, Segoe MDL2 Assets"));
    icon.FontSize(14);
    return icon;
}

controls::Button makeButton(const wchar_t* text, const wchar_t* glyph = L"", bool primary = false, bool danger = false)
{
    controls::Button button;
    button.MinHeight(38);
    button.MinWidth(176);
    button.Margin(mux::Thickness{0, 0, 10, 10});
    button.Padding(mux::Thickness{14, 7, 14, 7});
    button.CornerRadius(mux::CornerRadius{6});

    controls::StackPanel content;
    content.Orientation(controls::Orientation::Horizontal);
    content.Spacing(8);
    content.VerticalAlignment(mux::VerticalAlignment::Center);

    if (std::wcslen(glyph) > 0) {
        content.Children().Append(makeIcon(glyph));
    }

    controls::TextBlock label = makeTextBlock(text, 14);
    label.TextWrapping(mux::TextWrapping::NoWrap);
    content.Children().Append(label);
    button.Content(content);

    if (primary) {
        button.Background(brush(37, 99, 235));
        button.BorderBrush(brush(37, 99, 235));
        button.Foreground(brush(255, 255, 255));
    } else if (danger) {
        button.Background(brush(254, 242, 242));
        button.BorderBrush(brush(248, 113, 113));
        button.Foreground(brush(153, 27, 27));
    }

    return button;
}

controls::StackPanel makeCard(const wchar_t* title, const wchar_t* subtitle = L"")
{
    controls::StackPanel content;
    content.Spacing(10);

    controls::TextBlock header = makeTextBlock(title, 16);
    header.FontWeight(winrt::Windows::UI::Text::FontWeights::SemiBold());
    header.Foreground(brush(15, 23, 42));
    content.Children().Append(header);

    if (std::wcslen(subtitle) > 0) {
        controls::TextBlock hint = makeStatusText(subtitle);
        hint.Foreground(brush(71, 85, 105));
        content.Children().Append(hint);
    }

    return content;
}

controls::Border wrapCard(controls::StackPanel const& content)
{
    controls::Border border;
    border.Background(brush(255, 255, 255));
    border.BorderBrush(brush(226, 232, 240));
    border.BorderThickness(mux::Thickness{1});
    border.CornerRadius(mux::CornerRadius{8});
    border.Padding(mux::Thickness{18});
    border.Child(content);
    return border;
}

controls::Border makePill(const wchar_t* text, media::SolidColorBrush const& background, media::SolidColorBrush const& foreground)
{
    controls::TextBlock label = makeTextBlock(text, 12);
    label.FontWeight(winrt::Windows::UI::Text::FontWeights::SemiBold());
    label.Foreground(foreground);
    label.TextWrapping(mux::TextWrapping::NoWrap);

    controls::Border pill;
    pill.Background(background);
    pill.CornerRadius(mux::CornerRadius{999});
    pill.Padding(mux::Thickness{10, 4, 10, 4});
    pill.Child(label);
    return pill;
}

controls::ColumnDefinition makeColumn(mux::GridLength const& width)
{
    controls::ColumnDefinition column;
    column.Width(width);
    return column;
}

controls::RowDefinition makeRow(mux::GridLength const& height)
{
    controls::RowDefinition row;
    row.Height(height);
    return row;
}

void setGridPosition(mux::FrameworkElement const& element, int row, int column)
{
    controls::Grid::SetRow(element, row);
    controls::Grid::SetColumn(element, column);
}

std::wstring valueOrDash(const std::wstring& value)
{
    return value.empty() ? L"-" : value;
}

std::wstring serviceStatusText(long status, bool rpcAvailable)
{
    if (!rpcAvailable) {
        return L"Служба: RPC недоступен";
    }

    switch (status) {
    case SERVICE_STOPPED:
        return L"Служба: остановлена";
    case SERVICE_START_PENDING:
        return L"Служба: запускается";
    case SERVICE_STOP_PENDING:
        return L"Служба: останавливается";
    case SERVICE_RUNNING:
        return L"Служба работает";
    case SERVICE_PAUSED:
        return L"Служба: приостановлена";
    default:
        return L"Служба: состояние " + std::to_wstring(status);
    }
}

std::wstring authText(const antivirus::winui::AuthState& auth)
{
    if (!auth.lastError.empty()) {
        return L"Аккаунт: ошибка: " + auth.lastError;
    }

    if (auth.authenticated) {
        return L"Аккаунт: выполнен вход, " + valueOrDash(auth.displayName) + L" (" + valueOrDash(auth.login) + L")";
    }

    return L"Аккаунт: требуется вход";
}

std::wstring licenseText(const antivirus::winui::LicenseState& license)
{
    if (!license.lastError.empty()) {
        return L"Лицензия: ошибка: " + license.lastError;
    }

    if (license.licenseActive) {
        return L"Лицензия активна до " + valueOrDash(license.licenseExpiresAt);
    }

    if (!license.featureBlockedReason.empty()) {
        return L"Лицензия: " + license.featureBlockedReason;
    }

    return L"Лицензия: требуется активация";
}

std::wstring featureText(const antivirus::winui::FeatureState& feature)
{
    if (feature.functionalityEnabled) {
        return L"Функции сканирования и мониторинга доступны";
    }

    return L"Функции заблокированы: " + valueOrDash(feature.blockedReason);
}

std::wstring databaseText(const antivirus::winui::DatabaseInfo& database)
{
    if (database.loaded) {
        return L"Базы загружены: " + valueOrDash(database.releaseDate)
            + L", записей: " + std::to_wstring(database.recordCount);
    }

    if (!database.lastError.empty()) {
        return L"Базы: " + database.lastError;
    }

    return L"Базы не загружены";
}

std::wstring monitorText(const antivirus::winui::DirectoryMonitorStatus& status)
{
    if (status.running) {
        return L"Мониторинг включён: " + valueOrDash(status.path);
    }

    if (!status.lastError.empty()) {
        return L"Мониторинг: " + status.lastError;
    }

    return L"Мониторинг выключен";
}

std::wstring scheduleTargetText(long targetType)
{
    switch (targetType) {
    case antivirus::winui::kScanScheduleFile:
        return L"файл";
    case antivirus::winui::kScanScheduleDirectory:
        return L"папка";
    case antivirus::winui::kScanScheduleFixedDrives:
        return L"все несъёмные диски";
    default:
        return L"цель не выбрана";
    }
}

std::wstring scheduleText(const antivirus::winui::ScanScheduleStatus& status)
{
    if (!status.lastError.empty() && !status.running) {
        return L"Расписание: " + status.lastError;
    }

    if (!status.running) {
        return L"Расписание сканирования выключено";
    }

    std::wstring text = L"Расписание включено: " + scheduleTargetText(status.targetType)
        + L", интервал " + std::to_wstring(status.intervalSeconds) + L" сек.";

    if (!status.path.empty()) {
        text += L"\nЦель: " + status.path;
    }

    if (!status.lastRunAt.empty()) {
        text += L"\nПоследний запуск: " + status.lastRunAt;
    }

    if (!status.lastError.empty()) {
        text += L"\nПоследняя ошибка: " + status.lastError;
    }

    return text;
}

std::wstring formatScanResult(const antivirus::winui::ScanResult& result)
{
    std::wstringstream stream;

    if (!result.lastError.empty()) {
        stream << L"Ошибка: " << result.lastError << L"\n\n";
    }

    if (!result.details.empty()) {
        stream << result.details;
        return stream.str();
    }

    stream << L"Путь: " << valueOrDash(result.scannedPath) << L"\n";
    stream << L"Просканировано файлов: " << result.scannedFiles << L"\n";
    stream << L"Обнаружено угроз: " << result.maliciousFiles << L"\n";
    stream << (result.malicious ? L"Результат: обнаружена угроза" : L"Результат: угроз не обнаружено");

    if (result.malicious) {
        stream << L"\nУгроза: " << valueOrDash(result.threatName);
        stream << L"\nТип объекта: " << valueOrDash(result.objectType);
        stream << L"\nСмещение: " << result.detectionOffset;
    }

    return stream.str();
}

std::optional<std::wstring> pickFile()
{
    wchar_t buffer[MAX_PATH]{};

    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.lpstrFile = buffer;
    dialog.nMaxFile = static_cast<DWORD>(std::size(buffer));
    dialog.lpstrTitle = L"Выберите файл для сканирования";
    dialog.lpstrFilter = L"Все файлы\0*.*\0";
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

    if (!GetOpenFileNameW(&dialog)) {
        return std::nullopt;
    }

    return std::wstring(buffer);
}

std::optional<std::wstring> pickFolder(const wchar_t* title)
{
    BROWSEINFOW dialog{};
    dialog.lpszTitle = title;
    dialog.ulFlags = BIF_RETURNONLYFSDIRS | BIF_USENEWUI;

    PIDLIST_ABSOLUTE item = SHBrowseForFolderW(&dialog);
    if (item == nullptr) {
        return std::nullopt;
    }

    wchar_t path[MAX_PATH]{};
    const bool ok = SHGetPathFromIDListW(item, path) != FALSE;
    CoTaskMemFree(item);

    if (!ok) {
        return std::nullopt;
    }

    return std::wstring(path);
}

bool hasArgument(std::wstring_view expected)
{
    int argc = 0;
    PWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == nullptr) {
        return false;
    }

    bool found = false;
    for (int i = 1; i < argc; ++i) {
        if (expected == argv[i]) {
            found = true;
            break;
        }
    }

    LocalFree(argv);
    return found;
}

struct WindowSearch {
    HWND hwnd = nullptr;
};

BOOL CALLBACK findMainWindowProc(HWND hwnd, LPARAM lParam)
{
    wchar_t title[128]{};
    if (GetWindowTextW(hwnd, title, static_cast<int>(sizeof(title) / sizeof(title[0]))) <= 0) {
        return TRUE;
    }

    if (std::wstring_view{title} != kMainWindowTitle) {
        return TRUE;
    }

    auto* search = reinterpret_cast<WindowSearch*>(lParam);
    search->hwnd = hwnd;
    return FALSE;
}

std::optional<HWND> findExistingMainWindow()
{
    WindowSearch search{};
    EnumWindows(&findMainWindowProc, reinterpret_cast<LPARAM>(&search));
    if (search.hwnd == nullptr) {
        return std::nullopt;
    }

    return search.hwnd;
}

bool requestExistingGuiToShow(DWORD timeoutMilliseconds)
{
    const DWORD startedAt = GetTickCount();
    do {
        if (const std::optional<HWND> hwnd = findExistingMainWindow(); hwnd.has_value()) {
            PostMessageW(*hwnd, kShowMainWindowMessage, 0, 0);
            return true;
        }

        Sleep(250);
    } while (GetTickCount() - startedAt < timeoutMilliseconds);

    return false;
}

struct WinUiApp : mux::ApplicationT<WinUiApp, markup::IXamlMetadataProvider> {
    explicit WinUiApp(bool startHidden)
        : startHidden_(startHidden)
    {
    }

    void OnLaunched(mux::LaunchActivatedEventArgs const&)
    {
        buildUi();
        refreshState();

        pollingTimer_ = mux::DispatcherTimer();
        pollingTimer_.Interval(std::chrono::seconds(5));
        pollingTimer_.Tick([this](auto&&, auto&&) {
            refreshState();
        });
        pollingTimer_.Start();
    }

    markup::IXamlType GetXamlType(winrt::Windows::UI::Xaml::Interop::TypeName const& type)
    {
        return xamlProvider_.GetXamlType(type);
    }

    markup::IXamlType GetXamlType(winrt::hstring const& fullName)
    {
        return xamlProvider_.GetXamlType(fullName);
    }

    winrt::com_array<markup::XmlnsDefinition> GetXmlnsDefinitions()
    {
        return xamlProvider_.GetXmlnsDefinitions();
    }

private:
    void buildUi()
    {
        window_ = mux::Window();
        window_.Title(kMainWindowTitle);
        window_.AppWindow().Resize(winrt::Windows::Graphics::SizeInt32{1120, 760});

        controls::ScrollViewer scrollViewer;
        scrollViewer.HorizontalScrollBarVisibility(controls::ScrollBarVisibility::Disabled);
        scrollViewer.VerticalScrollBarVisibility(controls::ScrollBarVisibility::Auto);
        scrollViewer.Background(brush(248, 250, 252));

        controls::StackPanel root;
        root.Padding(mux::Thickness{24, 18, 24, 24});
        root.Spacing(16);
        root.Background(brush(248, 250, 252));
        root.MaxWidth(1180);
        root.HorizontalAlignment(mux::HorizontalAlignment::Center);

        controls::Grid header;
        header.ColumnSpacing(18);
        header.ColumnDefinitions().Append(makeColumn(mux::GridLengthHelper::FromValueAndType(1, mux::GridUnitType::Star)));
        header.ColumnDefinitions().Append(makeColumn(mux::GridLengthHelper::Auto()));

        controls::StackPanel titleBlock;
        titleBlock.Spacing(4);

        controls::TextBlock title = makeTextBlock(L"Антивирус GUI", 28);
        title.FontWeight(winrt::Windows::UI::Text::FontWeights::SemiBold());
        title.Foreground(brush(15, 23, 42));
        titleBlock.Children().Append(title);

        controls::TextBlock subtitle = makeTextBlock(L"Рабочая панель службы, лицензии, сканирования и мониторинга", 14);
        subtitle.Foreground(brush(71, 85, 105));
        titleBlock.Children().Append(subtitle);

        header.Children().Append(titleBlock);

        controls::StackPanel badges;
        badges.Orientation(controls::Orientation::Horizontal);
        badges.Spacing(8);
        badges.VerticalAlignment(mux::VerticalAlignment::Center);
        badges.Children().Append(makePill(L"2.1-2.6", brush(219, 234, 254), brush(30, 64, 175)));
        badges.Children().Append(makePill(L"WinUI", brush(220, 252, 231), brush(22, 101, 52)));
        setGridPosition(badges, 0, 1);
        header.Children().Append(badges);
        root.Children().Append(header);

        controls::Grid contentGrid;
        contentGrid.ColumnSpacing(16);
        contentGrid.ColumnDefinitions().Append(makeColumn(mux::GridLengthHelper::FromValueAndType(2.1, mux::GridUnitType::Star)));
        contentGrid.ColumnDefinitions().Append(makeColumn(mux::GridLengthHelper::FromValueAndType(1.0, mux::GridUnitType::Star)));

        controls::StackPanel leftColumn;
        leftColumn.Spacing(14);

        controls::StackPanel rightColumn;
        rightColumn.Spacing(14);

        controls::StackPanel serviceCard = makeCard(L"Статус службы");
        serviceLabel_ = makeStatusText(L"Служба: проверка...");
        serviceCard.Children().Append(serviceLabel_);
        rightColumn.Children().Append(wrapCard(serviceCard));

        controls::StackPanel accountCard = makeCard(L"Аккаунт и лицензия");
        accountLabel_ = makeStatusText(L"Аккаунт: не проверен");
        licenseLabel_ = makeStatusText(L"Лицензия: не проверена");
        featureLabel_ = makeStatusText(L"Функции: не проверены");
        accountCard.Children().Append(accountLabel_);
        accountCard.Children().Append(licenseLabel_);
        accountCard.Children().Append(featureLabel_);

        loginBox_ = controls::TextBox();
        loginBox_.Header(winrt::box_value(winrt::hstring{L"Логин"}));
        loginBox_.PlaceholderText(L"demo");
        loginBox_.MinWidth(180);
        loginBox_.HorizontalAlignment(mux::HorizontalAlignment::Stretch);

        passwordBox_ = controls::PasswordBox();
        passwordBox_.Header(winrt::box_value(winrt::hstring{L"Пароль"}));
        passwordBox_.PlaceholderText(L"demo");
        passwordBox_.MinWidth(180);
        passwordBox_.HorizontalAlignment(mux::HorizontalAlignment::Stretch);

        activationBox_ = controls::TextBox();
        activationBox_.Header(winrt::box_value(winrt::hstring{L"Код активации"}));
        activationBox_.PlaceholderText(L"DEMO-1234");
        activationBox_.MinWidth(180);
        activationBox_.HorizontalAlignment(mux::HorizontalAlignment::Stretch);

        controls::Grid accountFields;
        accountFields.ColumnSpacing(12);
        accountFields.ColumnDefinitions().Append(makeColumn(mux::GridLengthHelper::FromValueAndType(1, mux::GridUnitType::Star)));
        accountFields.ColumnDefinitions().Append(makeColumn(mux::GridLengthHelper::FromValueAndType(1, mux::GridUnitType::Star)));
        accountFields.ColumnDefinitions().Append(makeColumn(mux::GridLengthHelper::FromValueAndType(1, mux::GridUnitType::Star)));
        setGridPosition(loginBox_, 0, 0);
        setGridPosition(passwordBox_, 0, 1);
        setGridPosition(activationBox_, 0, 2);
        accountFields.Children().Append(loginBox_);
        accountFields.Children().Append(passwordBox_);
        accountFields.Children().Append(activationBox_);

        controls::StackPanel accountButtons;
        accountButtons.Orientation(controls::Orientation::Horizontal);
        accountButtons.Children().Append(loginButton_ = makeButton(L"Войти", L"\xE8B7", true));
        accountButtons.Children().Append(logoutButton_ = makeButton(L"Выйти", L"\xE8BB"));
        accountButtons.Children().Append(activateButton_ = makeButton(L"Активировать", L"\xE72E"));

        loginButton_.Click([this](auto&&, auto&&) {
            login();
        });
        logoutButton_.Click([this](auto&&, auto&&) {
            logout();
        });
        activateButton_.Click([this](auto&&, auto&&) {
            activateLicense();
        });

        accountCard.Children().Append(accountFields);
        accountCard.Children().Append(accountButtons);
        leftColumn.Children().Append(wrapCard(accountCard));

        controls::StackPanel databaseCard = makeCard(L"Антивирусные базы");
        databaseLabel_ = makeStatusText(L"Базы: не проверены");
        databaseCard.Children().Append(databaseLabel_);
        rightColumn.Children().Append(wrapCard(databaseCard));

        controls::StackPanel scanCard = makeCard(L"Сканирование");
        controls::TextBlock scanHint = makeSmallCaps(L"Доступно после входа и активации");
        scanCard.Children().Append(scanHint);

        controls::StackPanel scanButtons;
        scanButtons.Orientation(controls::Orientation::Horizontal);
        scanButtons.Children().Append(scanFileButton_ = makeButton(L"Файл", L"\xE8A5", true));
        scanButtons.Children().Append(scanDirectoryButton_ = makeButton(L"Папка", L"\xE8B7"));
        scanButtons.Children().Append(scanFixedDrivesButton_ = makeButton(L"Все диски", L"\xEDA2"));
        scanCard.Children().Append(scanButtons);

        scanFileButton_.Click([this](auto&&, auto&&) {
            scanFile();
        });
        scanDirectoryButton_.Click([this](auto&&, auto&&) {
            scanDirectory();
        });
        scanFixedDrivesButton_.Click([this](auto&&, auto&&) {
            scanFixedDrives();
        });
        leftColumn.Children().Append(wrapCard(scanCard));

        controls::StackPanel scheduleCard = makeCard(L"Сканирование по расписанию");
        scheduleLabel_ = makeStatusText(L"Расписание: не проверено");
        scheduleCard.Children().Append(scheduleLabel_);

        scheduleIntervalBox_ = controls::TextBox();
        scheduleIntervalBox_.Header(winrt::box_value(winrt::hstring{L"Интервал, секунд"}));
        scheduleIntervalBox_.Text(L"60");
        scheduleIntervalBox_.MinWidth(180);
        scheduleIntervalBox_.HorizontalAlignment(mux::HorizontalAlignment::Left);
        scheduleCard.Children().Append(scheduleIntervalBox_);

        controls::StackPanel scheduleButtons;
        scheduleButtons.Orientation(controls::Orientation::Horizontal);
        scheduleButtons.Children().Append(scheduleFileButton_ = makeButton(L"Файл", L"\xE823", true));
        scheduleButtons.Children().Append(scheduleDirectoryButton_ = makeButton(L"Папка", L"\xE8B7"));
        scheduleButtons.Children().Append(scheduleFixedDrivesButton_ = makeButton(L"Все диски", L"\xEDA2"));
        scheduleButtons.Children().Append(stopScheduleButton_ = makeButton(L"Остановить", L"\xE71A"));
        scheduleCard.Children().Append(scheduleButtons);

        scheduleFileButton_.Click([this](auto&&, auto&&) {
            startScheduledFileScan();
        });
        scheduleDirectoryButton_.Click([this](auto&&, auto&&) {
            startScheduledDirectoryScan();
        });
        scheduleFixedDrivesButton_.Click([this](auto&&, auto&&) {
            startScheduledFixedDriveScan();
        });
        stopScheduleButton_.Click([this](auto&&, auto&&) {
            stopScheduledScan();
        });
        leftColumn.Children().Append(wrapCard(scheduleCard));

        controls::StackPanel monitorCard = makeCard(L"Мониторинг");
        monitorLabel_ = makeStatusText(L"Мониторинг: не проверен");
        monitorCard.Children().Append(monitorLabel_);

        controls::StackPanel monitorButtons;
        monitorButtons.Orientation(controls::Orientation::Horizontal);
        monitorButtons.Children().Append(startMonitorButton_ = makeButton(L"Запустить", L"\xE768", true));
        monitorButtons.Children().Append(stopMonitorButton_ = makeButton(L"Остановить", L"\xE71A"));
        monitorCard.Children().Append(monitorButtons);

        startMonitorButton_.Click([this](auto&&, auto&&) {
            startMonitoring();
        });
        stopMonitorButton_.Click([this](auto&&, auto&&) {
            stopMonitoring();
        });
        leftColumn.Children().Append(wrapCard(monitorCard));

        controls::StackPanel serviceActionsCard = makeCard(L"Управление службой");
        controls::TextBlock stopHint = makeSmallCaps(L"Остановка с подтверждением Secure Desktop");
        serviceActionsCard.Children().Append(stopHint);
        serviceActionsCard.Children().Append(stopServiceButton_ = makeButton(L"Остановить службу", L"\xE71A", false, true));
        stopServiceButton_.Click([this](auto&&, auto&&) {
            stopService();
        });
        rightColumn.Children().Append(wrapCard(serviceActionsCard));

        controls::StackPanel trayCard = makeCard(L"Фоновый режим");
        controls::TextBlock trayHint = makeStatusText(L"Закрытие окна скрывает приложение в трей.");
        trayCard.Children().Append(trayHint);
        trayCard.Children().Append(hideToTrayButton_ = makeButton(L"Скрыть в трей", L"\xE73F"));
        hideToTrayButton_.Click([this](auto&&, auto&&) {
            hideMainWindow();
        });
        rightColumn.Children().Append(wrapCard(trayCard));

        setGridPosition(leftColumn, 0, 0);
        setGridPosition(rightColumn, 0, 1);
        contentGrid.Children().Append(leftColumn);
        contentGrid.Children().Append(rightColumn);
        root.Children().Append(contentGrid);

        controls::StackPanel resultCard = makeCard(L"Результат и журнал последней операции");
        busyLabel_ = makeStatusText(L"Последняя операция: ожидание действия");
        resultBox_ = controls::TextBox();
        resultBox_.PlaceholderText(L"Журнал операций появится здесь.");
        resultBox_.AcceptsReturn(true);
        resultBox_.IsReadOnly(true);
        resultBox_.TextWrapping(mux::TextWrapping::Wrap);
        resultBox_.MinHeight(190);
        resultCard.Children().Append(busyLabel_);
        resultCard.Children().Append(resultBox_);
        root.Children().Append(wrapCard(resultCard));

        scrollViewer.Content(root);
        window_.Content(scrollViewer);
        setupWindowInterop();
        if (startHidden_) {
            hideMainWindow();
        } else {
            showMainWindow();
        }
    }

    void setupWindowInterop()
    {
        auto nativeWindow = window_.as<IWindowNative>();
        winrt::check_hresult(nativeWindow->get_WindowHandle(&windowHandle_));
        taskbarCreatedMessage_ = RegisterWindowMessageW(L"TaskbarCreated");

        SetWindowSubclass(windowHandle_, &WinUiApp::windowProc, 1, reinterpret_cast<DWORD_PTR>(this));
        applyWindowIcons();

        trayMenu_ = CreatePopupMenu();
        AppendMenuW(trayMenu_, MF_STRING, kTrayOpenCommand, L"Открыть");
        AppendMenuW(trayMenu_, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(trayMenu_, MF_STRING, kTrayExitCommand, L"Выход");

        mainMenu_ = CreateMenu();
        HMENU fileMenu = CreatePopupMenu();
        AppendMenuW(fileMenu, MF_STRING, kTrayExitCommand, L"Выход");
        AppendMenuW(mainMenu_, MF_POPUP, reinterpret_cast<UINT_PTR>(fileMenu), L"Файл");
        SetMenu(windowHandle_, mainMenu_);

        window_.Closed([this](auto&&, mux::WindowEventArgs const& args) {
            if (!exiting_) {
                args.Handled(true);
                hideMainWindow();
                return;
            }

            cleanupNativeResources();
        });

        addTrayIcon();
    }

    void applyWindowIcons()
    {
        if (windowHandle_ == nullptr) {
            return;
        }

        if (largeWindowIcon_ == nullptr) {
            largeWindowIcon_ = createAppIcon(GetSystemMetrics(SM_CXICON));
        }
        if (smallWindowIcon_ == nullptr) {
            smallWindowIcon_ = createAppIcon(GetSystemMetrics(SM_CXSMICON));
        }

        if (largeWindowIcon_ != nullptr) {
            SendMessageW(windowHandle_, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(largeWindowIcon_));
        }
        if (smallWindowIcon_ != nullptr) {
            SendMessageW(windowHandle_, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(smallWindowIcon_));
        }
    }

    void cleanupNativeResources()
    {
        removeTrayIcon();

        if (windowHandle_ != nullptr) {
            RemoveWindowSubclass(windowHandle_, &WinUiApp::windowProc, 1);
        }

        if (trayMenu_ != nullptr) {
            DestroyMenu(trayMenu_);
            trayMenu_ = nullptr;
        }

        if (mainMenu_ != nullptr) {
            if (windowHandle_ != nullptr) {
                SetMenu(windowHandle_, nullptr);
            }
            DestroyMenu(mainMenu_);
            mainMenu_ = nullptr;
        }

        if (smallWindowIcon_ != nullptr) {
            DestroyIcon(smallWindowIcon_);
            smallWindowIcon_ = nullptr;
        }

        if (largeWindowIcon_ != nullptr) {
            DestroyIcon(largeWindowIcon_);
            largeWindowIcon_ = nullptr;
        }
    }

    static LRESULT CALLBACK windowProc(
        HWND hwnd,
        UINT message,
        WPARAM wParam,
        LPARAM lParam,
        UINT_PTR,
        DWORD_PTR refData
    )
    {
        auto* app = reinterpret_cast<WinUiApp*>(refData);
        if (app != nullptr) {
            if (message == app->taskbarCreatedMessage_) {
                app->trayIconAdded_ = false;
                app->addTrayIcon();
                return 0;
            }

            if (message == kShowMainWindowMessage) {
                app->showMainWindow();
                return 0;
            }

            if (message == kTrayMessage) {
                app->handleTrayMessage(static_cast<UINT>(LOWORD(lParam)));
                return 0;
            }

            if (message == WM_COMMAND && LOWORD(wParam) == kTrayExitCommand) {
                app->requestStopAndExit();
                return 0;
            }
        }

        return DefSubclassProc(hwnd, message, wParam, lParam);
    }

    void addTrayIcon()
    {
        if (windowHandle_ == nullptr) {
            return;
        }

        NOTIFYICONDATAW data{};
        data.cbSize = sizeof(data);
        data.hWnd = windowHandle_;
        data.uID = kTrayIconId;
        data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        data.uCallbackMessage = kTrayMessage;
        data.hIcon = smallWindowIcon_ != nullptr ? smallWindowIcon_ : LoadIconW(nullptr, IDI_APPLICATION);
        wcscpy_s(data.szTip, L"Antivirus GUI Coursework");

        if (trayIconAdded_) {
            Shell_NotifyIconW(NIM_MODIFY, &data);
            return;
        }

        if (Shell_NotifyIconW(NIM_ADD, &data)) {
            data.uVersion = NOTIFYICON_VERSION_4;
            Shell_NotifyIconW(NIM_SETVERSION, &data);
            trayIconAdded_ = true;
        }
    }

    void removeTrayIcon()
    {
        if (!trayIconAdded_ || windowHandle_ == nullptr) {
            return;
        }

        NOTIFYICONDATAW data{};
        data.cbSize = sizeof(data);
        data.hWnd = windowHandle_;
        data.uID = kTrayIconId;
        Shell_NotifyIconW(NIM_DELETE, &data);
        trayIconAdded_ = false;
    }

    void handleTrayMessage(UINT message)
    {
        switch (message) {
        case WM_LBUTTONUP:
        case WM_LBUTTONDBLCLK:
        case NIN_SELECT:
        case NIN_KEYSELECT:
            showMainWindow();
            break;
        case WM_RBUTTONUP:
        case WM_CONTEXTMENU:
            showTrayMenu();
            break;
        default:
            break;
        }
    }

    void showTrayMenu()
    {
        if (trayMenu_ == nullptr || windowHandle_ == nullptr) {
            return;
        }

        POINT point{};
        GetCursorPos(&point);
        SetForegroundWindow(windowHandle_);

        const UINT command = TrackPopupMenu(
            trayMenu_,
            TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_NONOTIFY,
            point.x,
            point.y,
            0,
            windowHandle_,
            nullptr
        );

        if (command == kTrayOpenCommand) {
            showMainWindow();
        } else if (command == kTrayExitCommand) {
            requestStopAndExit();
        }

        PostMessageW(windowHandle_, WM_NULL, 0, 0);
    }

    void showMainWindow()
    {
        window_.AppWindow().Show(true);
        window_.Activate();
        windowVisible_ = true;
    }

    void hideMainWindow()
    {
        window_.AppWindow().Hide();
        windowVisible_ = false;
    }

    bool requestServiceStopWithConfirmation()
    {
        if (!antivirus::common::confirmServiceStopOnSecureDesktop()) {
            resultBox_.Text(L"Остановка службы отменена пользователем.");
            busyLabel_.Text(L"Последняя операция отменена");
            return false;
        }

        const bool requested = rpcClient_.requestServiceStop();
        resultBox_.Text(requested
            ? L"Запрос на остановку службы отправлен."
            : L"Не удалось отправить запрос на остановку службы через RPC.");
        busyLabel_.Text(L"Последняя операция выполнена");
        return requested;
    }

    void requestStopAndExit()
    {
        if (!requestServiceStopWithConfirmation()) {
            showMainWindow();
            return;
        }

        exiting_ = true;
        window_.Close();
    }

    void refreshState()
    {
        if (busy_.load()) {
            return;
        }

        const bool rpcAvailable = rpcClient_.ping();
        serviceLabel_.Text(serviceStatusText(rpcClient_.serviceStatus(), rpcAvailable));

        const auto auth = rpcClient_.authState();
        const auto license = rpcClient_.licenseState();
        const auto feature = rpcClient_.featureState();
        const auto database = rpcClient_.databaseInfo();
        const auto monitor = rpcClient_.directoryMonitorStatus();
        const auto schedule = rpcClient_.scanScheduleStatus();

        accountLabel_.Text(authText(auth));
        licenseLabel_.Text(licenseText(license));
        featureLabel_.Text(featureText(feature));
        databaseLabel_.Text(databaseText(database));
        monitorLabel_.Text(monitorText(monitor));
        scheduleLabel_.Text(scheduleText(schedule));

        setActionButtonsEnabled(feature.functionalityEnabled, monitor.running, schedule.running, rpcAvailable);
    }

    void setActionButtonsEnabled(bool featureEnabled, bool monitorRunning, bool scheduleRunning, bool rpcAvailable)
    {
        const bool canUseFeature = featureEnabled && !busy_.load();
        const bool canCallRpc = rpcAvailable && !busy_.load();

        loginButton_.IsEnabled(canCallRpc);
        logoutButton_.IsEnabled(canCallRpc);
        activateButton_.IsEnabled(canCallRpc);
        scanFileButton_.IsEnabled(canUseFeature);
        scanDirectoryButton_.IsEnabled(canUseFeature);
        scanFixedDrivesButton_.IsEnabled(canUseFeature);
        scheduleFileButton_.IsEnabled(canUseFeature);
        scheduleDirectoryButton_.IsEnabled(canUseFeature);
        scheduleFixedDrivesButton_.IsEnabled(canUseFeature);
        stopScheduleButton_.IsEnabled(canUseFeature && scheduleRunning);
        startMonitorButton_.IsEnabled(canUseFeature);
        stopMonitorButton_.IsEnabled(canUseFeature && monitorRunning);
        stopServiceButton_.IsEnabled(canCallRpc);
        hideToTrayButton_.IsEnabled(!busy_.load());
    }

    void setAllButtonsEnabled(bool enabled)
    {
        loginButton_.IsEnabled(enabled);
        logoutButton_.IsEnabled(enabled);
        activateButton_.IsEnabled(enabled);
        scanFileButton_.IsEnabled(enabled);
        scanDirectoryButton_.IsEnabled(enabled);
        scanFixedDrivesButton_.IsEnabled(enabled);
        scheduleFileButton_.IsEnabled(enabled);
        scheduleDirectoryButton_.IsEnabled(enabled);
        scheduleFixedDrivesButton_.IsEnabled(enabled);
        stopScheduleButton_.IsEnabled(enabled);
        startMonitorButton_.IsEnabled(enabled);
        stopMonitorButton_.IsEnabled(enabled);
        stopServiceButton_.IsEnabled(enabled);
        hideToTrayButton_.IsEnabled(enabled);
    }

    void runBackground(const std::wstring& progressText, std::function<std::wstring()> operation)
    {
        if (busy_.exchange(true)) {
            resultBox_.Text(L"Операция уже выполняется. Дождитесь завершения.");
            return;
        }

        setAllButtonsEnabled(false);
        busyLabel_.Text(L"Последняя операция: выполняется");
        resultBox_.Text(progressText);

        dispatching::DispatcherQueue dispatcher = window_.DispatcherQueue();
        std::thread([this, dispatcher, operation = std::move(operation)]() mutable {
            std::wstring resultText;

            try {
                resultText = operation();
            } catch (...) {
                resultText = L"Ошибка: операция завершилась с исключением.";
            }

            dispatcher.TryEnqueue([this, resultText = std::move(resultText)]() {
                resultBox_.Text(resultText);
                busyLabel_.Text(L"Последняя операция выполнена");
                busy_.store(false);
                refreshState();
            });
        }).detach();
    }

    void login()
    {
        std::wstring login = loginBox_.Text().c_str();
        std::wstring password = passwordBox_.Password().c_str();

        runBackground(L"Выполняется вход...", [this, login = std::move(login), password = std::move(password)]() {
            const auto state = rpcClient_.login(login, password);
            if (!state.lastError.empty()) {
                return L"Вход не выполнен: " + state.lastError;
            }

            return state.authenticated
                ? L"Вход выполнен: " + valueOrDash(state.displayName)
                : std::wstring(L"Вход не выполнен. Проверьте логин и пароль.");
        });
    }

    void logout()
    {
        runBackground(L"Выполняется выход...", [this]() {
            const auto state = rpcClient_.logout();
            if (!state.lastError.empty()) {
                return L"Выход не выполнен: " + state.lastError;
            }

            return std::wstring(L"Выход выполнен. Функции сканирования и мониторинга заблокированы до нового входа и активации.");
        });
    }

    void activateLicense()
    {
        std::wstring activationCode = activationBox_.Text().c_str();

        runBackground(L"Выполняется активация лицензии...", [this, activationCode = std::move(activationCode)]() {
            const auto state = rpcClient_.activateProduct(activationCode);
            if (!state.lastError.empty()) {
                return L"Активация не выполнена: " + state.lastError;
            }

            return state.licenseActive
                ? L"Лицензия активна до " + valueOrDash(state.licenseExpiresAt)
                : L"Лицензия не активирована: " + valueOrDash(state.featureBlockedReason);
        });
    }

    void scanFile()
    {
        const std::optional<std::wstring> path = pickFile();
        if (!path.has_value()) {
            return;
        }

        runBackground(L"Сканирование файла...\n" + *path, [this, path = *path]() {
            return formatScanResult(rpcClient_.scanFile(path));
        });
    }

    void scanDirectory()
    {
        const std::optional<std::wstring> path = pickFolder(L"Выберите папку для сканирования");
        if (!path.has_value()) {
            return;
        }

        runBackground(L"Сканирование папки...\n" + *path, [this, path = *path]() {
            return formatScanResult(rpcClient_.scanDirectory(path));
        });
    }

    void scanFixedDrives()
    {
        runBackground(L"Сканирование всех несъёмных дисков...", [this]() {
            return formatScanResult(rpcClient_.scanFixedDrives());
        });
    }

    unsigned long scheduleIntervalSeconds() const
    {
        const std::wstring text = scheduleIntervalBox_.Text().c_str();
        try {
            const unsigned long value = std::stoul(text);
            if (value < 5) {
                return 5;
            }
            if (value > 86400) {
                return 86400;
            }
            return value;
        } catch (...) {
            return 60;
        }
    }

    std::wstring formatScheduleStartResult(const antivirus::winui::ScanScheduleStatus& status) const
    {
        if (!status.lastError.empty()) {
            return L"Расписание не запущено: " + status.lastError;
        }

        return L"Расписание запущено.\n" + scheduleText(status);
    }

    void startScheduledFileScan()
    {
        const std::optional<std::wstring> path = pickFile();
        if (!path.has_value()) {
            return;
        }

        const unsigned long intervalSeconds = scheduleIntervalSeconds();
        runBackground(L"Настройка сканирования файла по расписанию...\n" + *path, [this, path = *path, intervalSeconds]() {
            return formatScheduleStartResult(
                rpcClient_.startScanSchedule(antivirus::winui::kScanScheduleFile, path, intervalSeconds));
        });
    }

    void startScheduledDirectoryScan()
    {
        const std::optional<std::wstring> path = pickFolder(L"Выберите папку для сканирования по расписанию");
        if (!path.has_value()) {
            return;
        }

        const unsigned long intervalSeconds = scheduleIntervalSeconds();
        runBackground(L"Настройка сканирования папки по расписанию...\n" + *path, [this, path = *path, intervalSeconds]() {
            return formatScheduleStartResult(
                rpcClient_.startScanSchedule(antivirus::winui::kScanScheduleDirectory, path, intervalSeconds));
        });
    }

    void startScheduledFixedDriveScan()
    {
        const unsigned long intervalSeconds = scheduleIntervalSeconds();
        runBackground(L"Настройка сканирования всех несъёмных дисков по расписанию...", [this, intervalSeconds]() {
            return formatScheduleStartResult(
                rpcClient_.startScanSchedule(antivirus::winui::kScanScheduleFixedDrives, L"", intervalSeconds));
        });
    }

    void stopScheduledScan()
    {
        runBackground(L"Остановка сканирования по расписанию...", [this]() {
            const auto status = rpcClient_.stopScanSchedule();
            if (!status.lastError.empty()) {
                return L"Расписание остановлено с предупреждением: " + status.lastError;
            }

            return std::wstring(L"Расписание сканирования остановлено.");
        });
    }

    void startMonitoring()
    {
        const std::optional<std::wstring> path = pickFolder(L"Выберите папку для мониторинга");
        if (!path.has_value()) {
            return;
        }

        runBackground(L"Запуск мониторинга папки...\n" + *path, [this, path = *path]() {
            const auto status = rpcClient_.startDirectoryMonitor(path);
            if (!status.lastError.empty()) {
                return L"Мониторинг не запущен: " + status.lastError;
            }

            return L"Мониторинг запущен: " + valueOrDash(status.path);
        });
    }

    void stopMonitoring()
    {
        runBackground(L"Остановка мониторинга...", [this]() {
            const auto status = rpcClient_.stopDirectoryMonitor();
            if (!status.lastError.empty()) {
                return L"Мониторинг остановлен с предупреждением: " + status.lastError;
            }

            return std::wstring(L"Мониторинг остановлен.");
        });
    }

    void stopService()
    {
        requestServiceStopWithConfirmation();
    }

    antivirus::winui::RpcClientWin rpcClient_;
    std::atomic_bool busy_{false};

    bool startHidden_ = false;
    bool exiting_ = false;
    bool windowVisible_ = false;
    bool trayIconAdded_ = false;
    UINT taskbarCreatedMessage_ = 0;
    HWND windowHandle_ = nullptr;
    HMENU trayMenu_ = nullptr;
    HMENU mainMenu_ = nullptr;
    HICON smallWindowIcon_ = nullptr;
    HICON largeWindowIcon_ = nullptr;

    mux::Window window_{nullptr};
    mux::DispatcherTimer pollingTimer_{nullptr};

    controls::TextBlock serviceLabel_{nullptr};
    controls::TextBlock accountLabel_{nullptr};
    controls::TextBlock licenseLabel_{nullptr};
    controls::TextBlock featureLabel_{nullptr};
    controls::TextBlock databaseLabel_{nullptr};
    controls::TextBlock monitorLabel_{nullptr};
    controls::TextBlock scheduleLabel_{nullptr};
    controls::TextBlock busyLabel_{nullptr};

    controls::TextBox loginBox_{nullptr};
    controls::PasswordBox passwordBox_{nullptr};
    controls::TextBox activationBox_{nullptr};
    controls::TextBox scheduleIntervalBox_{nullptr};
    controls::TextBox resultBox_{nullptr};

    controls::Button loginButton_{nullptr};
    controls::Button logoutButton_{nullptr};
    controls::Button activateButton_{nullptr};
    controls::Button scanFileButton_{nullptr};
    controls::Button scanDirectoryButton_{nullptr};
    controls::Button scanFixedDrivesButton_{nullptr};
    controls::Button scheduleFileButton_{nullptr};
    controls::Button scheduleDirectoryButton_{nullptr};
    controls::Button scheduleFixedDrivesButton_{nullptr};
    controls::Button stopScheduleButton_{nullptr};
    controls::Button startMonitorButton_{nullptr};
    controls::Button stopMonitorButton_{nullptr};
    controls::Button stopServiceButton_{nullptr};
    controls::Button hideToTrayButton_{nullptr};

    xamltype::XamlControlsXamlMetaDataProvider xamlProvider_;
};

} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    const bool allowStandaloneDebug = hasArgument(L"--allow-standalone-debug");
    const bool serviceChild = hasArgument(L"--service-child");
    const bool forceShow = hasArgument(L"--show");
    const bool startHidden = !forceShow && (serviceChild || hasArgument(L"--hidden"));

    try {
        if (!allowStandaloneDebug) {
            antivirus::gui::ServiceClient serviceClient;
            if (!serviceClient.isRunning()) {
                if (!serviceClient.isInstalled()) {
                    antivirus::common::log_error(L"AntivirusGuiService не установлена");
                    return 1;
                }

                antivirus::common::log_info(L"Служба не запущена; пробуем запустить её и выйти");
                if (!serviceClient.startService() || !serviceClient.waitUntilRunning(15000)) {
                    antivirus::common::log_error(L"Не удалось запустить AntivirusGuiService");
                    return 1;
                }

                if (!serviceChild) {
                    if (!requestExistingGuiToShow(7000)) {
                        antivirus::common::log_warning(L"Служба запущена, но окно WinUI, принадлежащее службе, не найдено");
                    }
                    return 0;
                }
            }

            if (!serviceChild) {
                if (!requestExistingGuiToShow(3000)) {
                    antivirus::common::log_warning(L"Окно WinUI, принадлежащее службе, не найдено");
                }
                return 0;
            }

            if (!antivirus::gui::isParentProjectService()) {
                antivirus::common::log_error(L"В рабочем режиме GUI должен запускаться службой AntivirusService.exe");
                return 1;
            }
        }

        std::unique_ptr<antivirus::gui::SingleInstanceGuard> singleInstance;
        if (!allowStandaloneDebug) {
            singleInstance = std::make_unique<antivirus::gui::SingleInstanceGuard>();
            if (!singleInstance->isPrimaryInstance()) {
                antivirus::common::log_info(L"Второй экземпляр WinUI GUI завершается до создания иконки в трее");
                return 0;
            }
        }

        if (!allowStandaloneDebug) {
            antivirus::common::hardenCurrentProcessForDemo(L"AntivirusWinUi.exe", true);
        }
        winrt::init_apartment(winrt::apartment_type::single_threaded);
        const auto bootstrap = Microsoft::Windows::ApplicationModel::DynamicDependency::Bootstrap::Initialize();

        mux::Application::Start([startHidden](auto&&) {
            static winrt::com_ptr<WinUiApp> app;
            app = winrt::make_self<WinUiApp>(startHidden);
        });
    } catch (const winrt::hresult_error& error) {
        reportStartupError(
            L"Не удалось запустить WinUI-интерфейс.\nHRESULT: " + formatHresult(error.code()) + L"\n" +
            std::wstring(error.message().c_str()),
            serviceChild);
        return 1;
    } catch (const std::exception& error) {
        reportStartupError(L"Не удалось запустить WinUI-интерфейс.\n" + widenAscii(error.what()), serviceChild);
        return 1;
    } catch (...) {
        reportStartupError(L"Не удалось запустить WinUI-интерфейс: неизвестная ошибка.", serviceChild);
        return 1;
    }

    return 0;
}
