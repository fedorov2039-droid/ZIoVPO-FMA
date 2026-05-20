#include "common/process_hardening.h"

#include "common/logging.h"

#include <Aclapi.h>
#include <sddl.h>

#include <array>
#include <string>
#include <string_view>

namespace antivirus::common {
namespace {

class LocalSid {
public:
    explicit LocalSid(const wchar_t* sidText)
    {
        ConvertStringSidToSidW(sidText, &sid_);
    }

    ~LocalSid()
    {
        if (sid_ != nullptr) {
            LocalFree(sid_);
        }
    }

    LocalSid(const LocalSid&) = delete;
    LocalSid& operator=(const LocalSid&) = delete;

    [[nodiscard]] PSID get() const
    {
        return sid_;
    }

    [[nodiscard]] bool valid() const
    {
        return sid_ != nullptr;
    }

private:
    PSID sid_ = nullptr;
};

class LocalHandle {
public:
    explicit LocalHandle(HANDLE handle = nullptr)
        : handle_(handle)
    {
    }

    ~LocalHandle()
    {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
    }

    LocalHandle(const LocalHandle&) = delete;
    LocalHandle& operator=(const LocalHandle&) = delete;

    [[nodiscard]] HANDLE get() const
    {
        return handle_;
    }

    [[nodiscard]] bool valid() const
    {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

private:
    HANDLE handle_ = nullptr;
};

DWORD limitedProcessRights()
{
    return PROCESS_QUERY_LIMITED_INFORMATION |
           PROCESS_QUERY_INFORMATION |
           PROCESS_VM_READ |
           SYNCHRONIZE |
           READ_CONTROL;
}

EXPLICIT_ACCESSW makeEntry(PSID sid, DWORD accessMask, ACCESS_MODE mode)
{
    EXPLICIT_ACCESSW entry{};
    entry.grfAccessPermissions = accessMask;
    entry.grfAccessMode = mode;
    entry.grfInheritance = NO_INHERITANCE;
    entry.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    entry.Trustee.pMultipleTrustee = nullptr;
    entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entry.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    entry.Trustee.ptstrName = static_cast<LPWSTR>(sid);
    return entry;
}

std::wstring boolText(bool value)
{
    return value ? L"да" : L"нет";
}

bool applyHardeningToProcess(HANDLE processHandle, std::wstring_view componentName, bool protectFromAdministrators)
{
    if (processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE) {
        log_error(L"Защита процесса не применена: недопустимый дескриптор процесса");
        return false;
    }

    LocalSid localSystem(L"S-1-5-18");
    LocalSid administrators(L"S-1-5-32-544");
    LocalSid users(L"S-1-5-32-545");
    LocalSid authenticatedUsers(L"S-1-5-11");
    LocalSid everyone(L"S-1-1-0");

    if (!localSystem.valid() ||
        !administrators.valid() ||
        !users.valid() ||
        !authenticatedUsers.valid() ||
        !everyone.valid()) {
        log_error(L"Защита процесса не применена: не удалось создать системный SID");
        return false;
    }

    constexpr DWORD dangerousRights =
        PROCESS_TERMINATE |
        PROCESS_CREATE_THREAD |
        PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE |
        PROCESS_DUP_HANDLE |
        PROCESS_SET_INFORMATION |
        PROCESS_SET_QUOTA |
        WRITE_DAC |
        WRITE_OWNER |
        DELETE;

    const DWORD adminRights = protectFromAdministrators ? limitedProcessRights() : PROCESS_ALL_ACCESS;

    std::array<EXPLICIT_ACCESSW, 8> entries{
        makeEntry(users.get(), dangerousRights, DENY_ACCESS),
        makeEntry(authenticatedUsers.get(), dangerousRights, DENY_ACCESS),
        makeEntry(everyone.get(), PROCESS_TERMINATE, DENY_ACCESS),
        makeEntry(administrators.get(), protectFromAdministrators ? dangerousRights : 0, DENY_ACCESS),

        makeEntry(localSystem.get(), PROCESS_ALL_ACCESS, SET_ACCESS),
        makeEntry(administrators.get(), adminRights, SET_ACCESS),
        makeEntry(users.get(), limitedProcessRights(), SET_ACCESS),
        makeEntry(authenticatedUsers.get(), limitedProcessRights(), SET_ACCESS),
    };

    PACL newDacl = nullptr;
    const DWORD aclError = SetEntriesInAclW(
        static_cast<ULONG>(entries.size()),
        entries.data(),
        nullptr,
        &newDacl
    );

    if (aclError != ERROR_SUCCESS || newDacl == nullptr) {
        log_error(L"Защита процесса не применена: SetEntriesInAclW завершился ошибкой");
        return false;
    }

    const DWORD securityError = SetSecurityInfo(
        processHandle,
        SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        newDacl,
        nullptr
    );

    LocalFree(newDacl);

    if (securityError != ERROR_SUCCESS) {
        log_error(L"Защита процесса не применена: SetSecurityInfo завершился ошибкой");
        return false;
    }

    std::wstring message = L"Защита процесса включена для ";
    message += componentName;
    message += L"; защита от администраторов=";
    message += boolText(protectFromAdministrators);
    log_info(message);

    return true;
}

} // namespace

bool hardenCurrentProcessForDemo(std::wstring_view componentName, bool protectFromAdministrators)
{
    HANDLE duplicatedHandle = nullptr;

    const BOOL duplicated = DuplicateHandle(
        GetCurrentProcess(),
        GetCurrentProcess(),
        GetCurrentProcess(),
        &duplicatedHandle,
        WRITE_DAC | READ_CONTROL | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        0
    );

    if (!duplicated || duplicatedHandle == nullptr) {
        log_error(L"Защита процесса не применена: DuplicateHandle для текущего процесса завершился ошибкой");
        return false;
    }

    LocalHandle handle(duplicatedHandle);
    return applyHardeningToProcess(handle.get(), componentName, protectFromAdministrators);
}

bool hardenProcessHandleForDemo(HANDLE processHandle, std::wstring_view componentName, bool protectFromAdministrators)
{
    return applyHardeningToProcess(processHandle, componentName, protectFromAdministrators);
}

} // namespace antivirus::common
