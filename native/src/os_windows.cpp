#include "os_windows.h"
#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <memory>
#include <stdexcept>
#include <vector>
namespace dmash::windowsLocal {
namespace {
void require(bool yes) { if (!yes) throw std::runtime_error("Windows local ownership rejected"); }
struct Handle {
    HANDLE value = nullptr;
    explicit Handle(HANDLE h = nullptr) : value(h) {}
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
};
struct Local {
    void* value = nullptr;
    ~Local() { if (value) LocalFree(value); }
};
std::vector<unsigned char> tokenUser(HANDLE process) {
    Handle token;
    require(OpenProcessToken(process, TOKEN_QUERY, &token.value));
    DWORD bytes = 0;
    GetTokenInformation(token.value, TokenUser, nullptr, 0, &bytes);
    require(bytes >= sizeof(TOKEN_USER) && bytes <= 65536);
    std::vector<unsigned char> result(bytes);
    require(GetTokenInformation(token.value, TokenUser, result.data(), bytes, &bytes));
    return result;
}
PSID sid(std::vector<unsigned char>& user) { return reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid; }
void privateDacl(PACL acl, PSID current) {
    require(acl && IsValidAcl(acl));
    unsigned char system[SECURITY_MAX_SID_SIZE]; DWORD size = sizeof(system);
    require(CreateWellKnownSid(WinLocalSystemSid, nullptr, system, &size));
    bool ownerAllowed = false;
    for (DWORD i = 0; i < acl->AceCount; ++i) {
        void* raw = nullptr;
        require(GetAce(acl, i, &raw));
        const auto* header = static_cast<ACE_HEADER*>(raw);
        if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        require(header->AceType == ACCESS_ALLOWED_ACE_TYPE);
        const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
        auto* allowed = const_cast<DWORD*>(&ace->SidStart);
        require(IsValidSid(allowed));
        require(EqualSid(allowed, current) || EqualSid(allowed, system));
        if (EqualSid(allowed, current) && !(header->AceFlags & INHERIT_ONLY_ACE) && ace->Mask)
            ownerAllowed = true;
    }
    require(ownerAllowed);
}
void verifyFile(const std::wstring& path, bool missing, bool directory) {
    Handle file(CreateFileW(path.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                           nullptr));
    if (file.value == INVALID_HANDLE_VALUE && missing && GetLastError() == ERROR_FILE_NOT_FOUND)
        return;
    require(file.value != INVALID_HANDLE_VALUE);
    BY_HANDLE_FILE_INFORMATION info{};
    require(GetFileInformationByHandle(file.value, &info));
    require(!(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT));
    require(bool(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == directory);
    auto current = tokenUser(GetCurrentProcess());
    PSID owner = nullptr; PACL acl = nullptr; Local descriptor;
    require(GetSecurityInfo(file.value, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                            &owner, nullptr, &acl, nullptr, reinterpret_cast<PSECURITY_DESCRIPTOR*>(&descriptor.value)) == ERROR_SUCCESS);
    require(owner && EqualSid(owner, sid(current)));
    privateDacl(acl, sid(current));
}
}
void requireSameUserPipe(std::uintptr_t raw) {
    HANDLE pipe = reinterpret_cast<HANDLE>(raw);
    require(GetFileType(pipe) == FILE_TYPE_PIPE);
    DWORD flags = 0; ULONG pid = 0;
    require(GetNamedPipeInfo(pipe, &flags, nullptr, nullptr, nullptr));
    require((flags & PIPE_SERVER_END) ? GetNamedPipeClientProcessId(pipe, &pid)
                                    : GetNamedPipeServerProcessId(pipe, &pid));
    require(pid != 0);
    Handle peer(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    require(peer.value != nullptr);
    auto theirs = tokenUser(peer.value), current = tokenUser(GetCurrentProcess());
    require(EqualSid(sid(theirs), sid(current)));
}
void requirePrivatePipe(std::uintptr_t raw) {
    auto current = tokenUser(GetCurrentProcess()); PACL acl = nullptr; Local descriptor;
    require(GetSecurityInfo(reinterpret_cast<HANDLE>(raw), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                            nullptr, nullptr, &acl, nullptr, reinterpret_cast<PSECURITY_DESCRIPTOR*>(&descriptor.value)) == ERROR_SUCCESS);
    privateDacl(acl, sid(current));
}
void ensurePrivateProfile(const std::wstring& path) {
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        require(GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND);
        auto current = tokenUser(GetCurrentProcess()); Local stringSid, descriptor;
        require(ConvertSidToStringSidW(sid(current), reinterpret_cast<LPWSTR*>(&stringSid.value)));
        const std::wstring user = static_cast<wchar_t*>(stringSid.value);
        const std::wstring sddl = L"O:" + user + L"D:P(A;OICI;FA;;;" + user + L")(A;OICI;FA;;;SY)";
        require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1,
                    reinterpret_cast<PSECURITY_DESCRIPTOR*>(&descriptor.value), nullptr));
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor.value, FALSE};
        require(CreateDirectoryW(path.c_str(), &attributes));
    }
    verifyFile(path, false, true);
    for (const auto* file : {L"node.sqlite", L"node.sqlite-wal", L"node.sqlite-shm", L"owner.lock"})
        requirePrivateFile(path + L"\\" + file, true);
}
void requirePrivateFile(const std::wstring& path, bool allowMissing) { verifyFile(path, allowMissing, false); }
}
#endif
