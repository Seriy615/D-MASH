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
#include <utility>
namespace dmash::windowsLocal {
namespace {
void require(bool yes, const char* stage = "Windows local ownership rejected") { if (!yes) throw std::runtime_error(stage); }
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
    require(acl && IsValidAcl(acl), "WINDOWS_PRIVATE_DACL_INVALID");
    unsigned char system[SECURITY_MAX_SID_SIZE]; DWORD size = sizeof(system);
    require(CreateWellKnownSid(WinLocalSystemSid, nullptr, system, &size), "WINDOWS_PRIVATE_DACL_SYSTEM_SID");
    bool ownerAllowed = false;
    for (DWORD i = 0; i < acl->AceCount; ++i) {
        void* raw = nullptr;
        require(GetAce(acl, i, &raw), "WINDOWS_PRIVATE_DACL_READ_ACE");
        const auto* header = static_cast<ACE_HEADER*>(raw);
        if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        require(header->AceType == ACCESS_ALLOWED_ACE_TYPE, "WINDOWS_PRIVATE_DACL_ACE_TYPE");
        const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
        auto* allowed = const_cast<DWORD*>(&ace->SidStart);
        require(IsValidSid(allowed), "WINDOWS_PRIVATE_DACL_ACE_SID");
        require(EqualSid(allowed, current) || EqualSid(allowed, system), "WINDOWS_PRIVATE_DACL_OTHER_PRINCIPAL");
        if (EqualSid(allowed, current) && !(header->AceFlags & INHERIT_ONLY_ACE) && ace->Mask)
            ownerAllowed = true;
    }
    require(ownerAllowed, "WINDOWS_PRIVATE_DACL_OWNER_ACCESS");
}
void verifyFile(const std::wstring& path, bool missing, bool directory) {
    Handle file(CreateFileW(path.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                           nullptr));
    if (file.value == INVALID_HANDLE_VALUE && missing && GetLastError() == ERROR_FILE_NOT_FOUND)
        return;
    require(file.value != INVALID_HANDLE_VALUE, "WINDOWS_PROFILE_FILE_OPEN");
    BY_HANDLE_FILE_INFORMATION info{};
    require(GetFileInformationByHandle(file.value, &info), "WINDOWS_PROFILE_FILE_INFORMATION");
    require(!(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT), "WINDOWS_PROFILE_FILE_REPARSE");
    require(bool(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == directory, "WINDOWS_PROFILE_FILE_TYPE");
    auto current = tokenUser(GetCurrentProcess());
    PSID owner = nullptr; PACL acl = nullptr; Local descriptor;
    require(GetSecurityInfo(file.value, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                            &owner, nullptr, &acl, nullptr, reinterpret_cast<PSECURITY_DESCRIPTOR*>(&descriptor.value)) == ERROR_SUCCESS, "WINDOWS_PROFILE_SECURITY_INFORMATION");
    require(owner && EqualSid(owner, sid(current)), "WINDOWS_PROFILE_OWNER_MISMATCH");
    privateDacl(acl, sid(current));
}
}
ChildProcess::~ChildProcess() {
    if (parentPipe) CloseHandle(reinterpret_cast<HANDLE>(parentPipe));
    if (process) CloseHandle(reinterpret_cast<HANDLE>(process));
}
ChildProcess::ChildProcess(ChildProcess&& other) noexcept
    : process(std::exchange(other.process, 0)), parentPipe(std::exchange(other.parentPipe, 0)),
      pid(std::exchange(other.pid, 0)) {}
ChildProcess& ChildProcess::operator=(ChildProcess&& other) noexcept {
    if (this != &other) {
        if (parentPipe) CloseHandle(reinterpret_cast<HANDLE>(parentPipe));
        if (process) CloseHandle(reinterpret_cast<HANDLE>(process));
        process = std::exchange(other.process, 0);
        parentPipe = std::exchange(other.parentPipe, 0);
        pid = std::exchange(other.pid, 0);
    }
    return *this;
}
std::uintptr_t ChildProcess::releaseParentPipe() noexcept { return std::exchange(parentPipe, 0); }
ChildProcess spawnDaemon(const std::wstring& executable, const std::vector<std::wstring>& arguments) {
    require(!executable.empty() && executable.find(L'\0') == std::wstring::npos);
    // Windows CRT argv quoting, including trailing slashes and embedded quotes.
    auto quoted = [](const std::wstring& value) {
        require(value.find(L'\0') == std::wstring::npos);
        std::wstring result = L"\""; size_t slashes = 0;
        for (const wchar_t c : value) {
            if (c == L'\\') { ++slashes; continue; }
            if (c == L'\"') result.append(slashes * 2 + 1, L'\\');
            else result.append(slashes, L'\\');
            slashes = 0; result += c;
        }
        result.append(slashes * 2, L'\\'); result += L'\"'; return result;
    };
    auto current = tokenUser(GetCurrentProcess()); Local stringSid, descriptor;
    require(ConvertSidToStringSidW(sid(current), reinterpret_cast<LPWSTR*>(&stringSid.value)));
    const std::wstring user = static_cast<wchar_t*>(stringSid.value);
    const std::wstring sddl = L"O:" + user + L"D:P(A;;GA;;;" + user + L")(A;;GA;;;SY)";
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1,
                reinterpret_cast<PSECURITY_DESCRIPTOR*>(&descriptor.value), nullptr));
    unsigned char random[16]; HCRYPTPROV provider = 0;
    require(CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT));
    const bool generated = CryptGenRandom(provider, sizeof(random), random);
    CryptReleaseContext(provider, 0); require(generated);
    std::wstring name = L"\\\\.\\pipe\\dmash-bootstrap-";
    for (const auto byte : random) { name += L"0123456789abcdef"[byte >> 4]; name += L"0123456789abcdef"[byte & 15]; }
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor.value, FALSE};
    Handle server(CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 65536, 65536, 0, &attributes));
    require(server.value != INVALID_HANDLE_VALUE);
    attributes.bInheritHandle = TRUE;
    Handle child(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE | READ_CONTROL, 0, &attributes,
                             OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr));
    require(child.value != INVALID_HANDLE_VALUE);
    OVERLAPPED connected{}; Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr)); require(event.value);
    connected.hEvent = event.value;
    const bool connectedNow = ConnectNamedPipe(server.value, &connected);
    require(connectedNow || GetLastError() == ERROR_PIPE_CONNECTED);
    requirePrivatePipe(reinterpret_cast<std::uintptr_t>(server.value));
    requirePrivatePipe(reinterpret_cast<std::uintptr_t>(child.value));
    require(SetHandleInformation(server.value, HANDLE_FLAG_INHERIT, 0));
    std::wstring command = quoted(executable);
    for (const auto& arg : arguments) {
        for (const auto* reserved : {L"--bootstrap-handle", L"--bootstrap-fd", L"--bundle"})
            require(arg != reserved && arg.rfind(std::wstring(reserved) + L"=", 0) != 0);
        command += L" " + quoted(arg);
    }
    command += L" --bootstrap-handle " + std::to_wstring(reinterpret_cast<std::uintptr_t>(child.value));
    require(command.size() < 32767);
    SIZE_T bytes = 0; InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes); require(bytes > 0);
    std::vector<unsigned char> storage(bytes);
    auto* list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    require(InitializeProcThreadAttributeList(list, 1, 0, &bytes));
    struct AttributeCleanup { LPPROC_THREAD_ATTRIBUTE_LIST value; ~AttributeCleanup() { DeleteProcThreadAttributeList(value); } } cleanup{list};
    require(UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &child.value, sizeof(child.value), nullptr, nullptr));
    STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup); startup.lpAttributeList = list;
    PROCESS_INFORMATION info{};
    require(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, nullptr, nullptr, &startup.StartupInfo, &info));
    CloseHandle(info.hThread);
    ChildProcess result;
    result.process = reinterpret_cast<std::uintptr_t>(info.hProcess);
    result.parentPipe = reinterpret_cast<std::uintptr_t>(server.value); server.value = nullptr;
    result.pid = info.dwProcessId;
    return result;
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
        require(CreateDirectoryW(path.c_str(), &attributes), "WINDOWS_PROFILE_DIRECTORY_CREATE");
    }
    verifyFile(path, false, true);
    for (const auto* file : {L"node.sqlite", L"node.sqlite-wal", L"node.sqlite-shm", L"owner.lock"})
        requirePrivateFile(path + L"\\" + file, true);
}
void requirePrivateFile(const std::wstring& path, bool allowMissing) { verifyFile(path, allowMissing, false); }
}
#endif
