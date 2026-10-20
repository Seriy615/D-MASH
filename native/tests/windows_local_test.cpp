#include "os_windows.h"
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <iostream>
#include <stdexcept>
#include <vector>
void check(bool ok) { if (!ok) throw std::runtime_error("Windows local test failed"); }
void transfer(HANDLE pipe, bool write, char& byte) {
    OVERLAPPED operation{}; operation.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr); check(operation.hEvent);
    DWORD count = 0;
    const bool immediate = write ? WriteFile(pipe, &byte, 1, &count, &operation) : ReadFile(pipe, &byte, 1, &count, &operation);
    if (!immediate) { check(GetLastError() == ERROR_IO_PENDING); check(WaitForSingleObject(operation.hEvent, 5000) == WAIT_OBJECT_0); check(GetOverlappedResult(pipe, &operation, &count, FALSE)); }
    CloseHandle(operation.hEvent); check(count == 1);
}
int main(int argc, char** argv) {
    if (argc > 1 && std::string(argv[1]) == "--spawn-test") {
        check(argc == 6 && std::string(argv[4]) == "--bootstrap-handle");
        check(std::string(argv[3]) == "spaces and \"quotes\" ending\\");
        const auto inherited = reinterpret_cast<HANDLE>(std::stoull(argv[5]));
        DWORD flags = 0;
        check(GetHandleInformation(inherited, &flags));
        check(!GetHandleInformation(reinterpret_cast<HANDLE>(std::stoull(argv[2])), &flags));
        dmash::windowsLocal::requireSameUserPipe(reinterpret_cast<std::uintptr_t>(inherited));
        dmash::windowsLocal::requirePrivatePipe(reinterpret_cast<std::uintptr_t>(inherited));
        char byte = 0; transfer(inherited, false, byte); check(byte == 'Q'); byte = 'A'; transfer(inherited, true, byte);
        CloseHandle(inherited); return 42;
    }
    using namespace dmash::windowsLocal;
    HANDLE token = nullptr; check(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token));
    DWORD size = 0; GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<unsigned char> user(size); check(GetTokenInformation(token, TokenUser, user.data(), size, &size)); CloseHandle(token);
    LPWSTR sid = nullptr; check(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, &sid));
    const std::wstring sddl = std::wstring(L"D:P(A;;GA;;;") + sid + L")(A;;GA;;;SY)"; LocalFree(sid);
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    check(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr));
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
    const auto unique = std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
    const std::wstring pipeName = L"\\\\.\\pipe\\dmash-local-test-" + unique;
    HANDLE server = CreateNamedPipeW(pipeName.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096, 0, &attributes);
    LocalFree(descriptor); check(server != INVALID_HANDLE_VALUE);
    HANDLE client = CreateFileW(pipeName.c_str(), GENERIC_READ | GENERIC_WRITE | READ_CONTROL, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    check(client != INVALID_HANDLE_VALUE);
    OVERLAPPED connected{}; connected.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr); check(connected.hEvent);
    const auto result = ConnectNamedPipe(server, &connected); check(result || GetLastError() == ERROR_PIPE_CONNECTED);
    requireSameUserPipe(reinterpret_cast<std::uintptr_t>(server)); requireSameUserPipe(reinterpret_cast<std::uintptr_t>(client));
    requirePrivatePipe(reinterpret_cast<std::uintptr_t>(server)); requirePrivatePipe(reinterpret_cast<std::uintptr_t>(client));
    CloseHandle(connected.hEvent); CloseHandle(client); CloseHandle(server);
    wchar_t temp[MAX_PATH + 1]; check(GetTempPathW(MAX_PATH, temp));
    const std::wstring profile = std::wstring(temp) + L"dmash-local-test-" + unique;
    ensurePrivateProfile(profile);
    const auto file = profile + L"\\node.sqlite";
    HANDLE state = CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr); check(state != INVALID_HANDLE_VALUE); CloseHandle(state);
    requirePrivateFile(file); ensurePrivateProfile(profile);
    // Synthetic file only: a broad ACE must be rejected without rewriting state.
    check(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;FA;;;WD)", SDDL_REVISION_1, &descriptor, nullptr));
    BOOL present = FALSE, defaulted = FALSE; PACL acl = nullptr;
    check(GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted));
    check(SetNamedSecurityInfoW(const_cast<wchar_t*>(file.c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr) == ERROR_SUCCESS);
    LocalFree(descriptor);
    bool rejected = false; try { requirePrivateFile(file); } catch (const std::exception&) { rejected = true; } check(rejected);
    check(DeleteFileW(file.c_str())); check(RemoveDirectoryW(profile.c_str()));
    wchar_t executable[32768]; check(GetModuleFileNameW(nullptr, executable, 32768));
    SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE};
    HANDLE excluded = CreateEventW(&inherit, TRUE, FALSE, nullptr); check(excluded);
    auto spawned = spawnDaemon(executable, {L"--spawn-test", std::to_wstring(reinterpret_cast<std::uintptr_t>(excluded)), L"spaces and \"quotes\" ending\\"});
    check(spawned.process && spawned.parentPipe && spawned.pid);
    auto moved = std::move(spawned); check(!spawned.process && !spawned.parentPipe);
    HANDLE lease = reinterpret_cast<HANDLE>(moved.releaseParentPipe()); check(!moved.parentPipe);
    char byte = 'Q'; transfer(lease, true, byte); transfer(lease, false, byte); check(byte == 'A');
    check(WaitForSingleObject(reinterpret_cast<HANDLE>(moved.process), 5000) == WAIT_OBJECT_0);
    DWORD exitCode = 0; check(GetExitCodeProcess(reinterpret_cast<HANDLE>(moved.process), &exitCode)); check(exitCode == 42);
    // Parent retained no child endpoint: after draining, child exit breaks lease.
    DWORD available = 0; check(!PeekNamedPipe(lease, nullptr, 0, nullptr, &available, nullptr)); check(GetLastError() == ERROR_BROKEN_PIPE);
    CloseHandle(lease); CloseHandle(excluded);
    bool duplicateRejected = false;
    try { auto invalid = spawnDaemon(executable, {L"--bootstrap-handle=123"}); }
    catch (const std::exception&) { duplicateRejected = true; }
    check(duplicateRejected);
    std::cout << "Windows same-user private namedpipe, child-only inheritance, duplex lease, argument quoting and retained-profile ACL checks PASS\n";
}
#endif
