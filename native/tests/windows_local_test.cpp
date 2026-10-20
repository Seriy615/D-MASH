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
int main() {
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
    std::cout << "Windows same-user private namedpipe and retained-profile ACL checks PASS\n";
}
#endif
