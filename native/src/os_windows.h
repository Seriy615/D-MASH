#pragma once
#ifdef _WIN32
#include <cstdint>
#include <string>
#include <vector>
namespace dmash::windowsLocal {
// Owns only this spawned process handle and its broker lifetime lease. Closing
// process does not kill the child; the daemon observes bootstrap lease EOF.
struct ChildProcess final {
    std::uintptr_t process = 0, parentPipe = 0;
    std::uint32_t pid = 0;
    ChildProcess() = default;
    ~ChildProcess();
    ChildProcess(const ChildProcess&) = delete;
    ChildProcess& operator=(const ChildProcess&) = delete;
    ChildProcess(ChildProcess&&) noexcept;
    ChildProcess& operator=(ChildProcess&&) noexcept;
    // Transfer to QLocalSocket::setSocketDescriptor; its owner retains the lease.
    std::uintptr_t releaseParentPipe() noexcept;
};
// Arguments contain paths/options only, never credentials. Appends the private
// bootstrap handle; only that child pipe endpoint is inherited by CreateProcess.
ChildProcess spawnDaemon(const std::wstring& executable, const std::vector<std::wstring>& arguments);
// Shared by broker, daemon and GUI. No credential material enters these helpers.
void requireSameUserPipe(std::uintptr_t handle);
void requirePrivatePipe(std::uintptr_t handle);
void ensurePrivateProfile(const std::wstring& path);
void requirePrivateFile(const std::wstring& path, bool allowMissing = false);
}
#endif
