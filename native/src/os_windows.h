#pragma once
#ifdef _WIN32
#include <cstdint>
#include <string>
namespace dmash::windowsLocal {
// Shared by broker, daemon and GUI. No credential material enters these helpers.
void requireSameUserPipe(std::uintptr_t handle);
void requirePrivatePipe(std::uintptr_t handle);
void ensurePrivateProfile(const std::wstring& path);
void requirePrivateFile(const std::wstring& path, bool allowMissing = false);
}
#endif
