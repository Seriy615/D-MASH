# Native toolchain, 20 October 2026

This is environment/port feasibility evidence, not an application acceptance report. Product source is unchanged by these probes. Android, Windows and Linux are all targets; see [TARGETS.md](TARGETS.md). Account plaintext/E2EE and the credential broker stay outside the network process. Future shared native host receives scoped transport materials only.

## Recovery and current observations

A host reboot erased all former `/tmp` toolchains, binaries and original logs. [recovery-manifest.json](toolchain-proof/recovery-manifest.json) distinguishes surviving frozen audit artifacts from transcribed historical observations. Reconstructed source below is explicitly new and has been rerun; it is not represented as byte-identical to the lost source.

| Check | Current post-reboot result | Limits |
|---|---|---|
| Node reference | 24.19.0, official SHA256 verified | Shared exact test runtime, not native host |
| Linux Qt/QuickJS | PASS, Qt 6.12.0 + QuickJS 2026-06-04 | Fixed synthetic expression, no real Node protocol |
| Frozen 25-module source snapshot | PASS fresh six assertions | Original frozen synthetic harness; no real storage/transport |
| Linux SQLite | PASS transactional CAS, stale reject, rollback/reopen | Synthetic disposable DB; crash/fsync/power-loss not tested |
| Linux crypto | PASS CSPRNG, SHA256 and AES-GCM known vector | Initial rerun system OpenSSL 3.0.13 |
| Linux WSS | PASS localhost echo with certificate verification | No remote auth/Node interop, NAT or reconnect proof |
| Owned OpenSSL 3.5.9 / Argon profiles | PASS fresh owned TLS/crypto + both exact master fixtures | Synthetic inputs; no real root unlock/rewrap tested |
| Android arm64 JNI/Qt/Java/package | PASS current cross-link, DEX, OpenSSL suffix/NEEDED, signature and ELF/ZIP16K checks | Manual package lacks Qt loader/resources; install/device launch NOT RUN |
| Windows compiler/runtime | NOT RUN | Actual official MinGW kit metadata verified; no local compiler/Wine |

[Owned OpenSSL current rerun](toolchain-proof/linux-owned-current.txt) reports Qt 6.12.0 / OpenSSL 3.5.9 and six host checks plus both Argon profiles PASS. [Current Argon fixture output](toolchain-proof/argon-profile-current.txt) separately records both legacy D and versioned ID profiles. The first current output is [linux-system-openssl-current.txt](toolchain-proof/linux-system-openssl-current.txt). Native probe sources and reproducible command outline are in [toolchain-proof/README.md](toolchain-proof/README.md). The surviving frozen audit harness was also compiled and rerun against the restored QuickJS library: [six assertions and 25-module load](toolchain-proof/source-load-current.txt). This tests its bundled snapshot and synthetic adapters, not native Node authorization. No private certificate/key or executable is published.

## Selected tools and provenance

Durable owned cache: `/home/jcode/.cache/dmash-native-20261020`; isolated venv contains aqtinstall 3.3.0, CMake 4.4.4, Ninja 1.13.2 and patchelf 0.19.1.0. Builds started at `nice -n 15`; severe CPU starvation led to a recorded intentional cancellation of only verified owned compile subtrees, deletion of their partial object outputs, and sequential resume at `nice -n 5`, one compiler job while browser QA runs. Tool license notices retained in cache: aqtinstall MIT; Ninja Apache-2.0; patchelf GPL-3.0-or-later; CMake wheel wrapper Apache-2.0 with upstream CMake notices. Gradle archive LICENSE is Apache-2.0; Temurin legal/java.base contains GPLv2 plus Classpath exception. Android SDK/NDK retain SDK terms and per-component NOTICE/NOTICE.toolchain, rather than treating the complete tool bundle as one Apache-licensed work. No toolchain archives are redistributed here. No global package installation, shared SDK mutation, adb server/device operation or real profile access.

Qt **6.12.0** public open-source binaries were actually downloaded (qtbase, WebSockets, ICU 73.2 only) from the [official desktop repository](https://download.qt.io/online/qtsdkrepository/linux_x64/desktop/qt6_6120/qt6_6120/Updates.xml), package revision `6.12.0-0-202609280346`. Linux kit is `gcc_64`. Android kit is `android_arm64_v8a` under [all_os Android metadata](https://download.qt.io/online/qtsdkrepository/all_os/android/qt6_6120/qt6_6120_arm64_v8a/Updates.xml), not the legacy aqt Linux Android index.

[Qt supported platforms](https://doc.qt.io/qt-6/supported-platforms.html) specifies JDK 21, NDK r27c `27.2.12479018`, API 28–36 for this kit; restore only arm64/API36/build-tools36. Existing Java17 and another project's API35 SDK are not overwritten. Gradle9.5.1 was additionally restored from its official distribution and verified with upstream SHA256 `bafc141b619ad6350fd975fc903156dd5c151998cc8b058e8c1044ab5f7b031f`. AGP9.2.1 belongs to the later proper Qt packaging project; the disposable manual packaging test alone cannot establish Qt loader/service startup.

QuickJS **2026-06-04**, [official archive](https://bellard.org/quickjs/quickjs-2026-06-04.tar.xz), SHA256 `b376e839b322978313d929fd20663b11ba58b75df5a46c126dd19ea2fa70ad2a`; MIT. OpenSSL **3.5.9 LTS**, [official source release](https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz), SHA256 `603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a`; Apache-2.0. OpenSSL checksum was compared with upstream checksum. Preserve actual legacy ARGON2D and explicit new ARGON2ID profiles separately; do not globally correct the old enum or derive new identities. Public fixtures use the UTF8 base64 salt text unchanged.

Qt modules used here are offered under commercial or LGPLv3/GPL terms; retain notices, dynamic linking/relink information and review each deployed module. This proof adds no QML/WebEngine dependency. Actual Android shell is normal Java/Kotlin Views over service JNI/Binder; Desktop is Qt Widgets for selected Telegram Desktop UI parts. Neither selected UI is implemented by this toolchain probe. A read-only [Linux GUI dependency check](toolchain-proof/linux-gui-dependencies-current.json) found Qt Widgets present but the XCB plugin lacks several host xcb/xkbcommon runtime libraries; GL and xkbcommon development headers are also absent. Core/WSS proof does not establish GUI readiness. Restore needed official distro packages into an owned prefix before a real Widgets build/launch; no global apt installation has been performed.

## Windows concrete setup path

[Fresh actual kit metadata](toolchain-proof/windows-kit-selection-current.json) selects `qt.qt6.6120.win64_mingw`, `qt.qt6.6120.addons.qtwebsockets.win64_mingw` and compiler `qt.tools.win64_mingw1310`. [Fresh compiler metadata](toolchain-proof/windows-compiler-current.json) comes from the modern `tools_mingw1310` endpoint and confirms version `13.1.0-202407240918`, archive `mingw1310.7z`; the legacy generic tools_mingw index is obsolete. This binary kit requires **MinGW 13.1 POSIX/SEH/MSVCRT**, as its runtime archive name states; generic docs mentioning a newer compiler do not override the downloaded kit. Do not combine an arbitrary UCRT or Linux crosscompiler with it.

On a Windows x64 runner, fetch official Qt Online Installer and verify its published digest, install these components using [official installer CLI](https://doc.qt.io/qtinstallerframework/ifw-use-cases-cli.html), with credentials supplied privately if required. Example: `installer.exe --root C:\dmash-tools\Qt --accept-licenses --default-answer --confirm-command install qt.qt6.6120.win64_mingw qt.qt6.6120.addons.qtwebsockets.win64_mingw qt.tools.win64_mingw1310`. List installed versions and archive hashes in the runner artifact. Add matching compiler and Qt bin to PATH; build OpenSSL 3.5.9 `mingw64` shared with that compiler, then configure this public CMake probe with Qt and OpenSSL explicit prefixes, compile QuickJS from source and run CTest/probe with synthetic certs. Deploy via matching `windeployqt`, inspect DLL dependencies and run from a clean directory/VM. Installer dependency closure can include tools/examples; inspect and bound it before provisioning a permanent runner.

Acceptance still requires a real Windows build/run, trusted WSS failure cases, SQL reopening and packaged UI/service lifecycle. No Windows executable or launch has been observed on this Linux host.

## Android packaging checkpoint

[Current summary](toolchain-proof/android-packaging-summary-current.json) records every bundled library SHA256/ELF dependency and the disposable APK/DEX hash. [Build output](toolchain-proof/android-packaging-current.txt) shows APK signature verification and 16K ELF/ZIP checks. OpenSSL was cross-built from verified 3.5.9 sources, with `libssl_3.so` depending on `libcrypto_3.so`; LOAD offset/address congruence is checked in addition to alignment. The APK stays outside Git in the owned cache and is not a working Node application. No install, launch, lifecycle, Android TLS execution or Qt Java loader/resource acceptance was performed.

## Implementation gates after browser baseline

1. Linux owned OpenSSL rerun and Android shared-library/manual package inspection are complete. Keep Android runtime NOT RUN until proper Qt deployment resources and service bootstrap are generated and tested on a real device/emulator without touching another session.
2. Introduce explicit native interfaces for JS storage (`read/cas/quota`), timers/tasks, CSPRNG/WebCrypto and Qt sockets; retain Account-free Node dependency graph. An IndexedDB shim is not a substitute for transactional storage design.
3. Build lifecycle owner/service + scoped IPC on each platform, then real Python Node interop and crash/restart/fencing tests. Fixed JavaScript expression and TLS echo are not authorized Node behavior.
4. Android foreground/background service, Doze/reboot/policy/direct-off and Windows/Linux lifecycle acceptance remain separate gates. Physical NAT/ICE and retained-profile migrations are NOT RUN here.
