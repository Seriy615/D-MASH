# D-MASH development package dependency notices

This package is not covered by a single MIT label. Original D-MASH platform code and each dependency retain their own license; no Telegram code or assets are included in this checkpoint.

- Qt6.12.0 Core/Gui/Widgets/Network/WebSockets/Sql and Android Java bindings are dynamically linked/deployed from the official Qt kit. The open-source LGPL3/GPL3 license texts are included. Qt copyright belongs to The Qt Company and the respective contributors. The Android service uses a version-pinned CorePrivate API, so its matching Qt runtime is bundled. Qt module sources/notices and their third-party components must accompany a release's complete source offer; this development build is not a completed redistribution audit.
- OpenSSL3.5.9: Apache2.0, full upstream LICENSE included as OpenSSL-LICENSE.txt. Copyright The OpenSSL Project Authors and contributors.
- QuickJS2026-06-04: MIT, upstream LICENSE included as QuickJS-LICENSE.txt. Copyright Fabrice Bellard and Charlie Gordon. It executes the existing Node protocol modules in the separate transport process.
- Android libc++_shared from NDKr27c: LLVM Apache2.0 with LLVM exceptions, libcxx-LICENSE.txt. The text comes from llvm-project/llvmorg-18.1.8/libcxx/LICENSE.TXT; the NDK kit selects the actual deployed library.
- AndroidX Core1.17.0 and the AndroidX transitive support libraries selected by Qt's Gradle project: Apache2.0. Copyright the Android Open Source Project and contributors; Apache-2.0.txt included. Their dependency versions are visible in Gradle's resolved dependency metadata.
- Qt's SQLite driver contains SQLite, dedicated to the public domain by its authors. Qt module/driver terms still apply to the surrounding Qt implementation.

The Account library's exact legacy Kyber WASM/generated C and WABT notices are maintained separately in native/account and must be included when that library enters a platform package. That library is not linked into the Node service. Source hashes/limits are recorded in platform checkpoint evidence; dependency license texts are copied into actual APK assets/desktop install output by the platform build.
