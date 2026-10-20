# Disposable native toolchain proof

Sources were reconstructed after the host reboot. Current output files are reruns of these sources; `historical-*.txt` are explicitly transcribed observations whose original raw files and binaries were lost. No production runtime, real storage, credentials or private TLS material is included.

Linux commands (substitute your owned paths):

```sh
export TC="$HOME/.cache/dmash-native-20261020"
export PATH="$TC/venv/bin:$PATH"
cmake -S docs/native/2026-10-20/toolchain-proof -B "$TC/build-linux-probe" -G Ninja \
  -DCMAKE_PREFIX_PATH="$TC/Qt/6.12.0/gcc_64" \
  -DQJS_DIR="$TC/build/quickjs-2026-06-04" -DCMAKE_BUILD_TYPE=Release \
  '-DCMAKE_C_FLAGS_RELEASE=-O1 -DNDEBUG'
cmake --build "$TC/build-linux-probe" -j1
# Generate an isolated short-lived certificate with SAN DNS:localhost, IP:127.0.0.1.
# Supply its public cert and private key paths; never publish the key.
LD_LIBRARY_PATH="$TC/Qt/6.12.0/gcc_64/lib" \
QT_PLUGIN_PATH="$TC/Qt/6.12.0/gcc_64/plugins" \
"$TC/build-linux-probe/dmash_toolchain_probe" /private/localhost.crt /private/localhost.key
```

To use owned OpenSSL explicitly, set CMake OPENSSL_INCLUDE_DIR, OPENSSL_CRYPTO_LIBRARY and OPENSSL_SSL_LIBRARY to its prefix and prepend its lib directory to LD_LIBRARY_PATH. The program prints the actual Qt TLS backend/version. Compile `argon_profile_probe.c` with that prefix's headers/libs; system OpenSSL3.0 cannot run the ARGON2 profiles.

`desktop_main.cpp` checks a native QuickJS expression, native crypto vectors, SQLite CAS and verified synthetic localhost WSS. `android_main.cpp`, manifest and Java class are a disposable JNI/link/packaging skeleton, not a usable Node app or proven Qt loader startup. A real Android service needs proper Qt deployment resources and lifecycle integration. No adb install/start performed.

`windows-kit-selection-current.json` is fresh official metadata, not executable evidence. Archive/checksum metadata remains in the owned cache; public source/output hashes are in `public-manifest.json`. Recompute hashes after every legitimate change. Original frozen audit `verification/native-proof` is separate and unchanged.

Android cross-configure (separate clean build directory required):

```sh
"$TC/Qt/6.12.0/android_arm64_v8a/bin/qt-cmake" \
  -S docs/native/2026-10-20/toolchain-proof -B "$TC/build-android-arm64-probe" -G Ninja \
  -DANDROID_SDK_ROOT="$TC/sdk" -DANDROID_NDK_ROOT="$TC/sdk/ndk/27.2.12479018" \
  -DQT_HOST_PATH="$TC/Qt/6.12.0/gcc_64" -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-28 -DQJS_DIR="$TC/build/quickjs-2026-06-04" \
  -DCMAKE_BUILD_TYPE=Release '-DCMAKE_C_FLAGS_RELEASE=-O1 -DNDEBUG'
cmake --build "$TC/build-android-arm64-probe" -j1
```

Two setup failures were caught before accepting cross-build evidence: Qt's wrapper requires `ANDROID_NDK_ROOT` (using only `ANDROID_NDK` silently left the host compiler selected), and Python ZIP extraction must restore Unix symlinks from `external_attr` (otherwise NDK `clang` is a text file containing `clang-18`). Corrected owned extraction restores symlinks; CMake log must explicitly show NDK Clang and the `aarch64-none-linux-android28` target. Check the resulting ELF machine, not the build directory name.

The manually compiled Java binding uses JDK21 `javac -source 8 -target 8`, API36 `android.jar` as bootclasspath, Qt6Android.jar as classpath, and the kit's `src/android/java/src` as sourcepath. This does not replace proper Gradle/Qt deployment resource generation. Manual D8/aapt2/zipalign verification has a deliberately narrower scope than a runnable service APK.

The current `source-load-current.txt` was obtained by compiling the unchanged frozen audit `verification/native-proof/embed.c` against this build's `libqjs.a` plus system libcrypto, then executing its unchanged `source-load.js`. Those original public source hashes are recorded in recovery-manifest; the frozen sources were not edited. This is a current rerun of a historical bundled module snapshot, not a fresh product dependency graph or actual Node transport test.

OpenSSL Android was built from a separate verified 3.5.9 extraction (never a host-configured source tree), using owned NDK r27c bin on PATH:

```sh
export ANDROID_NDK_ROOT="$TC/sdk/ndk/27.2.12479018"
export PATH="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
cd "$TC/build/openssl-android-source/openssl-3.5.9"
CFLAGS=-O1 LDFLAGS=-Wl,-z,max-page-size=16384 ./Configure android-arm64 \
  -D__ANDROID_API__=28 shared no-tests --prefix="$TC/openssl-android"
make -j1 build_generated
make -j1 libcrypto.so libssl.so
```

Stage copies as `openssl-android/lib/libcrypto_3.so` and `libssl_3.so`; use owned patchelf with `--page-size 16384 --set-soname` for each matching suffixed name and `--replace-needed libcrypto.so libcrypto_3.so` on SSL. Copy the generated/source `include/openssl` into the same prefix. Android native CMake must explicitly point `OPENSSL_INCLUDE_DIR` and `OPENSSL_CRYPTO_LIBRARY` at that prefix/suffixed library; the Qt TLS plugin uses `ANDROID_OPENSSL_SUFFIX=_3`.

After JNI cross-link and SSL staging, run `build-android-proof.sh /your/repo`. It compiles the public Java class/binding using explicit JDK21, creates DEX, then calls `assemble-disposable-apk.py`. The latter checks each bundled ELF is AArch64 and LOAD alignment plus offset/address congruence support 16K pages, signs with a disposable task-only key, verifies APK signature and ZIP16K alignment. Only source/logs/JSON hashes are public. The APK and private signing key remain in the owned cache; no install/launch or Qt loader/resource acceptance follows from this result.
