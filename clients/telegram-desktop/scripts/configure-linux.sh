#!/usr/bin/env bash
# Actual upstream application target. This does not launch a Telegram account.
set -euo pipefail
cache=${DMASH_TOOLCHAIN_CACHE:-"$HOME/.cache/dmash-native-20261020"}
source_dir=${DMASH_TELEGRAM_DESKTOP_SOURCE:-"$cache/telegram-desktop-fork"}
build_dir=${DMASH_TELEGRAM_DESKTOP_BUILD:-"$cache/build-telegram-desktop-fork"}
recipe=$(cd "$(dirname "$0")/.." && pwd)
export PATH="$cache/venv/bin:$cache/telegram-dependencies/usr/bin:$PATH"
export LD_LIBRARY_PATH="$cache/telegram-dependencies/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PKG_CONFIG_SYSROOT_DIR="$cache/telegram-dependencies"
export PKG_CONFIG_LIBDIR="$cache/telegram-dependencies/usr/lib/x86_64-linux-gnu/pkgconfig:$cache/telegram-dependencies/usr/share/pkgconfig"
cmake -S "$source_dir" -B "$build_dir" -G Ninja \
 -DPKG_CONFIG_EXECUTABLE="$recipe/scripts/pkg-config" \
 -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS_RELEASE='-O1 -DNDEBUG' \
 -DCMAKE_PREFIX_PATH="$cache/Qt/6.12.0/gcc_64;$cache/platform-sysroot/usr;$cache/telegram-dependencies;$cache/telegram-dependencies/usr" \
 -DOPENGL_INCLUDE_DIR="$cache/platform-sysroot/usr/include" \
 -DOPENGL_opengl_LIBRARY="$cache/platform-sysroot/usr/lib/x86_64-linux-gnu/libOpenGL.so.0" \
 -DOPENGL_glx_LIBRARY=/usr/lib/x86_64-linux-gnu/libGLX.so.0 \
 -DOPENSSL_INCLUDE_DIR="$cache/openssl-desktop/include" \
 -DOPENSSL_CRYPTO_LIBRARY="$cache/openssl-desktop/lib/libcrypto.so" \
 -DOPENSSL_SSL_LIBRARY="$cache/openssl-desktop/lib/libssl.so" \
 -DDESKTOP_APP_USE_PACKAGED=ON -DDESKTOP_APP_DISABLE_AUTOUPDATE=ON \
 -DDESKTOP_APP_DISABLE_CRASH_REPORTS=ON -DTDESKTOP_DMASH_CLIENT=ON
