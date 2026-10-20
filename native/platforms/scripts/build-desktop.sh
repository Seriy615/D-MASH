#!/bin/sh
set -eu
CACHE=${DMASH_TOOLCHAIN_CACHE:-"$HOME/.cache/dmash-native-20261020"}
ROOT=${DMASH_SOURCE_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)}
BUILD=${DMASH_DESKTOP_BUILD:-"$CACHE/build-desktop-app"}
export PATH="$CACHE/venv/bin:$PATH"
cmake -S "$ROOT/native/platforms/desktop" -B "$BUILD" -G Ninja \
 -DDMASH_ACCOUNT_QUICKJS_DIR="$CACHE/build/quickjs-2026-06-04" \
 -DOPENSSL_INCLUDE_DIR="$CACHE/openssl-desktop/include" \
 -DOPENSSL_CRYPTO_LIBRARY="$CACHE/openssl-desktop/lib/libcrypto.so" \
 -DCMAKE_PREFIX_PATH="$CACHE/Qt/6.12.0/gcc_64;$CACHE/platform-sysroot/usr" \
 -DOPENGL_INCLUDE_DIR="$CACHE/platform-sysroot/usr/include" \
 -DOPENGL_gl_LIBRARY=/usr/lib/x86_64-linux-gnu/libGL.so.1 \
 -DOPENGL_glx_LIBRARY=/usr/lib/x86_64-linux-gnu/libGLX.so.0 \
 -DOPENGL_opengl_LIBRARY="$CACHE/platform-sysroot/usr/lib/x86_64-linux-gnu/libOpenGL.so.0"
cmake --build "$BUILD" --target dmash-desktop dmash_desktop_ui_test -j1
LD_LIBRARY_PATH="$CACHE/openssl-desktop/lib:$CACHE/Qt/6.12.0/gcc_64/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" ctest --test-dir "$BUILD" -R desktop-controls --output-on-failure
