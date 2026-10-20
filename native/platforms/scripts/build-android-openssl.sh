#!/bin/sh
set -eu
CACHE=${DMASH_TOOLCHAIN_CACHE:-"$HOME/.cache/dmash-native-20261020"}
ABI=${1:-x86_64}
case "$ABI" in
 x86_64) TARGET=android-x86_64; PREFIX="$CACHE/openssl-android-x86_64" ;;
 arm64-v8a) TARGET=android-arm64; PREFIX="$CACHE/openssl-android" ;;
 *) exit 2 ;;
esac
SOURCE="$CACHE/build/openssl-platform-$ABI/openssl-3.5.9"
mkdir -p "$CACHE/build/openssl-platform-$ABI" "$PREFIX/lib" "$PREFIX/include"
if [ ! -d "$SOURCE" ]; then tar -xf "$CACHE/archives/openssl-3.5.9.tar.gz" -C "$CACHE/build/openssl-platform-$ABI"; fi
export ANDROID_NDK_ROOT="$CACHE/sdk/ndk/27.2.12479018"
export PATH="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$CACHE/venv/bin:$PATH"
cd "$SOURCE"
./Configure "$TARGET" -D__ANDROID_API__=28 shared no-tests no-apps --prefix="$PREFIX" --libdir=lib -Wl,-z,max-page-size=16384
nice -n 5 make -j1 build_generated
nice -n 5 make -j1 libcrypto.so libssl.so
cp libcrypto.so "$PREFIX/lib/libcrypto_3.so"
cp libssl.so "$PREFIX/lib/libssl_3.so"
patchelf --page-size 16384 --set-soname libcrypto_3.so "$PREFIX/lib/libcrypto_3.so"
patchelf --page-size 16384 --set-soname libssl_3.so --replace-needed libcrypto.so libcrypto_3.so "$PREFIX/lib/libssl_3.so"
cp -R include/openssl "$PREFIX/include/"
