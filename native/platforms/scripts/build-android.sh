#!/bin/sh
set -eu
CACHE=${DMASH_TOOLCHAIN_CACHE:-"$HOME/.cache/dmash-native-20261020"}
ROOT=${DMASH_SOURCE_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)}
ABI=${DMASH_ANDROID_ABI:-arm64-v8a}
STAGE=${DMASH_ANDROID_STAGE:-all}
case "$STAGE" in all|native|package) ;; *) echo "Unsupported Android build stage" >&2; exit 2 ;; esac
case "$ABI" in
 arm64-v8a) QT_KIT=android_arm64_v8a; OPENSSL_KIT=openssl-android ;;
 x86_64) QT_KIT=android_x86_64; OPENSSL_KIT=openssl-android-x86_64 ;;
 *) echo "Unsupported Android ABI" >&2; exit 2 ;;
esac
export PATH="$CACHE/venv/bin:$PATH"
export JAVA_HOME="$CACHE/android-restored/jdk21/jdk-21.0.12.1+1"
export ANDROID_NDK_ROOT="$CACHE/sdk/ndk/27.2.12479018"
export ANDROID_HOME="$CACHE/sdk"
export GRADLE_USER_HOME=${DMASH_GRADLE_CACHE:-"$CACHE/platform-gradle-home"}
export PATH="$JAVA_HOME/bin:$PATH"
QT="$CACHE/Qt/6.12.0/$QT_KIT"
BUILD=${DMASH_ANDROID_BUILD:-"$CACHE/build-android-app-$ABI"}
"$QT/bin/qt-cmake" -S "$ROOT/native/platforms/android" -B "$BUILD" -G Ninja \
 -DANDROID_ABI="$ABI" -DANDROID_PLATFORM=android-28 \
 -DANDROID_SDK_ROOT="$CACHE/sdk" -DQT_HOST_PATH="$CACHE/Qt/6.12.0/gcc_64" \
 -DOPENSSL_INCLUDE_DIR="$CACHE/$OPENSSL_KIT/include" \
 -DOPENSSL_CRYPTO_LIBRARY="$CACHE/$OPENSSL_KIT/lib/libcrypto_3.so" \
 -DDMASH_QUICKJS_DIR="$CACHE/build/quickjs-2026-06-04"
if [ "$STAGE" != package ]; then
 cmake --build "$BUILD" --target dmash_node_service dmash_credential_service -j1
fi
if [ "$STAGE" = native ]; then exit 0; fi
test -s "$BUILD/libdmash_node_service_$ABI.so"
test -s "$BUILD/libdmash_credential_service_$ABI.so"
mkdir -p "$BUILD/android-build/libs/$ABI"
cp "$BUILD/libdmash_node_service_$ABI.so" "$BUILD/android-build/libs/$ABI/"
cp "$BUILD/libdmash_credential_service_$ABI.so" "$BUILD/android-build/libs/$ABI/"
"$CACHE/Qt/6.12.0/gcc_64/bin/androiddeployqt" --input "$BUILD/android-dmash_node_service-deployment-settings.json" --output "$BUILD/android-build" --apk "$BUILD/dmash-$ABI-debug.apk" --jdk "$JAVA_HOME"
