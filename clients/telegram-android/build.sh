#!/usr/bin/env bash
set -euo pipefail
# Build the actual Telegram source fork with the independent D-MASH services.
: "${DMASH_TELEGRAM_CHECKOUT:?set isolated prepared checkout}"
: "${DMASH_CORE_ANDROID_BUILD:?set coherent native Android deployment directory}"
: "${ANDROID_HOME:?set Android SDK with platform36/build-tools36/NDKr27c}"
: "${JAVA_HOME:?set JDK21}"
DMASH_TELEGRAM_ABI=${DMASH_TELEGRAM_ABI:-arm64-v8a}
case "$DMASH_TELEGRAM_ABI" in arm64-v8a|x86_64) ;; *) echo 'Only one owned ABI per build' >&2; exit 1;; esac
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
python3 "$script_dir/prepare.py" "$DMASH_TELEGRAM_CHECKOUT"
test -f "$DMASH_CORE_ANDROID_BUILD/libs/Qt6Android.jar"
test -f "$DMASH_CORE_ANDROID_BUILD/libs/$DMASH_TELEGRAM_ABI/libdmash_credential_service_$DMASH_TELEGRAM_ABI.so"
test -f "$DMASH_CORE_ANDROID_BUILD/libs/$DMASH_TELEGRAM_ABI/libdmash_node_service_$DMASH_TELEGRAM_ABI.so"
# Qt's deployment arrays must describe the same core binaries packaged below.
mkdir -p -- "$DMASH_TELEGRAM_CHECKOUT/TMessagesProj/build/generated/dmashQt/res/values"
cp -- "$DMASH_CORE_ANDROID_BUILD/res/values/libs.xml" "$DMASH_TELEGRAM_CHECKOUT/TMessagesProj/build/generated/dmashQt/res/values/libs.xml"
notice_dir="$DMASH_TELEGRAM_CHECKOUT/TMessagesProj_App/build/generated/dmashNotices/assets/licenses/dmash"
mkdir -p -- "$notice_dir"
cp -- "$script_dir/COPYING-TELEGRAM-GPL-2.0.txt" "$script_dir/COPYING-DMASH-CORE-MIT.txt" "$script_dir/UPSTREAM.json" "$notice_dir/"
printf 'sdk.dir=%s\n' "$ANDROID_HOME" > "$DMASH_TELEGRAM_CHECKOUT/local.properties"
if [[ -n "${DMASH_TELEGRAM_CMAKE_DIR:-}" ]]; then
    test -x "$DMASH_TELEGRAM_CMAKE_DIR/bin/cmake"
    printf 'cmake.dir=%s\n' "$DMASH_TELEGRAM_CMAKE_DIR" >> "$DMASH_TELEGRAM_CHECKOUT/local.properties"
fi
cd -- "$DMASH_TELEGRAM_CHECKOUT"
./gradlew :TMessagesProj_App:assembleAfatDebug \
    "-PdmashCoreBuild=$DMASH_CORE_ANDROID_BUILD" "-PdmashAbi=$DMASH_TELEGRAM_ABI" \
    --init-script "$script_dir/one-native-worker.gradle" \
    --no-daemon --max-workers=1 '-Dorg.gradle.jvmargs=-Xmx2g -XX:MaxMetaspaceSize=512m'
