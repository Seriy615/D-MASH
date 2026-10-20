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
printf 'sdk.dir=%s\n' "$ANDROID_HOME" > "$DMASH_TELEGRAM_CHECKOUT/local.properties"
cd -- "$DMASH_TELEGRAM_CHECKOUT"
./gradlew :TMessagesProj_App:assembleAfatDebug \
    "-PdmashCoreBuild=$DMASH_CORE_ANDROID_BUILD" "-PdmashAbi=$DMASH_TELEGRAM_ABI" \
    --no-daemon --max-workers=1 '-Dorg.gradle.jvmargs=-Xmx2g -XX:MaxMetaspaceSize=512m'
