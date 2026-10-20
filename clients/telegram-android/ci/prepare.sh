#!/usr/bin/env bash
# Toolchain only. This never builds or runs the former standalone Android UI.
set -euo pipefail
: "${DMASH_TOOLCHAIN_CACHE:?}" "${DMASH_CI_EVIDENCE:?}" "${ANDROID_SDK_ROOT:?}" "${JAVA_HOME:?}"
root=$(cd -- "$(dirname -- "$0")/../../.." && pwd)
cache=$DMASH_TOOLCHAIN_CACHE
mkdir -p "$cache/archives" "$cache/build" "$cache/private" "$cache/android-restored/jdk21" "$DMASH_CI_EVIDENCE"
chmod 700 "$cache/private"
ln -s "$ANDROID_SDK_ROOT" "$cache/sdk"
ln -s "$JAVA_HOME" "$cache/android-restored/jdk21/jdk-21.0.12.1+1"
python3 -m venv "$cache/venv"
"$cache/venv/bin/python" -m pip install cmake==4.2.3 ninja==1.13.0
export PATH="$cache/venv/bin:$JAVA_HOME/bin:$PATH"
if [[ -f "$cache/telegram-dependency-receipt.json" ]]; then
    python3 "$root/clients/telegram-android/ci/dependencies.py" verify
else
    python3 "$root/native/platforms/android/ci-qt.py" "$cache"
    curl --fail --location --retry 3 https://www.openssl.org/source/openssl-3.5.9.tar.gz -o "$cache/archives/openssl-3.5.9.tar.gz"
    echo "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a  $cache/archives/openssl-3.5.9.tar.gz" | sha256sum -c -
    curl --fail --location --retry 3 https://bellard.org/quickjs/quickjs-2026-06-04.tar.xz -o "$cache/archives/quickjs-2026-06-04.tar.xz"
    echo "b376e839b322978313d929fd20663b11ba58b75df5a46c126dd19ea2fa70ad2a  $cache/archives/quickjs-2026-06-04.tar.xz" | sha256sum -c -
    tar -xf "$cache/archives/quickjs-2026-06-04.tar.xz" -C "$cache/build"
    bash "$root/native/platforms/scripts/build-android-openssl.sh" x86_64
    python3 "$root/clients/telegram-android/ci/dependencies.py" write
fi
cp "$cache/qt-ci-manifest.json" "$DMASH_CI_EVIDENCE/qt-toolchain.json"
cp "$cache/telegram-dependency-receipt.json" "$DMASH_CI_EVIDENCE/dependency-receipt.json"
java -version 2> "$DMASH_CI_EVIDENCE/java-version.txt"
sdkmanager --list_installed > "$DMASH_CI_EVIDENCE/sdk-packages.txt"
