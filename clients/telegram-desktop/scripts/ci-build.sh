#!/usr/bin/env bash
# Full selected client and matching separate credential/Node executables.
set -euo pipefail
: "${DMASH_TOOLCHAIN_CACHE:?}" "${DMASH_CI_EVIDENCE:?}"
cache=$DMASH_TOOLCHAIN_CACHE
recipe=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$recipe/../.." && pwd)
export PATH="$cache/venv/bin:$cache/telegram-dependencies/usr/bin:$PATH"
export LD_LIBRARY_PATH="$cache/openssl-desktop/lib:$cache/Qt/6.12.0/gcc_64/lib:$cache/telegram-dependencies/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
python3 "$recipe/scripts/prepare-source-dependencies.py" --sources-only > "$DMASH_CI_EVIDENCE/dependency-sources.log" 2>&1
bash "$recipe/scripts/checkout.sh" > "$DMASH_CI_EVIDENCE/fork-checkout.log" 2>&1
bash "$recipe/scripts/configure-linux.sh" > "$DMASH_CI_EVIDENCE/fork-configure.log" 2>&1
bash "$recipe/scripts/build-linux.sh" > "$DMASH_CI_EVIDENCE/fork-build.log" 2>&1
cmake -S "$cache/telegram-desktop-fork/dmash" -B "$cache/build-fork-adapter" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$cache/Qt/6.12.0/gcc_64" > "$DMASH_CI_EVIDENCE/adapter-configure.log" 2>&1
cmake --build "$cache/build-fork-adapter" -j"${DMASH_BUILD_JOBS:-1}" > "$DMASH_CI_EVIDENCE/adapter-build.log" 2>&1
ctest --test-dir "$cache/build-fork-adapter" --output-on-failure -V > "$DMASH_CI_EVIDENCE/adapter-tests.log" 2>&1
curl --fail --location --retry 3 https://bellard.org/quickjs/quickjs-2026-06-04.tar.xz -o "$cache/archives/quickjs-2026-06-04.tar.xz"
echo "b376e839b322978313d929fd20663b11ba58b75df5a46c126dd19ea2fa70ad2a  $cache/archives/quickjs-2026-06-04.tar.xz" | sha256sum -c -
tar -xf "$cache/archives/quickjs-2026-06-04.tar.xz" -C "$cache/build"
common=(-G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$cache/Qt/6.12.0/gcc_64;$cache/telegram-dependencies/usr" -DOPENSSL_INCLUDE_DIR="$cache/openssl-desktop/include" -DOPENSSL_CRYPTO_LIBRARY="$cache/openssl-desktop/lib/libcrypto.so" -DOPENSSL_SSL_LIBRARY="$cache/openssl-desktop/lib/libssl.so")
cmake -S "$root/native" -B "$cache/build-native" "${common[@]}" -DDMASH_QUICKJS_DIR="$cache/build/quickjs-2026-06-04" > "$DMASH_CI_EVIDENCE/node-configure.log" 2>&1
cmake --build "$cache/build-native" -j"${DMASH_BUILD_JOBS:-1}" > "$DMASH_CI_EVIDENCE/node-build.log" 2>&1
ctest --test-dir "$cache/build-native" -R '^native-(nonce|storage|crypto|bundle|local-frame)$' --output-on-failure > "$DMASH_CI_EVIDENCE/node-tests.log" 2>&1
cmake -S "$root/native/credential_host" -B "$cache/build-credential-host" "${common[@]}" -DDMASH_ACCOUNT_QUICKJS_DIR="$cache/build/quickjs-2026-06-04" > "$DMASH_CI_EVIDENCE/credential-configure.log" 2>&1
cmake --build "$cache/build-credential-host" -j"${DMASH_BUILD_JOBS:-1}" > "$DMASH_CI_EVIDENCE/credential-build.log" 2>&1
ctest --test-dir "$cache/build-credential-host" -R '^credential-fresh-profile$' --output-on-failure > "$DMASH_CI_EVIDENCE/credential-tests.log" 2>&1
python3 "$recipe/scripts/ci-package.py"
