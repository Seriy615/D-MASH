#!/usr/bin/env bash
# MSYS2 build using the matching Qt MinGW compiler. No system tool modification.
set -euo pipefail
: "${DMASH_WINDOWS_BUILD:?}"
: "${DMASH_MINGW:?}"
cache=$(cygpath -u "$DMASH_WINDOWS_BUILD")
export PATH="$(cygpath -u "$DMASH_MINGW")/bin:$PATH"
mkdir -p "$cache/downloads" "$cache/sources"
curl --fail --location --retry 3 https://www.openssl.org/source/openssl-3.5.9.tar.gz -o "$cache/downloads/openssl.tar.gz"
echo "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a  $cache/downloads/openssl.tar.gz" | sha256sum -c -
curl --fail --location --retry 3 https://bellard.org/quickjs/quickjs-2026-06-04.tar.xz -o "$cache/downloads/quickjs.tar.xz"
echo "b376e839b322978313d929fd20663b11ba58b75df5a46c126dd19ea2fa70ad2a  $cache/downloads/quickjs.tar.xz" | sha256sum -c -
tar -xf "$cache/downloads/openssl.tar.gz" -C "$cache/sources"
tar -xf "$cache/downloads/quickjs.tar.xz" -C "$cache/sources"
cd "$cache/sources/openssl-3.5.9"
perl Configure mingw64 shared no-tests no-apps --prefix="$(cygpath -m "$cache/openssl")" --libdir=lib
make -j2 build_generated
make -j2 build_libs
make install_sw
