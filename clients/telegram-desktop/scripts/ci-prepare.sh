#!/usr/bin/env bash
set -euo pipefail
: "${DMASH_TOOLCHAIN_CACHE:?}"
cache=$DMASH_TOOLCHAIN_CACHE
recipe=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$cache/archives" "$cache/build"
python3 -m venv "$cache/venv"
"$cache/venv/bin/python" -m pip install cmake==4.4.4 ninja==1.13.2 py7zr==1.1.4
"$cache/venv/bin/python" "$recipe/scripts/ci-qt.py" "$cache"
python3 "$recipe/scripts/prepare-packages.py"
curl --fail --location --retry 3 https://www.openssl.org/source/openssl-3.5.9.tar.gz -o "$cache/archives/openssl-3.5.9.tar.gz"
echo "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a  $cache/archives/openssl-3.5.9.tar.gz" | sha256sum -c -
tar -xf "$cache/archives/openssl-3.5.9.tar.gz" -C "$cache/build"
cd "$cache/build/openssl-3.5.9"
./Configure linux-x86_64 shared no-tests --prefix="$cache/openssl-desktop" --libdir=lib
make -j"${DMASH_BUILD_JOBS:-1}"
make install_sw
python3 "$recipe/scripts/prepare-source-dependencies.py"
