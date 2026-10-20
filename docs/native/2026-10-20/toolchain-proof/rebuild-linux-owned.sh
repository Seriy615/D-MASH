#!/bin/sh
# Run only when no other owned make/ninja is operating in these build directories.
set -eu
TC=${DMASH_TOOLCHAIN_CACHE:-"$HOME/.cache/dmash-native-20261020"}
REPO=${1:?Pass repository checkout root}
export PATH="$TC/venv/bin:$PATH"
SRC="$TC/build/openssl-3.5.9"
(cd "$SRC" && nice -n 5 make -j1 libcrypto.so libssl.so)
mkdir -p "$TC/openssl-desktop/lib" "$TC/openssl-desktop/include"
cp -a "$SRC/include/openssl" "$TC/openssl-desktop/include/"
cp -a "$SRC/libcrypto.so" "$SRC/libcrypto.so.3" "$SRC/libssl.so" "$SRC/libssl.so.3" "$TC/openssl-desktop/lib/"
cmake -S "$REPO/docs/native/2026-10-20/toolchain-proof" -B "$TC/build-linux-probe" \
 -DOPENSSL_INCLUDE_DIR="$TC/openssl-desktop/include" \
 -DOPENSSL_CRYPTO_LIBRARY="$TC/openssl-desktop/lib/libcrypto.so" \
 -DOPENSSL_SSL_LIBRARY="$TC/openssl-desktop/lib/libssl.so"
nice -n 5 cmake --build "$TC/build-linux-probe" -j1
export LD_LIBRARY_PATH="$TC/openssl-desktop/lib:$TC/Qt/6.12.0/gcc_64/lib"
export QT_PLUGIN_PATH="$TC/Qt/6.12.0/gcc_64/plugins"
"$TC/build-linux-probe/dmash_toolchain_probe" "$TC/private/localhost.crt" "$TC/private/localhost.key"
cc -O1 -I"$TC/openssl-desktop/include" \
 "$REPO/docs/native/2026-10-20/toolchain-proof/argon_profile_probe.c" \
 -L"$TC/openssl-desktop/lib" -Wl,-rpath,"$TC/openssl-desktop/lib" -lcrypto -o "$TC/argon-profile-probe"
"$TC/argon-profile-probe"
