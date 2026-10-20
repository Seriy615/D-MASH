#!/usr/bin/env bash
# Build the selected original Telegram application, or explicit object targets.
set -euo pipefail
cache=${DMASH_TOOLCHAIN_CACHE:-"$HOME/.cache/dmash-native-20261020"}
build_dir=${DMASH_TELEGRAM_DESKTOP_BUILD:-"$cache/build-telegram-desktop-fork"}
recipe=$(cd "$(dirname "$0")/.." && pwd)
export PATH="$recipe/scripts:$cache/venv/bin:$cache/telegram-dependencies/usr/bin:$PATH"
export PKG_CONFIG_SYSROOT_DIR="$cache/telegram-dependencies"
export PKG_CONFIG_LIBDIR="$cache/telegram-dependencies/lib/pkgconfig:$cache/telegram-dependencies/usr/lib/x86_64-linux-gnu/pkgconfig:$cache/telegram-dependencies/usr/share/pkgconfig"
export LD_LIBRARY_PATH="$cache/telegram-dependencies/usr/lib/x86_64-linux-gnu:$cache/openssl-desktop/lib:$cache/Qt/6.12.0/gcc_64/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PYTHONPATH="$cache/telegram-dependencies/usr/lib/x86_64-linux-gnu/gobject-introspection:$cache/telegram-dependencies/usr/lib/python3/dist-packages${PYTHONPATH:+:$PYTHONPATH}"
export GI_GIR_PATH="$cache/telegram-dependencies/usr/share/gir-1.0"
export GI_TYPELIB_PATH="$cache/telegram-dependencies/usr/lib/x86_64-linux-gnu/girepository-1.0"
targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then targets=(Telegram); fi
exec nice -n 10 cmake --build "$build_dir" --target "${targets[@]}" -j"${DMASH_BUILD_JOBS:-1}"
