#!/usr/bin/env bash
set -euo pipefail
recipe=$(cd "$(dirname "$0")/.." && pwd)
prefix=${DMASH_TELEGRAM_DESKTOP_SOURCE:-"$HOME/.cache/dmash-native-20261020/telegram-desktop-fork"}
revision=86262333a457f62709726ee4ab9c48fa58824da4
if [ ! -d "$prefix/.git" ]; then
 mkdir -p "$prefix"
 git -C "$prefix" init
 git -C "$prefix" remote add origin https://github.com/telegramdesktop/tdesktop.git
 git -C "$prefix" fetch --filter=blob:none --depth 1 origin "$revision"
 git -C "$prefix" checkout -b codex/dmash-client "$revision"
fi
test "$(git -C "$prefix" rev-parse HEAD)" = "$revision"
git -C "$prefix" submodule update --init --depth 1 --jobs 2
for patch in "$recipe"/patches/*.patch; do
 [ -f "$patch" ] || continue
 if git -C "$prefix" apply --reverse --check "$patch" >/dev/null 2>&1; then continue; fi
 git -C "$prefix" apply --check "$patch"
 git -C "$prefix" apply "$patch"
done
