#!/usr/bin/env bash
set -euo pipefail
recipe=$(cd "$(dirname "$0")/.." && pwd)
cache=${DMASH_TOOLCHAIN_CACHE:-"$HOME/.cache/dmash-native-20261020"}
prefix=${DMASH_TELEGRAM_DESKTOP_SOURCE:-"$cache/telegram-desktop-fork"}
revision=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["commit"])' "$recipe/UPSTREAM.json")
repository=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["repository"])' "$recipe/UPSTREAM.json")
if [ ! -d "$prefix/.git" ]; then
 mkdir -p "$prefix"
 git -C "$prefix" init
 git -C "$prefix" remote add origin "$repository"
 git -C "$prefix" fetch --filter=blob:none --depth 1 origin "$revision"
 git -C "$prefix" checkout -b codex/dmash-client "$revision"
fi
python3 "$recipe/scripts/verify-source.py" "$recipe" "$prefix" preflight
git -C "$prefix" submodule update --init --recursive --depth 1 --jobs 2
# A later patch may alter an earlier hunk: recognize the whole final series.
if python3 "$recipe/scripts/verify-source.py" "$recipe" "$prefix" final >/dev/null 2>&1; then exit 0; fi
while IFS= read -r patch; do
 if git -C "$prefix" apply --reverse --check "$recipe/$patch" >/dev/null 2>&1; then continue; fi
 git -C "$prefix" apply --check "$recipe/$patch"
 git -C "$prefix" apply "$recipe/$patch"
done < <(python3 -c 'import json,sys;print("\n".join(p["path"] for p in json.load(open(sys.argv[1]))["patches"]))' "$recipe/UPSTREAM.json")
python3 "$recipe/scripts/verify-source.py" "$recipe" "$prefix" final
