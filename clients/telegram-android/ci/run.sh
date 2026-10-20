#!/usr/bin/env bash
# Own one new AVD. No installed Telegram data, old app harness, or software fallback.
set -euo pipefail
: "${ANDROID_SDK_ROOT:?}" "${DMASH_TOOLCHAIN_CACHE:?}" "${DMASH_CI_EVIDENCE:?}"
export PATH="$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/emulator:$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$PATH"
export ANDROID_SERIAL=emulator-5584 ANDROID_AVD_HOME="$DMASH_TOOLCHAIN_CACHE/fork-ci-avd"
mkdir -p "$ANDROID_AVD_HOME"
emulator -accel-check > "$DMASH_CI_EVIDENCE/acceleration.txt" 2>&1
grep -q 'KVM.*usable' "$DMASH_CI_EVIDENCE/acceleration.txt"
printf 'no\n' | avdmanager create avd --name dmash-fork-api35 --package 'system-images;android-35;google_apis;x86_64' --device pixel_2
emulator -avd dmash-fork-api35 -port 5584 -accel on -no-window -no-audio -no-boot-anim -no-snapshot -gpu swiftshader -memory 2048 -cores 2 > "$DMASH_TOOLCHAIN_CACHE/private/fork-emulator.log" 2>&1 &
emulator_pid=$!
cleanup(){ adb -s "$ANDROID_SERIAL" emu kill >/dev/null 2>&1 || true; if kill -0 "$emulator_pid" 2>/dev/null;then kill "$emulator_pid" 2>/dev/null || true;fi;wait "$emulator_pid" 2>/dev/null || true; }
trap cleanup EXIT
timeout 90 adb -s "$ANDROID_SERIAL" wait-for-device
booted=0
for attempt in $(seq 1 150);do
    if [[ "$(adb -s "$ANDROID_SERIAL" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]];then booted=1;break;fi
    kill -0 "$emulator_pid";sleep 2
done
test "$booted" = 1
adb -s "$ANDROID_SERIAL" shell input keyevent KEYCODE_WAKEUP
adb -s "$ANDROID_SERIAL" shell wm dismiss-keyguard
adb -s "$ANDROID_SERIAL" shell settings put system show_password 0
for animation in window_animation_scale transition_animation_scale animator_duration_scale;do adb -s "$ANDROID_SERIAL" shell settings put global "$animation" 0;done
python3 "$(dirname "$0")/runtime.py"
