#!/usr/bin/env bash
# Own one fresh disposable AVD. Require KVM; never silently fall back to software.
set -euo pipefail
: "${ANDROID_SDK_ROOT:?}"
: "${DMASH_TOOLCHAIN_CACHE:?}"
: "${DMASH_ANDROID_EVIDENCE:?}"
export PATH="$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/emulator:$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$PATH"
export ANDROID_SERIAL=emulator-5582
export ANDROID_AVD_HOME="$DMASH_TOOLCHAIN_CACHE/ci-avd"
mkdir -p "$ANDROID_AVD_HOME" "$DMASH_ANDROID_EVIDENCE"
emulator -accel-check > "$DMASH_ANDROID_EVIDENCE/acceleration.txt" 2>&1
grep -q 'KVM.*usable' "$DMASH_ANDROID_EVIDENCE/acceleration.txt"
printf 'no\n' | avdmanager create avd --name dmash-ci-api35 --package 'system-images;android-35;google_apis;x86_64' --device pixel_2
emulator -avd dmash-ci-api35 -port 5582 -accel on -no-window -no-audio -no-boot-anim -no-snapshot -gpu swiftshader -memory 2048 -cores 2 > "$DMASH_TOOLCHAIN_CACHE/private/emulator.log" 2>&1 &
emulator_pid=$!
cleanup() {
  adb -s "$ANDROID_SERIAL" emu kill >/dev/null 2>&1 || true
  if kill -0 "$emulator_pid" 2>/dev/null; then kill "$emulator_pid" 2>/dev/null || true; fi
  wait "$emulator_pid" 2>/dev/null || true
}
trap cleanup EXIT
timeout 90 adb -s "$ANDROID_SERIAL" wait-for-device
booted=0
for attempt in $(seq 1 150); do
  if [ "$(adb -s "$ANDROID_SERIAL" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; then booted=1; break; fi
  kill -0 "$emulator_pid"
  sleep 2
done
test "$booted" = 1
adb -s "$ANDROID_SERIAL" shell input keyevent KEYCODE_WAKEUP
adb -s "$ANDROID_SERIAL" shell wm dismiss-keyguard
adb -s "$ANDROID_SERIAL" shell settings put global window_animation_scale 0
adb -s "$ANDROID_SERIAL" shell settings put global transition_animation_scale 0
adb -s "$ANDROID_SERIAL" shell settings put global animator_duration_scale 0
"$DMASH_TOOLCHAIN_CACHE/venv/bin/python" "$(dirname "$0")/ci-runtime.py"
