#!/usr/bin/env bash
# Fresh CI-only toolchain layout. Calls the existing platform build unchanged.
set -euo pipefail
: "${DMASH_TOOLCHAIN_CACHE:?}"
: "${ANDROID_SDK_ROOT:?}"
: "${JAVA_HOME:?}"
root=$(cd "$(dirname "$0")/../../.." && pwd)
cache=$DMASH_TOOLCHAIN_CACHE
mkdir -p "$cache/archives" "$cache/build" "$cache/private" "$cache/android-restored/jdk21"
chmod 700 "$cache/private"
python3 - "$root" "$DMASH_ANDROID_EVIDENCE" <<'PY'
import hashlib,json,pathlib,subprocess,sys
root=pathlib.Path(sys.argv[1]);out=pathlib.Path(sys.argv[2])
files=subprocess.check_output(['git','ls-files','native','D-MASH PWA/not_messenger/js','.github/workflows/native-android.yml'],cwd=root,text=True).splitlines()
record={'sourceCommit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
        'sourceSha256':{name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in files},
        'scope':'Build and runtime evidence; full Account messaging/Doze/reboot NOT_RUN'}
(out/'source.json').write_text(json.dumps(record,indent=2)+'\n')
PY
ln -s "$ANDROID_SDK_ROOT" "$cache/sdk"
ln -s "$JAVA_HOME" "$cache/android-restored/jdk21/jdk-21.0.12.1+1"
python3 -m venv "$cache/venv"
"$cache/venv/bin/python" -m pip install cmake==4.2.3 ninja==1.13.0 pynacl==1.6.2 blake3==0.4.1
python3 "$root/native/platforms/android/ci-qt.py" "$cache"
cp "$cache/qt-ci-manifest.json" "$DMASH_ANDROID_EVIDENCE/qt-toolchain.json"
java -version 2> "$DMASH_ANDROID_EVIDENCE/java-version.txt"
sdkmanager --list_installed > "$DMASH_ANDROID_EVIDENCE/sdk-packages.txt"
curl --fail --location --retry 3 https://www.openssl.org/source/openssl-3.5.9.tar.gz -o "$cache/archives/openssl-3.5.9.tar.gz"
echo "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a  $cache/archives/openssl-3.5.9.tar.gz" | sha256sum -c -
curl --fail --location --retry 3 https://bellard.org/quickjs/quickjs-2026-06-04.tar.xz -o "$cache/archives/quickjs-2026-06-04.tar.xz"
echo "b376e839b322978313d929fd20663b11ba58b75df5a46c126dd19ea2fa70ad2a  $cache/archives/quickjs-2026-06-04.tar.xz" | sha256sum -c -
tar -xf "$cache/archives/quickjs-2026-06-04.tar.xz" -C "$cache/build"
bash "$root/native/platforms/scripts/build-android-openssl.sh" x86_64
DMASH_ANDROID_ABI=x86_64 bash "$root/native/platforms/scripts/build-android.sh"
"$cache/venv/bin/python" "$root/native/platforms/android/verify_apk.py" "$DMASH_ANDROID_BUILD/dmash-x86_64-debug.apk" "$cache" > "$DMASH_ANDROID_EVIDENCE/package.json"
