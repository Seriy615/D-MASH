#!/usr/bin/env bash
set -euo pipefail
: "${DMASH_TOOLCHAIN_CACHE:?}" "${DMASH_CI_EVIDENCE:?}" "${DMASH_ANDROID_BUILD:?}" "${DMASH_TELEGRAM_CHECKOUT:?}"
root=$(cd -- "$(dirname -- "$0")/../../.." && pwd)
cache=$DMASH_TOOLCHAIN_CACHE
export PATH="$cache/venv/bin:$ANDROID_SDK_ROOT/cmake/3.22.1/bin:$PATH"
export ANDROID_HOME=$ANDROID_SDK_ROOT
export DMASH_SOURCE_ROOT=$root DMASH_ANDROID_ABI=x86_64 DMASH_ANDROID_STAGE=native
# Compile only the independent services, not the former app's Java/Activity/APK.
bash "$root/native/platforms/scripts/build-android.sh"
mkdir -p "$DMASH_CI_EVIDENCE/cores"
cp "$DMASH_ANDROID_BUILD/libdmash_credential_service_x86_64.so" "$DMASH_ANDROID_BUILD/libdmash_node_service_x86_64.so" "$DMASH_CI_EVIDENCE/cores/"
cmake --build "$DMASH_ANDROID_BUILD" --target dmash_credential_service_prepare_apk_dir dmash_node_service_prepare_apk_dir --parallel 1
for component in credential node; do
    "$cache/Qt/6.12.0/gcc_64/bin/androiddeployqt" \
        --input "$DMASH_ANDROID_BUILD/android-dmash_${component}_service-deployment-settings.json" \
        --output "$DMASH_ANDROID_BUILD/android-build" --aux-mode
 done
export DMASH_CORE_ANDROID_BUILD="$DMASH_ANDROID_BUILD/android-build" DMASH_TELEGRAM_ABI=x86_64
bash "$root/clients/telegram-android/build.sh"
cp "$DMASH_TELEGRAM_CHECKOUT/TMessagesProj_App/build/outputs/apk/afat/debug/app.apk" "$DMASH_CI_EVIDENCE/actual-telegram-android.apk"
python3 - "$root" <<'PY'
import hashlib,json,os,pathlib,subprocess
root=pathlib.Path(__import__('sys').argv[1]);out=pathlib.Path(os.environ['DMASH_CI_EVIDENCE']);fork=pathlib.Path(os.environ['DMASH_TELEGRAM_CHECKOUT']);build=pathlib.Path(os.environ['DMASH_ANDROID_BUILD'])
names=subprocess.check_output(['git','ls-files','native','D-MASH PWA/not_messenger/js','clients/telegram-android','.github/workflows/telegram-android.yml'],cwd=root,text=True).splitlines()
record={'sourceCommit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'sourceSha256':{n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in names},'upstream':json.loads((root/'clients/telegram-android/UPSTREAM.json').read_text()),'coreLibraries':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in build.glob('libdmash_*_x86_64.so')},'status':'BUILD_ONLY','runtime':'NOT_RUN'}
(out/'source.json').write_text(json.dumps(record,indent=2)+'\n')
PY
