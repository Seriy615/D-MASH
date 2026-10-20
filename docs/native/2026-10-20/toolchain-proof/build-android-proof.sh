#!/bin/sh
# Disposable compiler/link/packaging proof. Does not install/start Android apps.
set -eu
TC=${DMASH_TOOLCHAIN_CACHE:-"$HOME/.cache/dmash-native-20261020"}
REPO=${1:?Pass repository checkout root}
QT="$TC/Qt/6.12.0/android_arm64_v8a"
export JAVA_HOME="$TC/android-restored/jdk21/jdk-21.0.12.1+1"
export PATH="$JAVA_HOME/bin:$TC/venv/bin:$PATH"
mkdir -p "$TC/android-package/classes" "$TC/android-package/dex"
nice -n 5 javac -source 8 -target 8 -bootclasspath "$TC/sdk/platforms/android-36/android.jar" \
 -classpath "$QT/jar/Qt6Android.jar" -sourcepath "$QT/src/android/java/src" \
 -d "$TC/android-package/classes" "$REPO/docs/native/2026-10-20/toolchain-proof/ProbeService.java"
jar cf "$TC/android-package/service.jar" -C "$TC/android-package/classes" .
nice -n 5 java -Xmx512m -cp "$TC/sdk/build-tools/36.0.0/lib/d8.jar" com.android.tools.r8.D8 \
 --lib "$TC/sdk/platforms/android-36/android.jar" --min-api 28 \
 --output "$TC/android-package/dex" "$TC/android-package/service.jar" \
 "$QT/jar/Qt6Android.jar" "$QT/jar/Qt6AndroidNetwork.jar"
nice -n 5 python3 "$REPO/docs/native/2026-10-20/toolchain-proof/assemble-disposable-apk.py" "$TC" "$REPO"
