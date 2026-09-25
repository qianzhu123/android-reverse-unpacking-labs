#!/usr/bin/env bash
# build_shell.sh — 编译「壳 dex」并打好 APK 骨架
#
# 用法（项目根目录执行）：bash build/build_shell.sh
#
# 产物：
#   build/shell/shell_classes.dex   壳 dex（会作为加固 APK 里的 classes.dex）
#   build/shell/shell.apk           已签名对齐的"只有壳、没有业务"的 APK 骨架
set -e
source build/env.sh
cd "$ROOT_W"

mkdir -p build/shell/classes build/shell/dex

echo "== [1/4] javac =="
"$JAVAC" -source 11 -target 11 -nowarn \
  -classpath "$ANDROID_JAR" \
  -d build/shell/classes \
  shell/src/com/ijiami/shell/*.java

echo "== [2/4] d8 =="
rm -f build/shell/dex/shell.zip
D8 --lib "$ANDROID_JAR" --output build/shell/dex/shell.zip \
   --min-api $MIN_SDK \
   build/shell/classes/com/ijiami/shell/*.class
"$PY" tools/apkutil.py extract-dex build/shell/dex/shell.zip build/shell/shell_classes.dex

echo "== [3/4] aapt2 link + inject =="
rm -f build/shell/shell_raw.apk
"$AAPT2" link -I "$ANDROID_JAR" \
  --manifest shell/AndroidManifest.xml \
  -o build/shell/shell_raw.apk \
  --min-sdk-version $MIN_SDK --target-sdk-version $TARGET_SDK
"$PY" tools/apkutil.py inject-dex build/shell/shell_raw.apk \
  build/shell/shell_classes.dex build/shell/shell_unaligned.apk
"$ZIPALIGN" -f 4 build/shell/shell_unaligned.apk build/shell/shell_aligned.apk

echo "== [4/4] 签名 =="
if [ ! -f "$KEYSTORE" ]; then
  "$KEYTOOL" -genkeypair -v -keystore "$KEYSTORE" -alias "$KEY_ALIAS" \
    -keyalg RSA -keysize 2048 -validity 10950 \
    -storepass "$KEY_STOREPASS" -keypass "$KEY_KEYPASS" \
    -dname "CN=AJM Lab, OU=Lab, O=AJM, L=Lab, S=Lab, C=CN"
fi
APK_SIGNER sign --ks "$KEYSTORE" --ks-key-alias "$KEY_ALIAS" \
  --ks-pass pass:"$KEY_STOREPASS" --key-pass pass:"$KEY_KEYPASS" \
  --out build/shell/shell.apk build/shell/shell_aligned.apk

echo
echo "[+] build/shell/shell_classes.dex  壳 dex"
echo "[+] build/shell/shell.apk          只有壳的 APK 骨架"
