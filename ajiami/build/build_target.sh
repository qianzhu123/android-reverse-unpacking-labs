#!/usr/bin/env bash
# build_target.sh — 编译「目标 App」：原始 dex + 原始 APK
#
# 用法（必须在项目根目录执行）：
#   bash build/build_target.sh
#
# 产物：
#   samples/classes_orig.dex    黄金对照样本（后面所有判断都以它为基准）
#   samples/app_orig.apk        未加固 APK（签名、zipalign，可被 adb install）
set -e
source build/env.sh
cd "$ROOT_W"

mkdir -p build/target/classes build/target/dex samples

echo "== [1/5] javac: 源码 -> class =="
"$JAVAC" -source 11 -target 11 -nowarn \
  -classpath "$ANDROID_JAR" \
  -d build/target/classes \
  app/src/com/demo/target/*.java

echo "== [2/5] d8: class -> classes.dex =="
rm -f build/target/dex/target.zip
D8 --lib "$ANDROID_JAR" --output build/target/dex/target.zip \
   --min-api $MIN_SDK \
   build/target/classes/com/demo/target/*.class
"$PY" tools/apkutil.py extract-dex build/target/dex/target.zip samples/classes_orig.dex

echo "== [3/5] aapt2 link: manifest -> apk 骨架 =="
rm -f build/target/app_orig_raw.apk
"$AAPT2" link -I "$ANDROID_JAR" \
  --manifest app/AndroidManifest.xml \
  -o build/target/app_orig_raw.apk \
  --min-sdk-version $MIN_SDK --target-sdk-version $TARGET_SDK

echo "== [4/5] 塞入 classes.dex =="
"$PY" tools/apkutil.py inject-dex build/target/app_orig_raw.apk \
  samples/classes_orig.dex build/target/app_orig_unaligned.apk
"$ZIPALIGN" -f 4 build/target/app_orig_unaligned.apk build/target/app_orig_aligned.apk

echo "== [5/5] 签名 =="
if [ ! -f "$KEYSTORE" ]; then
  "$KEYTOOL" -genkeypair -v -keystore "$KEYSTORE" -alias "$KEY_ALIAS" \
    -keyalg RSA -keysize 2048 -validity 10950 \
    -storepass "$KEY_STOREPASS" -keypass "$KEY_KEYPASS" \
    -dname "CN=AJM Lab, OU=Lab, O=AJM, L=Lab, S=Lab, C=CN"
fi
APK_SIGNER sign --ks "$KEYSTORE" --ks-key-alias "$KEY_ALIAS" \
  --ks-pass pass:"$KEY_STOREPASS" --key-pass pass:"$KEY_KEYPASS" \
  --out samples/app_orig.apk build/target/app_orig_aligned.apk
APK_SIGNER verify --print-certs samples/app_orig.apk | tail -3

echo
echo "[+] samples/classes_orig.dex  原始 dex（黄金对照）"
echo "[+] samples/app_orig.apk      未加固 APK"
