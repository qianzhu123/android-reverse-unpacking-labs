#!/usr/bin/env bash
# build_golden.sh — 编译黄金基线样本（明文逻辑，无任何虚拟机）
#
# 用法（在 lab 根目录执行）：
#   bash build/build_golden.sh
#
# 前置：先跑 `python tools/vmgen.py emit` 生成 src/com/demo/calc/CalcLogic.java
#
# 产物：
#   samples/dex/golden.dex     黄金对照 dex（后面所有还原都以它为准）
#   samples/apks/app_golden.apk 可直接 adb install 的黄金 APK
#
# 与各难度样本的关系：受保护样本的 dex 与 golden.dex 是**同一份业务**的不同表示，
# 设备上两者必须打印同一行（见 CalcActivity 的 CALC 日志）。
set -e
source build/env.sh
cd "$ROOT_W"

mkdir -p build/golden/classes build/golden/dex

echo "== [1/5] javac: src -> class =="
"$JAVAC" -source 11 -target 11 -nowarn \
  -classpath "$ANDROID_JAR" \
  -d build/golden/classes \
  src/com/demo/calc/*.java

echo "== [2/5] d8: class -> classes.dex =="
rm -f build/golden/dex/golden.zip
D8 --lib "$ANDROID_JAR" --output build/golden/dex/golden.zip \
   --min-api $MIN_SDK \
   build/golden/classes/com/demo/calc/*.class
"$PY" tools/apkutil.py extract-dex build/golden/dex/golden.zip samples/dex/golden.dex

echo "== [3/5] aapt2 link: manifest -> apk 骨架 =="
rm -f build/golden/golden_raw.apk
"$AAPT2" link -I "$ANDROID_JAR" \
  --manifest src/AndroidManifest.xml \
  -o build/golden/golden_raw.apk \
  --min-sdk-version $MIN_SDK --target-sdk-version $TARGET_SDK

echo "== [4/5] 塞入 classes.dex + 对齐 =="
"$PY" tools/apkutil.py inject-dex build/golden/golden_raw.apk \
  samples/dex/golden.dex build/golden/golden_unaligned.apk
"$ZIPALIGN" -f 4 build/golden/golden_unaligned.apk build/golden/golden_aligned.apk

echo "== [5/5] 签名 =="
if [ ! -f "$KEYSTORE" ]; then
  "$KEYTOOL" -genkeypair -v -keystore "$KEYSTORE" -alias "$KEY_ALIAS" \
    -keyalg RSA -keysize 2048 -validity 10950 \
    -storepass "$KEY_STOREPASS" -keypass "$KEY_KEYPASS" \
    -dname "CN=Calc Lab, OU=Lab, O=Calc, L=Lab, S=Lab, C=CN"
fi
APK_SIGNER sign --ks "$KEYSTORE" --ks-key-alias "$KEY_ALIAS" \
  --ks-pass pass:"$KEY_STOREPASS" --key-pass pass:"$KEY_KEYPASS" \
  --out samples/apks/app_golden.apk build/golden/golden_aligned.apk
APK_SIGNER verify --print-certs samples/apks/app_golden.apk | tail -2

echo
echo "[+] samples/dex/golden.dex       黄金 dex"
echo "[+] samples/apks/app_golden.apk  黄金 APK"
echo "[+] 下一步（设备）：adb install -r samples/apks/app_golden.apk && adb shell am start -n com.demo.calc/.CalcActivity && adb logcat -s CALC"
