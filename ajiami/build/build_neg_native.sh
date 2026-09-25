#!/usr/bin/env bash
# build_neg_native.sh — 构建「干净 native」负样本 neg_native.apk
#
# 目的：锁住 B13 / B12 的【干净 Native】路径 —— 一个正常 App 用了 NDK .so，
#       绝不能因此被判壳。它和真实计算器 App 的 libcalculator.so 同理：
#       干净的 NDK 产物经 ELF 检查应是 anomalies=[]，B13 不触发，B12 因 native
#       占比被大量普通 Java 方法压在 30% 以下也不触发。
#
# 依赖：NDK（locate.sh 已能探测 $NDK / $CLANG）。无 NDK 的机器上本脚本跳过并告警，
#       不会让 build/build_negatives.sh 整体失败。
set -e
source build/env.sh
cd "$ROOT_W"

if [ -z "$NDK" ]; then
  echo "[!] 未探测到 NDK，跳过 neg_native.apk 构建（不影响其它负样本）"
  exit 0
fi

CLANG_DIR="$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin"
CC="$CLANG_DIR/aarch64-linux-android21-clang.cmd"
if [ ! -f "$CC" ]; then
  echo "[!] 找不到 NDK clang 包装器：$CC，跳过 neg_native.apk"
  exit 0
fi

mkdir -p build/neg/native_classes build/neg/native_dex samples

echo "== [1] javac：native 包装类 + 一批普通 Java 方法（压住 native 占比）=="
"$JAVAC" -source 11 -target 11 -nowarn -classpath "$ANDROID_JAR" -d build/neg/native_classes neg/native/src/com/demo/negnative/*.java

echo "== [2] d8：产出 classes.dex =="
rm -f build/neg/native_dex.zip
D8 --lib "$ANDROID_JAR" --output build/neg/native_dex.zip --min-api $MIN_SDK build/neg/native_classes/com/demo/negnative/*.class
python tools/apkutil.py extract-dex build/neg/native_dex.zip build/neg/native.dex

echo "== [3] aapt2 link：native manifest =="
rm -f build/neg/raw_native.apk
"$AAPT2" link -I "$ANDROID_JAR" --manifest neg/native/AndroidManifest.xml -o build/neg/raw_native.apk --min-sdk-version $MIN_SDK --target-sdk-version $TARGET_SDK

echo "== [4] NDK clang：编译干净 .so（arm64-v8a）=="
"$CC" -shared -fPIC -o "$ROOT_W/build/neg/libcalc.so" "$ROOT_W/neg/native/jni/calc.c"

echo "== [5] 组装 neg_native.apk（classes.dex + lib/arm64-v8a/libcalc.so）=="
python tools/mkneg.py build/neg/raw_native.apk build/neg/neg_native_unaligned.apk \
    --dex classes.dex=build/neg/native.dex \
    --asset lib/arm64-v8a/libcalc.so=build/neg/libcalc.so

echo "== [6] zipalign + 签名 =="
if [ ! -f "$KEYSTORE" ]; then
  "$KEYTOOL" -genkeypair -v -keystore "$KEYSTORE" -alias "$KEY_ALIAS" -keyalg RSA -keysize 2048 -validity 10950 -storepass "$KEY_STOREPASS" -keypass "$KEY_KEYPASS" -dname "CN=AJM Lab, OU=Lab, O=AJM, L=Lab, S=Lab, C=CN"
fi
"$ZIPALIGN" -f 4 build/neg/neg_native_unaligned.apk build/neg/neg_native_aligned.apk
APK_SIGNER sign --ks "$KEYSTORE" --ks-key-alias "$KEY_ALIAS" --ks-pass pass:"$KEY_STOREPASS" --key-pass pass:"$KEY_KEYPASS" --out "samples/neg_native.apk" "build/neg/neg_native_aligned.apk"

echo
echo "[+] samples/neg_native.apk  负样本：正常 native 应用（含合法 NDK .so）"
echo "[!] 必须被 detect.py 判为「未见已知加固特征」，且不得命中 B6/B7/B8/B11/B12/B13"

echo
echo "== [7] 正样本对照：把同一个 .so 的 .text 加密，做成『被加壳 SO』=="
python tools/mkpacked_so.py build/neg/libcalc.so build/neg/libcalc_packed.so 90
python tools/mkneg.py build/neg/raw_native.apk build/neg/app_so_packed_unaligned.apk \
    --dex classes.dex=build/neg/native.dex \
    --asset lib/arm64-v8a/libcalc.so=build/neg/libcalc_packed.so
"$ZIPALIGN" -f 4 build/neg/app_so_packed_unaligned.apk build/neg/app_so_packed_aligned.apk
APK_SIGNER sign --ks "$KEYSTORE" --ks-key-alias "$KEY_ALIAS" --ks-pass pass:"$KEY_STOREPASS" --key-pass pass:"$KEY_KEYPASS" --out "samples/app_so_packed.apk" "build/neg/app_so_packed_aligned.apk"

echo
echo "[+] samples/app_so_packed.apk  正样本：SO 被加壳（.text 加密），应触发 B13"
echo "[!] 必须被 detect.py 判为「疑似 SO 加壳 / 自实现 Linker」，见 tools/check_negatives.py"
