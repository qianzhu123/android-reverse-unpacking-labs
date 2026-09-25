#!/usr/bin/env bash
# build_vmp.sh — 编译 DEX VMP 教学样本（独立源码树 vmp/，不改动 app/src 与既有样本）
#
# 用法（项目根目录执行）：bash build/build_vmp.sh
#
# 产物：
#   build/vmp/vmp_classes.dex   VMP 样本的 dex（业务方法体 = 调用解释器）
#   samples/apks/app_vmp.apk         可直接被 detect.py 判定的 VMP 样本
#
# 教学目的（见 SCRIPT.md §2.5 / §3.5）：
#   用它验证"空方法率 B3 判据对 VMP 失效"——方法体不是全 0，而是对 Vmp.run 的调用。
set -e
source build/env.sh
cd "$ROOT_W"

mkdir -p build/vmp/classes build/vmp/dex

echo "== [1/4] javac（vmp 解释器 + 业务类）=="
"$JAVAC" -source 11 -target 11 -nowarn -classpath "$ANDROID_JAR" -d build/vmp/classes vmp/src/com/ijiami/vmp/*.java vmp/src/com/demo/vmapp/*.java

echo "== [2/4] d8: class -> dex =="
rm -f build/vmp/dex/vmp.zip
D8 --lib "$ANDROID_JAR" --output build/vmp/dex/vmp.zip --min-api $MIN_SDK build/vmp/classes/com/ijiami/vmp/*.class build/vmp/classes/com/demo/vmapp/*.class
"$PY" tools/apkutil.py extract-dex build/vmp/dex/vmp.zip build/vmp/vmp_classes.dex

echo "== [3/4] aapt2 link + inject dex + zipalign =="
rm -f build/vmp/vmp_raw.apk
"$AAPT2" link -I "$ANDROID_JAR" --manifest vmp/AndroidManifest.xml -o build/vmp/vmp_raw.apk --min-sdk-version $MIN_SDK --target-sdk-version $TARGET_SDK
"$PY" tools/apkutil.py inject-dex build/vmp/vmp_raw.apk build/vmp/vmp_classes.dex build/vmp/vmp_unaligned.apk
"$ZIPALIGN" -f 4 build/vmp/vmp_unaligned.apk build/vmp/vmp_aligned.apk

echo "== [4/4] 签名 =="
if [ ! -f "$KEYSTORE" ]; then
  "$KEYTOOL" -genkeypair -v -keystore "$KEYSTORE" -alias "$KEY_ALIAS" -keyalg RSA -keysize 2048 -validity 10950 -storepass "$KEY_STOREPASS" -keypass "$KEY_KEYPASS" -dname "CN=AJM Lab, OU=Lab, O=AJM, L=Lab, S=Lab, C=CN"
fi
APK_SIGNER sign --ks "$KEYSTORE" --ks-key-alias "$KEY_ALIAS" --ks-pass pass:"$KEY_STOREPASS" --key-pass pass:"$KEY_KEYPASS" --out samples/apks/app_vmp.apk build/vmp/vmp_aligned.apk

echo
echo "[+] samples/apks/app_vmp.apk   DEX VMP 教学样本"
echo "[+] 下一步：python tools/detect.py samples/apks/app_vmp.apk   （观察 B3 是否失效）"
