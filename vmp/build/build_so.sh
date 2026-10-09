#!/usr/bin/env bash
# build_so.sh — 构建 S1..S3 三个 **SO/ARM64 虚拟机**样本 APK
#
# 用法（lab 根目录执行）：
#   python tools/build_so_levels.py     # 先生成 build/gen/so_S* 源码
#   bash build/build_so.sh
#
# 产物：
#   samples/native/libcalc_s{1,2,3}_arm64.so   各层 arm64-v8a 原生库（分析对象）
#   samples/native/libcalc_s{1,2,3}_x86_64.so  各层 x86_64 副本（供模拟器）
#   samples/apks/app_s{1,2,3}.apk              可直接 adb install 的样本
#
# 需要 NDK（locate.sh 已导出 CLANG_AARCH64 / CLANG_X86_64 包装器）。
set -e
source build/env.sh
cd "$ROOT_W"

if [ -z "$CLANG_AARCH64" ] || [ ! -f "$CLANG_AARCH64" ]; then
  echo "[!] 找不到 NDK 的 arm64 编译器包装器：$CLANG_AARCH64"
  echo "    设 ANDROID_NDK_HOME 指向 NDK（见 build/env.sh.example）"
  exit 1
fi

for LV in S1 S2 S3; do
  SRCDIR="build/gen/so_$LV"
  if [ ! -d "$SRCDIR" ]; then
    echo "[!] 缺少 $SRCDIR —— 先跑 python tools/build_so_levels.py"; exit 1
  fi
  N=${LV#S}
  echo "==== $LV ===="
  mkdir -p "build/so/$LV/lib/arm64-v8a" "build/so/$LV/lib/x86_64" "build/so/$LV/classes" "build/so/$LV/dex"

  # S1 用 -O0：分派保持「比较级联 + 独立 case 体」，静态可切成 handler；
  # S2/S3 用 -O2：优化后分派退化成跳转表/回调，正是它们「难」的地方。
  if [ "$LV" = "S1" ]; then OPT="-O0"; else OPT="-O2"; fi

  echo "  [1/7] clang arm64-v8a -> libcalc.so ($OPT)"
  "$CLANG_AARCH64" -shared -fPIC $OPT -o "build/so/$LV/lib/arm64-v8a/libcalc.so" "$SRCDIR/native/core.c"

  echo "  [2/7] clang x86_64 -> libcalc.so ($OPT)"
  "$CLANG_X86_64" -shared -fPIC $OPT -o "build/so/$LV/lib/x86_64/libcalc.so" "$SRCDIR/native/core.c"

  echo "  [3/7] javac (CalcActivity + CalcLogic)"
  "$JAVAC" -source 11 -target 11 -nowarn -classpath "$ANDROID_JAR" \
    -d "build/so/$LV/classes" "$SRCDIR"/com/demo/calc/*.java

  echo "  [4/7] d8 -> classes.dex"
  rm -f "build/so/$LV/dex/out.zip"
  D8 --lib "$ANDROID_JAR" --output "build/so/$LV/dex/out.zip" --min-api $MIN_SDK \
     "build/so/$LV/classes/com/demo/calc/"*.class
  "$PY" tools/apkutil.py extract-dex "build/so/$LV/dex/out.zip" "samples/dex/level_$LV.dex"

  echo "  [5/7] aapt2 link + 注入 dex"
  rm -f "build/so/$LV/raw.apk"
  "$AAPT2" link -I "$ANDROID_JAR" --manifest src/AndroidManifest.xml \
    -o "build/so/$LV/raw.apk" --min-sdk-version $MIN_SDK --target-sdk-version $TARGET_SDK
  "$PY" tools/apkutil.py inject-dex "build/so/$LV/raw.apk" \
    "samples/dex/level_$LV.dex" "build/so/$LV/withdex.apk"

  echo "  [6/7] 放入 lib/arm64-v8a 与 x86_64 + 对齐"
  "$PY" tools/apkutil.py add-file "build/so/$LV/withdex.apk" \
    "lib/arm64-v8a/libcalc.so" "build/so/$LV/lib/arm64-v8a/libcalc.so" "build/so/$LV/withlib1.apk"
  "$PY" tools/apkutil.py add-file "build/so/$LV/withlib1.apk" \
    "lib/x86_64/libcalc.so" "build/so/$LV/lib/x86_64/libcalc.so" "build/so/$LV/withlib.apk"
  "$ZIPALIGN" -f 4 "build/so/$LV/withlib.apk" "build/so/$LV/aligned.apk"

  echo "  [7/7] 签名 -> samples/apks/app_s$N.apk"
  if [ ! -f "$KEYSTORE" ]; then
    "$KEYTOOL" -genkeypair -v -keystore "$KEYSTORE" -alias "$KEY_ALIAS" \
      -keyalg RSA -keysize 2048 -validity 10950 \
      -storepass "$KEY_STOREPASS" -keypass "$KEY_KEYPASS" \
      -dname "CN=Calc Lab, OU=Lab, O=Calc, L=Lab, S=Lab, C=CN" >/dev/null 2>&1
  fi
  APK_SIGNER sign --ks "$KEYSTORE" --ks-key-alias "$KEY_ALIAS" \
    --ks-pass pass:"$KEY_STOREPASS" --key-pass pass:"$KEY_KEYPASS" \
    --out "samples/apks/app_s$N.apk" "build/so/$LV/aligned.apk" >/dev/null 2>&1

  cp "build/so/$LV/lib/arm64-v8a/libcalc.so" "samples/native/libcalc_s${N}_arm64.so"
  cp "build/so/$LV/lib/x86_64/libcalc.so"    "samples/native/libcalc_s${N}_x86_64.so"
  echo "  -> samples/apks/app_s$N.apk  +  samples/native/libcalc_s${N}_{arm64,x86_64}.so"
done

echo
echo "[+] 下一步（arm64 设备）：adb install -r samples/apks/app_s1.apk && adb logcat -s CALC"
