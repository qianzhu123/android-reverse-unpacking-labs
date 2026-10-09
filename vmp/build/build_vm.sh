#!/usr/bin/env bash
# build_vm.sh — 构建 L1..L5 各难度的 DEX-VM 样本 APK
#
# 用法（lab 根目录执行）：
#   python tools/build_levels.py      # 先生成 build/gen/level_* 源码与载荷
#   bash build/build_vm.sh
#
# 产物：
#   samples/dex/level_L1.dex .. level_L5.dex       受保护 dex（分析对象）
#   samples/apks/app_l1.apk  .. app_l5.apk         可直接 adb install 的样本
#
# 与黄金样本的关系：这些 APK 与 samples/apks/app_golden.apk 是**同一份业务**的不同
# 表示；设备上应打印与黄金版完全相同的 CALC 日志。
set -e
source build/env.sh
cd "$ROOT_W"

for LV in L1 L2 L3 L4 L5; do
  SRCDIR="build/gen/level_$LV"
  if [ ! -d "$SRCDIR" ]; then
    echo "[!] 缺少 $SRCDIR —— 先跑 python tools/build_levels.py"; exit 1
  fi
  echo "==== $LV ===="
  rm -rf "build/vm/$LV"
  mkdir -p "build/vm/$LV/classes" "build/vm/$LV/dex"

  echo "  [1/6] javac"
  "$JAVAC" -source 11 -target 11 -nowarn \
    -classpath "$ANDROID_JAR" \
    -d "build/vm/$LV/classes" \
    "$SRCDIR"/com/demo/calc/*.java

  echo "  [2/6] d8 -> classes.dex"
  rm -f "build/vm/$LV/dex/out.zip"
  D8 --lib "$ANDROID_JAR" --output "build/vm/$LV/dex/out.zip" --min-api $MIN_SDK \
     "build/vm/$LV/classes/com/demo/calc/"*.class
  "$PY" tools/apkutil.py extract-dex "build/vm/$LV/dex/out.zip" "samples/dex/level_$LV.dex"

  echo "  [3/6] aapt2 link -> 骨架"
  rm -f "build/vm/$LV/raw.apk"
  "$AAPT2" link -I "$ANDROID_JAR" \
    --manifest src/AndroidManifest.xml \
    -o "build/vm/$LV/raw.apk" \
    --min-sdk-version $MIN_SDK --target-sdk-version $TARGET_SDK

  echo "  [4/6] 注入 dex"
  "$PY" tools/apkutil.py inject-dex "build/vm/$LV/raw.apk" \
    "samples/dex/level_$LV.dex" "build/vm/$LV/withdex.apk"

  echo "  [5/6] 资源（如该层需要）+ 对齐"
  WORK="build/vm/$LV/withdex.apk"
  if [ -f "samples/payloads/level_$LV.reassets" ]; then
    # 某些层把载荷作为 assets 内文件；映射写在 level_$LV.reassets 里：<zip内路径> <本lab相对路径>
    while read -r INNER LOCAL; do
      [ -z "$INNER" ] && continue
      "$PY" tools/apkutil.py add-file "$WORK" "$INNER" "$LOCAL" "build/vm/$LV/withextra.apk"
      WORK="build/vm/$LV/withextra.apk"
    done < "samples/payloads/level_$LV.reassets"
  fi
  "$ZIPALIGN" -f 4 "$WORK" "build/vm/$LV/aligned.apk"

  echo "  [6/6] 签名 -> samples/apks/app_l${LV#L}.apk"
  if [ ! -f "$KEYSTORE" ]; then
    "$KEYTOOL" -genkeypair -v -keystore "$KEYSTORE" -alias "$KEY_ALIAS" \
      -keyalg RSA -keysize 2048 -validity 10950 \
      -storepass "$KEY_STOREPASS" -keypass "$KEY_KEYPASS" \
      -dname "CN=Calc Lab, OU=Lab, O=Calc, L=Lab, S=Lab, C=CN" >/dev/null 2>&1
  fi
  OUT="samples/apks/app_l${LV#L}.apk"
  APK_SIGNER sign --ks "$KEYSTORE" --ks-key-alias "$KEY_ALIAS" \
    --ks-pass pass:"$KEY_STOREPASS" --key-pass pass:"$KEY_KEYPASS" \
    --out "$OUT" "build/vm/$LV/aligned.apk" >/dev/null 2>&1
  echo "  -> $OUT"
done

echo
echo "[+] 下一步（设备）：逐个 adb install -r samples/apks/app_l*.apk 并看 adb logcat -s CALC"
