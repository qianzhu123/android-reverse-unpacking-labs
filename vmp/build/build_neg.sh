#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
build_neg.sh — 构建四个对抗性负样本 APK

用法（lab 根目录执行）：
  python tools/build_negatives.py
  bash build/build_neg.sh

产物：
  samples/apks/neg_plain.apk / neg_bigswitch.apk / neg_hub.apk / neg_extract.apk
  samples/dex/neg_*.dex

neg_extract 额外做一步：把业务方法的 dalvik 指令**抽空成 nop**（旧式「函数抽取」
的保护形态，不是 VMP）——用来检验判定不会把「方法体异常」一律当 VMP。
"""
set -e
source build/env.sh
cd "$ROOT_W"

for NAME in plain bigswitch hub extract; do
  SRCDIR="build/gen/neg_$NAME"
  [ -d "$SRCDIR" ] || { echo "[!] 缺少 $SRCDIR，先跑 python tools/build_negatives.py"; exit 1; }
  echo "==== neg_$NAME ===="
  mkdir -p "build/neg/$NAME/classes" "build/neg/$NAME/dex"

  "$JAVAC" -source 11 -target 11 -nowarn -classpath "$ANDROID_JAR" \
    -d "build/neg/$NAME/classes" "$SRCDIR"/com/demo/calc/*.java

  rm -f "build/neg/$NAME/dex/out.zip"
  D8 --lib "$ANDROID_JAR" --output "build/neg/$NAME/dex/out.zip" --min-api $MIN_SDK \
     "build/neg/$NAME/classes/com/demo/calc/"*.class
  "$PY" tools/apkutil.py extract-dex "build/neg/$NAME/dex/out.zip" "samples/dex/neg_$NAME.dex"

  if [ "$NAME" = "extract" ]; then
    echo "  [extract] 抽空业务方法体（nop 化）"
    "$PY" tools/nop_methods.py samples/dex/neg_$NAME.dex
  fi

  rm -f "build/neg/$NAME/raw.apk"
  "$AAPT2" link -I "$ANDROID_JAR" --manifest src/AndroidManifest.xml \
    -o "build/neg/$NAME/raw.apk" --min-sdk-version $MIN_SDK --target-sdk-version $TARGET_SDK
  "$PY" tools/apkutil.py inject-dex "build/neg/$NAME/raw.apk" \
    "samples/dex/neg_$NAME.dex" "build/neg/$NAME/withdex.apk"
  "$ZIPALIGN" -f 4 "build/neg/$NAME/withdex.apk" "build/neg/$NAME/aligned.apk"

  if [ ! -f "$KEYSTORE" ]; then
    "$KEYTOOL" -genkeypair -v -keystore "$KEYSTORE" -alias "$KEY_ALIAS" \
      -keyalg RSA -keysize 2048 -validity 10950 \
      -storepass "$KEY_STOREPASS" -keypass pass:"$KEY_KEYPASS" \
      -dname "CN=Calc Lab, OU=Lab, O=Calc, L=Lab, S=Lab, C=CN" >/dev/null 2>&1 || true
  fi
  APK_SIGNER sign --ks "$KEYSTORE" --ks-key-alias "$KEY_ALIAS" \
    --ks-pass pass:"$KEY_STOREPASS" --key-pass pass:"$KEY_KEYPASS" \
    --out "samples/apks/neg_$NAME.apk" "build/neg/$NAME/aligned.apk" >/dev/null 2>&1
  echo "  -> samples/apks/neg_$NAME.apk"
done

echo
echo "[+] 下一步：python tools/check_negatives.py"
