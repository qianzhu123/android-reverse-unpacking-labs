#!/usr/bin/env bash
# build_merged.sh — 把「业务源码 + 壳源码」编译进同一个 classes.dex
#
# 为什么需要它：
#   二代（类抽取）/三代（抽取+混淆）的典型形态是 —— classes.dex 里既能看到业务类名，
#   也能看到壳的 ProxyApplication（因为它必须声明在 manifest 里，必然存在），
#   只是业务方法的 code_item 被抽空了。
#   要还原这种形态，壳类必须和业务类在同一个 dex 里，所以这里一次性编译两份源码。
#
# 用法（项目根目录执行）：bash build/build_merged.sh
#
# 产物：
#   build/merged/merged_classes.dex   合并后的原始 dex（= v2/v3 的输入）
#   build/merged/merged_raw.apk       aapt2 产出的未签名骨架（classes.dex 留空位）
set -e
source build/env.sh
cd "$ROOT_W"

mkdir -p build/merged/classes build/merged/dex

echo "== [1/3] javac（app + shell 一起编译）=="
"$JAVAC" -source 11 -target 11 -nowarn \
  -classpath "$ANDROID_JAR" \
  -d build/merged/classes \
  app/src/com/demo/target/*.java \
  shell/src/com/ijiami/shell/*.java

echo "== [2/3] d8 =="
rm -f build/merged/dex/merged.zip
D8 --lib "$ANDROID_JAR" --output build/merged/dex/merged.zip \
   --min-api $MIN_SDK \
   build/merged/classes/com/demo/target/*.class \
   build/merged/classes/com/ijiami/shell/*.class
"$PY" tools/apkutil.py extract-dex build/merged/dex/merged.zip \
  build/merged/merged_classes.dex

echo "== [3/3] aapt2 link（manifest 用壳的，Application 指向 ProxyApplication）=="
rm -f build/merged/merged_raw.apk
"$AAPT2" link -I "$ANDROID_JAR" \
  --manifest shell/AndroidManifest.xml \
  -o build/merged/merged_raw.apk \
  --min-sdk-version $MIN_SDK --target-sdk-version $TARGET_SDK

echo
echo "[+] build/merged/merged_classes.dex  合并 dex（v2/v3 的输入）"
"$PY" tools/dexlib.py build/merged/merged_classes.dex | head -6
