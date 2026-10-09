#!/usr/bin/env bash
# build_dyn.sh — 构建「动态版（dyn）」样本 APK：在受保护样本上额外带一个**一次性探针**
#
# 为什么要它：静态跑不通的档（L3 反射分派 / L4 融合算子 / S2 运行期装配 / S3 threaded），
# 需要动态 trace 才能拿到 opcode 表。而设备上的 trace 脚本要能**读到那段自定义字节码**——
# 本脚本生成的 dyn 版在样本里多带两个方法：
#     CalcActivity.peek(int id) -> byte[]     入口，一次性
#     Core.peekCode(int id) / Core.wipe()     取载荷并立即清空
# 它们**只在 dyn 版存在**；正式样本（samples/apks/app_lN.apk）**没有**这两个方法
# （所以「正式样本不含任何可用探针」这条边界仍然成立）。
#
# 用法（lab 根目录执行）：
#   bash build/build_dyn.sh
#
# 产物：
#   samples/apks/app_lN_dbg.apk   动态版（同包名 com.demo.calc，可被 frida spawn/attach）
#   samples/dex/level_LN_dbg.dex  对应的 dex（分析对照用）
#
# 二者是同一份业务、同一套 opcode 表，只是 dyn 版多了探针 —— 用来**动态**取真值，
# 再回到静态路线里核实「静态能推出多少」。
set -e
source build/env.sh
cd "$ROOT_W"

echo "== [0/2] 生成 dyn 源（--dyn）=="
"$PY" tools/build_levels.py --dyn >/dev/null

restore() { "$PY" tools/build_levels.py >/dev/null; }
trap restore EXIT          # 无论成功失败，都把 build/gen 还原成正式（非 dyn）源

for LV in L1 L2 L3 L4 L5; do
  SRCDIR="build/gen/level_$LV"
  N=${LV#L}
  echo "==== dyn $LV ===="
  rm -rf "build/dyn/$LV"; mkdir -p "build/dyn/$LV/classes" "build/dyn/$LV/dex"

  echo "  [1/5] javac"
  "$JAVAC" -source 11 -target 11 -nowarn -classpath "$ANDROID_JAR" \
    -d "build/dyn/$LV/classes" "$SRCDIR"/com/demo/calc/*.java

  echo "  [2/5] d8 -> dex"
  rm -f "build/dyn/$LV/dex/out.zip"
  D8 --lib "$ANDROID_JAR" --output "build/dyn/$LV/dex/out.zip" --min-api $MIN_SDK \
     "build/dyn/$LV/classes/com/demo/calc/"*.class
  "$PY" tools/apkutil.py extract-dex "build/dyn/$LV/dex/out.zip" "samples/dex/level_L${N}_dbg.dex"

  echo "  [3/5] aapt2 + 注入 dex"
  rm -f "build/dyn/$LV/raw.apk"
  "$AAPT2" link -I "$ANDROID_JAR" --manifest src/AndroidManifest.xml \
    -o "build/dyn/$LV/raw.apk" --min-sdk-version $MIN_SDK --target-sdk-version $TARGET_SDK
  "$PY" tools/apkutil.py inject-dex "build/dyn/$LV/raw.apk" \
    "samples/dex/level_L${N}_dbg.dex" "build/dyn/$LV/withdex.apk"

  echo "  [4/5] 资源（如该层需要）+ 对齐"
  WORK="build/dyn/$LV/withdex.apk"
  if [ -f "samples/payloads/level_$LV.reassets" ]; then
    while read -r INNER LOCAL; do
      [ -z "$INNER" ] && continue
      "$PY" tools/apkutil.py add-file "$WORK" "$INNER" "$LOCAL" "build/dyn/$LV/withextra.apk"
      WORK="build/dyn/$LV/withextra.apk"
    done < "samples/payloads/level_$LV.reassets"
  fi
  "$ZIPALIGN" -f 4 "$WORK" "build/dyn/$LV/aligned.apk"

  echo "  [5/5] 签名 -> samples/apks/app_l${N}_dbg.apk"
  if [ ! -f "$KEYSTORE" ]; then
    "$KEYTOOL" -genkeypair -v -keystore "$KEYSTORE" -alias "$KEY_ALIAS" \
      -keyalg RSA -keysize 2048 -validity 10950 \
      -storepass "$KEY_STOREPASS" -keypass "$KEY_KEYPASS" \
      -dname "CN=Calc Lab, OU=Lab, O=Calc, L=Lab, S=Lab, C=CN" >/dev/null 2>&1
  fi
  APK_SIGNER sign --ks "$KEYSTORE" --ks-key-alias "$KEY_ALIAS" \
    --ks-pass pass:"$KEY_STOREPASS" --key-pass pass:"$KEY_KEYPASS" \
    --out "samples/apks/app_l${N}_dbg.apk" "build/dyn/$LV/aligned.apk" >/dev/null 2>&1
  rm -f "samples/apks/app_l${N}_dbg.apk.idsig"
  echo "  -> samples/apks/app_l${N}_dbg.apk"
done

echo
echo "[+] 下一步：python tools/trace_vm.py --package com.demo.calc --script frida/trace_dispatch.js"
