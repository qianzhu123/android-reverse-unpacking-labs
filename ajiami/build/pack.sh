#!/usr/bin/env bash
# pack.sh — 生成三个加固样本 APK + 对应的散装分析文件
#
# 用法（项目根目录执行）：bash build/pack.sh
#
# 前置：
#   bash build/build_target.sh   # 原始 dex / 原始 APK
#   bash build/build_shell.sh    # 壳 dex / 壳 APK 骨架
#   bash build/build_merged.sh   # 合并 dex / 二代三代骨架
#
# 产物：
#   samples/app_packed_v1.apk   一代：-business dex 被整体加密进 assets
#   samples/app_packed_v2.apk   二代：类抽取，方法体全 nop
#   samples/app_packed_v3.apk   三代：选择性抽取 + 混淆资源名 + 诱饵文件
#   samples/payload_*.bin / codetable_*.bin / *_extracted.dex   散装分析对象
set -e
source build/env.sh
cd "$ROOT_W"

echo "===== [1/4] 生成三代加壳产物 ====="
"$PY" tools/packer.py all

echo "===== [2/4] 组装 APK ====="
"$PY" tools/mkapk.py build/merged/merged_raw.apk samples/app_packed_v1.apk \
  --dex build/v1/classes.dex \
  --asset assets/ijm_payload.bin=build/v1/ijm_payload.bin

"$PY" tools/mkapk.py build/merged/merged_raw.apk samples/app_packed_v2.apk \
  --dex build/v2/extracted.dex \
  --asset assets/ijm_codes.bin=build/v2/ijm_codes.bin

"$PY" tools/mkapk.py build/merged/merged_raw.apk samples/app_packed_v3.apk \
  --dex build/v3/extracted.dex \
  --asset assets/brand_res_v3.dat=build/v3/brand_res_v3.dat \
  --asset assets/config.txt=build/v3/config_decoy.txt

echo "===== [3/4] 散装分析文件 ====="
cp build/v1/ijm_payload.bin    samples/payload_v1.bin
cp build/v2/ijm_codes.bin      samples/codetable_v2.bin
cp build/v3/brand_res_v3.dat   samples/brand_res_v3.dat
cp build/v2/extracted.dex      samples/extracted_v2.dex
cp build/v3/extracted.dex      samples/extracted_v3.dex
cp build/shell/shell_classes.dex samples/classes_shell_v1.dex
cp build/merged/merged_classes.dex samples/classes_merged_orig.dex

echo "===== [4/4] 生成变种样本 ====="
"$PY" tools/make_variant.py all

echo
echo "===== samples/ 产物一览 ====="
ls -la samples/
