#!/usr/bin/env bash
# pack.sh — 生成"标准 UPX 样本"与"变种 UPX 样本"
# 用法：在项目根目录执行  bash build/pack.sh
#
# UPX 不写死：默认用工程根自带的 upx.exe（与 README 实测版本一致，保证可复现）；
# 要换版本就 `UPX=<路径> bash build/pack.sh`，或先把 upx 加进 PATH（见 build/locate.sh）。
set -e
source "$(dirname "${BASH_SOURCE[0]}")/locate.sh"
locate_require UPX PY
cd "$ROOT"

# 清理旧产物，避免 UPX 因输出文件已存在而报错
rm -f libtarget_upx.so libtarget_upx_variant.so libtarget_stripped.so _tmp_orig.so

# 1) 复制原始 .so 并临时把 e_type 改成 ET_EXEC(2)，官方 UPX 4.2.4 才会打包
cp libtarget_orig.so _tmp_orig.so
printf '\x02\x00' | dd of=_tmp_orig.so bs=1 seek=16 conv=notrunc 2>/dev/null
"$UPX" --force-overwrite -o libtarget_upx.so _tmp_orig.so
rm -f _tmp_orig.so

# 2) 变种：去除 UPX! / UPX0/1/2 指纹（upx -d 将失败）
"$PY" tools/make_variant.py libtarget_upx.so libtarget_upx_variant.so

# 3) B13 正样本：从原始 .so 剥离节头表（自实现 Linker 形态，无 UPX 特征）
"$PY" tools/make_stripped_so.py libtarget_orig.so libtarget_stripped.so

echo "[+] 使用 UPX: $UPX"
echo "[+] 标准样本 : libtarget_upx.so            (upx -t / upx -d 可用)"
echo "[+] 变种样本 : libtarget_upx_variant.so    (upx -t / upx -d 失败，需手工/动态脱壳)"
echo "[+] B13 样本 : libtarget_stripped.so       (节头剥离，触发 B13：疑似自实现 Linker)"
