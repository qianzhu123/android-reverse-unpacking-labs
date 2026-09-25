#!/usr/bin/env bash
# pack.sh — 生成"标准 360 加固样本"与"变种 360 加固样本"
# 用法：在项目根目录执行  bash build/pack.sh
#
# 模型说明（详见 README）：360 加固的 native 层 = 改版 UPX（历史基础）。
#   - 标准 360：UPX 打包、UPX! 魔数保留 -> upx -d 可解（"可恢复配置"）
#   - 变种 360：UPX! 被 360 改写成 4 字节 token -> upx -d 失败（需手工/动态脱壳）
#
# UPX 不写死：默认用工程根自带的 upx.exe（与 README 实测版本一致，保证可复现）；
# 要换版本就 `UPX=<路径> bash build/pack.sh`，或先把 upx 加进 PATH（见 build/locate.sh）。
set -e
source "$(dirname "${BASH_SOURCE[0]}")/locate.sh"
locate_require UPX PY
cd "$ROOT"

rm -f libtarget_360.so libtarget_360_variant.so libtarget_stripped.so _tmp_orig.so

# 1) 复制原始 .so 并临时把 e_type 改成 ET_EXEC(2)：官方 UPX 4.2.4 才会打包
#    （Android .so 是 ET_DYN，UPX 4.2.4 拒绝打包 ET_DYN，见 README §7）
cp libtarget_orig.so _tmp_orig.so
printf '\x02\x00' | dd of=_tmp_orig.so bs=1 seek=16 conv=notrunc 2>/dev/null
"$UPX" --force-overwrite -o libtarget_360.so _tmp_orig.so
rm -f _tmp_orig.so

# 2) 给"标准 360"尝试注入一个明文 360 标记（把 stub 里的版本串 "UPX 4.24" 改成 "360 4.24"）。
#    仅当 upx -t 仍通过才保留；否则回退（说明该字节属于 UPX 校验范围，不能动）。
"$PY" - <<'PY'
src = "libtarget_360.so"
d = bytearray(open(src, "rb").read())
if b"UPX 4.24" in d and b"360 4.24" not in d:
    cand = d.replace(b"UPX 4.24", b"360 4.24")
    open(src, "wb").write(cand)
    print("[*] 已把版本串 UPX 4.24 -> 360 4.24（360 明文标记），稍后用 upx -t 验证")
else:
    print("[*] 无 UPX 版本串可改写，标准样本保持原 UPX 版本串")
PY
if "$UPX" -t libtarget_360.so >/dev/null 2>&1; then
  echo "[+] 360 标记注入后 upx -t 通过：标准样本携带明文 360 标记"
else
  # 回退：版本串改写破坏了 UPX 校验，撤销
  "$PY" - <<'PY'
src = "libtarget_360.so"
d = bytearray(open(src, "rb").read())
if b"360 4.24" in d:
    open(src, "wb").write(d.replace(b"360 4.24", b"UPX 4.24"))
PY
  echo "[-] 360 标记注入导致 upx -t 失败，已回退（标准样本保持原 UPX 版本串）"
fi

# 3) 变种：把 UPX! 魔数改写成 360 token（JG!! = JiāGù），upx -t / upx -d 将失败
"$PY" tools/make_360_variant.py libtarget_360.so libtarget_360_variant.so

# 4) B13 正样本：从原始 .so 剥离节头表（自实现 Linker 形态，无 UPX 特征）
"$PY" tools/make_stripped_so.py libtarget_orig.so libtarget_stripped.so

echo
echo "[+] 使用 UPX: $UPX"
echo "[+] 标准样本 : libtarget_360.so            (upx -t / upx -d 可用)"
echo "[+] 变种样本 : libtarget_360_variant.so    (upx -t / upx -d 失败，需手工/动态脱壳)"
echo "[+] B13 样本 : libtarget_stripped.so       (节头剥离，触发 B13：疑似自实现 Linker)"
