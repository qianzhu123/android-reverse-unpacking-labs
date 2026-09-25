#!/usr/bin/env python
# make_variant.py — 由"标准 UPX 包"生成一个"变种 UPX"样本
# 做法（对应文档：修改 Stub / 删除明显特征）：
#   1) 把 l_info 里的 UPX! 魔数改成 XXXX  -> upx -t / upx -d 直接失败
#   2) 把段名 UPX0/UPX1/UPX2 改成 SEC0/SEC1/SEC2 -> 去掉明显的 UPX 字符串特征
# 这样标准工具无法自动解包，必须走动态/内存分析路线。
import sys

def make_variant(src, dst, scramble_stub=False):
    data = bytearray(open(src, "rb").read())
    c1 = data.count(b"UPX!")
    data = data.replace(b"UPX!", b"XXXX")
    c0 = data.count(b"UPX0"); data = data.replace(b"UPX0", b"SEC0")
    c1b = data.count(b"UPX1"); data = data.replace(b"UPX1", b"SEC1")
    c2 = data.count(b"UPX2"); data = data.replace(b"UPX2", b"SEC2")
    if scramble_stub:
        # 可选：再把 stub 开头一小段清 0，模拟"修改控制流"（仅练习用，不保证可运行）
        for i in range(0x40, 0x80):
            if i < len(data):
                data[i] = 0x00
    open(dst, "wb").write(data)
    print(f"[+] variant -> {dst}")
    print(f"    patched UPX! x{c1}, UPX0/1/2 x{c0}/{c1b}/{c2}")

if __name__ == "__main__":
    s = sys.argv[1]
    d = sys.argv[2]
    sc = "--scramble-stub" in sys.argv
    make_variant(s, d, sc)
