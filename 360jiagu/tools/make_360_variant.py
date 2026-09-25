#!/usr/bin/env python
# make_360_variant.py — 由"标准 360 包（UPX 基础）"生成一个"变种 360"样本
#
# 模型（对应文档：360 native 层 = 改版 UPX）：
#   把 l_info 里的 UPX! 魔数改写成 360 的 4 字节 token（默认 JG!! = JiāGù），
#   官方 upx -t / upx -d 会直接失败（UPX 校验和覆盖全部内嵌魔数）。
#   段名 UPX0/1/2 在本机 UPX 4.2.4 的 ARM 产物里并不存在（count=0），
#   所以这里只改魔数即可达到"变种"效果。
#
# 用法:
#   python tools/make_360_variant.py <标准.so> <变种.so> [--token JG!!]
import sys

MAGIC = b"UPX!"
DEFAULT_TOKEN = b"JG!!"   # JiāGù（加固）的 360 占位魔数

def make_variant(src, dst, token=DEFAULT_TOKEN):
    data = bytearray(open(src, "rb").read())
    c1 = data.count(MAGIC)
    data = data.replace(MAGIC, token)
    open(dst, "wb").write(data)
    print("[+] variant -> %s" % dst)
    print("    改写 UPX! x%d -> %r（%d 处）" % (c1, token, c1))

if __name__ == "__main__":
    s = sys.argv[1] if len(sys.argv) > 1 else None
    d = sys.argv[2] if len(sys.argv) > 2 else None
    tok = DEFAULT_TOKEN
    if "--token" in sys.argv:
        i = sys.argv.index("--token")
        if i + 1 < len(sys.argv):
            tok = sys.argv[i + 1].encode("latin1")
    if not s or not d:
        print("用法: python tools/make_360_variant.py <标准.so> <变种.so> [--token JG!!]")
        sys.exit(1)
    make_variant(s, d, tok)
