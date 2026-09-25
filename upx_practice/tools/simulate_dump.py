#!/usr/bin/env python
# simulate_dump.py — 由 ELF 生成"模拟内存镜像"
# 用途：在没有真机/模拟器的情况下，演示 dump_fix.py 的"内存 dump -> ELF Fix"流程。
# 做法：按 PT_LOAD 把文件映射进内存（filesz 拷贝 + memsz 补零），得到加载后的平坦镜像。
#
# 【可复用】不依赖任何具体项目；自动识别 32/64 位 ELF。
#
# 用法:
#   python simulate_dump.py <input.so> <output.bin>
import sys, struct

def parse_segs(data):
    """返回 [(vaddr, offset, filesz, memsz)], 自动识别 ELF32/ELF64（仅小端）。"""
    if data[:4] != b"\x7fELF":
        print("[!] 不是 ELF 文件"); return []
    is64 = data[4] == 2
    if is64:
        e_phoff = struct.unpack_from("<Q", data, 32)[0]
        e_phentsize = struct.unpack_from("<H", data, 54)[0]
        e_phnum = struct.unpack_from("<H", data, 56)[0]
    else:
        e_phoff = struct.unpack_from("<I", data, 28)[0]
        e_phentsize = struct.unpack_from("<H", data, 42)[0]
        e_phnum = struct.unpack_from("<H", data, 44)[0]
    segs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if is64:
            t = struct.unpack_from("<I", data, o)[0]
            if t != 1: continue
            off = struct.unpack_from("<Q", data, o + 8)[0]
            va = struct.unpack_from("<Q", data, o + 16)[0]
            fsz = struct.unpack_from("<Q", data, o + 32)[0]
            msz = struct.unpack_from("<Q", data, o + 40)[0]
        else:
            t = struct.unpack_from("<I", data, o)[0]
            if t != 1: continue
            off = struct.unpack_from("<I", data, o + 4)[0]
            va = struct.unpack_from("<I", data, o + 8)[0]
            fsz = struct.unpack_from("<I", data, o + 16)[0]
            msz = struct.unpack_from("<I", data, o + 20)[0]
        segs.append((va, off, fsz, msz))
    return segs

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    src = sys.argv[1]; out = sys.argv[2]
    data = open(src, "rb").read()
    segs = parse_segs(data)
    if not segs:
        print("[!] no PT_LOAD"); sys.exit(1)
    lo = min(s[0] for s in segs)
    hi = max(s[0] + s[3] for s in segs)
    img = bytearray(b"\x00" * (hi - lo))
    for va, off, fsz, msz in segs:
        img[va - lo:va - lo + fsz] = data[off:off + fsz]
    open(out, "wb").write(bytes(img))
    print("[+] simulated dump -> %s  base=0x%X size=%d (from %d PT_LOAD, %d-bit)" % (
          out, lo, len(img), len(segs), 64 if data[4] == 2 else 32))
