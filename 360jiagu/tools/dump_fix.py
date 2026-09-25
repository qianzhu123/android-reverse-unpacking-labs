#!/usr/bin/env python
# dump_fix.py — 变种 UPX 解法 B（通用）：内存 dump -> ELF Fix（重建可载入 IDA 的 ELF）
#
# 真实对抗里，变种往往还改了 Stub / 控制流，此时"修特征"无效，
# 唯一通用办法是：让程序跑起来 -> 等 Stub 解压完 -> dump 进程内存 -> 重建 ELF。
#
# 用法:
#   python dump_fix.py <dump.bin> <base_vaddr_hex> <out.so> [--arch arm|arm64] [--entry-rva HEX]
# 例:
#   python dump_fix.py dump.bin 0xb6d00000 fixed.so --arch arm --entry-rva 0x1234
import sys, struct

def build(dump, base, arch="arm", entry_rva=None, out="fixed.so"):
    is64 = (arch=="arm64")
    machine = 0xb7 if is64 else 0x28
    ehsize = 64 if is64 else 52
    phentsize = 56 if is64 else 32
    shentsize = 64 if is64 else 40

    # 布局: [ehdr][phdrs] ... pad到0x1000 ... [dump数据] ... [shdrs][shstrtab]
    phnum = 1
    data_off = 0x1000
    shdrs_off = data_off + len(dump)
    # shstrtab
    names = b"\x00.text\x00.shstrtab\x00"
    name_text = 1
    name_shstr = 7
    shstr_off = shdrs_off + shentsize*3   # 3个节: NULL + .text + .shstrtab

    entry = base + (entry_rva if entry_rva else 0)

    if is64:
        eh = struct.pack("<16sHHIQQQIHHHHHH",
            b"\x7fELF\x02\x01\x01"+b"\x00"*9, 3, machine, 1,
            entry, ehsize, shdrs_off, 0, ehsize, phentsize, phnum,
            shentsize, 3, 2)
        ph = struct.pack("<IIQQQQQQ", 1, 7, data_off, base, base,
                         len(dump), len(dump), 0x1000)
    else:
        eh = struct.pack("<16sHHIIIIIHHHHHH",
            b"\x7fELF\x01\x01\x01"+b"\x00"*9, 3, machine, 1,
            entry, ehsize, shdrs_off, 0, ehsize, phentsize, phnum,
            shentsize, 3, 2)
        ph = struct.pack("<IIIIIIII", 1, data_off, base, base,
                         len(dump), len(dump), 7, 0x1000)

    def sh32(name, typ, flags, addr, off, size, link=0, info=0, align=1, entsize=0):
        return struct.pack("<IIIIIIIIII", name, typ, flags, addr, off, size,
                           link, info, align, entsize)
    def sh64(name, typ, flags, addr, off, size, link=0, info=0, align=1, entsize=0):
        return struct.pack("<IIQQQQIIQQ", name, typ, flags, addr, off, size,
                           link, info, align, entsize)
    sh = sh64 if is64 else sh32
    shdrs = (sh(0,0,0,0,0,0) +
             sh(name_text, 1, 0x6, base, data_off, len(dump), align=16) +
             sh(name_shstr, 3, 0x2, 0, shstr_off, len(names), align=1))

    blob = bytearray()
    blob += eh + ph
    blob += b"\x00"*(data_off - len(blob))
    blob += dump
    blob += shdrs + names
    open(out,"wb").write(bytes(blob))
    print("[+] wrote %s: base=0x%X size=%d arch=%s entry=0x%X"%(
          out, base, len(dump), arch, entry))
    return out

if __name__=="__main__":
    if len(sys.argv)<4:
        print(__doc__); sys.exit(1)
    dump=open(sys.argv[1],"rb").read()
    base=int(sys.argv[2],0)
    out=sys.argv[3]
    arch="arm64" if "--arch" in sys.argv and sys.argv[sys.argv.index("--arch")+1]=="arm64" else "arm"
    entry_rva=None
    if "--entry-rva" in sys.argv:
        entry_rva=int(sys.argv[sys.argv.index("--entry-rva")+1],0)
    build(dump, base, arch, entry_rva, out)
