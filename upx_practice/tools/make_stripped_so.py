#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
make_stripped_so.py — 造一个"被加壳 / 自实现 Linker"的 SO（只用于验证 B13 是否会正确触发）。

真实的 SO 保护常把 ELF 节头表干掉（e_shoff / e_shnum / e_shstrndx 清零）：
自实现 Linker 往往不写标准节头，自己按 Program Header 装载。
这是 B13 的 no_section_headers 异常，对"正常 NDK .so"绝不成立
（NDK 产物永远带完整节头），所以是干净、可靠、不会误伤的信号。

用法：
  python tools/make_stripped_so.py <干净.so> <输出.so>
"""
import os
import sys

ET_DYN = 3


def _strip_section_headers(blob):
    """把 ELF 头里的节头表字段清零（保留 Program Header / exec_load）。"""
    is64 = (blob[4] == 2)
    if is64:
        # ELF64: e_shoff@40(8) e_shnum@60(2) e_shstrndx@62(2)
        blob[40:48] = b'\x00' * 8
        blob[60:64] = b'\x00' * 4
    else:
        # ELF32: e_shoff@32(4) e_shnum@48(2) e_shstrndx@50(2)
        blob[32:36] = b'\x00' * 4
        blob[48:52] = b'\x00' * 4
    return blob


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    src, dst = sys.argv[1], sys.argv[2]
    blob = bytearray(open(src, 'rb').read())
    if len(blob) < 64 or blob[:4] != b'\x7fELF':
        raise SystemExit('源文件不是 ELF：%s' % src)
    if blob[4] not in (1, 2):
        raise SystemExit('暂只支持 32/64 位 little-endian ELF')

    _strip_section_headers(blob)
    open(dst, 'wb').write(bytes(blob))
    print('  已写出 %s（e_type=ET_DYN，e_shnum=0，节头表已剥离）' % dst)
    print('  预期 B13：no_section_headers 触发（自实现 Linker 形态）')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
