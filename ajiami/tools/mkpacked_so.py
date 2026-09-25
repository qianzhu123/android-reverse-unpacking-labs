#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
mkpacked_so.py — 造一个"被加壳 / 自实现 Linker"的 SO（只用于测 B13 是否会【正确触发】）。

真实的 SO 保护常做两件事，这里都模拟：
  1) 把 ELF 节头表干掉（e_shoff/e_shnum/e_shstrndx 清零）——
     自实现 Linker 往往不写标准节头，自己按 Program Header 装载。
     这是 B13 里 no_section_headers 异常，对"正常 NDK .so"绝不成立
     （NDK 产物永远带完整节头），所以是干净、可靠、不会误伤的信号。
  2) 把 .text 节字节 XOR 成随机流，模拟"代码段被加密/压缩"——
     对应 B13 的 high_text_entropy 异常（仅当 .text 足够大才会触发，
     小函数体受样本量限制熵上不到 8.0，所以 1) 才是主触发）。

用法：
  python tools/mkpacked_so.py <干净.so> <输出.so>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import elfinspect

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

    # 先定位 .text（在改节头前），做"代码加密"模拟
    r = elfinspect.inspect(bytes(blob), os.path.basename(src))
    text = [e for e in r.get('section_entropy', []) if e['name'] == '.text']
    if text:
        off, size = text[0]['offset'], text[0]['size']
        ks = os.urandom(size)
        for i in range(size):
            blob[off + i] ^= ks[i]
        print('  .text @%#x len=%d 原 entropy=%.4f' % (off, size, text[0]['entropy']))

    # 再干掉节头表 —— 主触发：no_section_headers
    _strip_section_headers(blob)

    open(dst, 'wb').write(bytes(blob))

    r2 = elfinspect.inspect(bytes(blob), os.path.basename(dst))
    print('  输出：class=%s type=%s sh_count=%s exec_load=%s' % (
        r2.get('class'), r2.get('type'), r2.get('sh_count'), r2.get('exec_load')))
    print('  触发的 anomalies=%s' % r2.get('anomalies'))
    if not r2.get('anomalies'):
        raise SystemExit('!! 改造后仍未触发任何 anomaly —— B13 验证失败')
    print('  已写出 %s' % dst)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
