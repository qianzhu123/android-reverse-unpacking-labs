#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
walkthrough.py — 把"脱壳还原"拆成可在十六进制编辑器里手动复现的字节步骤。

不依赖任何反编译/脱壳框架，只用本工程的 dexlib / crypto_lab（手写实现）。
每一步都打印「在哪个文件、哪个偏移、期望看到什么字节」，方便手算核对，
也方便验证我们写的脚本没有"偷偷"做超出手算范围的事。

用法：
    python tools/walkthrough.py samples/app_packed_v1.apk
    python tools/walkthrough.py samples/app_packed_v2.apk
    python tools/walkthrough.py samples/app_packed_v3.apk
    python tools/walkthrough.py samples/app_packed_v2_variant.apk
"""

import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import crypto_lab
import dexlib

KEY_DESC = 'XOR(key=%s, key 每字节再 ^ (i & 0xFF)，i 从 0 计数)' % crypto_lab.KEY.hex()


def _find_payload(apk):
    z = zipfile.ZipFile(apk)
    for n in z.namelist():
        if n.startswith('assets/'):
            d = z.read(n)
            if d[4:8] == crypto_lab.MAGIC:
                return n, d, z.getinfo(n).header_offset
    return None, None, None


def _find_table(apk):
    z = zipfile.ZipFile(apk)
    for n in z.namelist():
        if n.startswith('assets/'):
            d = z.read(n)
            if d[:4] == crypto_lab.TABLE_MAGIC:
                return n, d, z.getinfo(n).header_offset
    return None, None, None


def walk_v1(apk):
    name, payload, zoff = _find_payload(apk)
    print('[一代 · 整体加密] payload 位于 APK 内 %s' % name)
    print('  APK 文件内偏移 (local header) = 0x%X' % zoff)
    decl_len = crypto_lab.u32le(payload, 0)
    magic = payload[4:8]
    print('  payload[0:4]  = int32_le 声明长度 = %d (0x%X)' % (decl_len, decl_len))
    print('  payload[4:8]  = magic = %r' % bytes(magic))
    print('  钥  匙        = %s' % KEY_DESC)
    # 解密后的 dex 前 8 字节应该是 dex 魔数
    head = crypto_lab.xor(payload[8:16])
    print('  payload[8:16] 经 XOR 流解密后 = %r  （应为 dex\\n037\\0）' % bytes(head))
    print('  手工复现：把这 %d 字节按 XOR 流逐字节还原，即得原始 classes.dex' % decl_len)


def walk_v2(apk):
    name, table, zoff = _find_table(apk)
    print('[二代/三代 · 类抽取] 侧表位于 APK 内 %s' % name)
    print('  APK 文件内偏移 (local header) = 0x%X' % zoff)
    print('  table[0:4]    = magic = %r' % bytes(table[:4]))
    count = crypto_lab.u32le(table, 4)
    print('  table[4:8]    = int32_le 条目数 = %d' % count)
    print('  每条目布局：u4 class_idx | u4 method_idx | u4 code_off | u4 insns_len | insns_len 字节密文')

    _apk = zipfile.ZipFile(apk)
    # 【多 dex 防护】本脚本讲习的是单 dex 样本的字节布局；多 dex 时
    # code_off 只相对主 dex 有意义，必须显式说明，避免读者误以为全已还原。
    _all_dex = sorted(n for n in _apk.namelist() if n.endswith('.dex'))
    if [n for n in _all_dex if n != 'classes.dex']:
        print('  [!] 该 APK 含多个 dex（%s）；本节演练只针对 classes.dex，'
              '其余 dex 不在本次讲解范围内' % ', '.join(_all_dex))
    dex_blob = _apk.read('classes.dex')
    dx = dexlib.Dex(dex_blob)

    # 1) dex 里有哪些方法的 code_item 是空的（insns 全 0x00 = nop）
    print('')
    print('  --- dex 内"被抽空"的方法（insns 全 0x00）---')
    st = dx.method_code_stats()
    for cname, kind, m in dx.iter_methods():
        if m['code_off'] == 0:
            continue
        ci = dx.code_item(m['code_off'])
        if ci['insns'].count(0) == len(ci['insns']) and ci['insns_size'] > 0:
            clazz, midx, proto, mname = dx.method_at(m['method_idx'])
            print('    %-38s %-12s code_off=0x%X  insns_size=%d(=%d 字节)'
                  % (clazz + '->' + mname, kind, m['code_off'], ci['insns_size'], ci['insns_size'] * 2))

    # 2) 侧表里的真实指令，回填到上面的 code_off + 16 处
    print('')
    print('  --- 侧表里的真实指令（回填目标 = dex 偏移 code_off + %d）---' % dexlib.CODE_ITEM_HEADER)
    entries = crypto_lab.parse_code_table(table)[0]
    for e in entries:
        ins = e['insns']
        expect = dexlib.CODE_ITEM_HEADER  # 16
        print('    code_off=0x%X  insns_len=%d  解密后前 8 字节=%s ...'
              % (e['code_off'], len(ins), ins[:8].hex()))
    print('  手工复现：对每条目按 code_off 定位 code_item，把解密后的 insns 写回')
    print('            偏移 code_off+%d 起的 insns_size*2 字节，最后重算 checksum/signature。' % expect)
    print('  还原后空方法数应为 0（当前 %d，还原后 %d）。' % (st['empty'], 0))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    apk = sys.argv[1]
    if not os.path.exists(apk):
        print('不存在: %s' % apk)
        return 1
    payload_name, _, _ = _find_payload(apk)
    if payload_name:
        walk_v1(apk)
    else:
        table_name, _, _ = _find_table(apk)
        if table_name:
            walk_v2(apk)
        else:
            print('未在 assets/ 找到 AJM\\x01 或 AJMT 标记，可能不是本工程产物')
            return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
