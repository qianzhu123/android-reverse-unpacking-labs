#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
unpack_v2.py — 二代/三代「类抽取」脱壳（静态还原 method body）

要点（呼应 SCRIPT.md §4.2 / MANUAL.md §4.2 的教学）：
  二代加固把每个方法的 code_item.insns 抽空成 nop，真实指令存在 assets 侧表。
  这里把侧表读回来，按 (code_off, 长度) 精准填回对应位置，再重算 checksum/signature。

  三种输入形态都能处理：
    a) APK：自动扫描 assets 里带 'AJMT' 魔数的文件（不靠文件名！v3 把文件名改了）
    b) dex + 侧表文件
    c) 已经解出的散装 dex（samples/dex/extracted_v2.dex）+ samples/payloads/codetable_v2.bin

用法：
  python tools/unpack_v2.py samples/apks/app_packed_v2.apk analysis_output/unpack_v2_dex.dex --pristine samples/dex/classes_merged_orig.dex
  python tools/unpack_v2.py samples/apks/app_packed_v3.apk analysis_output/unpack_v3_dex.dex --pristine samples/dex/classes_merged_orig.dex
  python tools/unpack_v2.py samples/dex/extracted_v2_variant.dex samples/payloads/codetable_v2_variant.bin analysis_output/unpack_v2_variant_dex.dex --pristine build/variant/merged_orig_variant.dex
"""

import argparse
import hashlib
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import crypto_lab
import dexlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def find_table_in_apk(apk):
    z = zipfile.ZipFile(apk)
    for n in z.namelist():
        if n.startswith('assets/'):
            data = z.read(n)
            if data[:4] == b'AJMT':
                return n, data
    return None, None


def decode_table(blob):
    """解析 AJMT 侧表 -> [(class_idx, method_idx, code_off, insns)]"""
    if blob[:4] != b'AJMT':
        raise ValueError('不是 AJMT 侧表')
    count = crypto_lab.u32le(blob, 4)
    p = 8
    out = []
    for _ in range(count):
        class_idx = crypto_lab.u32le(blob, p)
        method_idx = crypto_lab.u32le(blob, p + 4)
        code_off = crypto_lab.u32le(blob, p + 8)
        inslen = crypto_lab.u32le(blob, p + 12)
        enc = blob[p + 16:p + 16 + inslen]
        out.append((class_idx, method_idx, code_off, crypto_lab.xor(enc)))
        p += 16 + inslen
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('a', help='APK，或 已抽取的 dex 文件')
    ap.add_argument('b', help='输出 dex，或 侧表文件（当 a 为 dex 时）')
    ap.add_argument('c', nargs='?', help='输出 dex（当 a 为 dex、b 为侧表时）')
    ap.add_argument('--pristine', help='黄金对照 dex，用于 sha256 比对')
    args = ap.parse_args()

    # 形态判断
    if args.a.lower().endswith('.apk') or zipfile.is_zipfile(args.a):
        apk = args.a
        out_dex = args.b
        name, table_blob = find_table_in_apk(apk)
        if not name:
            print('[!] 没在 assets 里找到 AJMT 魔数的侧表')
            return 1
        print('[1] 在 APK 里定位侧表: %s  (%d bytes)' % (name, len(table_blob)))
        z = zipfile.ZipFile(apk)
        # 【多 dex 防护】AJMT 侧表条目里记的是 code_off（单 dex 内偏移），
        # 没有"属于哪个 dex"的字段。所以本工具只能回填主 dex。
        # 若样本是多 dex，必须【显式告警】，否则会静默产出残缺结果
        # （次级 dex 的抽取方法没被回填，却照样打印成功）。
        all_dex = sorted(n for n in z.namelist() if n.endswith('.dex'))
        extra = [n for n in all_dex if n != 'classes.dex']
        if extra:
            print('[!] 检测到多 dex：%s' % ', '.join(all_dex))
            print('    AJMT 侧表格式只有一个 code_off，无法跨 dex 定位，'
                  '本工具只能回填 classes.dex。')
            print('    以下 dex 若也含被抽取方法，将【不会被回填】，产出结果是残缺的：')
            print('      %s' % ', '.join(extra))
        dex_blob = z.read('classes.dex')
    else:
        dex_blob = open(args.a, 'rb').read()
        table_blob = open(args.b, 'rb').read()
        out_dex = args.c
        print('[1] 直接读取 dex(%d bytes) + 侧表(%d bytes)'
              % (len(dex_blob), len(table_blob)))

    print('[2] 解析侧表...')
    entries = decode_table(table_blob)
    print('    侧表条目数 = %d' % len(entries))

    dx = dexlib.Dex(dex_blob)
    print('[3] 把指令回填到 dex 的 code_item.insns 区...')
    restored = 0
    for class_idx, method_idx, code_off, insns in entries:
        ci = dx.code_item(code_off)
        if ci is None:
            print('    [跳过] code_off=0x%x 不是合法 code_item' % code_off)
            continue
        if ci['insns_size'] * 2 != len(insns):
            print('    [跳过] 长度不符 code_off=0x%x 期望 %d 实际 %d'
                  % (code_off, ci['insns_size'] * 2, len(insns)))
            continue
        dx.write_insns(code_off, insns)
        restored += 1
    print('    成功回填 %d 个方法' % restored)

    out = dx.finalize()
    print('[4] 重算 checksum/signature 完成')

    os.makedirs(os.path.dirname(os.path.abspath(out_dex)) or '.', exist_ok=True)
    open(out_dex, 'wb').write(out)
    print('[5] 已写出: %s' % out_dex)
    print('    sha256 = %s' % hashlib.sha256(out).hexdigest())

    st = dexlib.Dex(out).method_code_stats()
    print('    还原后：空方法数 = %d / %d' % (st['empty'], st['with_code']))

    if args.pristine:
        gold = open(args.pristine, 'rb').read()
        ok = hashlib.sha256(gold).hexdigest() == hashlib.sha256(out).hexdigest()
        print('[6] 与黄金 %s 对照: %s'
              % (os.path.basename(args.pristine), '完全一致 ✓' if ok else '不一致 ✗'))
        if not ok:
            return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
