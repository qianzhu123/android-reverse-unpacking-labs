#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
verify.py — 脱壳还原的量化验证（不只看"能不能解开"）。

验证三件事：
  1) sha256：还原 dex 与黄金样本是否逐字节一致
  2) 锚点：原始样本里的 AJM-ANCHOR-xxxx 字符串是否都还在（缺失=没真解开）
  3) 字节差异：若不一致，给出差异字节数 + 首个差异偏移（帮助定位还原错了哪里）

用法：
  python tools/verify.py analysis_output/unpack_v1_dex.dex samples/classes_orig.dex
  python tools/verify.py analysis_output/unpack_v2_dex.dex samples/classes_merged_orig.dex
  python tools/verify.py analysis_output/unpack_v2_variant_dex.dex build/variant/merged_orig_variant.dex
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dexlib

ANCHOR_PREFIX = 'AJM-ANCHOR-'


def sha(b):
    return hashlib.sha256(b).hexdigest()


def find_anchors(dex_blob):
    dx = dexlib.Dex(dex_blob)
    return [s for _, s in dx.all_strings() if s.startswith(ANCHOR_PREFIX)]


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    a = sys.argv[1]
    gold_path = sys.argv[2]
    restored = open(a, 'rb').read()
    gold = open(gold_path, 'rb').read()

    print('还原：%s' % a)
    print('黄金：%s' % gold_path)

    # 1) sha256
    same = sha(restored) == sha(gold)
    print('[1] sha256: %s' % ('一致 ✓' if same else '不一致 ✗'))
    print('    还原  %s' % sha(restored))
    print('    黄金  %s' % sha(gold))

    # 2) 锚点
    ra = find_anchors(restored)
    ga = find_anchors(gold)
    print('[2] 锚点字符串: 还原 %d 个 / 黄金 %d 个' % (len(ra), len(ga)))
    missing = [s for s in ga if s not in ra]
    if missing:
        print('    缺失锚点: %s' % missing)
    else:
        print('    全部锚点都在 ✓')

    # 3) 字节差异
    if not same:
        n = min(len(restored), len(gold))
        diff = sum(1 for i in range(n) if restored[i] != gold[i])
        if len(restored) != len(gold):
            diff += abs(len(restored) - len(gold))
        first = None
        for i in range(n):
            if restored[i] != gold[i]:
                first = i
                break
        print('[3] 差异字节数 = %d，首个差异偏移 = 0x%x' % (diff, first or 0))
    else:
        print('[3] 无差异 ✓')

    ok = same and not missing
    print('\n=> 结论：%s' % ('还原成功，与黄金样本完全一致' if ok else '还原有问题，见上'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
