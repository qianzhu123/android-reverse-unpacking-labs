#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
check_negatives.py — 正负样本回归断言

为什么必须有它（见 SCRIPT.md §3.8 / MANUAL.md §3.8 负样本回归）：
    本项目所有样本都是自己合成的，只拿它们做"能检出"的验证属于循环论证。
    负样本的作用是**证伪** —— 它们是专门为触发历史误报而设计的陷阱；
    而本脚本让防止回归变成**自动化**，而不依赖"我还记着"。

双向断言：
    正向  —— 真样本必须被判成对应的代次/VMP（防止改过头把真壳漏掉）
    负向  —— 干净样本绝不允许被判成『已加固』，也不允许命中特定误报判据
             （防止把多 dex / 高熵资源 / 相对类名等正常形态误判成壳）

用法：
    python tools/check_negatives.py
退出码：全部通过 0，任一失败 1
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import detect

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 正向样本：期望结论（写前缀即可，用 startswith 匹配）
POSITIVE = [
    ('samples/apks/app_packed_v1.apk', '已加固：DEX 整体加密型（一代）'),
    ('samples/apks/app_packed_v2.apk', '已加固：类抽取型（二代及以上）'),
    ('samples/apks/app_packed_v3.apk', '已加固：类抽取型（二代及以上）'),
    ('samples/apks/app_packed_v2_variant.apk', '已加固：类抽取型（二代及以上）'),
    ('samples/apks/app_vmp.apk', '疑似 DEX VMP'),
    ('samples/apks/app_so_packed.apk', '疑似 SO 加壳'),
]

# 负向样本：绝不允许被判成『已加固』；并明确禁止哪些判据命中
NEGATIVE = [
    ('samples/apks/neg_multidex.apk', ['B6', 'B7', 'B11', 'B12'],
     '多 dex：manifest 声明的组件类在 classes2.dex'),
    ('samples/apks/neg_highentropy.apk', ['B6', 'B7', 'B11', 'B12'],
     '多 dex + 合法高熵 asset（守住 B1 不得单独定性）'),
    ('samples/apks/app_orig.apk', ['B6', 'B7', 'B11', 'B12'],
     '原始未加固 APK（历史负样本）'),
    ('samples/apks/neg_native.apk', ['B6', 'B7', 'B8', 'B11', 'B12', 'B13'],
     '正常 native 应用：含合法 NDK .so，不得因 SO/动态加载判壳（锁 B13/B12 干净路径）'),
]


def run(path):
    f = detect.apk_features(path)
    concl, rules, _naive, _hints, _notes = detect.verdict(f)
    return concl, [r.split(' ')[0] for r in rules]


def main():
    fails = 0
    print('=' * 70)
    print('正向样本：必须检出（防止过度修正把真壳漏掉）')
    print('=' * 70)
    for rel, expect in POSITIVE:
        p = os.path.join(ROOT, rel.replace('/', os.sep))
        if not os.path.exists(p):
            print('  [MISS] %s  文件不存在' % rel)
            fails += 1
            continue
        concl, codes = run(p)
        ok = concl.startswith(expect)
        fails += 0 if ok else 1
        print('  [%s] %-34s -> %s' % ('OK  ' if ok else 'FAIL', rel, concl))
        if not ok:
            print('        期望前缀：%s    实得规则：%s' % (expect, codes))

    print()
    print('=' * 70)
    print('负向样本：绝不允许被判成"已加固"（防止把正常 App 误判成壳）')
    print('=' * 70)
    for rel, forbid, why in NEGATIVE:
        p = os.path.join(ROOT, rel.replace('/', os.sep))
        if not os.path.exists(p):
            print('  [MISS] %s  文件不存在' % rel)
            fails += 1
            continue
        concl, codes = run(p)
        bad_codes = [c for c in codes if any(c.startswith(x) for x in forbid)]
        hard_claim = concl.startswith('已加固')
        ok = not hard_claim and not bad_codes
        fails += 0 if ok else 1
        print('  [%s] %-32s -> %s' % ('OK  ' if ok else 'FAIL', rel, concl))
        print('        陷阱：%s' % why)
        if bad_codes:
            print('        !! 误命中的判据：%s' % bad_codes)
        if hard_claim:
            print('        !! 被判成"已加固" —— 负样本不应出现此结论')

    print()
    print('=' * 70)
    if fails:
        print('结果：%d 项失败 —— 判定逻辑回归了，请修完再跑一遍' % fails)
        return 1
    print('结果：全部通过（正向 %d 项 / 负向 %d 项）' % (len(POSITIVE), len(NEGATIVE)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
