#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
regression.py — 跨工程双向回归（全仓库级混淆矩阵）。

为什么需要它（PROMPT.md 负样本纪律的仓库级延伸）：
  三个 lab 各自的 check_*.py 只在自己样本域内验证自己的检测器。
  unpacker 聚合了全部检测器，因此必须验证「全检测器 × 全样本」：
    · 正向：已知壳样本必须被正确分类（防"改过头把真壳漏掉"）
    · 负向：干净样本必须落到「未见已知特征」（≠未加固）（防误报）
    · 交叉：A 工程的样本喂给 B 工程的检测器，结论方向必须一致
      （SO 管线同时跑 360/UPX 两个检测器，互为交叉验证）

用法：
  python unpacker/regression.py           # 跑全矩阵，exit 0 = 全绿
  python unpacker/regression.py --json    # 机器可读输出

样本期望表（EXPECTED）与各 lab 自己的 check_negatives.py / check_so_samples.py
的期望**保持同源**（期望前缀直接搬自各 lab），若 lab 期望变更而本表未同步，
本脚本的失败输出会明确指出"期望表与 lab 断言可能已失同步"。
"""

import argparse
import contextlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import labs  # noqa: E402
from analyzer import analyze, sniff_kind  # noqa: E402

# ------------------------------------------------------------ 期望表
# (相对仓库根路径, 期望结论方向, 期望前缀/None, 说明)
#   期望方向: 'packed'   -> is_packed 必须 True
#             'clean'    -> 结论必须是「未见已知加固特征」
#             'suspect'  -> 必须是「疑似」但不得是「已加固」（认知边界样本）
#   期望前缀: 若非 None，统一结论必须以它开头（更严）
EXPECTED = [
    # ---- 360jiagu SO 样本（期望同 360jiagu/tools/check_so_samples.py）----
    ('360jiagu/libtarget_orig.so',        'clean',   '未见已知加固特征', '原始 SO 黄金基线（负向）'),
    ('360jiagu/libtarget_360.so',         'packed', '标准 360 加固',    '标准 360（UPX! 保留）'),
    ('360jiagu/libtarget_360_variant.so', 'packed', '★ 变种 360 加固',  '变种 360（UPX!→JG!!）'),
    ('360jiagu/libtarget_stripped.so',    'suspect', '疑似 SO 加壳',    'B13 正样本：节头剥离'),
    # ---- upx_practice SO 样本（期望同 upx_practice/tools/check_so_samples.py）----
    ('upx_practice/libtarget_orig.so',        'clean',   '未见已知加固特征', '原始 SO 黄金基线（负向）'),
    ('upx_practice/libtarget_upx.so',         'packed', '标准 UPX 壳',      '标准 UPX'),
    ('upx_practice/libtarget_upx_variant.so',  'packed', '★ 变种 UPX',      '变种 UPX（魔数被抹）'),
    ('upx_practice/libtarget_stripped.so',     'suspect', '疑似 SO 加壳',     'B13 正样本：节头剥离'),
    # ---- ajiami APK 样本（期望同 ajiami/tools/check_negatives.py）----
    ('ajiami/samples/apks/app_packed_v1.apk',        'packed', '已加固：DEX 整体加密型（一代）', '一代整体加密'),
    ('ajiami/samples/apks/app_packed_v2.apk',        'packed', '已加固：类抽取型（二代及以上）', '二代类抽取'),
    ('ajiami/samples/apks/app_packed_v3.apk',        'packed', '已加固：类抽取型（二代及以上）', '三代选择性抽取'),
    ('ajiami/samples/apks/app_packed_v2_variant.apk','packed', '已加固：类抽取型（二代及以上）', '二代·字符串混淆变种'),
    ('ajiami/samples/apks/app_packed_v1_variant.apk','packed', '已加固：DEX 整体加密型（一代）', '一代·字符串混淆变种'),
    # 认知边界样本：必须被判「疑似」——判「已加固」或「未见特征」都算失败
    ('ajiami/samples/apks/app_vmp.apk',       'suspect', '疑似 DEX VMP', 'VMP 教学样本（必须判不明）'),
    ('ajiami/samples/apks/app_so_packed.apk', 'suspect', '疑似 SO 加壳', 'SO 侧加固（需 ELF 层确认）'),
    # 负样本：必须「未见已知特征」，绝不允许「已加固」
    ('ajiami/samples/apks/app_orig.apk',       'clean', '未见已知加固特征', '原始未加固 APK'),
    ('ajiami/samples/apks/neg_multidex.apk',   'clean', '未见已知加固特征', '多 dex 正常态'),
    ('ajiami/samples/apks/neg_highentropy.apk','clean', '未见已知加固特征', '高熵资源正常态'),
    ('ajiami/samples/apks/neg_native.apk',     'clean', '未见已知加固特征', '正常 native 应用'),
]

# SO 检测器交叉验证：360 样本喂 UPX 检测器、UPX 样本喂 360 检测器，
# is_packed 方向必须一致（壳种命名允许不同——360 检测器多 360 归属标记）。
CROSS_CHECKS = [
    ('360jiagu/libtarget_360.so',         'upx'),
    ('360jiagu/libtarget_360_variant.so', 'upx'),
    ('upx_practice/libtarget_upx.so',      '360'),
    ('upx_practice/libtarget_upx_variant.so', '360'),
]


def classify(res):
    """把统一结果折叠成一个类别标签（与期望方向对齐用）。

    SO 管线主结论来自检测器的 is_packed（B13 / 标准 / 变种壳都算"已检出"），
    因此 SO 正样本（含 B13）统一折叠为 packed；APK 管线按 ajiami 结论三分类。
    """
    v = (res.get('verdict') or '')
    if res.get('is_packed') is True:
        if v.startswith('疑似'):
            return 'suspect'
        return 'packed'
    if v.startswith('已加固'):
        return 'packed'
    if v.startswith('疑似'):
        return 'suspect'
    if v.startswith('未见已知加固特征'):
        return 'clean'
    if v.startswith('无法识别'):
        return 'unknown-kind'
    return 'other:' + v[:20]


def run_matrix():
    rows = []
    for rel, want_dir, want_prefix, note in EXPECTED:
        full = os.path.join(REPO_ROOT, rel)
        if not os.path.exists(full):
            rows.append({'sample': rel, 'error': '文件不存在（样本被移动或 reset 未还原？）'})
            continue
        try:
            res = analyze(full)
        except Exception as e:
            rows.append({'sample': rel, 'error': repr(e)})
            continue
        got = classify(res)
        ok = (got == want_dir)
        if ok and want_prefix:
            ok = (res.get('verdict') or '').startswith(want_prefix)
        rows.append({
            'sample': rel, 'expect': want_dir, 'expect_prefix': want_prefix,
            'got': got, 'verdict': res.get('verdict'), 'is_packed': res.get('is_packed'),
            'kind': res.get('kind'), 'note': note, 'pass': ok,
        })
    return rows


def run_cross():
    """SO 检测器交叉验证：同一文件两个检测器的 is_packed 必须一致。"""
    out = []
    for rel, _ in CROSS_CHECKS:
        full = os.path.join(REPO_ROOT, rel)
        if not os.path.exists(full):
            out.append({'sample': rel, 'error': '文件不存在'})
            continue
        res = analyze(full)
        sos = [r for r in res.get('so_results', []) if 'is_packed' in r]
        if len(sos) < 2:
            out.append({'sample': rel, 'error': 'SO 检测器结果不足 2 个'})
            continue
        agree = sos[0]['is_packed'] == sos[1]['is_packed']
        out.append({
            'sample': rel,
            'det360': sos[0].get('verdict'), 'det360_packed': sos[0]['is_packed'],
            'detupx': sos[1].get('verdict'), 'detupx_packed': sos[1]['is_packed'],
            'pass': agree,
        })
    return out


def main():
    ap = argparse.ArgumentParser(description='跨工程双向回归（全仓库混淆矩阵）')
    ap.add_argument('--json', action='store_true', help='机器可读输出')
    args = ap.parse_args()

    rows = run_matrix()
    cross = run_cross()
    fails = [r for r in rows if not r.get('pass', False)]
    cross_fails = [r for r in cross if not r.get('pass', False)]

    if args.json:
        print(json.dumps({'matrix': rows, 'cross': cross,
                          'pass': len(rows) - len(fails), 'fail': len(fails)},
                         ensure_ascii=False, indent=2))
        return 1 if (fails or cross_fails) else 0

    # 人类可读输出
    print('=' * 78)
    print('跨工程双向回归 · 样本×检测器混淆矩阵（正向防漏报 / 负向防误报 / 交叉防分歧）')
    print('=' * 78)
    for r in rows:
        if r.get('error'):
            print('  [FAIL] %-52s %s' % (r['sample'], r['error']))
            continue
        mark = 'PASS ' if r['pass'] else 'FAIL '
        print('  [%s] %-52s 期望=%s 实得=%s' % (mark, r['sample'], r['expect'], r['got']))
        if not r['pass']:
            print('         期望前缀: %s' % r['expect_prefix'])
            print('         实得结论: %s' % r['verdict'])
            print('         说明: %s' % r['note'])
    print('-' * 78)
    print('SO 检测器交叉验证（360 ↔ UPX，is_packed 方向必须一致，壳种命名可不同）:')
    for r in cross:
        if r.get('error'):
            print('  [FAIL] %-52s %s' % (r['sample'], r['error']))
            continue
        mark = 'PASS ' if r['pass'] else 'FAIL '
        print('  [%s] %-52s 360=%s | UPX=%s' % (
            mark, r['sample'],
            ('加壳' if r['det360_packed'] else '未检出') + '(' + (r['det360'] or '')[:14] + ')',
            ('加壳' if r['detupx_packed'] else '未检出') + '(' + (r['detupx'] or '')[:14] + ')'))
    print('-' * 78)
    total = len(rows)
    print('结果: %d/%d 通过, 交叉 %d/%d 通过' % (
        total - len(fails), total, len(cross) - len(cross_fails), len(cross)))
    if fails or cross_fails:
        print('[!] 存在失败项——若因 lab 断言更新导致，请同步本脚本的 EXPECTED 表。')
        return 1
    print('[+] 全部通过。')
    return 0


if __name__ == '__main__':
    sys.exit(main())
