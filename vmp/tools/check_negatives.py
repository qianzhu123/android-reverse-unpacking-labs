#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
check_negatives.py — 双向回归断言（**必须两个方向都过**，单边通过一律判失败）。

为什么要双向：
  · 只测正向 -> 判据可能宽到把正常程序也判成 VMP（误报）；
  · 只测负向 -> 判据可能窄到把真样本漏掉（漏报）。
  自建样本工程天生有「样本 = 规格 = 测试集」的循环论证风险，双向断言是解药。

正向（positive）：每个 VMP 样本**必须**被判为 virtual machine，并命中其代号。
负向（negative）：每个负样本**必须不**被判为 VM。其中 neg_bigswitch 允许出现
「解释器状形状」的提示，但**结论不得**是 VM。

判定文本来自 detect_vm.py 的 verdict，判据代号来自它的 codes 列表。

用法：
    python tools/check_negatives.py            # 两个方向都跑
    python tools/check_negatives.py --json
失败时非零退出、红色打印。
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import detect_vm

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APKS = os.path.join(ROOT, 'samples', 'apks')
NATIVE = os.path.join(ROOT, 'samples', 'native')

# 正向：样本 -> 必须出现的判据代号（全都必须命中）
POSITIVE = {
    'app_l1.apk': ['V1', 'V4'],
    'app_l2.apk': ['V1', 'V4', 'V3'],
    'app_l3.apk': ['V1'],
    'app_l4.apk': ['V1', 'V4', 'V6'],
    'app_l5.apk': ['V4', 'V5'],
}
# 正向 SO：文件 -> 必须命中的代号
POSITIVE_SO = {
    'libcalc_s1_arm64.so': ['VN1'],
    'libcalc_s2_arm64.so': ['VN1', 'VN2'],
    'libcalc_s3_arm64.so': ['VN1', 'VN2'],
}
# 负向：必须 NOT 判 VM
NEGATIVE = ['neg_plain.apk', 'neg_bigswitch.apk', 'neg_hub.apk', 'neg_extract.apk']
# 基线：必须「未见特征」
BASELINE = ['app_golden.apk']

VM_MARK = 'virtual machine'


def _apk_verdict(name):
    f = detect_vm.apk_features(os.path.join(APKS, name))
    return f['verdict'], f['codes']


def _so_verdict(name):
    f = detect_vm.so_features(os.path.join(NATIVE, name))
    return f['verdict'], f['codes']


def run(json_out=False):
    results = []

    def rec(kind, name, ok, detail):
        results.append({'kind': kind, 'name': name, 'ok': ok, 'detail': detail})
        if not json_out:
            flag = '\033[32m PASS \033[0m' if ok else '\033[31m FAIL \033[0m'
            print('[%s] %-12s %-26s %s' % (flag, kind, name, detail))

    print('== 正向：DEX VMP 样本必须判为 VM，且命中代号 ==')
    for name, want in POSITIVE.items():
        v, codes = _apk_verdict(name)
        miss = [c for c in want if c not in codes]
        ok = (VM_MARK in v) and not miss
        rec('positive', name, ok, 'codes=%s verdict=%r%s'
            % (','.join(codes) or '-', v, '' if not miss else ' MISSING=%s' % miss))

    print('\n== 正向：SO/ARM64 VMP 样本 ==')
    for name, want in POSITIVE_SO.items():
        v, codes = _so_verdict(name)
        miss = [c for c in want if c not in codes]
        ok = (VM_MARK in v or 'VM' in v) and not miss
        rec('positive', name, ok, 'codes=%s verdict=%r%s'
            % (','.join(codes) or '-', v, '' if not miss else ' MISSING=%s' % miss))

    print('\n== 负向：干净/非 VM 样本必须 NOT 判为 VM ==')
    for name in NEGATIVE:
        v, codes = _apk_verdict(name)
        ok = VM_MARK not in v
        rec('negative', name, ok, 'verdict=%r' % v)

    print('\n== 基线：黄金样本必须「未见已知特征」 ==')
    for name in BASELINE:
        v, codes = _apk_verdict(name)
        ok = 'no known hardening signature' in v
        rec('baseline', name, ok, 'verdict=%r' % v)

    passed = sum(1 for r in results if r['ok'])
    total = len(results)
    if json_out:
        print(json.dumps({'passed': passed, 'total': total, 'results': results},
                         indent=2, ensure_ascii=False))
    print('\n=> %d/%d %s' % (passed, total, 'ALL PASS' if passed == total else 'FAILURES'))
    return 0 if passed == total else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args()
    return run(a.json)


if __name__ == '__main__':
    sys.exit(main())
