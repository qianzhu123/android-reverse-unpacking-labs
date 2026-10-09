#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
nop_methods.py — 把某个类的方法体**抽空成 nop**（旧式「函数抽取」保护形态）。

这与 VMP 是两回事：抽取只是把 dalvik 指令原样搬走（方法体变成 nop），
指令**仍是合法 dalvik、只是被搬到了别处**；VMP 是把指令换成对解释器的调用。
本 lab 用它造 neg_extract 负样本 —— 检验判定不会把「方法体异常」当成 VMP。

用法：
    python tools/nop_methods.py <in.dex> [out.dex] [--class Lcom/demo/calc/CalcLogic;]

不带 out.dex 时就地改写。改完重算 checksum/signature（dexlib.finalize）。
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dexlib


def nop_class(dx, class_name, keep_init=True):
    hit = 0
    seen = set()
    for cname, kind, m in dx.iter_methods():
        if cname != class_name:
            continue
        if keep_init and (m['access_flags'] & 0x10000):   # ACC_CONSTRUCTOR
            continue
        if m['code_off'] == 0 or m['code_off'] in seen:
            continue
        seen.add(m['code_off'])
        ci = dx.code_item(m['code_off'])
        dx.write_insns(m['code_off'], b'\x00' * ci['insns_bytes'])
        hit += 1
    return hit


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('dex')
    ap.add_argument('out', nargs='?')
    ap.add_argument('--class', dest='klass', default='Lcom/demo/calc/CalcLogic;')
    ap.add_argument('--all-classes', action='store_true')
    a = ap.parse_args()

    dx = dexlib.load(a.dex)
    if a.all_classes:
        total = 0
        for cd in dx.class_defs():
            total += nop_class(dx, dx.class_name(cd))
        n = total
    else:
        n = nop_class(dx, a.klass)
    out = a.out or a.dex
    with open(out, 'wb') as f:
        f.write(dx.finalize())
    print('[nop] %d methods emptied -> %s' % (n, out))
    return 0


if __name__ == '__main__':
    sys.exit(main())
