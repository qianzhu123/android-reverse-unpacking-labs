#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
verify_gen.py — 语义 oracle（不需要设备）：证明「样本 == 黄金逻辑」。

本 lab 的等价性不靠肉眼比对，而靠一条**可复算的链**：

    规范(vmlang.PROGRAMS)
        ├── 黄金 Java 源码 (src/com/demo/calc/CalcLogic.java)
        ├── 各层自定义字节码   (samples/payloads/level_*.bin / 源码内常量数组)
        └── golden_ops.json    (规范操作流 + 测试向量 + 黄金结果)

verify_gen.py 逐个复算：

  1. 读 golden_ops.json，用 vmlang.interpret 重跑规范操作流 -> 必须等于记录的 results；
  2. 对每层载荷：解密（L2）-> 按该层 opmap 反汇编 -> interpret -> 必须等于同一组 results；
  3. 对 L3（无 switch）用它的 opmap 反汇编同样的字节码，验证「恢复出的 handler 语义」
     与基础指令表一致；
  4. 打印每一层的 opcode 与操作流，供文档引用。

任何一项不符 -> 非零退出。

用法：python tools/verify_gen.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vmlang
import vmgen
import build_so_levels

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAYLOADS = os.path.join(ROOT, 'samples', 'payloads')
DEX_LEVELS = ['L1', 'L2', 'L3', 'L4', 'L5']
SO_LEVELS = ['S1', 'S2', 'S3']


def _load_gold():
    with open(os.path.join(PAYLOADS, 'golden_ops.json'), encoding='utf-8') as f:
        return json.load(f)


def _l2_plain():
    """L2 的明文载荷（[lens]+三段字节码）。密钥从生成的 Core.java 里读，避免重复。"""
    import re
    core = os.path.join(ROOT, 'build', 'gen', 'level_L2', 'com', 'demo', 'calc', 'Core.java')
    src = open(core, encoding='utf-8').read()
    key = bytes((int(x) & 0xFF) for x in re.search(r'KEY = \{([^}]*)\}', src).group(1).split(','))
    enc = open(os.path.join(PAYLOADS, 'level_L2.bin'), 'rb').read()
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(enc))


def _split(plain):
    lens = list(plain[:3])
    off = 3
    segs = {}
    for name, n in zip(['mix', 'twist', 'digest'], lens):
        segs[name] = plain[off:off + n]
        off += n
    return segs


def check_golden(gold):
    ok = True
    for name, m in gold['methods'].items():
        toks = [tuple(t) for t in m['ops']]
        for a, exp in zip(m['vectors'], m['results']):
            got = vmlang.interpret(toks, a)
            mark = 'OK' if got == exp else 'FAIL'
            if got != exp:
                ok = False
            print('  %-7s %-14s expect=%-5s got=%-5s  %s'
                  % (name, 'args=%s' % (a,), exp, got, mark))
    return ok


def check_dex_level(level, gold):
    """反汇编该层字节码 -> interpret -> 与黄金结果比对。"""
    names = ['mix', 'twist', 'digest']
    opmap = vmgen.level_opmap(level)
    if level == 'L2':
        segs = _split(_l2_plain())
    else:
        plain = open(os.path.join(PAYLOADS, 'level_%s.bin' % level), 'rb').read()
        segs = _split(plain)
    ok = True
    for name in names:
        toks = vmlang.disassemble(segs[name], opmap)
        m = gold['methods'][name]
        for a, exp in zip(m['vectors'], m['results']):
            got = vmlang.interpret(toks, a)
            if got != exp:
                ok = False
                print('    %s FAIL args=%s expect=%s got=%s' % (name, a, exp, got))
    return ok


def check_so_level(level, gold):
    """SO 层用 SO_OPMAP 反汇编同一段字节码（字节码来自同一规范）。"""
    bc = build_so_levels.so_bytecode()
    ok = True
    for name in ['mix', 'twist', 'digest']:
        toks = vmlang.disassemble(bc[name], build_so_levels.SO_OPMAP)
        m = gold['methods'][name]
        for a, exp in zip(m['vectors'], m['results']):
            got = vmlang.interpret(toks, a)
            if got != exp:
                ok = False
                print('    %s FAIL args=%s expect=%s got=%s' % (name, a, exp, got))
    return ok


def main():
    gold = _load_gold()
    print('== 1. 黄金规范复算 ==')
    ok = check_golden(gold)

    print('\n== 2. DEX 层字节码 -> 反汇编 -> 语义 ==')
    for lv in DEX_LEVELS:
        r = check_dex_level(lv, gold)
        ok = ok and r
        print('  %-3s %s' % (lv, 'OK' if r else 'FAIL'))

    print('\n== 3. SO 层字节码 -> 反汇编 -> 语义 ==')
    for lv in SO_LEVELS:
        r = check_so_level(lv, gold)
        ok = ok and r
        print('  %-3s %s' % (lv, 'OK' if r else 'FAIL'))

    print('\n=> %s' % ('ALL OK' if ok else 'FAILURES PRESENT'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
