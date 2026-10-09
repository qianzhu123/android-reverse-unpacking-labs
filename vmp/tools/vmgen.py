#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
vmgen.py — 「规范 -> 黄金源码 / 字节码 / 黄金答案」的生成器。

设计要点：全 lab 只有一份「表达式规范」（见 vmlang.PROGRAMS）。本脚本从它派生出：

  · src/com/demo/calc/GoldenLogic.java   黄金 Java（明文表达式，无虚拟机）
  · samples/payloads/golden_ops.json     规范操作流 + 测试向量 + 黄金答案
                                          （verify_gen.py 的语义 oracle 依据）
  · 各难度样本用到的字节码               由 build_levels.py 调用本模块的函数产出

于是「受保护样本」与「黄金样本」语义等价是**结构性**保证，不靠肉眼比对。

用法：
    python tools/vmgen.py emit      # 生成 golden Java + golden_ops.json
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vmlang

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GEN = os.path.join(ROOT, 'build', 'gen')
GOLDEN_JAVA = os.path.join(ROOT, 'src', 'com', 'demo', 'calc', 'CalcLogic.java')
PAYLOADS = os.path.join(ROOT, 'samples', 'payloads')

# 方法名 -> (参数名列表, 规范程序函数)
METHODS = [
    ('mix',    ['a', 'b'], vmlang.program_mix),
    ('twist',  ['a'],      vmlang.program_twist),
    ('digest', ['a', 'b'], vmlang.program_digest),
]


# ------------------------------------------------------------------ 规范 -> Java 表达式
def tokens_to_expr(tokens, argnames):
    """把规范操作流编译成一个 Java 表达式（黄金语义的可读形态）。"""
    st = []
    for t in tokens:
        op = t[0]
        if op == 'LOADARG':
            st.append(argnames[t[1]])
        elif op == 'PUSH':
            st.append(str(t[1]))
        elif op == 'XOR':
            b = st.pop(); a = st.pop(); st.append('(%s ^ %s)' % (a, b))
        elif op == 'ADD':
            b = st.pop(); a = st.pop(); st.append('(%s + %s)' % (a, b))
        elif op == 'MUL':
            b = st.pop(); a = st.pop(); st.append('(%s * %s)' % (a, b))
        elif op == 'SUB':
            b = st.pop(); a = st.pop(); st.append('(%s - %s)' % (a, b))
        elif op == 'ADDK':
            a = st.pop(); st.append('(%s + %s)' % (a, t[1]))
        elif op == 'MULK':
            a = st.pop(); st.append('(%s * %s)' % (a, t[1]))
        elif op == 'XORK':
            a = st.pop(); st.append('(%s ^ %s)' % (a, t[1]))
        elif op == 'ADDMUL':
            a = st.pop(); st.append('((%s * %s) + %s)' % (a, t[2], t[1]))
        elif op == 'RET':
            return st.pop()
        else:
            raise ValueError('未知指令 %r' % (t,))
    raise ValueError('程序缺少 RET')


def golden_java():
    lines = [
        'package com.demo.calc;',
        '',
        '/**',
        ' * CalcLogic —— 黄金业务逻辑（**明文**，没有任何虚拟机）。',
        ' *',
        ' * 由 tools/vmgen.py 从「表达式规范」（tools/vmlang.py 的 PROGRAMS）生成，',
        ' * 与各难度受保护样本是同一份语义：同一组测试向量必须得到同一组结果。',
        ' *',
        ' * 锚点串 ANCHOR-* 用于确认「还原出来的确实是这段业务」。',
        ' *',
        ' * 不要手改本文件：改 tools/vmlang.py 的 PROGRAMS 后重新跑',
        ' *     python tools/vmgen.py emit',
        ' */',
        'public final class CalcLogic {',
        '',
    ]
    for name, args, fn in METHODS:
        params = ', '.join('int %s' % a for a in args)
        expr = tokens_to_expr(fn(), args)
        lines += [
            '    /** %s —— %s */' % (name, _doc_for(name)),
            '    public static int %s(%s) {' % (name, params),
            '        return %s;' % expr,
            '    }',
            '',
        ]
    lines += [
        '    /** 分析锚点（golden 与各样本共用）；刻意不含 "vmp"/产品名等可见特征串 */',
        '    public static String anchor1() { return "ANCHOR-0001:LOGIC-MIX"; }',
        '    public static String anchor2() { return "ANCHOR-0002:LOGIC-DIGEST"; }',
        '',
        '    private CalcLogic() { }',
        '}',
        '',
    ]
    return '\n'.join(lines)


def _doc_for(name):
    return {'mix': '((a ^ b) + 0x11) * 3',
            'twist': '(a * 7) - 5',
            'digest': '((a * b) ^ (a + b)) + 0x5A'}[name]


# ------------------------------------------------------------------ 黄金答案 / json
def golden_ops():
    """规范操作流 + 测试向量 + 黄金答案（语义 oracle 的基准）。"""
    data = {'note': 'canonical op stream + vectors + golden results; 由 tools/vmgen.py 生成',
            'methods': {}}
    for name, args, fn in METHODS:
        toks = [list(t) for t in fn()]
        vec = vmlang.VECTORS[name]
        results = [vmlang.interpret(fn(), a) for a in vec]
        data['methods'][name] = {
            'args': len(args),
            'ops': toks,
            'vectors': [list(a) for a in vec],
            'results': results,
        }
    return data


def emit():
    os.makedirs(os.path.dirname(GOLDEN_JAVA), exist_ok=True)
    os.makedirs(PAYLOADS, exist_ok=True)
    with open(GOLDEN_JAVA, 'w', encoding='utf-8', newline='\n') as f:
        f.write(golden_java())
    data = golden_ops()
    with open(os.path.join(PAYLOADS, 'golden_ops.json'), 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write('\n')
    print('[emit] %s' % os.path.relpath(GOLDEN_JAVA, ROOT).replace('\\', '/'))
    print('[emit] samples/payloads/golden_ops.json')
    for name, m in data['methods'].items():
        print('  %-8s %d ops  vectors=%s  results=%s'
              % (name, len(m['ops']), m['vectors'], m['results']))


# ------------------------------------------------------------------ 各难度字节码
# 各难度的 opmap 种子（确定性；写进文档，便于复现）
SEEDS = {'L1': 0, 'L2': 0, 'L3': 0, 'L4': 0x51A7, 'L5': 0}


def level_opmap(level):
    """按难度返回 opmap。L1..L3 用固定小 opcode；L4 用 seed 随机值（不连续）。"""
    if level == 'L4':
        return vmlang.make_opmap(seed=SEEDS['L4'], shuffle=True, superops=True)
    return vmlang.make_opmap(seed=0, shuffle=False, superops=False)


def level_tokens(level):
    """按难度返回各方法的规范操作流（L4 用超算子版本）。"""
    if level == 'L4':
        return {'mix': vmlang.program_mix_super(),
                'twist': vmlang.program_twist(),
                'digest': vmlang.program_digest()}
    return {n: fn() for n, _a, fn in METHODS}


def level_bytecode(level):
    """返回 {方法名: 自定义字节码 bytes}。imm_width 对 L4 超算子用 1（立即数 <=0xFF）。"""
    opmap = level_opmap(level)
    toks = level_tokens(level)
    return {name: vmlang.assemble(t, opmap) for name, t in toks.items()}


def main():
    ap = argparse.ArgumentParser(description='规范 -> 黄金源码 / 字节码 / 黄金答案')
    ap.add_argument('cmd', choices=['emit'])
    a = ap.parse_args()
    if a.cmd == 'emit':
        emit()
        return 0
    return 1


if __name__ == '__main__':
    sys.exit(main())
