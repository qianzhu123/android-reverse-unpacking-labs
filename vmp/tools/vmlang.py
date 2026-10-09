#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
vmlang.py — 本 lab 的「表达式虚拟机」语言内核（纯 Python，零依赖）。

它同时扮演三个角色，保证「受保护样本」与「黄金样本」语义等价是**结构性**的，
而不是靠肉眼比对：

  1. 汇编器   assemble(tokens, opmap)   —— 规范操作流 -> 自定义字节码
  2. 反汇编   disassemble(code, opmap)  —— 字节码 -> 规范操作流（去虚拟化的目标产物）
  3. 参考解释器 interpret(tokens, args) —— 规范操作流 -> 结果（黄金语义）

「规范操作流」（tokens）是本 lab 的中立货币：
  · 黄金 Java 源码由它生成；
  · 各难度样本的自定义字节码由它 assemble；
  · 去虚拟化工具的目标产物就是把它**逐字节还原**；
  · payloads/golden_ops.json 保存它，供 verify_gen.py 做语义 oracle。

指令集（栈式）：
  ('LOADARG', k)  取第 k 个参数入栈        ('PUSH', v) 压入立即数 v
  ('XOR',) ('ADD',) ('MUL',) ('SUB',)     二元运算（弹 2 压 1），注意操作数顺序 a op b
  ('RET',)        返回栈顶
  —— 超算子（L4 用，语义上等价于两条基础指令）：
  ('ADDK', v)     = PUSH v; ADD             ('MULK', v) = PUSH v; MUL
  ('XORK', v)     = PUSH v; XOR             ('ADDMUL', k, v) = PUSH v; MUL; ADD
"""

# ---- 基础指令 -> 用于黄金源码 / 参考解释器 ----
BASE_OPS = ['LOADARG', 'PUSH', 'XOR', 'ADD', 'MUL', 'SUB', 'RET']
# 超算子（L4）：一个 handler 完成多条逻辑指令
SUPER_OPS = ['ADDK', 'MULK', 'XORK', 'ADDMUL']

# 各指令的立即数个数（超算子可能带 2 个）
N_IMM = {'LOADARG': 1, 'PUSH': 1, 'XOR': 0, 'ADD': 0, 'MUL': 0, 'SUB': 0, 'RET': 0,
         'ADDK': 1, 'MULK': 1, 'XORK': 1, 'ADDMUL': 2}


# ------------------------------------------------------------------ 参考解释器
def interpret(tokens, args, wrap32=True):
    """参考语义：把规范操作流跑一遍，返回整数结果。黄金答案由它给出。"""
    st = []
    for t in tokens:
        op = t[0]
        if op == 'LOADARG':
            st.append(int(args[t[1]]))
        elif op == 'PUSH':
            st.append(int(t[1]))
        elif op == 'XOR':
            b = st.pop(); a = st.pop(); st.append(a ^ b)
        elif op == 'ADD':
            b = st.pop(); a = st.pop(); st.append(a + b)
        elif op == 'MUL':
            b = st.pop(); a = st.pop(); st.append(a * b)
        elif op == 'SUB':
            b = st.pop(); a = st.pop(); st.append(a - b)
        elif op == 'RET':
            v = st.pop()
            return _w32(v) if wrap32 else v
        # ---- 超算子：等价展开 ----
        elif op == 'ADDK':
            st.append(st.pop() + int(t[1]))
        elif op == 'MULK':
            st.append(st.pop() * int(t[1]))
        elif op == 'XORK':
            st.append(st.pop() ^ int(t[1]))
        elif op == 'ADDMUL':   # push v; mul; add  == (a * v) + b
            v = int(t[2]); b = st.pop(); a = st.pop(); st.append((a * v) + b)
        else:
            raise ValueError('未知指令 %r' % (t,))
    raise ValueError('程序缺少 RET')


def _w32(v):
    v &= 0xFFFFFFFF
    if v >= 0x80000000:
        v -= 0x100000000
    return v


def expand(tokens):
    """把超算子展开成基础指令（便于黄金 Java 生成与人工阅读）。"""
    out = []
    for t in tokens:
        op = t[0]
        if op == 'ADDK':
            out += [('PUSH', t[1]), ('ADD',)]
        elif op == 'MULK':
            out += [('PUSH', t[1]), ('MUL',)]
        elif op == 'XORK':
            out += [('PUSH', t[1]), ('XOR',)]
        elif op == 'ADDMUL':
            out += [('PUSH', t[2]), ('MUL',), ('PUSH', t[1]), ('ADD',)]
        else:
            out.append(t)
    return out


# ------------------------------------------------------------------ 字节码层
def assemble(tokens, opmap, imm_width=1):
    """规范操作流 -> 自定义字节码。opmap: {op名: 字节值}。立即数按 imm_width 字节小端。"""
    out = bytearray()
    for t in tokens:
        op = t[0]
        if op not in opmap:
            raise ValueError('opmap 缺少指令 %s' % op)
        out.append(opmap[op] & 0xFF)
        for k in range(1, len(t)):
            v = int(t[k]) & ((1 << (8 * imm_width)) - 1)
            for i in range(imm_width):
                out.append((v >> (8 * i)) & 0xFF)
    return bytes(out)


def disassemble(code, opmap, imm_width=1):
    """字节码 -> 规范操作流。opmap 反向查找；未知字节报错（正是去虚拟化要解决的）。"""
    inv = {}
    for name, b in opmap.items():
        inv[b & 0xFF] = name
    toks = []
    i = 0
    while i < len(code):
        b = code[i]; i += 1
        if b not in inv:
            raise ValueError('未知 opcode 0x%02X @0x%X' % (b, i - 1))
        name = inv[b]
        n = N_IMM[name]
        imms = []
        for _ in range(n):
            v = 0
            for k in range(imm_width):
                v |= (code[i + k] & 0xFF) << (8 * k)
            i += imm_width
            imms.append(v)
        toks.append(tuple([name] + imms))
    return toks


def make_opmap(seed=0, shuffle=True, superops=False):
    """构造 opmap。

    L1/L2/L3：固定小 opcode（0x01.. 连续），便于教学对照；
    L4：seed 决定随机值，且 case 值不构成 0..N 连续小集合（对应判据 V6）。
    """
    import random
    names = list(BASE_OPS) + (list(SUPER_OPS) if superops else [])
    if not shuffle:
        return {n: i + 1 for i, n in enumerate(names)}      # 0x01, 0x02, ...
    rng = random.Random(seed)
    # 在 0x10..0xEF 里取互不相同的随机值，刻意避开 0x00..0x0F 连续区间
    pool = list(range(0x10, 0xF0))
    rng.shuffle(pool)
    return {n: pool[i] for i, n in enumerate(names)}


def opmap_inverse(opmap):
    return {v & 0xFF: k for k, v in opmap.items()}


# ------------------------------------------------------------------ 黄金程序
# 三个业务函数；输入 -> 输出由 interpret 唯一确定，黄金 Java 与所有样本共用。
def program_mix():
    """((a ^ b) + 0x11) * 3"""
    return [('LOADARG', 0), ('LOADARG', 1), ('XOR',),
            ('PUSH', 0x11), ('ADD',), ('PUSH', 3), ('MUL',), ('RET',)]


def program_twist():
    """(a * 7) - 5"""
    return [('LOADARG', 0), ('PUSH', 7), ('MUL',), ('PUSH', 5), ('SUB',), ('RET',)]


def program_digest():
    """((a * b) ^ (a + b)) + 0x5A"""
    return [('LOADARG', 0), ('LOADARG', 1), ('MUL',),
            ('LOADARG', 0), ('LOADARG', 1), ('ADD',), ('XOR',),
            ('PUSH', 0x5A), ('ADD',), ('RET',)]


def program_mix_super():
    """((a ^ b) + 0x11) * 3，用超算子表达：XOR;ADDK 0x11;MULK 3"""
    return [('LOADARG', 0), ('LOADARG', 1), ('XOR',),
            ('ADDK', 0x11), ('MULK', 3), ('RET',)]


PROGRAMS = {
    'mix': program_mix,
    'twist': program_twist,
    'digest': program_digest,
}

# 测试向量：固定输入 -> 结果（黄金基线；设备上的 oracle 也用它）
VECTORS = {
    'mix':    [(7, 3), (0, 0), (-1, 5)],
    'twist':  [(7,), (0,), (-9,)],
    'digest': [(7, 3), (1, 1), (12, 5)],
}


if __name__ == '__main__':
    for name, fn in PROGRAMS.items():
        toks = fn()
        outs = [interpret(toks, a) for a in VECTORS[name]]
        print('%-8s %s' % (name, ' '.join('%s->%d' % (a, r) for a, r in zip(VECTORS[name], outs))))
    # 自检：超算子展开后语义必须一致
    assert interpret(program_mix_super(), (7, 3)) == interpret(program_mix(), (7, 3))
    assert interpret(expand(program_mix_super()), (7, 3)) == interpret(program_mix(), (7, 3))
    print('super-op expand semantics OK')
