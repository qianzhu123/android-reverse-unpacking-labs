#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
devirt_so.py — SO/ARM64 层**静态分析**：定位 native 解释器、判读分派形态、抽取内嵌的
自定义字节码，并在可能时还原 opcode→handler 的语义。

静态可做（本工具会做）：
  1. 用 llvm-objdump 反汇编，找出「指令最多的函数」= 解释器；
  2. 判读它的分派形态：中心 switch（比较级联）/ 间接调用（运行期装配）/ threaded；
  3. 从 .rodata / .data 抽出候选自定义字节码（短小的非文本数据段）；
  4. S1（中心比较级联）：符号化模拟比较树分派，对每个 case 体的**数据运算**做指纹，
     还原 opcode→语义。

静态做不了的（**诚实边界**，工具会明说并指向动态）：
  · S2：handler 表在运行期装配、opcode→槽位是算出来的 —— 静态没有稳定 case 边界；
  · S3：threaded 分派，处理器之间直接跳 —— 没有中心函数可切。
  这两档必须动态 trace（frida/trace_dispatch.js / so_vm_trace.js）。

用法：
    python tools/devirt_so.py samples/native/libcalc_s1_arm64.so
    python tools/devirt_so.py samples/native/libcalc_s2_arm64.so --json
"""

import argparse
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import elfinspect
import detect_vm

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------- objdump 封装
def _objdump(path):
    exe = detect_vm._find_llvm_objdump()
    if not exe:
        return None
    return subprocess.run([exe, '-d', path], capture_output=True, text=True, timeout=60).stdout


def _funcs(text):
    parts = re.split(r'\n(?=[0-9a-f]{16} <)', text)
    res = []
    for p in parts:
        m = re.match(r'([0-9a-f]{16}) <(.+)>:', p)
        if m:
            res.append((int(m.group(1), 16), m.group(2), p))
    return res


def _insns(block):
    """-> [(addr, mnemonic, operands)]"""
    out = []
    for line in block.split('\n'):
        m = re.match(r'\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+(\S+)(.*)$', line)
        if m:
            out.append((int(m.group(1), 16), m.group(2), m.group(3).strip()))
    return out


def _biggest(text):
    fns = _funcs(text)
    return max(fns, key=lambda f: len(_insns(f[2]))) if fns else None


# ---------------------------------------------------------------- S1：比较级联
def _switch_chain(ins):
    """识别 switch 的「比较级联」（clang 未优化时的经典形态）：

        subs wR, wR, #imm     ; 与某个 case 值比较（相等 -> Z=1）
        b.eq <case_body>      ; 命中 -> case 体
        b    <next_node>      ; 未命中 -> 下一个比较节点

    返回 (reg, nodes)：nodes = {addr: (imm, case_target, next_addr)}。
    """
    nodes = {}
    reg = None
    for i, (a, m, o) in enumerate(ins):
        if m not in ('subs', 'cmp'):
            continue
        mm = (re.match(r'w(\d+),\s*w\d+,\s*#0x([0-9a-f]+)', o) or
              re.match(r'w(\d+),\s*#0x([0-9a-f]+)', o))
        if not mm:
            continue
        r, imm = 'w' + mm.group(1), int(mm.group(2), 16)
        case_t = next_t = None
        for j in range(i + 1, min(i + 6, len(ins))):
            nm, no = ins[j][1], ins[j][2]
            bb = re.search(r'0x([0-9a-f]+)', no)
            if not bb:
                continue
            if nm == 'b.eq' and case_t is None:
                case_t = int(bb.group(1), 16)
            elif nm == 'b' and next_t is None:
                next_t = int(bb.group(1), 16)
            if case_t is not None and next_t is not None:
                break
        if case_t is not None:
            nodes[a] = (imm, case_t, next_t)
            reg = r
    return (reg, nodes) if len(nodes) >= 4 else (None, {})


def _simulate_chain(nodes, value):
    """在比较级联上走一遍：命中返回 case 体地址，未命中返回 None。

    next_t 指向下一个比较节点的**函数体**，可能比 subs 指令本身早一两条 —— 走的时候
    吸附到「>= 它的最近节点」。
    """
    if not nodes:
        return None
    keys = sorted(nodes)
    addr, seen = keys[0], set()
    while addr is not None and addr not in seen:
        seen.add(addr)
        if addr not in nodes:
            cand = [k for k in keys if k >= addr]
            if not cand:
                return None
            addr = cand[0]
        imm, case_t, next_t = nodes[addr]
        if value == imm:
            return case_t
        addr = next_t
    return None


def _case_body(ins, start_i, cap=80):
    """从一个 case 体入口收集指令，直到遇到无条件跳（回循环尾）或 ret。"""
    body = []
    for i in range(start_i, min(start_i + cap, len(ins))):
        a, m, o = ins[i]
        body.append((a, m, o))
        if m == 'b' or m.split('.')[0] == 'ret':
            break
    return body


def _fingerprint_a64(body):
    """case 体 -> VM 语义名。

    关键区分：**数据运算**作用在两个 w 寄存器上（`add w8, w8, w9` / `eor w8,w8,w9`），
    而**指针/下标簿记**用立即数（`add x9, x9, #0x14`）—— 后者要排除，否则每个 case 都被
    误当成 ADD。
    """
    data = set()
    has_ldrb = False
    has_index_load = False
    has_ret = False
    for _a, m, o in body:
        base = m.split('.')[0]
        if base in ('add', 'subs') and re.match(r'w\d+,\s*w\d+,\s*w\d+', o):
            data.add('ADD' if base == 'add' else 'SUB')
        elif base == 'sub' and re.match(r'w\d+,\s*w\d+,\s*w\d+', o):
            data.add('SUB')
        elif base in ('mul', 'madd'):
            data.add('MUL')
        elif base == 'eor':
            data.add('XOR')
        elif m.startswith('ldrb'):
            has_ldrb = True
        elif m.startswith('ldr') and ('lsl #2' in o or 'sxtw #2' in o):
            has_index_load = True
        elif base == 'ret':
            has_ret = True
    if 'XOR' in data:
        return 'XOR'
    if 'MUL' in data:
        return 'MUL'
    if 'SUB' in data:
        return 'SUB'
    if 'ADD' in data:
        return 'ADD'
    if has_ret:
        return 'RET'
    # LOADARG：读一个 code 字节 (ldrb) 再按它索引 args (带缩放的 ldr)
    if has_ldrb and has_index_load:
        return 'LOADARG'
    if has_ldrb:
        return 'PUSH'
    # RET：从栈数组弹一个元素（带缩放的 ldr，无 ldrb）
    if has_index_load:
        return 'RET'
    return None


def _recover_switch_opmap(rep, ins):
    reg, nodes = _switch_chain(ins)
    if not nodes:
        rep['dynamic_needed'] = True
        rep['notes'].append('no recognizable switch comparison chain -> dynamic tracing required')
        return
    rep['switch_reg'] = reg
    by = {a: i for i, (a, _m, _o) in enumerate(ins)}
    opmap = {}
    for addr in sorted(nodes):
        imm = nodes[addr][0]
        landing = _simulate_chain(nodes, imm)
        if landing in by:
            name = _fingerprint_a64(_case_body(ins, by[landing]))
            if name:
                opmap[imm] = name
    rep['opmap'] = {'%d' % k: v for k, v in sorted(opmap.items())}
    rep['notes'].append('switch opmap: %d/%d cases fingerprinted via comparison-chain simulation'
                        % (len(opmap), len(nodes)))


# ---------------------------------------------------------------- 主流程
def analyze(path):
    rep = {'path': path, 'dispatch': None, 'disp_method': None, 'candidate_bytecode': [],
           'opmap': {}, 'notes': [], 'dynamic_needed': False}
    text = _objdump(path)
    if not text:
        rep['notes'].append('llvm-objdump not found -> cannot disassemble')
        rep['dynamic_needed'] = True
        return rep
    big = _biggest(text)
    if not big:
        rep['notes'].append('no functions found')
        return rep
    rep['disp_method'] = big[1]
    ins = _insns(big[2])
    n_cmp = sum(1 for _a, m, o in ins
                if m in ('cmp', 'subs') and re.search(r'w\d+,\s*(w\d+,\s*)?#', o))
    n_blr = sum(1 for _a, m, _o in ins if m == 'blr')
    n_br = sum(1 for _a, m, _o in ins if m == 'br')
    if n_br >= 4:
        rep['dispatch'] = 'threaded'
    elif n_cmp >= 5:
        rep['dispatch'] = 'switch'
    elif n_blr >= 1:
        rep['dispatch'] = 'indirect'
    else:
        rep['dispatch'] = 'linear'
    rep['notes'].append('interpreter = %s (%d insns, dispatch=%s)' % (big[1], len(ins), rep['dispatch']))

    blob = open(path, 'rb').read()
    info = elfinspect.inspect(blob, os.path.basename(path))
    for s in info.get('section_entropy_all', info.get('section_entropy', [])):
        if s['name'] in ('.rodata', '.data.rel.ro') and 8 <= s['size'] <= 4096:
            rep['candidate_bytecode'].append({'section': s['name'], 'size': s['size'],
                                              'entropy': s['entropy'], 'offset': s['offset']})

    if rep['dispatch'] == 'switch':
        _recover_switch_opmap(rep, ins)
    else:
        rep['dynamic_needed'] = True
        rep['notes'].append('dispatch is %s -> need dynamic tracing to recover the '
                            'opcode->handler mapping' % rep['dispatch'])
    return rep


def main():
    ap = argparse.ArgumentParser(description='SO/ARM64 层静态分析')
    ap.add_argument('targets', nargs='+')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args()
    for i, t in enumerate(a.targets):
        if i:
            print()
        rep = analyze(t)
        if a.json:
            print(json.dumps(rep, indent=2, ensure_ascii=False))
            continue
        print('== %s ==' % t)
        for n in rep['notes']:
            print('  note: %s' % n)
        for c in rep['candidate_bytecode']:
            print('  candidate bytecode: %s %d B H=%.3f @0x%x'
                  % (c['section'], c['size'], c['entropy'], c['offset']))
        if rep['opmap']:
            print('  switch opmap: %s' % ', '.join('%s=%s' % kv for kv in rep['opmap'].items()))
        if rep['dynamic_needed']:
            print('  ! static devirtualization not sufficient for this dispatch shape '
                  '-> dynamic trace (frida/trace_dispatch.js)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
