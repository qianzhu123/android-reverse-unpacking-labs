#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
dexscan.py — DEX 方法体形状 / 分派形态的**只读扫描**（detect_vm.py 与
devirt_dex.py 共用）。

这里只做一件事：把每个方法的 dalvik 指令走一遍，回答
  · 方法有多少 code unit（体量）
  · 它 invoke 了哪些方法（拿 method_idx -> 名字）
  · 有没有 packed/sparse-switch，case 值是多少（packed 可直读）
  · 有没有回边（循环）

「虚拟化」在 DEX 层留下的痕迹就是这些形状特征：
  · 业务方法体极短、只有一句 invoke 到同一个 hub（V1 汇聚调用）
  · hub 里有 switch + 回边（V4 解释器）
  · 多个方法含同一组 case 值（V5 内联 VM，无 hub 时唯一的抓手）

**不靠类名/方法名/字符串** —— 只靠形状。

dalvik 指令长度表只覆盖本 lab 用到的范围；未知长度按 2 code unit 保守推进，
只影响极少数方法体的边界估算，不影响「invoke/switch/回边」的识别。
"""

import struct

# 指令长度（单位：16 位 code unit）
INSN_SIZE = {}
for _op in (0x00, 0x01, 0x04, 0x07, 0x0a, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x1d,
            0x1e, 0x21, 0x27, 0x28, 0x39, 0x3d, 0x3e, 0x43, 0x73, 0x79, 0x7a, 0x7b,
            0xe3, 0xfa, 0xfb, 0xfc, 0xfd):
    INSN_SIZE[_op] = 1
for _op in (0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f, 0x20,
            0x22, 0x23, 0x29, 0x2a, 0x3f, 0x41, 0x42, 0x44, 0x45, 0x46, 0x47, 0x48,
            0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54,
            0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
            0x6d, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda,
            0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xfe, 0xff):
    INSN_SIZE[_op] = 2
for _op in list(range(0x2d, 0x32)) + list(range(0x32, 0x3e)):
    INSN_SIZE[_op] = 2      # cmp / if
for _op in range(0x6e, 0x79):
    INSN_SIZE[_op] = 3      # invoke
for _op in (0x03, 0x06, 0x09, 0x14, 0x17, 0x1b, 0x24, 0x25, 0x26, 0x2b, 0x2c):
    INSN_SIZE[_op] = 3      # 3-reg, 35c, switch(2+payload)
for _op in (0x18,):
    INSN_SIZE[_op] = 5
INSN_SIZE[0xfa] = 4         # invoke-polymorphic
INSN_SIZE[0xfb] = 4         # invoke-polymorphic/range

INVOKE_OPS = set(range(0x6e, 0x79))     # invoke-* (含 range)
GOTO_OPS = {0x28: 'b', 0x29: 'h', 0x2a: 'i'}
SWITCH_PACKED, SWITCH_SPARSE = 0x2b, 0x2c


def _u2(b, o):
    return struct.unpack_from('<H', b, o)[0]


def scan(insns):
    """走一遍方法体。返回 dict：
        units, invokes(list of method_idx), switches(list of list|None),
        has_backbranch, n_insns_scanned
    """
    n = len(insns) // 2
    res = {'units': n, 'invokes': [], 'switches': [], 'has_backbranch': False}
    i = 0
    while i < n:
        op = insns[i * 2]
        size = INSN_SIZE.get(op, 2)
        if op in INVOKE_OPS and i + 2 < n:
            res['invokes'].append(_u2(insns, (i + 1) * 2))
        if op == SWITCH_PACKED and i + 2 < n:
            rel = struct.unpack_from('<i', insns, (i + 1) * 2)[0]
            tgt = i + rel
            # packed-switch-payload: u2 ident(0x0100) | u2 size | s4 first_key | size*s4 targets
            if 0 <= tgt + 2 <= n:
                size_cases = _u2(insns, (tgt + 1) * 2)
                first = struct.unpack_from('<i', insns, (tgt + 2) * 2)[0]
                res['switches'].append([first + k for k in range(size_cases)])
            else:
                res['switches'].append(None)
        elif op == SWITCH_SPARSE and i + 2 < n:
            rel = struct.unpack_from('<i', insns, (i + 1) * 2)[0]
            tgt = i + rel
            # sparse-switch-payload 布局（按 dex 规范）：
            #   u2 ident(0x0200) | u2 size | s4 keys[size] | s4 targets[size]
            #   两个数组分开存放，不是 (key,target) 交错。
            if 0 <= tgt + 2 <= n:
                size_cases = _u2(insns, (tgt + 1) * 2)
                keys = []
                for k in range(size_cases):
                    off = (tgt + 2 + 2 * k) * 2
                    if off + 4 <= len(insns):
                        keys.append(struct.unpack_from('<i', insns, off)[0])
                res['switches'].append(keys or None)
            else:
                res['switches'].append(None)
        if op in GOTO_OPS and i + 1 < n:
            fmt = GOTO_OPS[op]
            if fmt == 'b':
                off = struct.unpack_from('<b', insns, i * 2 + 1)[0]
            elif fmt == 'h':
                off = struct.unpack_from('<h', insns, (i + 1) * 2)[0]
            else:
                off = struct.unpack_from('<i', insns, (i + 1) * 2)[0]
            if off < 0:
                res['has_backbranch'] = True
        if 0x32 <= op <= 0x3d and i + 1 < n:      # if-test -> 回边 = 循环
            off = struct.unpack_from('<h', insns, (i + 1) * 2)[0]
            if off < 0:
                res['has_backbranch'] = True
        i += size
    return res


def is_dense_small(cases):
    """case 值是否是 0..N / 1..N 这类连续小集合（框架解释器的常见形状）。"""
    s = sorted(set(cases))
    if not s:
        return True
    return (s[-1] - s[0] + 1 == len(s)) and s[0] in (0, 1) and s[-1] <= 0xFF


class MethodShape(object):
    def __init__(self, cls, name, sig, units, scan_res):
        self.cls = cls
        self.name = name
        self.sig = sig
        self.units = units
        self.invokes = scan_res['invokes']
        self.switches = scan_res['switches']
        self.has_backbranch = scan_res['has_backbranch']

    @property
    def key(self):
        return '%s->%s' % (self.cls, self.name)

    def __repr__(self):
        return '<%s units=%d invokes=%d switches=%d loop=%s>' % (
            self.key, self.units, len(self.invokes), len(self.switches), self.has_backbranch)


def each_method(dx):
    """产出 (class_name, MethodShape)，跳过没有 code 的方法。"""
    for cname, kind, m in dx.iter_methods():
        if m['code_off'] == 0:
            continue
        ci = dx.code_item(m['code_off'])
        sc = scan(ci['insns'])
        _c, _idx, _proto, mname = dx.method_at(m['method_idx'])
        yield cname, MethodShape(cname, mname, dx.method_signature(m), sc['units'], sc)


def method_names(dx):
    """method_idx -> (class, name)，供 invokes 解析。"""
    out = {}
    for i in range(dx.method_ids_size):
        c, idx, proto, name = dx.method_at(i)
        out[i] = (c, name)
    return out


# ---- 判定用的形状阈值（**写死在这里，是判定的一部分，不是魔法数字**）----
TINY_UNITS = 24       # 「极短方法体」上限：业务方法退化为「构造数组+调用+返回」时的体量
HUB_UNITS = 30        # 「大方法」下限：解释器循环的体量
MIN_CALLERS = 2       # 汇聚判据要求至少 N 个极短方法调用同一个大方法

# ==================== 去虚拟化辅助：切分 switch case + 指纹 ====================
# 这些是「静态还原 opcode 语义」的核心：把解释器的 switch 每个 case 切出来，
# 看它体内用了哪条算术指令，从而认出「这个 opcode 其实是 XOR / ADD / ...」。

ARITH = {0x90: 'ADD', 0x91: 'SUB', 0x92: 'MUL', 0x93: 'DIV', 0x94: 'REM',
         0x95: 'XOR', 0x96: 'SHL', 0x97: 'SHR', 0x98: 'USHR',
         0x9a: 'ADD', 0x9b: 'SUB', 0x9c: 'MUL', 0x9e: 'XOR',
         0xb0: 'ADD', 0xb1: 'SUB', 0xb2: 'MUL', 0xb7: 'XOR'}   # lit8 变体
RETURN_OPS = {0x0e, 0x0f, 0x10, 0x11}
# 带内联立即数的算术指令（lit8 0xd8..0xe2 / lit16 0xd0..0xd7）—— 超算子的形态
LIT_ARITH = set(range(0xb0, 0xe3))   # binop/lit16 (0xb0-0xd7) + binop/lit8 (0xd8-0xe2)
AGET_OBJ, AGET, AGET_BYTE = 0x46, 0x44, 0x48
TERMINATORS = set(RETURN_OPS) | {0x27, 0x28, 0x29, 0x2a}   # return*/throw/goto*


def find_switch(insns):
    """找第一个 switch（packed 或 sparse）。返回 (switch_idx, [(key, target), ...])，无则 None。

    key = case 值（= VM 的 opcode），target = 该 case 体在方法里的 code unit 偏移。
    """
    n = len(insns) // 2
    i = 0
    while i < n:
        op = insns[i * 2]
        if op in (SWITCH_PACKED, SWITCH_SPARSE) and i + 2 < n:
            rel = struct.unpack_from('<i', insns, (i + 1) * 2)[0]
            tgt = i + rel
            if 0 <= tgt + 2 <= n:
                size_cases = _u2(insns, (tgt + 1) * 2)
                pairs = []
                if op == SWITCH_PACKED:
                    first = struct.unpack_from('<i', insns, (tgt + 2) * 2)[0]
                    for k in range(size_cases):
                        off = (tgt + 4 + 2 * k) * 2
                        if off + 4 > len(insns):
                            break
                        r = struct.unpack_from('<i', insns, off)[0]
                        pairs.append((first + k, i + r))
                else:
                    # keys[] 在前、targets[] 在后（各 size 个 s4）
                    kbase = tgt + 2
                    tbase = kbase + 2 * size_cases
                    for k in range(size_cases):
                        koff = (kbase + 2 * k) * 2
                        toff = (tbase + 2 * k) * 2
                        if toff + 4 > len(insns):
                            break
                        key = struct.unpack_from('<i', insns, koff)[0]
                        r = struct.unpack_from('<i', insns, toff)[0]
                        pairs.append((key, i + r))
                if pairs:
                    return i, pairs
        i += INSN_SIZE.get(op, 2)
    return None


def case_opcodes(insns, target, others, cap=80):
    """从 target 起收集 case 体的指令 opcode，直到遇到终结指令或下一个 case 边界。

    case 体在方法里按**地址顺序**排布，所以边界 = 所有 case 目标里「比 target 大的最小值」。
    注意 others 里可能有重复/乱序（相邻 case 可以共享一个体），必须先取集合再排序。
    """
    n = len(insns) // 2
    later = sorted(set(o for o in others if o > target))
    stop = later[0] if later else n
    ops = []
    i = target
    while i < n and i < stop and len(ops) < cap:
        op = insns[i * 2]
        ops.append(op)
        if op in TERMINATORS:
            break
        i += INSN_SIZE.get(op, 2)
    return ops


def fingerprint(opcodes):
    """case 体的 opcode 列表 -> 该 case 代表的 VM 指令名。认不出返回 None。"""
    st = set(opcodes)
    if AGET_BYTE not in st and not (st & RETURN_OPS):
        # 没有任何「取立即数」/返回特征，多半不是基础 handler
        pass
    arith = set(ARITH[o] for o in opcodes if o in ARITH)
    imm_reads = opcodes.count(AGET_BYTE)          # 读 code[pc++] 的次数
    has_ret = bool(st & RETURN_OPS)
    # 注：融合算子（L4 的 XORK/MULK…）用带内联立即数的算术指令实现，静态指纹只能认出
    # 其中的算术种类（会当成 XOR/MUL），**分不出那个立即数**。这是本工具的已知边界，
    # 上层用「opcode 非连续 + 还原出的语义套不上黄金结果」把它暴露出来 -> 转动态。
    if 'XOR' in arith:
        return 'XOR'
    if 'ADD' in arith:
        return 'ADD'
    if 'MUL' in arith:
        return 'MUL'
    if 'SUB' in arith:
        return 'SUB'
    if has_ret:
        return 'RET'
    if AGET_BYTE in st and AGET in st:
        return 'LOADARG'
    if AGET_BYTE in st:
        return 'PUSH'
    return None


def recover_opmap_from_switch(insns):
    """静态还原 opcode->语义：切 case 体 + 指纹。返回 {opcode:int -> name:str}。"""
    fs = find_switch(insns)
    if not fs:
        return None
    _idx, pairs = fs
    targets = [t for _k, t in pairs]
    opmap = {}
    for key, tgt in pairs:
        ops = case_opcodes(insns, tgt, targets)
        name = fingerprint(ops)
        if name:
            opmap[key & 0xFF] = name
    return opmap


def find_fill_array_data(insns):
    """抽取方法体里所有 fill-array-data 的原始字节（按出现顺序）。用于取静态 byte[]。"""
    out = []
    n = len(insns) // 2
    i = 0
    while i < n:
        op = insns[i * 2]
        if op == 0x26 and i + 1 < n:          # fill-array-data 31t
            rel = struct.unpack_from('<i', insns, (i + 1) * 2)[0]
            p = (i + rel) * 2
            if 0 <= p and p + 8 <= len(insns):
                ident = _u2(insns, p)
                if ident == 0x0300:
                    width = _u2(insns, p + 2)
                    size = struct.unpack_from('<I', insns, p + 4)[0]
                    start = p + 8
                    out.append(bytes(insns[start:start + size * width]))
        i += INSN_SIZE.get(op, 2)
    return out
