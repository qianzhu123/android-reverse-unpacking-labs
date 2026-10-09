#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
devirt_dex.py — DEX 层**静态去虚拟化**：把「方法体只剩一句调用解释器」的样本，
还原回可读的规范操作流 + 结果。

思路（全部只读结构、不靠类名方法名）：
  1. 定位解释器：找含 packed-switch 且带循环的大方法（detect_vm 的 V4 形态）；
  2. 还原 opcode 映射：把 switch 每个 case 体切出来做**指纹**
     （体内用 XOR/ADD/MUL/…，就是该 opcode 的语义）-> {opcode: 语义}；
  3. 取自定义字节码：
       · 字节码在源码数组里（第一档）-> 取 fill-array-data 的原始字节；
       · 字节码外置 assets（第二档）-> 用静态字段里的 byte[] 作 key 解密该资源；
  4. 用还原出的 opcode 映射反汇编字节码 -> 规范操作流；
  5. **验证**：用规范操作流跑一遍测试向量，必须得到与黄金逻辑一致的结果
     （向量与期望值取自 samples/payloads/golden_ops.json，那是「语义 oracle」）。

L3（反射分派，无 switch）静态不足以还原 opcode 映射 —— 本工具会**明确报告**
「需要动态 trace」而不是硬猜（诚实边界）。

用法：
    python tools/devirt_dex.py samples/apks/app_l1.apk
    python tools/devirt_dex.py samples/apks/app_l4.apk --json
"""

import argparse
import json
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dexlib
import dexscan
import vmlang

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOLDEN = os.path.join(ROOT, 'samples', 'payloads', 'golden_ops.json')


def load_golden():
    with open(GOLDEN, encoding='utf-8') as f:
        return json.load(f)


def _interp_switch_method(dx):
    """找「含 packed-switch 且方法体较大」的解释器方法，返回 (MethodShape, insns)。"""
    best = None
    for cname, ms in dexscan.each_method(dx):
        if not ms.switches:
            continue
        ins = ms_insns(dx, ms)
        if dexscan.find_switch(ins):        # packed 或 sparse 都认
            if best is None or ms.units > best[0].units:
                best = (ms, ins)
    return best


def ms_insns(dx, ms):
    # MethodShape 不存 insns，用 key 找到 code_off 重新取
    for cname, kind, m in dx.iter_methods():
        if '%s->%s' % (cname, dx.method_at(m['method_idx'])[3]) == ms.key and m['code_off']:
            return dx.code_item(m['code_off'])['insns']
    return b''


def collect_fill_arrays(dx):
    """所有方法体里的 fill-array-data 原始字节（按出现顺序）。"""
    out = []
    for cname, ms in dexscan.each_method(dx):
        for b in dexscan.find_fill_array_data(ms_insns(dx, ms)):
            out.append((ms.key, b))
    return out


def referenced_asset(z, all_strings):
    for n in z.namelist():
        if n.startswith('assets/'):
            base = n.rsplit('/', 1)[-1]
            if base in all_strings:
                return n, z.read(n)
    return None, None


def devirt_apk(path):
    rep = {'path': path, 'opmap': {}, 'programs': {}, 'notes': [], 'dynamic_needed': False}
    with zipfile.ZipFile(path) as z:
        dex_name = sorted(n for n in z.namelist() if n.endswith('.dex'))[0]
        dx = dexlib.Dex(z.read(dex_name))
        all_strings = set(s for _i, s in dx.all_strings())

        # 1) 还原 opcode 映射
        found = _interp_switch_method(dx)
        if found:
            ms, insns = found
            opmap = dexscan.recover_opmap_from_switch(insns)
            rep['opmap'] = {'%d' % k: v for k, v in sorted((opmap or {}).items())}
            rep['notes'].append('opmap recovered from switch in %s' % ms.key)
        else:
            rep['dynamic_needed'] = True
            rep['notes'].append('no packed-switch interpreter found -> reflection/dispatch needs '
                                'dynamic tracing (see frida/trace_dispatch.js)')
            return rep

        # 2) 取字节码
        arrays = collect_fill_arrays(dx)
        asset_name, asset = referenced_asset(z, all_strings)

        programs = {}
        if asset is not None:
            # 第二档：外置载荷，用唯一的一个静态 byte[] 作 key 解密
            key = None
            for _k, b in arrays:
                if len(b) <= 32:      # 密钥是小字节数组
                    key = b
                    break
            if key:
                plain = bytes(asset[i] ^ key[i % len(key)] for i in range(len(asset)))
                lens = list(plain[:3])
                off = 3
                for i, ln in enumerate(lens):
                    programs['prog%d' % i] = plain[off:off + ln]
                    off += ln
                rep['notes'].append('payload %s decrypted with %d-byte key from static field'
                                    % (asset_name, len(key)))
        else:
            for i, (k, b) in enumerate(arrays):
                if len(b) >= 5:
                    programs['prog%d' % i] = b

        # 3) 反汇编（vmlang 要的是 {name: byte}，我们刚才是 {byte: name}，先反转）
        om = {v: int(k) for k, v in rep['opmap'].items()}
        for name, blob in programs.items():
            try:
                toks = vmlang.disassemble(blob, om)
                rep['programs'][name] = {'bytes': len(blob),
                                         'ops': [list(t) for t in toks]}
            except Exception as e:
                rep['programs'][name] = {'bytes': len(blob), 'error': str(e)}
        rep['_program_blobs'] = {k: v for k, v in programs.items()}
    return rep


def verify_against_golden(rep, gold):
    """把每个还原出的程序，用测试向量跑一遍，看它语义等价于哪个黄金方法。"""
    matched = {}
    for name, pr in rep['programs'].items():
        if 'ops' not in pr:
            continue
        toks = [tuple(t) for t in pr['ops']]
        for gm, meta in gold['methods'].items():
            ok = True
            for a, exp in zip(meta['vectors'], meta['results']):
                try:
                    if vmlang.interpret(toks, a) != exp:
                        ok = False
                        break
                except Exception:
                    ok = False
                    break
            if ok:
                matched[name] = gm
    return matched


def report(rep, gold, as_json=False):
    matched = verify_against_golden(rep, gold)
    out = {'path': rep['path'], 'opmap': rep['opmap'], 'notes': rep['notes'],
           'matched': matched, 'dynamic_needed': rep['dynamic_needed'],
           'programs': {k: {'bytes': v.get('bytes'), 'n_ops': len(v.get('ops', [])),
                            'ops': v.get('ops')}
                        for k, v in rep['programs'].items()}}
    if as_json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return out
    print('== %s ==' % rep['path'])
    for n in rep['notes']:
        print('  note: %s' % n)
    if rep['dynamic_needed'] and not rep['programs']:
        print('  (static devirtualization insufficient — dynamic route required)')
        return out
    print('  recovered opmap (%d entries): %s' % (
        len(rep['opmap']), ', '.join('%s=%s' % (k, v) for k, v in list(rep['opmap'].items())[:12])))
    for name, pr in rep['programs'].items():
        gm = matched.get(name, '?')
        print('  %-7s %2d bytes -> %2d ops  => semantics == golden %s'
              % (name, pr.get('bytes', 0), len(pr.get('ops', [])), gm))
        if pr.get('ops'):
            print('          %s' % ' '.join(_fmt(t) for t in pr['ops']))
        elif pr.get('error'):
            print('          (disassembly incomplete: %s)' % pr['error'])
    unresolved = [n for n in rep['programs'] if n not in matched]
    fused = _looks_fused(rep.get('opmap', {}))
    if unresolved:
        why = ('fused/inline-immediate opcodes present (static fingerprint cannot split the '
               'immediate out)' if fused else 'unresolved opcodes')
        print('  ! %s -> static devirtualization is PARTIAL; dynamic trace required '
              '(see frida/trace_dispatch.js)' % why)
        out['dynamic_needed'] = True
    return out


def _looks_fused(opmap):
    """opcode 值非连续/非小集合 -> 多半是随机 opcode + 融合算子（L4 形态）。"""
    vals = []
    for k in opmap:
        try:
            vals.append(int(k) & 0xFF)
        except ValueError:
            return False
    if not vals:
        return False
    return not dexscan.is_dense_small(vals)


def _fmt(t):
    return t[0] if len(t) == 1 else '%s:%s' % (t[0], ','.join(str(x) for x in t[1:]))


def main():
    ap = argparse.ArgumentParser(description='DEX 层静态去虚拟化')
    ap.add_argument('targets', nargs='+')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args()
    gold = load_golden()
    rc = 0
    for i, t in enumerate(a.targets):
        if i:
            print()
        rep = devirt_apk(t)
        out = report(rep, gold, a.json)
        if not rep['dynamic_needed']:
            unmatched = [n for n in rep['programs'] if n not in out['matched']]
            if unmatched:
                rc = 1
    return rc


if __name__ == '__main__':
    sys.exit(main())
