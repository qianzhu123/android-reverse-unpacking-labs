#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
detect_vm.py — VMP（虚拟化）结构判定（只读）。**不靠文件名、不靠类名、不靠字符串**，
只看方法体形状 / 分派形态 / 载荷结构 / ELF 结构。

判据代号（V 系列；B13 沿用本仓 SO/ELF 通用判据）：

  DEX 侧（形状来自 dexscan.py）
    V1  汇聚调用：>=2 个「极短方法体」invoke 同一个「大方法」      -> 疑似 DEX VM
    V2  业务方法体形状固定：只有「构造数组 + 调解释器 + 返回」（统计量，辅助）
    V3  非 dalvik 载荷：assets 里出现高熵小字节流（长度像指令流）  -> 载荷外置
    V4  解释器形态：某个大方法内含 packed-switch + 回边（循环）     -> 解释器定位
    V5  内联 VM：无统一 hub，但 >=2 个方法体内含**同一组 switch case**
    V6  随机 opcode：switch 的 case 值不构成 0..N 连续小集合

  SO 侧
    VN1 SO 里有 Java_* 导出（native 业务入口）+ 紧凑数据段          -> native 业务
    VN2 SO 分派形态：objdump 见间接调用/计算跳转而非中心 switch      -> 运行期装配/threaded
    B13 SO：ET_DYN 且节头表被剥离（自实现 Linker / 加壳）

认知边界（**必须一起读**）：本工具只回答「样本**呈现出**哪一类虚拟化/保护形态」，
**不回答**「它一定被 VMP」「一定没被保护」。以下静态不可判定、需动态 trace：
  · 不走汇聚调用、把解释器内联进每个方法的自定义 VM（V1/V5 都可能漏）
  · 运行期才装配的分派/opcode 映射（S2/S3 的静态形态）
  · handler 语义是数据驱动的，形状本身不能证明 VMP
「未见已知特征」永远**不等于**「未加固」。

用法：
    python tools/detect_vm.py samples/apks/app_l1.apk
    python tools/detect_vm.py samples/native/libcalc_s2_arm64.so
    python tools/detect_vm.py samples/apks/app_l2.apk --json
"""

import argparse
import json
import os
import re
import subprocess
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import apkutil
import dexlib
import dexscan
import elfinspect

ROOT = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(ROOT)

BOUNDARY_DEX = [
    'hub-less / fully-inlined custom VM can still evade V1 (V5 is the fallback)',
    'runtime-assembled dispatch and opcode maps are invisible statically',
    'handler semantics are data-driven — shape alone cannot prove VMP',
]
BOUNDARY_SO = [
    'SO VM interpreter may be an ordinary large function — static shape is not proof',
    'runtime-assembled handler tables / opcode maps need dynamic tracing',
    'threaded dispatch can be invisible without following indirect-branch targets',
]


# ---------------------------------------------------------------- DEX 特征
def dex_features(dx, label):
    names = dexscan.method_names(dx)
    callees = {}          # callee_idx -> [caller MethodShape]
    shapes = []
    tiny = set()
    switch_sigs = {}      # case 元组 -> [method key]

    for cname, ms in dexscan.each_method(dx):
        shapes.append(ms)
        if ms.units <= dexscan.TINY_UNITS:
            tiny.add(ms.key)
        for tgt in ms.invokes:
            callees.setdefault(tgt, []).append(ms)
        for sw in ms.switches:
            if sw:
                switch_sigs.setdefault(tuple(sw), []).append(ms.key)

    by_key = {m.key: m for m in shapes}

    v1 = []
    for callee_idx, callers in callees.items():
        tiny_callers = [c for c in callers if c.key in tiny]
        cname, mname = names.get(callee_idx, ('?', '?'))
        hub = by_key.get('%s->%s' % (cname, mname))
        if len(tiny_callers) >= dexscan.MIN_CALLERS and hub and hub.units >= dexscan.HUB_UNITS:
            v1.append({'hub': hub.key, 'units': hub.units,
                       'tiny_callers': sorted(c.key for c in tiny_callers)})

    v4 = [{'method': m.key, 'units': m.units, 'n_switch': len(m.switches)}
          for m in shapes
          if m.switches and m.has_backbranch and m.units >= dexscan.HUB_UNITS]

    v5 = [{'cases': len(sig), 'methods': ks}
          for sig, ks in switch_sigs.items() if len(ks) >= 2]

    # V6：去掉常见 RET 哨兵 0xFF 后，case 值仍不构成 0..N 连续小集合
    def _v6_signal(sw):
        c = [x for x in sw if x != 0xFF]
        return bool(c) and not dexscan.is_dense_small(c)
    v6 = any(sw and _v6_signal(sw) for m in shapes for sw in m.switches)

    # V2：极短方法里「只有调用、无 switch、无回边」的比例
    fixed_shape = [m for m in shapes if m.units <= dexscan.TINY_UNITS
                   and not m.switches and not m.has_backbranch and m.invokes]

    return {'label': label, 'n_methods': len(shapes), 'n_tiny': len(tiny),
            'v1_hubs': v1, 'v2_fixed_shape': len(fixed_shape),
            'v4_interp': v4, 'v5_inline': v5, 'v6_random_opcode': v6}


# ---------------------------------------------------------------- APK
def apk_features(path):
    out = {'kind': 'apk', 'path': path, 'dex': [], 'assets': [], 'native': [],
           'codes': [], 'verdict': 'no known hardening signature observed (≠ none)',
           'boundary': BOUNDARY_DEX}
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        all_strings = set()
        for dn in sorted(n for n in names if n.endswith('.dex')):
            dx = dexlib.Dex(z.read(dn))
            out['dex'].append(dex_features(dx, dn))
            for _i, st in dx.all_strings():
                all_strings.add(st)
        for an in sorted(n for n in names if n.startswith('assets/')):
            data = z.read(an)
            base = an.rsplit('/', 1)[-1]
            out['assets'].append({'name': an, 'size': len(data),
                                  'entropy': round(apkutil.shannon_entropy(data), 4),
                                  'referenced': base in all_strings})
        seen_abi = set()
        for sn in sorted(n for n in names if n.startswith('lib/') and n.endswith('.so')):
            abi = sn.split('/')[1]
            blob = z.read(sn)
            f = elf_features(blob, sn)
            out['native'].append(f)
            for c in f['codes']:
                if c not in out['codes']:
                    out['codes'].append(c)
    _verdict_apk(out)
    return out


def _verdict_apk(out):
    any_v1 = any(d['v1_hubs'] for d in out['dex'])
    any_v4 = any(d['v4_interp'] for d in out['dex'])
    any_v5 = any(d['v5_inline'] for d in out['dex'])
    any_v6 = any(d['v6_random_opcode'] for d in out['dex'])
    # V3：代码里引用了的小体积「不透明」资源（自定义字节码/载荷的典型外置形态）。
    # 光看熵对小载荷不可靠（39B 的异或流熵高不上去），所以主信号是「资源名出现在 dex
    # 字符串池 + 体积小 + 非纯文本」，熵只作辅证。
    high_asset = [a for a in out['assets']
                  if a.get('referenced') and 8 <= a['size'] <= 4096 and a['entropy'] > 4.2]
    native_vm = [n for n in out['native'] if n.get('vn1')]

    for c, hit in (('V1', any_v1), ('V3', bool(high_asset)), ('V4', any_v4),
                   ('V5', any_v5), ('V6', any_v6)):
        if hit and c not in out['codes']:
            out['codes'].append(c)

    out['codes'].sort(key=lambda c: (c[1:].isdigit() and 0 or 1, c))
    # 定性只看「结构性证据」：V1（方法体塌缩为对 hub 的调用）或 V5（无 hub 但多方法内联同一
    # switch）。V4/V6 是**辅助**信号 —— 合法的大 switch 状态机同样有 switch+循环、case 也不
    # 连续（负样本 neg_bigswitch 当场验证），单独不足以定性。
    if any_v1:
        out['verdict'] = ('suspected DEX virtual machine — business methods collapse to a '
                          'hub method (V1); corroborated by V4/V6 when present')
    elif any_v5:
        out['verdict'] = ('suspected inline DEX virtual machine — no hub, but several methods '
                          'embed the same interpreter switch (V5)')
    elif any_v4 or any_v6:
        out['verdict'] = ('no VM hub/inline signature (≠ none) — V4/V6 interpreter-like shape '
                          'observed, but a normal state machine also matches; corroborate dynamically')
    elif native_vm:
        out['verdict'] = 'native (SO) code carrying embedded dispatch — see VN1/VN2'


# ---------------------------------------------------------------- SO / ELF
def elf_features(blob, name):
    info = elfinspect.inspect(blob, name)
    f = {'name': name, 'size': len(blob), 'codes': [], 'vn1': False,
        'vn2': None, 'b13': False, 'sections': info.get('sections', []),
        'text_entropy': info.get('text_entropy'),
        'anomalies': info.get('anomalies', [])}
    has_jni = (b'Java_' in blob) or info.get('has_jni_onload')
    # 紧凑数据段（.rodata / .data*）——像自定义字节码表
    ALL = info.get('section_entropy_all', info.get('section_entropy', []))
    compact = [s for s in ALL
               if 8 <= s['size'] <= 4096 and s['name'] in ('.rodata', '.data', '.data.rel.ro')]
    if has_jni and compact:
        f['vn1'] = True
        f['codes'].append('VN1')
        f['data_sections'] = compact
    if any('no_section_headers' in a for a in f['anomalies']):
        f['b13'] = True
        f['codes'].append('B13')
    return f


def so_features(path):
    with open(path, 'rb') as fh:
        blob = fh.read()
    out = {'kind': 'so', 'path': path}
    f = elf_features(blob, os.path.basename(path))
    out.update(f)
    out['vn2'] = _dispatch_shape(path)
    disp = out['vn2']
    codes = list(f['codes'])
    if disp and disp.get('shape') in ('indirect', 'threaded'):
        if 'VN2' not in codes:
            codes.append('VN2')
    out['codes'] = codes
    if f['vn1'] and disp and disp.get('shape') == 'switch':
        out['verdict'] = ('suspected native (SO) VM — central-switch interpreter over an '
                          'embedded table (VN1 + switch dispatch)')
    elif f['vn1'] and disp and disp.get('shape') in ('indirect', 'threaded'):
        out['verdict'] = ('suspected native (SO) VM — dispatch is %s, not a central switch'
                          % disp['shape'])
    elif f['vn1']:
        out['verdict'] = 'native (SO) business entry with an embedded data table — corroborate dynamically'
    elif f['b13']:
        out['verdict'] = 'suspected SO packing / self-implemented linker (ELF section headers stripped)'
    else:
        out['verdict'] = 'no known hardening signature observed (≠ none)'
    out['boundary'] = BOUNDARY_SO
    return out


def _dispatch_shape(path):
    """用 llvm-objdump 粗判最大函数的**分派形态**：switch / indirect / threaded / linear。

    逐行取「地址 + 原始字 + 助记符」里的助记符后再匹配，避免把指令编码当操作数。
    """
    objdump = _find_llvm_objdump()
    if not objdump:
        return None
    try:
        res = subprocess.run([objdump, '-d', path], capture_output=True, text=True, timeout=60)
    except Exception:
        return None
    if not res.stdout:
        return None
    text = res.stdout
    funcs = re.split(r'\n(?=[0-9a-f]{16} <)', text)
    MNE = re.compile(r'^\s*[0-9a-f]+:\s+[0-9a-f]{8}\s+(\S.*)$', re.M)

    def lines_of(s):
        return MNE.findall(s)

    biggest, n = '', 0
    for fn in funcs:
        m = len(lines_of(fn))
        if m > n:
            biggest, n = fn, m
    mn = ' | '.join(lines_of(biggest))
    n_cmp = len(re.findall(r'\bcmp\s+w\d+,', mn)) + len(re.findall(r'\bsubs\s+w\d+,', mn))
    n_bl = len(re.findall(r'\bbl\s+0x', mn))
    n_blr = len(re.findall(r'\bblr\s+x\d+', mn))
    n_br = len(re.findall(r'\bbr\s+x\d+', mn))
    n_b = len(re.findall(r'\bb\s+0x', mn))
    # 分派形态判读（aarch64）：先看 basic-block 网，再看中心跳转表，
    # 再看间接调用；都没有 -> 线性代码
    if n_br >= 4:
        shape = 'threaded'
    elif n_cmp >= 5:
        shape = 'switch'
    elif n_blr >= 1:
        shape = 'indirect'
    else:
        shape = 'linear'
    return {'shape': shape, 'n_insns': n, 'cmp': n_cmp, 'bl': n_bl,
            'blr': n_blr, 'br': n_br, 'b': n_b}


def _find_llvm_objdump():
    try:
        import envload
        envload.ensure_env()
    except Exception:
        pass
    ndbin = _ndk_bin()
    if ndbin:
        for exe in ('llvm-objdump.exe', 'llvm-objdump'):
            p = os.path.join(ndbin, exe)
            if os.path.exists(p):
                return p
    import shutil
    return shutil.which('llvm-objdump')


def _ndk_bin():
    try:
        out = subprocess.run(['bash', os.path.join(ROOT, 'build', 'locate.sh'), '--dump'],
                             capture_output=True, text=True, timeout=30)
        for line in out.stdout.splitlines():
            if line.startswith('NDBIN='):
                return line.split('=', 1)[1].strip()
    except Exception:
        pass
    return None


# ---------------------------------------------------------------- 输出
def report(f, as_json=False):
    if as_json:
        print(json.dumps(f, indent=2, ensure_ascii=False))
        return
    print('== %s ==' % f['path'])
    if f['kind'] == 'apk':
        for d in f['dex']:
            print('  dex %-14s methods=%d tiny=%d | V1 hubs=%d V4 interp=%d V5 inline=%d V6=%s'
                  % (d['label'], d['n_methods'], d['n_tiny'],
                     len(d['v1_hubs']), len(d['v4_interp']), len(d['v5_inline']),
                     d['v6_random_opcode']))
            for h in d['v1_hubs']:
                print('      V1: %s (%d units) <- %d tiny callers: %s'
                      % (h['hub'], h['units'], len(h['tiny_callers']),
                         ', '.join(x.split('/')[-1] for x in h['tiny_callers'][:6])))
        for a in f['assets']:
            flag = '  <-- high-entropy (V3)' if a['entropy'] > 7.0 and a['size'] <= 4096 else ''
            print('  asset %-24s %6d B  H=%.4f%s' % (a['name'], a['size'], a['entropy'], flag))
        for n in f['native']:
            print('  so    %-30s codes=%s' % (n['name'], ','.join(n['codes']) or '-'))
    else:
        if f.get('vn2'):
            print('  dispatch shape: %-9s %s' % (f['vn2']['shape'], f['vn2']))
        if f.get('data_sections'):
            print('  data sections : %s' % f['data_sections'])
    print('  codes  : %s' % (', '.join(f['codes']) or '(none)'))
    print('  verdict: %s' % f['verdict'])
    print('  boundary (static cannot decide):')
    for b in f['boundary']:
        print('    - %s' % b)


def _is_elf(path):
    try:
        with open(path, 'rb') as fh:
            return fh.read(4) == b'\x7fELF'
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser(description='VMP 结构判定（只读）')
    ap.add_argument('targets', nargs='+')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args()
    for i, t in enumerate(a.targets):
        if i:
            print()
        if _is_elf(t):
            report(so_features(t), a.json)
        else:
            report(apk_features(t), a.json)
    return 0


if __name__ == '__main__':
    sys.exit(main())
