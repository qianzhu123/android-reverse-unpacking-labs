#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
packer.py — 「类爱加密」三代加壳器（离线版）。

    v1  一代·整体加密  业务 dex 全量加密塞进 assets，classes.dex 只剩壳
    v2  二代·类抽取    业务类/方法名保留，全部 code_item 的 insns 抽空(nop)，
                       真实指令抽走存进侧表 assets
    v3  三代·抽取+混淆 只抽部分类，并加诱饵文件/随机资源名，让朴素阈值失效

设计原则（遵守 PROMPT 的要求）：
  * 每一步产出的字节结构都能用十六进制编辑器手动定位（ see tools/walkthrough.py）
  * 加壳前的 dex 与脱壳后还原的 dex 必须能逐字节对得上 -> 用 samples/dex/classes_orig.dex 做黄金对照
  * 脚本只是手动步骤的自动化，不是唯一答案

用法：
  python tools/packer.py v1                         # 默认路径即可
  python tools/packer.py v2
  python tools/packer.py v3 --targets SecretLogic,TokenUtil
  python tools/packer.py all
"""

import argparse
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import crypto_lab
import dexlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ORIG_DEX = os.path.join(ROOT, 'samples', 'classes_orig.dex')
SHELL_DEX = os.path.join(ROOT, 'build', 'shell', 'shell_classes.dex')
MERGED_DEX = os.path.join(ROOT, 'build', 'merged', 'merged_classes.dex')

SHELL_PKG = 'com/ijiami/'
BUSINESS_PKG = 'com/demo/'


def _w(path, data):
    os.makedirs(os.path.dirname(os.path.abspath(path)) or '.', exist_ok=True)
    with open(path, 'wb') as f:
        f.write(data)
    return path


def _rel(path):
    """产物（pack_report.json / 屏幕输出）里只落相对路径，不落盘符绝对路径。"""
    try:
        rp = os.path.relpath(os.path.abspath(path), ROOT)
        if not rp.startswith('..'):
            return rp.replace('\\', '/')
    except Exception:
        pass
    return os.path.basename(path)


def is_business_class(cname):
    """只看业务包，不碰壳自己的类 —— 壳的类必须能在运行时跑起来。"""
    return BUSINESS_PKG in cname and SHELL_PKG not in cname


# ------------------------------------------------------------------ v1
def do_v1(args):
    outdir = os.path.join(ROOT, 'build', 'v1')
    dex = open(ORIG_DEX, 'rb').read()
    payload = crypto_lab.encrypt(dex)

    p_payload = _w(os.path.join(outdir, 'ijm_payload.bin'), payload)
    p_dex = _w(os.path.join(outdir, 'classes.dex'), open(SHELL_DEX, 'rb').read())

    report = {
        'mode': 'v1',
        'input_dex': _rel(ORIG_DEX),
        'input_dex_size': len(dex),
        'payload_file': _rel(p_payload),
        'payload_size': len(payload),
        'payload_header': 'AJM\\x01 + int32_le length=%d' % len(dex),
        'classes_dex': _rel(p_dex),
        'classes_dex_size': os.path.getsize(p_dex),
        'asset_name': 'assets/ijm_payload.bin',
        'note': 'classes.dex 里一条业务类都没有；真正的 dex 是 assets 里的加密 payload',
    }
    _w(os.path.join(outdir, 'pack_report.json'),
       json.dumps(report, ensure_ascii=False, indent=2).encode())
    _echo(report)
    return report


# ------------------------------------------------------------------ v2 / v3 公共抽取逻辑
def extract(dx, targets=None, shuffle_table=False):
    """把 dex 里业务方法的 insns 抽空，返回被抽走的原始数据。

    返回: (entries, stat)
      entries: [{class_idx, method_idx, code_off, insns_len, insns, class_name, method_name}]
      stat:    统计信息
    """
    entries = []
    seen_code_off = set()
    stat = {'classes_total': dx.class_defs_size, 'classes_hit': 0,
            'methods_hit': 0, 'methods_skipped': 0, 'bytes_hit': 0}

    for cd in dx.class_defs():
        cname = dx.class_name(cd)
        if not is_business_class(cname):
            continue
        if targets is not None and not any(t in cname for t in targets):
            continue
        data = dx.class_data(cd['class_data_off'])
        stat['classes_hit'] += 1
        for kind in ('direct', 'virtual'):
            for m in data[kind]:
                if m['code_off'] == 0:
                    stat['methods_skipped'] += 1
                    continue
                # 同一个 code_item 可能被多个 method 引用，只处理一次
                if m['code_off'] in seen_code_off:
                    continue
                seen_code_off.add(m['code_off'])
                ins = dx.read_insns(m['code_off'])
                if not ins:
                    continue
                clazz, midx, proto, mname = dx.method_at(m['method_idx'])
                entries.append({
                    'class_idx': cd['class_idx'],
                    'method_idx': m['method_idx'],
                    'code_off': m['code_off'],
                    'insns_len': len(ins),
                    'insns': ins,
                    'class_name': cname,
                    'method_name': mname,
                    'signature': dx.method_signature(m),
                })
                # 就地写 0 —— dalvik opcode 0x00 就是 nop，所以 dex 仍然合法、仍然能被加载
                dx.write_insns(m['code_off'], b'\x00' * len(ins))
                stat['methods_hit'] += 1
                stat['bytes_hit'] += len(ins)

    if shuffle_table:
        # 三代加一层：侧表按随机顺序存放，脱离 dex 里的 method 顺序
        import random
        random.Random(20260922).shuffle(entries)
    return entries, stat


def do_v2(args):
    outdir = os.path.join(ROOT, 'build', 'v2')
    dx = dexlib.load(MERGED_DEX)
    entries, stat = extract(dx)

    out_dex = dx.finalize()
    table = crypto_lab.build_code_table(entries)

    p_dex = _w(os.path.join(outdir, 'extracted.dex'), out_dex)
    p_tab = _w(os.path.join(outdir, 'ijm_codes.bin'), table)

    new_stats = dexlib.Dex(out_dex).method_code_stats()
    report = {
        'mode': 'v2',
        'input_dex': _rel(MERGED_DEX),
        'input_dex_size': os.path.getsize(MERGED_DEX),
        'classes_dex': _rel(p_dex),
        'classes_dex_size': len(out_dex),
        'code_table': _rel(p_tab),
        'code_table_size': len(table),
        'code_table_header': 'AJMT + int32_le count=%d' % len(entries),
        'extract': stat,
        'after_extract': {
            'methods_total': new_stats['total'],
            'methods_with_code': new_stats['with_code'],
            'methods_empty': new_stats['empty'],
            'empty_ratio': round(new_stats['empty_ratio'], 4),
        },
        'asset_name': 'assets/ijm_codes.bin',
        'note': '类名/方法名还在 dex 里，但方法体全是 nop —— 必须靠侧表回填',
    }
    _w(os.path.join(outdir, 'pack_report.json'),
       json.dumps(report, ensure_ascii=False, indent=2).encode())
    _echo(report)
    return report


def do_v3(args):
    outdir = os.path.join(ROOT, 'build', 'v3')
    targets = args.targets.split(',') if args.targets else ['SecretLogic', 'TokenUtil']
    dx = dexlib.load(MERGED_DEX)
    entries, stat = extract(dx, targets=targets, shuffle_table=True)

    out_dex = dx.finalize()
    table = crypto_lab.build_code_table(entries)

    p_dex = _w(os.path.join(outdir, 'extracted.dex'), out_dex)
    # 三代：资源名不再带 ijiami 字样，改成一个看起来像正常资源的名字
    asset_name = 'assets/brand_res_v3.dat'
    p_tab = _w(os.path.join(outdir, 'brand_res_v3.dat'), table)
    # 诱饵：一个低熵的假配置文件，让"找高熵文件"的朴素判据失手
    decoy = ('{}\n'.format(json.dumps({'version': 3, 'vendor': 'ajm', 'magic': 'AJM'}))).encode() * 3
    p_decoy = _w(os.path.join(outdir, 'config_decoy.txt'), decoy)

    new_stats = dexlib.Dex(out_dex).method_code_stats()
    report = {
        'mode': 'v3',
        'input_dex': _rel(MERGED_DEX),
        'input_dex_size': os.path.getsize(MERGED_DEX),
        'targets': targets,
        'classes_dex': _rel(p_dex),
        'classes_dex_size': len(out_dex),
        'code_table': _rel(p_tab),
        'code_table_size': len(table),
        'decoy': _rel(p_decoy),
        'decoy_size': len(decoy),
        'decoy_entropy_note': '诱饵是低熵明文，专门用来让"按熵找 payload"的判据误报',
        'extract': stat,
        'after_extract': {
            'methods_total': new_stats['total'],
            'methods_with_code': new_stats['with_code'],
            'methods_empty': new_stats['empty'],
            'empty_ratio': round(new_stats['empty_ratio'], 4),
        },
        'asset_name': asset_name,
        'note': '只抽部分业务类，dex 里仍有大量正常方法 —— 整体空率低于阈值，朴素判据会漏报',
    }
    _w(os.path.join(outdir, 'pack_report.json'),
       json.dumps(report, ensure_ascii=False, indent=2).encode())
    _echo(report)
    return report


def _echo(report):
    print('---- pack report (%s) ----' % report['mode'])
    for k, v in report.items():
        if k in ('mode',):
            continue
        print('  %-20s %s' % (k, v))
    print()


def main():
    ap = argparse.ArgumentParser(description='类爱加密三代加壳器')
    ap.add_argument('mode', choices=['v1', 'v2', 'v3', 'all'])
    ap.add_argument('--targets', help='v3: 指定要抽取的类名子串，逗号分隔')
    args = ap.parse_args()

    if not os.path.exists(ORIG_DEX) or not os.path.exists(MERGED_DEX):
        print('缺少输入：先执行 bash build/build_target.sh 与 bash build/build_merged.sh')
        return 1

    if args.mode == 'v1':
        do_v1(args)
    elif args.mode == 'v2':
        do_v2(args)
    elif args.mode == 'v3':
        do_v3(args)
    else:
        do_v1(args)
        do_v2(args)
        do_v3(args)
    return 0


if __name__ == '__main__':
    sys.exit(main())
