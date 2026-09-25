#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
make_variant.py — 把标准样本改造成「变种」。

变种做什么：
  把 classes.dex 的 string 池、以及 AndroidManifest 里所有含家族特征的字符串，
  全部替换成「等长的乱序串」（字母表倒序映射），于是：

    com/ijiami/shell/ProxyApplication  ->  xlw/rqzrnm/hsoow/KurmbZbkovvrgmlrq
    ijiami_shell_version               ->  rqzrnm_hsoow_svmgrlrq

  结果是 ——
    ✗ 搜 "ijiami" 搜不到
    ✗ 看 Application 类名也认不出是爱加密
    ✓ 但 dex 的结构特征（哪些方法的 code_item 是空的、payload 是否存在）
      一个字节都没变 —— 所以 PROMPT 才要求「禁止只靠字符串下结论」

为什么必须"等长"替换：
  dex 的 string_data_item 是 [uleb128 utf16_size][bytes][0x00]，
  只要替换串与被替换串的 ASCII 长度相同，就不需要移动任何数据，
  既不会错位，也不需要重算任何偏移量 —— 这是最安全的最小改写。

用法：
  python tools/make_variant.py v1|v2|all
"""

import json
import os
import shutil
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dexlib
import mkapk

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SKELETON = os.path.join(ROOT, 'build', 'merged', 'merged_raw.apk')

# 只有字符串里含有这些标记时才参与变形（保证 java/lang/Object 之类不被破坏）
RULES = ['ijiami', 'ProxyApplication', 'ShellClassLoader', 'PayloadLoader',
         'ApplicationSwap', 'AJM', 'ijm_']

_LOWER_SRC = 'abcdefghijklmnopqrstuvwxyz_'   # 27
_LOWER_DST = 'zyxwvutsrqponmlkjihgfedcba9'   # 27
_UPPER_SRC = _LOWER_SRC[:-1].upper()         # 26
_UPPER_DST = _LOWER_DST[:-1].upper()         # 26
_TRANS = str.maketrans(_LOWER_SRC + _UPPER_SRC, _LOWER_DST + _UPPER_DST)


def alias(s):
    """等长变形：只换大小写字母和下划线，其它字符（. / ; 等）原样保留。"""
    return s.translate(_TRANS)


def need_rewrite(s):
    return any(r in s for r in RULES)


def patch_dex(src_dex, dst_dex):
    dx = dexlib.load(src_dex)
    changed = []
    seen_off = set()
    for idx in range(dx.string_ids_size):
        s = dx.string_at(idx)
        if not need_rewrite(s):
            continue
        off = dexlib._u4(dx.data, dx.string_ids_off + idx * 4)
        if off in seen_off:      # 同一份 string_data 被多个 idx 引用时只改一次
            continue
        seen_off.add(off)
        size, p = dexlib.read_uleb128(dx.data, off)
        end = dx.data.index(b'\x00', p)
        raw = bytes(dx.data[p:end])
        old = dx.string_at(idx)
        new_s = alias(old)
        new_b = new_s.encode('ascii', 'replace')
        if len(new_b) != len(raw):
            # 理论上不会发生（等长映射），保个底
            continue
        dx.data[p:p + len(new_b)] = new_b
        changed.append((old, new_s, off))
    out = dx.finalize()
    os.makedirs(os.path.dirname(os.path.abspath(dst_dex)) or '.', exist_ok=True)
    with open(dst_dex, 'wb') as f:
        f.write(out)
    return out, changed


def patch_binary_xml(blob):
    """把 APK 里已编译的 AndroidManifest.xml 里的特征串也改掉（同样是等长替换）。"""
    hits = []
    for rule in ['ijiami', 'ProxyApplication', 'ijiami_shell_version',
                 'ijiami_real_application']:
        new_rule = alias(rule)
        # UTF-8 形态
        b = rule.encode()
        nb = new_rule.encode()
        n = blob.count(b)
        if n:
            blob = blob.replace(b, nb)
        # UTF-16LE 形态
        b16 = rule.encode('utf-16-le')
        nb16 = new_rule.encode('utf-16-le')
        n16 = blob.count(b16)
        if n16:
            blob = blob.replace(b16, nb16)
        if n or n16:
            hits.append((rule, new_rule, n, n16))
    return blob, hits


def make_skeleton(out_apk_path, manifest_blob):
    """复制骨架 apk，只替换其中的 AndroidManifest.xml"""
    os.makedirs(os.path.dirname(os.path.abspath(out_apk_path)) or '.', exist_ok=True)
    items = []
    with zipfile.ZipFile(SKELETON) as z:
        for info in z.infolist():
            items.append((info, z.read(info.filename)))
    with zipfile.ZipFile(out_apk_path, 'w', zipfile.ZIP_DEFLATED) as out:
        for info, blob in items:
            if info.filename == 'AndroidManifest.xml':
                out.writestr(info, manifest_blob)
            else:
                out.writestr(info, blob)


def build_variant_v1():
    outdir = os.path.join(ROOT, 'build', 'variant')
    os.makedirs(outdir, exist_ok=True)

    # v1 的 classes.dex 是纯壳 dex（build/v1/classes.dex）
    dex_in = os.path.join(ROOT, 'build', 'v1', 'classes.dex')
    dex_out = os.path.join(outdir, 'classes_v1_variant.dex')
    _, changed = patch_dex(dex_in, dex_out)

    payload = os.path.join(ROOT, 'build', 'v1', 'ijm_payload.bin')
    asset_inner = 'assets/' + alias('ijm_payload.bin')

    with zipfile.ZipFile(SKELETON) as z:
        manifest = z.read('AndroidManifest.xml')
    manifest, hits = patch_binary_xml(manifest)
    skel = os.path.join(outdir, 'skeleton_v1.apk')
    make_skeleton(skel, manifest)

    out = os.path.join(ROOT, 'samples', 'app_packed_v1_variant.apk')
    mkapk.build(skel, out, dex=dex_out, assets=['%s=%s' % (asset_inner, payload)])
    shutil.copy(payload, os.path.join(ROOT, 'samples', 'payload_v1_variant.bin'))
    shutil.copy(dex_out, os.path.join(ROOT, 'samples', 'classes_shell_v1_variant.dex'))

    report = {'mode': 'v1-variant', 'dex_strings_changed': len(changed),
              'dex_samples': [(a, b) for a, b, _ in changed[:8]],
              'manifest_hits': hits, 'asset': asset_inner}
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print('[+] %s' % out)
    return report


def build_variant_v2():
    outdir = os.path.join(ROOT, 'build', 'variant')
    os.makedirs(outdir, exist_ok=True)

    dex_in = os.path.join(ROOT, 'build', 'v2', 'extracted.dex')
    dex_out = os.path.join(outdir, 'classes_v2_variant.dex')
    _, changed = patch_dex(dex_in, dex_out)

    table = os.path.join(ROOT, 'build', 'v2', 'ijm_codes.bin')
    asset_inner = 'assets/' + alias('ijm_codes.bin')

    with zipfile.ZipFile(SKELETON) as z:
        manifest = z.read('AndroidManifest.xml')
    manifest, hits = patch_binary_xml(manifest)
    skel = os.path.join(outdir, 'skeleton_v2.apk')
    make_skeleton(skel, manifest)

    # 变种版的"抽取前原 dex"：给 verify 做黄金对照用（存在 build 下，不放进 samples）
    pristine_src = os.path.join(ROOT, 'build', 'merged', 'merged_classes.dex')
    pristine_out = os.path.join(outdir, 'merged_orig_variant.dex')
    patch_dex(pristine_src, pristine_out)

    out = os.path.join(ROOT, 'samples', 'app_packed_v2_variant.apk')
    mkapk.build(skel, out, dex=dex_out, assets=['%s=%s' % (asset_inner, table)])
    shutil.copy(table, os.path.join(ROOT, 'samples', 'codetable_v2_variant.bin'))
    shutil.copy(dex_out, os.path.join(ROOT, 'samples', 'extracted_v2_variant.dex'))

    report = {'mode': 'v2-variant', 'dex_strings_changed': len(changed),
              'dex_samples': [(a, b) for a, b, _ in changed[:8]],
              'manifest_hits': hits, 'asset': asset_inner}
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print('[+] %s' % out)
    return report


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'all'
    if mode in ('v1', 'all'):
        build_variant_v1()
    if mode in ('v2', 'all'):
        build_variant_v2()
    return 0


if __name__ == '__main__':
    sys.exit(main())
