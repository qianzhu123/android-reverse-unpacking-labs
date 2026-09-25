#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
reset_lab.py — 实验台复位 / 备份 / 状态（PROMPT.md 要求）

本工程所有"可被污染"的产物都在 samples/。reset_lab 用一份 sha256 清单把
samples/ 的"干净状态"固化到 pristine/，之后随时可以：

    backup    把 samples/ 当前内容快照到 pristine/ 并写 MANIFEST（相对名 -> sha256）
    status    对比 samples/ 与 MANIFEST，报告 OK / DIFF / MISSING / EXTRA
    restore   用 pristine/ 覆盖 samples/（仅当 sha256 不同；--force 强制全量）

为什么不直接用 git：
  样本里有 .apk（带签名）这类二进制，且实验过程中常常要把 samples/ 改坏来
  观察检测/脱壳行为。把"可还原的干净基线"单独用 sha256 管理，比 git checkout
  更轻、更不容易误伤别的改动。

用法：
    python tools/reset_lab.py backup
    python tools/reset_lab.py status
    python tools/reset_lab.py restore [--force]
"""

import argparse
import hashlib
import json
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, 'samples')
PRISTINE = os.path.join(ROOT, 'pristine')
MANIFEST = os.path.join(PRISTINE, 'MANIFEST.json')


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def iter_sample_files():
    """递归遍历 samples/ 下所有文件，返回 (相对路径, 绝对路径)。
    相对路径以 samples/ 为根（如 'apks/app_orig.apk'、'dex/classes_orig.dex'、
    'payloads/brand_res_v3.dat'），作为 MANIFEST 的 key，使 samples/ 内的
    apks/dex/payloads 子目录也能被备份 / 还原。"""
    if not os.path.isdir(SAMPLES):
        return
    for root, _dirs, files in os.walk(SAMPLES):
        for fn in sorted(files):
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, SAMPLES).replace(os.sep, '/')
            yield rel, full


def cmd_backup():
    os.makedirs(PRISTINE, exist_ok=True)
    manifest = {}
    for rel, full in iter_sample_files():
        dst = os.path.join(PRISTINE, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(full, dst)
        manifest[rel] = sha256_file(full)
    with open(MANIFEST, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
    print('[backup] %d 个文件 -> %s' % (len(manifest), PRISTINE))
    for k in sorted(manifest):
        print('  %-40s %s' % (k, manifest[k]))
    return 0


def cmd_status():
    if not os.path.exists(MANIFEST):
        print('[status] 没有 MANIFEST，请先执行 backup')
        return 1
    manifest = json.load(open(MANIFEST, encoding='utf-8'))
    print('[status] 对照 MANIFEST（%d 项）' % len(manifest))
    ok = diff = miss = extra = 0
    for rel, gold in sorted(manifest.items()):
        cur = os.path.join(SAMPLES, rel)
        if not os.path.exists(cur):
            print('  MISSING  %s' % rel)
            miss += 1
            continue
        cur_h = sha256_file(cur)
        if cur_h == gold:
            print('  OK       %s' % rel)
            ok += 1
        else:
            print('  DIFF     %s  (%s.. != %s..)' % (rel, cur_h[:12], gold[:12]))
            diff += 1
    live = dict(iter_sample_files())
    for rel in sorted(live):
        if rel not in manifest:
            print('  EXTRA    %s' % rel)
            extra += 1
    print('=> OK=%d  DIFF=%d  MISSING=%d  EXTRA=%d' % (ok, diff, miss, extra))
    return 0 if (diff == 0 and miss == 0) else 1


def cmd_restore(force):
    if not os.path.exists(MANIFEST):
        print('[restore] 没有 MANIFEST，无法恢复')
        return 1
    manifest = json.load(open(MANIFEST, encoding='utf-8'))
    n = 0
    for rel, gold in sorted(manifest.items()):
        src = os.path.join(PRISTINE, rel)
        dst = os.path.join(SAMPLES, rel)
        if not os.path.exists(src):
            print('  SKIP(无 pristine 副本) %s' % rel)
            continue
        if os.path.exists(dst) and not force and sha256_file(dst) == gold:
            continue
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
        n += 1
        print('  restore %s' % rel)
    print('=> 已恢复 %d 个文件' % n)
    return 0


def main():
    ap = argparse.ArgumentParser(description='实验台复位/备份/状态')
    ap.add_argument('cmd', choices=['backup', 'status', 'restore'])
    ap.add_argument('--force', action='store_true', help='restore 时强制覆盖全部')
    a = ap.parse_args()
    if a.cmd == 'backup':
        return cmd_backup()
    if a.cmd == 'status':
        return cmd_status()
    if a.cmd == 'restore':
        return cmd_restore(a.force)
    return 1


if __name__ == '__main__':
    sys.exit(main())
