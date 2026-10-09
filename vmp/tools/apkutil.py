#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
apkutil.py — APK(zip) 层的通用操作 + 熵计算。

子命令：
  extract-dex <d8输出的zip> <out.dex>        从 d8 产出的 zip 里取出 classes.dex
  inject-dex <apk> <dex> <out.apk>           替换/插入 APK 里的 classes.dex
  add-file  <apk> <zip内路径> <本地文件> <out.apk>
  entries   <apk>                            列出 ZIP 条目（大小/CRC/压缩方式）
  entropy   <file>                           计算香农熵
  entropy   <apk> <zip内的文件名>            计算 APK 内某成员的熵（免解包）
"""

import os
import sys
import zipfile
import math


def extract_dex(zip_path, out_path, member='classes.dex'):
    with zipfile.ZipFile(zip_path) as z:
        data = z.read(member)
    _write(out_path, data)
    return len(data)


def inject_dex(apk_in, dex_path, apk_out, member='classes.dex'):
    """替换 APK 内的 classes.dex。保持 DEFLATED + 对齐友好。"""
    with open(dex_path, 'rb') as f:
        dex = f.read()
    names = None
    with zipfile.ZipFile(apk_in) as z:
        items = [(i, z.read(i.filename)) for i in z.infolist()]
        names = [i.filename for i in z.infolist()]
    os.makedirs(os.path.dirname(os.path.abspath(apk_out)) or '.', exist_ok=True)
    seen = False
    with zipfile.ZipFile(apk_out, 'w', zipfile.ZIP_DEFLATED) as out:
        for info, blob in items:
            if info.filename == member:
                _put(out, member, dex)
                seen = True
            else:
                out.writestr(info, blob)
        if not seen:
            _put(out, member, dex)
    return True


def add_file(apk_in, inner, local, apk_out):
    with open(local, 'rb') as f:
        data = f.read()
    with zipfile.ZipFile(apk_in) as z:
        items = [(i, z.read(i.filename)) for i in z.infolist()]
    with zipfile.ZipFile(apk_out, 'w', zipfile.ZIP_DEFLATED) as out:
        for info, blob in items:
            if info.filename == inner:
                continue
            out.writestr(info, blob)
        _put(out, inner, data)
    return True


def _put(zf, name, data):
    info = zipfile.ZipInfo(name)
    info.compress_type = zipfile.ZIP_DEFLATED
    zf.writestr(info, data)


def entries(apk):
    out = []
    with zipfile.ZipFile(apk) as z:
        for i in z.infolist():
            out.append((i.filename, i.file_size, i.compress_size, i.compress_type))
    return out


def shannon_entropy(data):
    """返回 0~8 bit/byte 的香农熵。>7.5 基本可以判定为压缩或加密过的 payload。"""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = float(len(data))
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log(p, 2)
    return h


def _write(path, data):
    d = os.path.dirname(os.path.abspath(path))
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, 'wb') as f:
        f.write(data)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    cmd = sys.argv[1]
    if cmd == 'extract-dex':
        n = extract_dex(sys.argv[2], sys.argv[3])
        print('extracted %d bytes -> %s' % (n, sys.argv[3]))
    elif cmd == 'inject-dex':
        inject_dex(sys.argv[2], sys.argv[3], sys.argv[4])
        print('injected %s -> %s' % (sys.argv[3], sys.argv[4]))
    elif cmd == 'add-file':
        add_file(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
        print('added %s -> %s' % (sys.argv[3], sys.argv[5]))
    elif cmd == 'entries':
        for name, size, csize, ct in entries(sys.argv[2]):
            print('%-50s %10d %10d  %s' % (name, size, csize,
                                           'DEFLATE' if ct == zipfile.ZIP_DEFLATED else 'STORE'))
    elif cmd == 'entropy':
        path = sys.argv[2]
        if path.lower().endswith(('.apk', '.zip', '.jar')) and len(sys.argv) > 3:
            # APK(zip) 内成员：entropy <apk> <zip内的文件名>
            member = sys.argv[3]
            with zipfile.ZipFile(path) as z:
                d = z.read(member)
            print('%s  %.4f bit/byte  (%d bytes)' % (member, shannon_entropy(d), len(d)))
        else:
            with open(path, 'rb') as f:
                d = f.read()
            print('%.4f bit/byte  (%d bytes)' % (shannon_entropy(d), len(d)))
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
