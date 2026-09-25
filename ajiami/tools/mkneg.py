#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
mkneg.py — 组装「负样本 APK」。

为什么不直接改 apkutil.inject_dex：inject-dex 做的是「替换 classes.dex」，
而负样本的核心形态是【多 dex】（把某些 manifest 声明的组件类单独放进
classes2.dex，模拟真实 App 里 AndroidX Provider/Receiver 被分到次级 dex 的情况），
同时还要塞一个「合法但高熵」的 asset 来守 B6/B1。这是另一件事，单独一个脚本更清楚。

用法：
  python tools/mkneg.py <骨架apk> <输出apk> --dex classes.dex=<p> --dex classes2.dex=<p> [--asset <zip内名>=<本地路径>]

示例（见 build/build_negatives.sh）：
  python tools/mkneg.py build/neg/raw.apk samples/neg_multidex.apk \
      --dex classes.dex=build/neg/biz.dex --dex classes2.dex=build/neg/lib.dex
"""

import argparse
import os
import shutil
import zipfile


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('skeleton', help='aapt2 link 产出的 APK 骨架')
    ap.add_argument('out', help='输出 APK')
    ap.add_argument('--dex', action='append', default=[],
                    help='重复传入：<zip内 dex 名>=<本地 dex 路径>')
    ap.add_argument('--asset', action='append', default=[],
                    help='重复传入：<zip内 asset 名>=<本地文件路径>')
    args = ap.parse_args()

    dexes = [tuple(x.split('=', 1)) for x in args.dex]
    assets = [tuple(x.split('=', 1)) for x in args.asset]

    for name, path in dexes + assets:
        if not os.path.exists(path):
            raise SystemExit('找不到输入文件：%s' % path)

    tmp = args.out + '.tmp'
    if os.path.exists(tmp):
        os.remove(tmp)
    shutil.copyfile(args.skeleton, tmp)

    zin = zipfile.ZipFile(args.skeleton, 'r')
    try:
        with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as zout:
            for info in zin.infolist():
                zout.writestr(info, zin.read(info.filename), info.compress_type)
            for name, path in dexes:
                with open(path, 'rb') as f:
                    zout.writestr(name, f.read(), zipfile.ZIP_DEFLATED)
                print('  + dex   %s <- %s (%d bytes)' % (name, path, os.path.getsize(path)))
            for name, path in assets:
                with open(path, 'rb') as f:
                    zout.writestr(name, f.read(), zipfile.ZIP_DEFLATED)
                print('  + asset %s <- %s (%d bytes)' % (name, path, os.path.getsize(path)))
    finally:
        zin.close()

    if os.path.exists(args.out):
        os.remove(args.out)
    os.rename(tmp, args.out)
    print('  已写出 %s' % args.out)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
