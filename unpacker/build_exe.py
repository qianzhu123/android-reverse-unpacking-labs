#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
build_exe.py — 把 unpacker 打成单文件 exe（PyInstaller）。

用法（在仓库根执行）：
  python unpacker/build_exe.py            # 打包 -> dist/unpacker.exe
  python unpacker/build_exe.py --clean    # 打包前清掉 build/ dist/ 缓存

打包内容：
  · unpacker/*.py（analyzer / unpack / regression / labs / main）
  · 三个 lab 的 tools/*.py 作为内置兜底副本（labs_bundle/）——exe 单独分发
    且找不到仓库时仍可做判定与解固；找到仓库时优先用仓库的（与 lab 同步）。
  · 不打进任何第三方二进制（upx.exe 走 PATH / 仓库定位，keystore/exe 均不涉及）。

PyInstaller 细节：
  · onefile 模式，运行时解包到 %TEMP%\_MEIxxxx，labs_bundle 通过 sys._MEIPASS 找到
  · console 模式（工具输出靠 stdout，[!]/[*]/[+] 约定）
"""

import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
DIST = os.path.join(REPO_ROOT, 'dist')
BUILD = os.path.join(REPO_ROOT, 'build')


def prepare_bundle():
    """把三个 lab 的 tools/*.py 复制到 build/labs_bundle/<lab>/tools/。"""
    bundle = os.path.join(BUILD, 'labs_bundle')
    if os.path.exists(bundle):
        shutil.rmtree(bundle)
    for lab in ('360jiagu', 'upx_practice', 'ajiami'):
        src = os.path.join(REPO_ROOT, lab, 'tools')
        if not os.path.isdir(src):
            print('[!] 缺 %s/tools/，无法做内置兜底副本。' % lab)
            return None
        dst = os.path.join(bundle, lab, 'tools')
        os.makedirs(dst, exist_ok=True)
        for f in os.listdir(src):
            if f.endswith('.py'):
                shutil.copy2(os.path.join(src, f), os.path.join(dst, f))
        # anchors.txt 是 solve 的默认锚点清单，也带上
        anc = os.path.join(src, 'anchors.txt')
        if os.path.exists(anc):
            shutil.copy2(anc, os.path.join(dst, 'anchors.txt'))
    print('[+] 内置兜底副本就绪: build/labs_bundle/ (%d 个 lab)' % 3)
    return bundle


def main():
    if '--clean' in sys.argv:
        for d in (DIST, BUILD):
            if os.path.exists(d):
                shutil.rmtree(d)
        print('[+] 已清理 build/ dist/')

    bundle = prepare_bundle()
    if bundle is None:
        return 1

    cmd = [
        sys.executable, '-m', 'PyInstaller',
        '--noconfirm',
        '--onefile',
        '--console',
        '--name', 'unpacker',
        '--paths', HERE,
        '--add-data', '%s;labs_bundle' % bundle,
        os.path.join(HERE, 'main.py'),
    ]
    print('[*] PyInstaller: %s' % ' '.join(cmd[2:]))
    r = subprocess.run(cmd, cwd=REPO_ROOT)
    if r.returncode != 0:
        print('[!] 打包失败。')
        return 1
    exe = os.path.join(DIST, 'unpacker.exe')
    if not os.path.exists(exe):
        print('[!] 未找到产物 %s' % exe)
        return 1
    print('[+] 打包成功: %s (%d bytes)' % (os.path.relpath(exe, REPO_ROOT),
                                           os.path.getsize(exe)))
    print('    验证: dist/unpacker.exe analyze 360jiagu/libtarget_360_variant.so')
    return 0


if __name__ == '__main__':
    sys.exit(main())
