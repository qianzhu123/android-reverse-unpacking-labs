#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
build_exe.py — 把 unpacker 打成单文件 exe（PyInstaller），一次出两个：

  unpacker/dist/unpacker.exe      GUI 版（--noconsole：双击只出界面，无黑色控制台窗口）
  unpacker/dist/unpacker-cli.exe  CLI 版（--console：analyze/unpack/regression 子命令用）

用法（在仓库根执行）：
  python unpacker/build_exe.py            # 打包两个 exe
  python unpacker/build_exe.py --clean    # 打包前清掉 unpacker/build/ dist/ 缓存

所有构建产物都收在 unpacker/ 内部（build/ dist/ labs_bundle 临时副本），
不在仓库根目录留任何东西。

打包内容：
  · unpacker/*.py（analyzer / unpack / regression / labs / gui / main）
  · 三个 lab 的 tools/*.py 作为内置兜底副本（labs_bundle/）——exe 单独分发
    且找不到仓库时仍可做判定与解固；找到仓库时优先用仓库的（与 lab 同步）。
  · tkinterdnd2（原生 tkdnd 库，--collect-all 收进来）
  · 不打进任何第三方二进制（upx.exe 走 PATH / 仓库定位，keystore/exe 均不涉及）。

PyInstaller 细节：
  · onefile 模式，运行时解包到 %TEMP%\_MEIxxxx，labs_bundle 通过 sys._MEIPASS 找到
  · GUI 版 --noconsole 下 sys.stdout/stderr 为 None——main.py 已做兜底
    （替换成可丢弃流；错误改走 tk 弹窗）
"""

import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
DIST = os.path.join(HERE, 'dist')
BUILD = os.path.join(HERE, 'build')


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


def build_one(name, console):
    """打一个 exe。console=False 时 GUI 版不带黑色控制台窗口（双击只出界面）。"""
    cmd = [
        sys.executable, '-m', 'PyInstaller',
        '--noconfirm',
        '--onefile',
        '--name', name,
        '--paths', HERE,
        '--add-data', '%s;labs_bundle' % os.path.join(os.path.relpath(BUILD, HERE)),
        '--collect-all', 'tkinterdnd2',
    ]
    if console:
        cmd.append('--console')
    else:
        cmd.append('--noconsole')
    cmd.append(os.path.join(HERE, 'main.py'))
    print('[*] PyInstaller[%s]: %s' % (name, ' '.join(cmd[2:])))
    r = subprocess.run(cmd, cwd=HERE)
    if r.returncode != 0:
        print('[!] %s 打包失败。' % name)
        return None
    exe = os.path.join(DIST, name + '.exe')
    if not os.path.exists(exe):
        print('[!] 未找到产物 %s' % exe)
        return None
    print('[+] 打包成功: unpacker/dist/%s.exe (%d bytes)%s' % (
        name, os.path.getsize(exe), '' if console else '  (无黑色控制台窗口)'))
    return exe


def main():
    if '--clean' in sys.argv:
        for d in (DIST, BUILD):
            if os.path.exists(d):
                shutil.rmtree(d)
        print('[+] 已清理 build/ dist/')

    bundle = prepare_bundle()
    if bundle is None:
        return 1

    # 两个产物：
    #   unpacker.exe     GUI 版（--noconsole：双击只出界面，无黑色窗口）——分发主形态
    #   unpacker-cli.exe CLI 版（--console：analyze/unpack/regression 子命令用）
    # 同一份 main.py：GUI 版跑 CLI 子命令时错误改走弹窗；stdout 为 None 已在 main.py 兜底。
    ok = True
    for name, console in (('unpacker', False), ('unpacker-cli', True)):
        if build_one(name, console) is None:
            ok = False
    if not ok:
        return 1
    print('[*] 验证:')
    print('    unpacker/dist/unpacker.exe            # 双击=GUI（无黑色窗口）；也支持 gui 子命令')
    print('    unpacker/dist/unpacker-cli.exe analyze 360jiagu/libtarget_360_variant.so')
    print('    unpacker/dist/unpacker-cli.exe regression')
    return 0


if __name__ == '__main__':
    sys.exit(main())
