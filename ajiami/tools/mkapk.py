#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
mkapk.py — 组装最终 APK：替换 classes.dex / 添加 assets / zipalign / 签名。

用法：
  python tools/mkapk.py <骨架apk> <输出apk> --dex <dex文件> [--asset <zip内路径>=<本地文件> ...]

它依赖 build/env.sh 导出的环境变量（先 source build/env.sh）：
  AJ_JAVA AJ_ZIPALIGN AJ_APKSIGNER_JAR AJ_KEYSTORE AJ_KEY_ALIAS AJ_STOREPASS AJ_KEYPASS

之所以不直接用 python 实现 zipalign/签名：
  这两个步骤的语义（对齐单位、v2/v3 签名块）用官方工具最可靠，
  Python 这边只负责把 dex 与 payload 正确地摆进 zip 里。
"""

import os
import subprocess
import sys
import tempfile
import zipfile

import envload

# 直接从 build/env.sh 读取 AJ_* 配置 —— 无需先在 shell 里 source，
# 因此 PowerShell / CMD 下也能直接跑（source/export 是 bash 专有语法）。
envload.ensure_env()

REQUIRED_ENV = ['AJ_JAVA', 'AJ_ZIPALIGN', 'AJ_APKSIGNER_JAR', 'AJ_KEYSTORE',
                'AJ_KEY_ALIAS', 'AJ_STOREPASS', 'AJ_KEYPASS']


def _env(name):
    v = os.environ.get(name)
    if not v:
        raise SystemExit('缺少环境变量 %s —— 本工具会自动从 build/env.sh 读取，'
                         '请检查该文件里是否导出了它' % name)
    return v


def build(skeleton, out, dex=None, assets=None):
    env = {k: _env(k) for k in REQUIRED_ENV}

    # 1) 读取骨架，替换 classes.dex，追加 assets
    tmp_dir = tempfile.mkdtemp(prefix='ajmmk_')
    stage1 = os.path.join(tmp_dir, 'stage1.apk')
    items = []
    with zipfile.ZipFile(skeleton) as z:
        for info in z.infolist():
            items.append((info, z.read(info.filename)))

    dex_blob = open(dex, 'rb').read() if dex else None
    asset_map = {}
    for a in (assets or []):
        inner, local = a.split('=', 1)
        asset_map[inner] = open(local, 'rb').read()

    with zipfile.ZipFile(stage1, 'w', zipfile.ZIP_DEFLATED) as out_z:
        for info, blob in items:
            if dex_blob is not None and info.filename == 'classes.dex':
                continue
            out_z.writestr(info, blob)
        if dex_blob is not None:
            _put(out_z, 'classes.dex', dex_blob)
        for inner, blob in asset_map.items():
            _put(out_z, inner, blob)

    # 2) zipalign
    stage2 = os.path.join(tmp_dir, 'aligned.apk')
    subprocess.run([env['AJ_ZIPALIGN'], '-f', '4', stage1, stage2], check=True)

    # 3) apksigner
    cmd = [env['AJ_JAVA'], '-jar', env['AJ_APKSIGNER_JAR'], 'sign',
           '--ks', env['AJ_KEYSTORE'], '--ks-key-alias', env['AJ_KEY_ALIAS'],
           '--ks-pass', 'pass:' + env['AJ_STOREPASS'],
           '--key-pass', 'pass:' + env['AJ_KEYPASS'],
           '--out', os.path.abspath(out), stage2]
    subprocess.run(cmd, check=True)

    with zipfile.ZipFile(out) as z:
        names = [i.filename for i in z.infolist()]
    return sorted(names)


def _put(zf, name, data):
    info = zipfile.ZipInfo(name)
    info.compress_type = zipfile.ZIP_DEFLATED
    zf.writestr(info, data)


def main(argv):
    args = argv[1:]
    assets = []
    dex = None
    positional = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == '--dex':
            dex = args[i + 1]
            i += 2
        elif a == '--asset':
            assets.append(args[i + 1])
            i += 2
        else:
            positional.append(a)
            i += 1
    if len(positional) < 2:
        print(__doc__)
        return 1
    skeleton, out = positional[0], positional[1]
    os.makedirs(os.path.dirname(os.path.abspath(out)) or '.', exist_ok=True)
    names = build(skeleton, out, dex, assets)
    print('[+] %s' % out)
    print('    entries: %s' % ', '.join(names))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
