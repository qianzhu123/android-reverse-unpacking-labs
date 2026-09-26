#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
main.py — unpacker.exe 的入口。单 exe 多命令：

  unpacker.exe analyze  <文件>... [--json] [--verify]   # 判定（只读体检）
  unpacker.exe unpack   <文件> [-o 目录] [--pristine X] # 解固（判定→路由→验证）
  unpacker.exe regression [--json]                       # 全仓回归矩阵
  unpacker.exe gui                                        # 无参数拖拽/双击友好入口

与源码版（unpacker/*.py）的差异——exe 打包后没有仓库源码目录，因此：
  ① 仓库根的定位：命令行 --repo > 环境变量 ANDROID_REVERSE_LABS >
     exe 同目录 > exe 同目录下按名找 360jiagu/upx_practice/ajiami > 仓库内打包兜底。
     找不到仓库时：analyze 的 SO 管线可用（检测逻辑已随包打进 exe），
     但 DEX 管线与 unpack 解固路由依赖 lab 模块，会明确报错并给出设置方法。
  ② 打包时用 --add-data 把三个 lab 的 tools/*.py 一起收进 exe，
     优先用内置副本；仓库存在时用仓库的（保证与 lab 同步更新）。

输出纪律不变：[!]=失败 [*]=步骤 [+]=成功；认知边界永远随结论打印。
"""

import os
import sys

# 控制台中文输出：exe 场景没有 PYTHONIOENCODING 时 Windows 控制台默认 GBK，
# 本工具全中文输出，统一强制 UTF-8（Python 3.7+ 重配置 stdout 即时生效）。
os.environ.setdefault('PYTHONIOENCODING', 'utf-8')
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding='utf-8')
    except Exception:
        pass


def _resolve_repo(cli_repo=None):
    """exe 场景下定位仓库根：CLI > env > exe 旁 > exe 旁按名搜索 > 打包内置。"""
    here = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, 'frozen', False)
                                           else __file__))
    cands = []
    if cli_repo:
        cands.append(os.path.abspath(cli_repo))
    if os.environ.get('ANDROID_REVERSE_LABS'):
        cands.append(os.path.abspath(os.environ['ANDROID_REVERSE_LABS']))
    cands.append(here)
    # exe 放在仓库根或仓库某子目录时，向上找带三个 lab 名的目录
    d = here
    for _ in range(4):
        if all(os.path.isdir(os.path.join(d, n)) for n in ('360jiagu', 'upx_practice', 'ajiami')):
            cands.insert(2, d)  # 内置优先级仅次于显式指定
            break
        d = os.path.dirname(d)
    for c in cands:
        if all(os.path.isdir(os.path.join(c, n)) for n in ('360jiagu', 'upx_practice', 'ajiami')):
            return c
    # 打包内置副本（PyInstaller --add-data 解包到 _MEIPASS/labs_bundle）
    meip = getattr(sys, '_MEIPASS', '')
    if meip:
        b = os.path.join(meip, 'labs_bundle')
        if os.path.isdir(b):
            return b
    return None


def _setup(cli_repo=None):
    """设置 labs.REPO_ROOT（若仓库可用）并返回可用性说明。"""
    repo = _resolve_repo(cli_repo)
    import labs
    if repo:
        labs.REPO_ROOT = repo
        return repo, None
    return None, ('未找到练习工程目录（需要 360jiagu / upx_practice / ajiami 三个子目录）。\n'
                  '解决方式任选其一：把 exe 放进仓库根目录；或设环境变量 '
                  'ANDROID_REVERSE_LABS=<仓库根>；或用 --repo <仓库根> 参数。')


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    # 剥全局参数 --repo <path>
    repo_arg = None
    if '--repo' in argv:
        i = argv.index('--repo')
        if i + 1 < len(argv):
            repo_arg = argv[i + 1]
            argv = argv[:i] + argv[i + 2:]
        else:
            print('[!] --repo 需要一个路径参数。')
            return 2

    if not argv or argv[0] in ('-h', '--help', 'help'):
        print(__doc__)
        print('用法示例（在仓库根目录放 exe 时）：')
        print('  unpacker.exe analyze 360jiagu/libtarget_360_variant.so')
        print('  unpacker.exe unpack 360jiagu/libtarget_360_variant.so --pristine 360jiagu/libtarget_orig.so')
        print('  unpacker.exe regression')
        return 0

    cmd = argv[0]
    rest = argv[1:]

    if cmd == 'analyze':
        repo, err = _setup(repo_arg)
        if err:
            print('[!] ' + err)
            return 2
        import analyzer
        return analyzer.main_with_repo(rest, repo)
    elif cmd == 'unpack':
        repo, err = _setup(repo_arg)
        if err:
            print('[!] ' + err)
            return 2
        import unpack
        return unpack.main_with_repo(rest, repo)
    elif cmd == 'regression':
        repo, err = _setup(repo_arg)
        if err:
            print('[!] ' + err)
            return 2
        import regression
        return regression.main_with_repo(rest, repo)
    elif cmd == 'gui':
        # 双击/拖拽兜底：把 exe 当"对单文件做判定"用
        repo, err = _setup(repo_arg)
        if err:
            print('[!] ' + err)
            return 2
        files = rest
        if not files:
            print('[*] 未给文件。把文件拖到 exe 图标上，或：unpacker.exe gui <文件>...')
            input('回车退出...')
            return 0
        import analyzer
        rc = analyzer.main_with_repo(files, repo)
        try:
            input('\n回车退出...')
        except EOFError:
            pass
        return rc
    else:
        # 未知子命令：当作文件路径直接判定（与 gui 相同语义，兼容拖拽）
        repo, err = _setup(repo_arg)
        if err:
            print('[!] ' + err)
            return 2
        if os.path.exists(cmd) or cmd.lower().endswith(('.apk', '.so', '.dex', '.xapk')):
            import analyzer
            rc = analyzer.main_with_repo(argv, repo)
            try:
                if getattr(sys, 'frozen', False):
                    input('\n回车退出...')
            except EOFError:
                pass
            return rc
        print('[!] 未知命令: %s（可用: analyze / unpack / regression / gui）' % cmd)
        return 2


if __name__ == '__main__':
    sys.exit(main())
