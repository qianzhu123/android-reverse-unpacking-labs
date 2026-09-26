#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
main.py — unpacker.exe 的入口。

  unpacker.exe                    # 双击/无参数 → 打开图形界面（拖放 + 按钮）
  unpacker.exe gui                # 同上（显式）
  unpacker.exe analyze  <文件>... # CLI：判定（只读体检）
  unpacker.exe unpack   <文件>    # CLI：解固（判定→路由→验证）
  unpacker.exe regression         # CLI：全仓回归矩阵

与源码版（unpacker/*.py）的差异——exe 打包后没有仓库源码目录，因此：
  ① 仓库根的定位：命令行 --repo > 环境变量 ANDROID_REVERSE_LABS >
     exe 同目录向上 4 级找 360jiagu/upx_practice/ajiami > exe 内置兜底副本。
     找不到仓库时：SO 判定可用（检测逻辑已随包打进 exe），DEX 管线与解固路由
     依赖 lab 模块，用内置副本兜底（不保证与 lab 最新代码同步）。
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
        # 无参数：exe 双击 → 直接开 GUI（这正是"打开一个界面"的主入口）
        repo, err = _setup(repo_arg)
        if err:
            print('[!] ' + err)
            input('回车退出...')
            return 2
        import gui
        gui.launch(repo)
        return 0

    cmd = argv[0]
    rest = argv[1:]

    if cmd in ('gui', '--gui'):
        repo, err = _setup(repo_arg)
        if err:
            print('[!] ' + err)
            return 2
        import gui
        gui.launch(repo)
        return 0
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
    else:
        # 未知子命令：当作文件路径直接判定（把文件拖到 exe 图标上的场景）
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
        print('[!] 未知命令: %s（可用: analyze / unpack / regression / gui；无参数=开界面）' % cmd)
        return 2


if __name__ == '__main__':
    sys.exit(main())
