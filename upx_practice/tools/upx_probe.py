#!/usr/bin/env python
# upx_probe.py — 对样本执行官方 UPX 的 -t / -l / -d，记录成功/失败
# 对应文档第一步"先排除标准 UPX"：upx -t 检查, upx -l 看信息, upx -d 解包。
#
# 【可复用】不依赖任何具体项目：upx 通过 --upx / 环境变量 UPX / PATH 定位。
#
# 用法:
#   python upx_probe.py <file> [<file> ...] [--upx <path>]
import sys, os, subprocess, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _disp(p):
    """产物/日志里不落绝对路径：工程内路径显示成相对路径，工程外只显示文件名。"""
    try:
        rp = os.path.relpath(os.path.abspath(p), ROOT)
        if not rp.startswith('..'):
            return rp.replace('\\', '/')
    except Exception:
        pass
    return os.path.basename(p)

def _upx_from_path():
    """在 PATH 里找 upx。
    注意: Windows 下 shutil.which() 会优先搜索"当前目录"，会让项目自带的 upx.exe
    意外盖掉系统 upx，所以这里手动遍历 PATH 并跳过当前目录。
    """
    cwd = os.path.abspath(os.getcwd())
    names = ("upx.exe", "upx") if os.name == "nt" else ("upx",)
    for d in (os.environ.get("PATH") or "").split(os.pathsep):
        d = d.strip().strip('"')
        if not d: continue
        try:
            if os.path.abspath(d) == cwd: continue
        except Exception:
            continue
        for n in names:
            p = os.path.join(d, n)
            if os.path.isfile(p): return p
    return None

def find_upx(explicit=None):
    """优先级: --upx > 环境变量 UPX > 项目内 upx.exe/upx > PATH 中的 upx/upx.exe > tools/upx396.exe

    项目内优先于 PATH：本 lab 的实测数值基于项目自带版本，换版本可能复现不出同样样本；
    要换版本请显式 --upx / UPX=，不要靠 PATH 偷偷切。
    """
    if explicit: return explicit
    env = os.environ.get("UPX")
    if env and os.path.exists(env): return env
    root = ROOT
    for c in (os.path.join(root, "upx.exe"), os.path.join(root, "upx")):
        if os.path.exists(c): return c
    w = _upx_from_path()
    if w: return w
    for c in (os.path.join(HERE, "upx396.exe"),):
        if os.path.exists(c): return c
    return None

def make_runner(UPX):
    def run(args):
        try:
            r = subprocess.run([UPX] + args, capture_output=True, text=True, timeout=60)
            return r.returncode, (r.stdout + r.stderr).strip()
        except Exception as e:
            return -1, str(e)
    return run

def probe(path, run):
    print("=" * 60)
    print("SAMPLE:", _disp(path))
    rc, out = run(["-t", path])
    print("  upx -t : %s" % (("OK" if rc == 0 else "FAIL") + "  (rc=%d)" % rc))
    if rc == 0:
        for line in out.splitlines():
            if "testing" in line or "OK" in line: print("          " + line.strip())
    rc, out = run(["-l", path])
    print("  upx -l : %s" % ("OK" if rc == 0 else "FAIL (rc=%d)" % rc))
    if rc == 0:
        for line in out.splitlines():
            if "linux" in line or "Format" in line or "Ratio" in line or "->" in line:
                print("          " + line.strip())
    # 解包产物落到 analysis_output/（reset_lab 会清理；路径保持相对，不落系统临时目录）
    outdir = os.path.join(ROOT, "analysis_output")
    os.makedirs(outdir, exist_ok=True)
    tmp = os.path.join(outdir, os.path.basename(path) + ".probed_unpacked.so")
    rc, out = run(["-d", path, "-o", tmp])
    if rc == 0 and os.path.exists(tmp):
        sz = os.path.getsize(tmp)
        print("  upx -d : OK -> %s (%d bytes)" % (_disp(tmp), sz))
        os.remove(tmp)
    else:
        print("  upx -d : FAIL (rc=%d) -- 需要手工/动态脱壳" % rc)
    print()

if __name__ == '__main__':
    argv = sys.argv[1:]
    files = [a for a in argv if not a.startswith("--")]
    upx_path = None
    if "--upx" in argv and argv.index("--upx") + 1 < len(argv):
        upx_path = argv[argv.index("--upx") + 1]
    UPX = find_upx(upx_path)
    if not UPX:
        print("[!] 未找到 upx。请把 upx 加入 PATH，或设置环境变量 UPX，或用 --upx <路径> 指定。")
        sys.exit(1)
    if not files:
        print("用法: python upx_probe.py <file> [<file> ...] [--upx <path>]")
        sys.exit(1)
    print("[*] 使用的 upx: %s\n" % _disp(UPX))
    for p in files:
        probe(p, make_runner(UPX))
