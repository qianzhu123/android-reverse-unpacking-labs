#!/usr/bin/env python
# solve_variant.py — 变种 UPX 解法 A：特征修复 + 官方解包 + 结果校验
#
# 思路（对应"不要只依赖 UPX 字符串"）：
#   1) 变种把内嵌的 UPX! 魔数替换成了别的 4 字节 token
#   2) 该 token 在文件里会出现多次（stub 里、l_info 里）
#   3) 把它换回 'UPX!' 后，UPX 的校验和才能对上，upx -t / upx -d 才工作
#
# 自动发现 token：枚举"重复出现的 4 字节序列"作为候选，逐个替换并用 upx -t 验证。
#   这不需要事先知道变种用了什么 token。
#
# 【可复用】本脚本不含任何项目专属内容：
#   - upx 路径 : --upx 指定 > 环境变量 UPX > PATH 里的 upx > 项目内兜底
#   - 校验锚点 : --anchor 逐个指定 / --anchors-file 文件(一行一个) /
#                默认读取 <脚本同目录>/anchors.txt（不存在则跳过锚点校验）
#   - 临时文件写入系统临时目录，不污染项目目录
#
# 用法:
#   python solve_variant.py <变种.so> <输出.so> [--orig 原始.so] [--token XXXX]
#                           [--upx PATH] [--anchor 字符串]... [--anchors-file PATH]
import sys, os, subprocess, collections, shutil, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MAGIC = b"UPX!"


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
    """定位 UPX 可执行文件（与具体项目无关）。
    优先级: --upx > 环境变量 UPX > 项目内 upx.exe/upx > PATH 中的 upx/upx.exe > tools/upx396.exe
    项目内优先于 PATH：本 lab 的实测数值基于项目自带版本，换版本可能复现不出同样样本。
    """
    if explicit: return explicit
    env = os.environ.get("UPX")
    if env and os.path.exists(env): return env
    root = ROOT
    for c in (os.path.join(root, "upx.exe"), os.path.join(root, "upx")):
        if os.path.exists(c): return c
    w = _upx_from_path()
    if w: return w
    c = os.path.join(HERE, "upx396.exe")
    if os.path.exists(c): return c
    return None

def load_anchors(explicit=(), anchor_file=None):
    """收集"脱壳后应能找回的锚点字符串"（bytes 列表）。

    如果显式给了 --anchor 或 --anchors-file，就只用这些；
    否则尝试读取脚本同目录的 anchors.txt；都没有则返回空列表（跳过锚点校验）。
    """
    def lines(p):
        return [l.strip() for l in open(p, "rb").read().splitlines()
                if l.strip() and not l.strip().startswith(b"#")]
    if explicit or anchor_file:
        out = [a.encode("utf-8", "surrogateescape") for a in explicit]
        if anchor_file:
            if not os.path.exists(anchor_file):
                print("[!] anchors-file 不存在: %s" % anchor_file)
            else:
                out += lines(anchor_file)
        return out
    default = os.path.join(HERE, "anchors.txt")
    return lines(default) if os.path.exists(default) else []

def upx_t(upx, path):
    try:
        r = subprocess.run([upx, "-t", path], capture_output=True, text=True, timeout=60)
        return r.returncode == 0
    except Exception:
        return False

def candidates(data, limit=60, trailer=96):
    # 统计所有重复出现的 4 字节序列；优先"出现在文件尾部(l_info 附近)"的
    cnt = collections.Counter()
    for i in range(len(data) - 3):
        g = data[i:i + 4]
        if g != MAGIC:
            cnt[g] += 1
    tail = data[max(0, len(data) - trailer):]
    cand = [g for g, c in cnt.items() if c >= 2]
    cand.sort(key=lambda g: (1 if g in tail else 0, cnt[g]), reverse=True)
    return cand[:limit]

def solve(src, out, orig=None, token=None, upx_path=None, anchors=()):
    UPX = find_upx(upx_path)
    if not UPX:
        print("[!] 未找到 upx。请把 upx 加入 PATH，或设置环境变量 UPX，或用 --upx <路径> 指定。")
        return False

    data = bytearray(open(src, "rb").read())
    print("[*] 样本: %s (%d bytes)" % (src, len(data)))
    print("[*] 现有 'UPX!' 数量: %d" % data.count(MAGIC))
    print("[*] 使用的 upx: %s" % _disp(UPX))

    tried = []
    if token:
        tried = [token.encode()]
    if data.count(MAGIC) == 0:
        tried += candidates(bytes(data))
    found = None
    tmp = os.path.join(tempfile.gettempdir(), "_solve_probe.so")
    for tok in tried:
        if data.count(tok) == 0: continue
        patched = bytearray(bytes(data).replace(tok, MAGIC))
        open(tmp, "wb").write(patched)
        ok = upx_t(UPX, tmp)
        print("    候选 token %r x%d -> upx -t %s" % (tok, data.count(tok), "OK" if ok else "FAIL"))
        if os.path.exists(tmp): os.remove(tmp)
        if ok:
            found = (tok, patched); break
    if not found:
        print("[!] 未能通过特征修复使 upx -t 通过 -> 该变种改了 Stub/校验，需走内存 dump 路线")
        return False

    tok, patched = found
    print("[+] 确定被篡改的 token: %r -> 还原为 'UPX!'（共 %d 处）" % (tok, data.count(tok)))
    repaired = os.path.join(tempfile.gettempdir(), "_solve_repaired.so")
    open(repaired, "wb").write(patched)

    # 用官方 UPX 解包
    if os.path.exists(out): os.remove(out)
    r = subprocess.run([UPX, "--force-overwrite", "-d", repaired, "-o", out],
                       capture_output=True, text=True)
    if os.path.exists(repaired): os.remove(repaired)
    if not os.path.exists(out):
        print("[!] upx -d 失败:", r.stdout.strip(), r.stderr.strip()); return False
    rec = open(out, "rb").read()
    print("[+] 解包成功: %s (%d bytes)" % (out, len(rec)))

    # 校验锚点
    if not anchors:
        print("\n[*] 未配置锚点，跳过锚点校验（可用 --anchor 指定，或放 anchors.txt）")
    else:
        print("\n[*] 校验：脱壳后应找回的锚点")
        for a in anchors:
            s = a.decode("utf-8", "replace")
            print("    %-30s %s" % (s, "OK 找到" if a in rec else "-- 缺失"))

    if orig:
        o = open(orig, "rb").read()
        print("\n[*] 与原始 SO 对比: %s (%d bytes)" % (orig, len(o)))
        print("    大小: %d vs %d  %s" % (len(rec), len(o),
              "一致" if len(rec) == len(o) else "不一致"))
        if len(rec) == len(o):
            # e_type(偏移16,2字节)可能因打包形式不同而不同，比较时忽略
            diff = [k for k in range(len(o)) if rec[k] != o[k] and not (16 <= k < 18)]
            print("    除 e_type 外差异字节数: %d  %s" % (len(diff),
                  "=> 内容一致，脱壳成功" if len(diff) == 0 else ""))
            if diff:
                print("    差异位置示例:", [hex(k) for k in diff[:10]])
    return True

if __name__ == "__main__":
    argv = sys.argv[1:]
    pos = [a for a in argv if not a.startswith("--")]
    if len(pos) < 2:
        print(__doc__)
        sys.exit(1)

    def val(flag):
        i = argv.index(flag)
        return argv[i + 1] if i + 1 < len(argv) else None

    orig = val("--orig") if "--orig" in argv else (pos[2] if len(pos) > 2 else None)
    token = val("--token") if "--token" in argv else None
    upx_path = val("--upx") if "--upx" in argv else None
    anchor_file = val("--anchors-file") if "--anchors-file" in argv else None

    anchors = []
    i = 0
    while i < len(argv):
        if argv[i] == "--anchor" and i + 1 < len(argv):
            anchors.append(argv[i + 1]); i += 2
        else:
            i += 1

    solve(pos[0], pos[1], orig, token, upx_path, load_anchors(anchors, anchor_file))
