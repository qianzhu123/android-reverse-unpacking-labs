#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
unpack.py — 统一解固工具 · 解固入口（判定 → 按壳种路由到对应解法 → 验证）。

用法：
  python unpacker/unpack.py <文件> -o <输出目录> [--pristine <黄金样本>] [--keep]

流程（与各 lab SCRIPT.md 的「判定→脱壳→验证」三步完全同源）：
  ① 判定：调 analyzer.analyze()（只读体检）
  ② 路由：按判定结论选解法——
       标准 UPX/360 壳     -> upx -d 直接解（用 PATH 里的 upx；与 lab 默认行为的差异见下）
       变种 UPX/360 壳     -> 复用 lab 的 solve（候选 token 逐个打补丁 upx -t 实证 → 还原 → -d）
       ajiami 一代         -> 复用 lab 的 unpack_v1（payload 解密还原 dex）
       ajiami 二/三代      -> 复用 lab 的 unpack_v2（AJMT 侧表回填 insns）
       疑似(VMP/B13/Java2CPP) / 未见已知特征 -> 拒绝解固（认知边界：静态不可解，须动态 trace）
  ③ 验证：两级验证等级，如实报告——
       byte-exact：给了 --pristine 黄金样本 → sha256 / 逐字节比对（lab 验证等级）
       anchor-only：无黄金样本 → 只验证脱壳产物锚点/结构，明确说明「无字节级对照」

upx 版本约定（重要——与本机 PATH 中的 upx 5.2.1 实测冲突的教训）：
  本工具**默认用 PATH 里的 upx**（用户环境已装好，且实测 5.2.1 能解开本仓库全部
  标准/变种 UPX 样本）。但注意 upx 的 env-var 语义坑：**UPX 这个环境变量会被
  upx 自身当成选项字符串解析**，设成 exe 路径会让 upx 5.2.1 直接报
  "invalid string ... in environment variable 'UPX'" 而拒绝工作——lab 的
  solve 脚本恰好在 env 里找不到 UPX 时才会回退 PATH，因此：
    · 本工具调用 lab solve 之前，会把进程 env 里的 UPX 变量**临时摘掉**，
      强制它走 --upx 显式参数（值 = 我们解析到的 PATH upx），杜绝这个坑。
    · 若 PATH 没有 upx，则回退用各 lab 自带的 upx.exe（4.2.4，lab 实测基线）。

输出纪律（PROMPT.md）：[!]=失败告警 [*]=步骤 [+]成功；产物一律写进 -o 目录，
不污染样本所在目录；每步都有明确结论行，失败时给「下一步该做什么」。
"""

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import labs  # noqa: E402
from analyzer import analyze, sniff_kind  # noqa: E402


# ---------------------------------------------------------------- upx 定位
def find_upx_path():
    """PATH 优先（用户环境装好的 upx 5.2.1 实测可用），lab 自带 4.2.4 兜底。"""
    for name in ('upx.exe', 'upx'):
        w = shutil.which(name)
        if w:
            return os.path.abspath(w)
    for lab in ('360jiagu', 'upx_practice'):
        cand = os.path.join(REPO_ROOT, lab, 'upx.exe')
        if os.path.exists(cand):
            return cand
    return None


def sha256_file(p):
    return hashlib.sha256(open(p, 'rb').read()).hexdigest()


def byte_diff_excl_etype(a_path, b_path):
    """lab 的 SO 验证口径：忽略 e_type(偏移16,2字节) 后的逐字节差异。"""
    a = open(a_path, 'rb').read()
    b = open(b_path, 'rb').read()
    if len(a) != len(b):
        return len(a), len(b), -1  # 大小都不同
    diff = [k for k in range(len(a)) if a[k] != b[k] and not (16 <= k < 18)]
    return len(a), len(b), len(diff)


# ---------------------------------------------------------------- SO 解法
def unpack_so_std(path, out):
    """标准壳：upx -d 直接解。"""
    upx = find_upx_path()
    if not upx:
        print('[!] 未找到 upx（PATH 与 lab 目录都没有）。安装 upx 或把任一 lab 的 upx.exe 放回原处。')
        return False
    print('[*] 使用 upx: %s' % upx)
    r = subprocess.run([upx, '--force-overwrite', '-d', path, '-o', out],
                       capture_output=True, text=True, env=_env_no_upxvar())
    if r.returncode != 0 or not os.path.exists(out):
        print('[!] upx -d 失败: %s' % (r.stderr or r.stdout).strip()[:200])
        print('    下一步：确认样本真的可被 upx 解（analyzer 判定应为"标准壳"）；'
              '变种壳请让本工具走 solve 路线而不是直接 -d。')
        return False
    print('[+] 解包成功: %s (%d bytes)' % (out, os.path.getsize(out)))
    return True


def unpack_so_variant(path, out, orig=None, lab='360jiagu'):
    """变种壳：复用 lab 的 solve（候选 token 实证还原 → upx -d）。"""
    solve = labs.load_360_solve() if lab == '360jiagu' else labs.load_upx_solve()
    anchors_file = labs.lab_path(lab, 'tools', 'anchors.txt')
    anchors = solve.load_anchors((), anchors_file) if os.path.exists(anchors_file) else ()
    upx = find_upx_path()
    # 关键：显式传 --upx（进程 env 的 UPX 变量会被 upx 5.2.1 当选项串解析而报错）
    ok = solve.solve(path, out, orig=orig, token=None, upx_path=upx, anchors=anchors)
    if not ok:
        print('[!] 特征修复解包失败——该变种可能改了 Stub/校验（解法 A 失效）。')
        print('    下一步：走解法 B（真机/模拟器运行 + Frida dump + dump_fix.py ELF Fix），'
              '参见 %s 的 MANUAL/README §5。' % lab)
    return ok


# ------------------------------------------------------------- ajiami 解法
def unpack_ajiami_v1(apk, out, pristine=None):
    """一代：payload 解密。lab 脚本接口是 main() CLI，这里用受控 argv 调用。"""
    mod = labs.load_ajiami_unpack_v1()
    argv = [apk, out]
    if pristine:
        argv += ['--pristine', pristine]
    old = sys.argv
    try:
        sys.argv = ['unpack_v1.py'] + argv
        rc = mod.main()
    finally:
        sys.argv = old
    return rc == 0


def unpack_ajiami_v2(apk, out, pristine=None):
    """二/三代：AJMT 侧表回填。"""
    mod = labs.load_ajiami_unpack_v2()
    argv = [apk, out]
    if pristine:
        argv += ['--pristine', pristine]
    old = sys.argv
    try:
        sys.argv = ['unpack_v2.py'] + argv
        rc = mod.main()
    finally:
        sys.argv = old
    return rc == 0


# ---------------------------------------------------------------- env 工具
def _env_no_upxvar():
    """去掉 UPX 环境变量的 env 副本（upx 5.2.1 会把 UPX 当选项串解析，路径值直接报错）。"""
    env = dict(os.environ)
    env.pop('UPX', None)
    return env


# ---------------------------------------------------------------- 验证
def verify_out(out, pristine, kind):
    """两级验证等级，如实报告。返回 True=验证通过（等级无所谓）。"""
    if not pristine or not os.path.exists(pristine):
        print('[*] 未提供黄金样本(--pristine)——本次为 anchor-only 级验证：')
        print('    产物 %s (%d bytes, sha256=%s)' % (
            out, os.path.getsize(out), sha256_file(out)[:16] + '…'))
        print('    [!] 无字节级对照。如需 byte-exact 验证，请给 --pristine <原始样本>。')
        return True
    if kind == 'elf':
        la, lb, diff = byte_diff_excl_etype(out, pristine)
        print('[*] 与黄金 %s 对照: 大小 %d vs %d' % (os.path.basename(pristine), la, lb))
        if diff == 0:
            print('[+] 除 e_type 外 0 字节差异 => 内容一致，解固成功（byte-exact）')
            return True
        print('[!] 除 e_type 外差异 %d 字节 => 内容不一致（%s）' % (
            diff, '含大小不同' if diff < 0 else '见差异位置清单'))
        return False
    # dex/apk 走 sha256
    so, sp = sha256_file(out), sha256_file(pristine)
    if so == sp:
        print('[+] sha256 与黄金一致 => 解固成功（byte-exact）')
        return True
    print('[!] sha256 与黄金不一致: %s vs %s' % (so[:16], sp[:16]))
    # dex 有独立 verify 工具可给差异细节
    v = labs.load_ajiami_verify()
    restored = open(out, 'rb').read()
    gold = open(pristine, 'rb').read()
    ra, ga = v.find_anchors(restored), v.find_anchors(gold)
    missing = [s for s in ga if s not in ra]
    print('    锚点: 还原 %d / 黄金 %d 个%s' % (len(ra), len(ga),
          ('，缺失: %s' % missing) if missing else ''))
    return False


# ---------------------------------------------------------------- 主流程
def route(res, path, outdir, pristine):
    """按判定结论路由到解法。返回 (是否解固, 输出文件列表)。"""
    v = res.get('verdict') or ''
    os.makedirs(outdir, exist_ok=True)
    outs = []

    if res.get('kind') == 'elf':
        if v.startswith('标准 360') or v.startswith('标准 UPX'):
            out = os.path.join(outdir, 'unpacked.so')
            if unpack_so_std(path, out):
                outs.append(out)
        elif v.startswith('★ 变种 360'):
            out = os.path.join(outdir, 'unpacked.so')
            if unpack_so_variant(path, out, orig=pristine, lab='360jiagu'):
                outs.append(out)
        elif v.startswith('★ 变种 UPX'):
            out = os.path.join(outdir, 'unpacked.so')
            if unpack_so_variant(path, out, orig=pristine, lab='upx_practice'):
                outs.append(out)
        else:
            print('[!] 判定为「%s」——静态不可自动解固。' % v)
            print('    下一步：B13/自实现 Linker 走内存 dump + ELF Fix；'
                  'SO VMP 须动态 trace（认知边界）。')
            return False, outs
    elif res.get('kind') in ('apk', 'dex'):
        if v.startswith('已加固：DEX 整体加密'):
            out = os.path.join(outdir, 'unpacked_v1.dex')
            if unpack_ajiami_v1(path, out, pristine):
                outs.append(out)
        elif v.startswith('已加固：类抽取'):
            out = os.path.join(outdir, 'unpacked_v2.dex')
            if unpack_ajiami_v2(path, out, pristine):
                outs.append(out)
        else:
            print('[!] 判定为「%s」——静态不可自动解固。' % v)
            if v.startswith('未见已知加固特征'):
                print('    下一步：这不是已知壳种。先跑 analyzer --json 复核规则明细；'
                      '若怀疑未知加固，须动态 trace（认知边界）。')
            else:
                print('    下一步：VMP 须定位解释器动态分析；SO 侧走 dump_fix.py。')
            return False, outs
    else:
        print('[!] 无法识别的文件类型，不解固。')
        return False, outs

    if not outs:
        return False, outs
    ok = all(verify_out(o, pristine, res.get('kind')) for o in outs)
    return ok, outs


def main():
    ap = argparse.ArgumentParser(
        description='统一解固工具 · 解固入口：判定 → 按壳种路由解法 → 两级验证')
    ap.add_argument('input', help='待解固文件（APK / so）')
    ap.add_argument('-o', '--outdir', default=None,
                    help='产物目录（默认 unpacker_output/<文件名>/）')
    ap.add_argument('--pristine', default=None,
                    help='黄金对照样本（给了就做 byte-exact 验证，不给只做 anchor-only）')
    args = ap.parse_args()

    path = args.input if os.path.isabs(args.input) else os.path.join(REPO_ROOT, args.input)
    if not os.path.exists(path):
        print('[!] 不存在: %s' % args.input)
        return 1
    outdir = args.outdir or os.path.join(
        REPO_ROOT, 'unpacker_output', os.path.splitext(os.path.basename(path))[0])
    pristine = (args.pristine if os.path.isabs(args.pristine or '')
                else (os.path.join(REPO_ROOT, args.pristine) if args.pristine else None))

    print('[*] ① 判定（只读体检）...')
    res = analyze(path)
    print('    判定结论: %s' % res.get('verdict'))
    print('[*] ② 按壳种路由解法，产物目录: %s' % os.path.relpath(outdir, REPO_ROOT))
    ok, outs = route(res, path, outdir, pristine)
    if not outs:
        return 1
    print('[*] ③ 完成。产物:')
    for o in outs:
        print('    %s (%d bytes)' % (os.path.relpath(o, REPO_ROOT), os.path.getsize(o)))
    print('[%s] 解固%s（验证等级: %s）' % (
        '+' if ok else '!', '成功' if ok else '失败',
        'byte-exact' if pristine else 'anchor-only'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
