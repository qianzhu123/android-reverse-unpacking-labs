#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
analyzer.py — 统一解固工具 · 判定入口（只读体检，不修改任何文件）

用法：
  python unpacker/analyzer.py <文件>... [--json] [--verify]

拖入 APK / dex / .so 任意文件，自动分派：
  · ELF (.so / 无 zip 结构的 ELF 文件)  -> SO 管线（360/UPX/变种/B13）
  · APK / ZIP                          -> DEX 管线（ajiami 三代 + VMP + SO侧B13）
  · 裸 dex                              -> DEX 管线（按 dex 文件分析）

判定结果语义（与各 lab 检测器完全一致，本工具只做聚合，不改写任何结论）：
  · 「已加固：xxx」        = 已知壳种，可走 unpacker/unpack.py 自动解固
  · 「疑似 xxx」            = 结构异常但证据不足以下定性（VMP / 自实现 Linker / Java2CPP）
  · 「未见已知加固特征」   = 认知边界内的兜底结论，**绝不等于未加固**

多检测器关系说明（诚实声明，防止误解为"冗余"）：
  SO 管线跑 detect_360（超集）与 detect_packer（子集）两个检测器——360 版多一套
  360 归属标记（JG!!/360 4.24），UPX 版没有。两者对同一文件给出的「是否加壳」
  结论一致（实测互跑对方样本均一致），分歧只在壳种命名归属。
  本工具以「首个给出已知壳种结论的检测器」为主结论，另一个作为交叉验证打印。

输出约定（仓库 PROMPT.md 的输出纪律）：
  · stdout 的 [!] = 失败/告警；[*] = 步骤说明；[+] = 成功；认知边界永远随结论打印。
  · --json 输出结构化结果（供 unpack.py / regression.py 消费）。
"""

import argparse
import contextlib
import io
import json
import os
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import labs  # noqa: E402  (unpacker/labs.py — 只读桥接层)


# ---------------------------------------------------------------- 文件分派
def sniff_kind(path):
    """返回 'elf' / 'apk' / 'dex' / 'unknown'。只看结构（魔数），不看文件名。"""
    try:
        with open(path, 'rb') as fh:
            head = fh.read(8)
    except OSError:
        return 'unknown'
    if head[:4] == b'\x7fELF':
        return 'elf'
    if head[:4] == b'dex\n':
        return 'dex'
    try:
        if zipfile.is_zipfile(path):
            return 'apk'
    except OSError:
        return 'unknown'
    return 'unknown'


# ---------------------------------------------------------------- SO 管线
def analyze_so(path, verify=False):
    """跑 360 / UPX 两个 SO 检测器。detect() 自带打印，这里捕获后聚合。"""
    results = []
    for name, loader in (('360', labs.load_360_detect),
                         ('UPX', labs.load_upx_detect)):
        mod = loader()
        buf = io.StringIO()
        res = None
        with contextlib.redirect_stdout(buf):
            try:
                res = mod.detect(path, brief=True, verify=False)
            except Exception as e:  # 检测器对非 ELF / 损坏文件可能直接 return None
                res = None
                results.append({'detector': name, 'error': repr(e)})
                continue
        if res is None:
            results.append({'detector': name, 'error': 'not-elf-or-failed'})
            continue
        res = dict(res)
        res['detector'] = name
        res['raw_output'] = buf.getvalue()
        results.append(res)
    return results


# --------------------------------------------------------------- DEX 管线
def analyze_apk_or_dex(path):
    """跑 ajiami 检测器（APK 或裸 dex 均支持）。"""
    mod = labs.load_ajiami_detect()
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            if zipfile.is_zipfile(path):
                f = mod.apk_features(path)
            else:
                f = mod.dex_file_features(path)
            concl, rules, naive, hints, notes = mod.verdict(f)
    except Exception as e:
        return {'detector': 'ajiami', 'error': repr(e), 'raw_output': buf.getvalue()}
    return {
        'detector': 'ajiami',
        'verdict': concl,
        'rules': rules,
        'is_packed': concl.startswith('已加固'),
        'suspected': concl.startswith('疑似'),
        'raw_output': buf.getvalue(),
    }


# ------------------------------------------------------------------ 主入口
def analyze(path, verify=False):
    kind = sniff_kind(path)
    if kind == 'unknown':
        return {'path': path, 'kind': kind,
                'verdict': '无法识别的文件类型（非 ELF / 非 ZIP / 非 dex）',
                'is_packed': None}
    out = {'path': path, 'kind': kind}
    if kind == 'elf':
        out['so_results'] = analyze_so(path, verify)
        # 主结论：取第一个「已知壳种或疑似」结论；两个检测器都没检出则透传认知边界语义
        primary = None
        for r in out['so_results']:
            if r.get('verdict') and r.get('is_packed'):
                primary = r
                break
        if primary is None and out['so_results']:
            cand = [r for r in out['so_results'] if 'verdict' in r]
            primary = cand[0] if cand else None
        out['primary'] = primary
        out['verdict'] = (primary or {}).get('verdict', '未见已知加固特征（≠未加壳）')
        out['is_packed'] = (primary or {}).get('is_packed', False)
    else:
        r = analyze_apk_or_dex(path)
        out['apk_result'] = r
        out['verdict'] = r.get('verdict', '检测失败')
        out['is_packed'] = r.get('is_packed')
    return out


COVERAGE = ('认知边界：未见已知特征 ≠ 未加固。SO VMP / 非汇聚形态自定义 VMP / '
            '精巧字符串加密 / 完整性校验，均须动态 trace 定性，本工具静态不可确认。')


def print_report(res, show_raw=False):
    p = res['path']
    print('=' * 72)
    print('目标: %s   类型: %s' % (p, res.get('kind')))
    print('=' * 72)
    if res.get('kind') == 'elf':
        for r in res.get('so_results', []):
            if 'error' in r:
                print('  [%s 检测器] 失败: %s' % (r['detector'], r['error']))
                continue
            print('  [%s 检测器] 得分=%s  b13=%s' % (r['detector'], r.get('score'), r.get('b13')))
            print('             结论: %s' % r.get('verdict'))
        print('-' * 72)
    elif res.get('kind') in ('apk', 'dex'):
        r = res.get('apk_result', {})
        if 'error' in r and not r.get('verdict'):
            print('  [ajiami 检测器] 失败: %s' % r['error'])
        else:
            for rule in r.get('rules', []):
                print('  【判据】%s' % rule)
    print('  >> 统一结论: %s' % res.get('verdict'))
    print('  >> ' + COVERAGE)
    print('=' * 72 + '')


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(
        description='统一解固工具 · 判定入口（只读体检）。拖入 APK / dex / so 均可。')
    # 相对路径按仓库根解析（与各 lab 的习惯一致：cd <lab> 后跑相对路径）
    ap.add_argument('files', nargs='+', help='待判定文件（APK / dex / so），可多个')
    ap.add_argument('--json', action='store_true', help='输出 JSON（含原始检测器输出）')
    ap.add_argument('--verify', action='store_true',
                    help='SO 变种壳魔数候选用 upx -t 实证（需 upx 在 PATH 或 UPX 环境变量）')
    args = ap.parse_args()

    results = []
    fail = 0
    for p in args.files:
        full = p if os.path.isabs(p) else os.path.join(REPO_ROOT, p)
        if not os.path.exists(full):
            print('[!] 不存在: %s' % p)
            fail += 1
            continue
        res = analyze(full, verify=args.verify)
        results.append(res)
        if not args.json:
            print_report(res)
    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    return 1 if fail else 0


if __name__ == '__main__':
    sys.exit(main())
