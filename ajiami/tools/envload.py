#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
envload.py — 让 Python 工具**不需要先 source build/env.sh** 也能拿到工具链路径。

为什么需要它：
  build/env.sh 是 bash 脚本（用 export 导出变量）。PowerShell 里执行
  `source build/env.sh` 会直接报 "The term 'source' is not recognized" —— 因为
  source 是 bash 内建命令，PowerShell 根本没有它，PowerShell 也没有 export。
  与其强制用户开 Git Bash，不如让 Python 工具自己把 env.sh 里的纯赋值读出来，
  于是 bash / PowerShell / CMD 下都能直接跑，构建链路不再依赖 shell 种类。

做法（最小解析，不做完整 bash 解释器）：
  1. 先跑 `bash build/locate.sh --dump` 拿自动探测结果（ROOT / JAVA / SDK / BT ...）。
     bash 不可用时退化为「只用 env.sh 自身 + os.environ」，并在下面打印提示。
  2. 解析 env.sh 里两种纯赋值：NAME="value"  和  export NAME="value"
  3. 反复展开其中的 $VAR / ${VAR} 引用（可能多层，例如
      BT="$SDK/build-tools/37.0.0"
      APK_SIGNER_JAR="$BT/lib/apksigner.jar"
      export AJ_APKSIGNER_JAR="$APK_SIGNER_JAR"
  需要迭代到稳定）。env.sh 里的函数定义（D8() / APK_SIGNER()）与 if 分支
  本工程用不到，直接忽略。

【零绝对路径】env.sh / env.sh.example 里不再写任何盘符路径，变量全部来自
  build/locate.sh 的探测结果；本模块只是把它搬到 Python 侧。

用法：
    import envload
    envload.ensure_env()      # 把 AJ_* 变量补进 os.environ（已存在的不覆盖）

    python tools/envload.py   # 直接运行可自检：打印从 env.sh 解析出的变量
"""

import os
import re
import subprocess

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_HERE)
ENV_SH = os.path.join(_PROJECT_ROOT, 'build', 'env.sh')
LOCATE_SH = os.path.join(_PROJECT_ROOT, 'build', 'locate.sh')


def _windows_style(p):
    """把 X:\\a\\b 变成 X:/a/b（给 java / aapt2 这类 Windows 程序用）。"""
    return p.replace('\\', '/')


def _locate_vals():
    """运行 `bash build/locate.sh --dump` 取探测结果；bash 不可用时返回 {}。

    这是「自动探测」这一档在 Python 侧的复用入口：env.sh 里只剩变量引用，
    真正的值由 locate.sh 按 环境变量 > PATH > SDK/NDK 标准布局 推出来。
    """
    if not os.path.isfile(LOCATE_SH):
        return {}
    cands = [os.environ.get('BASH') or '', 'bash', 'sh']
    for exe in cands:
        if not exe:
            continue
        try:
            out = subprocess.run([exe, LOCATE_SH, '--dump'],
                                 capture_output=True, text=True, timeout=30)
        except Exception:
            continue
        if out.returncode == 0:
            vals = {}
            for line in out.stdout.splitlines():
                if '=' in line:
                    k, v = line.split('=', 1)
                    vals[k.strip()] = v.strip()
            return vals
    return {}

_ASSIGN = re.compile(r'^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)="([^"]*)"', re.M)
_REF_BRACE = re.compile(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}')
_REF_PLAIN = re.compile(r'\$([A-Za-z_][A-Za-z0-9_]*)')


def parse_env_sh(path=ENV_SH):
    """解析 env.sh，返回 {变量名: 展开后的值}。文件不存在返回 {}。"""
    try:
        with open(path, encoding='utf-8') as f:
            text = f.read()
    except IOError:
        return {}

    # 基础值：locate.sh 探测结果 + 本地推导的工程根（bash 不可用时的兜底）
    vals = _locate_vals()
    vals.setdefault('ROOT', _PROJECT_ROOT)
    vals.setdefault('ROOT_W', _windows_style(_PROJECT_ROOT))
    for m in _ASSIGN.finditer(text):
        vals[m.group(1)] = m.group(2)

    def rep(mo):
        name = mo.group(1)
        return vals.get(name) or os.environ.get(name) or ''

    for _ in range(8):                      # $VAR 可能多层引用，迭代到稳定
        changed = False
        for k, v in list(vals.items()):
            if '$' not in v:
                continue
            newv = _REF_BRACE.sub(rep, v)
            newv = _REF_PLAIN.sub(rep, newv)
            if newv != v:
                vals[k] = newv
                changed = True
        if not changed:
            break
    return vals


def ensure_env(path=ENV_SH, prefix='AJ_'):
    """把 env.sh 里 prefix 开头的变量补进 os.environ（已存在则保留原值）。

    返回本次真正补进去的 {name: value}，便于自检/打印。
    """
    vals = parse_env_sh(path)
    added = {}
    for k, v in vals.items():
        if not k.startswith(prefix):
            continue
        if not os.environ.get(k):
            os.environ[k] = v
            added[k] = v
    return added


if __name__ == '__main__':
    got = ensure_env()
    if not got:
        print('未能从 %s 解析出 AJ_* 变量（检查文件是否存在）' % ENV_SH)
        raise SystemExit(1)
    print('从 %s 解析出 %d 个 AJ_* 变量：' % (ENV_SH, len(got)))
    for k in sorted(got):
        print('  %-22s %s' % (k, got[k]))
