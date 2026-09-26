#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
labs.py — unpacker 对三个练习工程（360jiagu / upx_practice / ajiami）的**只读桥接层**。

铁律（与仓库 PROMPT.md 一致）：
  · 绝不修改任何练习工程的代码——本模块只通过 sys.path 注入 + import 复用它们的
    检测器 / 解壳器，labs 目录对桥是**只读**的。
  · 零绝对路径：仓库根从本文件自身位置推导（unpacker/ 的上一级）。
  · 认知边界透传：各检测器的「未见已知特征（≠未加固）」语义原样保留，绝不改写。

桥接的三个工程模块与复用函数：
  360jiagu    tools/detect_360.py    detect(path, brief, verify, upx) -> dict(verdict, score, b13, is_packed, ...)
              tools/solve_360.py     solve(src, out, orig, token, upx_path, anchors) -> bool
  upx_practice tools/detect_packer.py  同上结构
              tools/solve_variant.py    同上结构
  ajiami      tools/detect.py        apk_features(path) -> f ; verdict(f) -> (结论, 规则, 朴素, 提示, 复核)
              tools/unpack_v1.py     main() CLI（一代整体加密脱壳）
              tools/unpack_v2.py     main() CLI（二/三代类抽取脱壳）
              tools/verify.py        sha() / find_anchors()
  三个工程还各有一份 reset_lab.py，供状态/复位（本工具不调用，避免误改 lab 状态）。

注意：ajiami 的检测器 import 时依赖 aapt2 之外的纯自建库（apkutil/dexlib/elfinspect），
全部在 lab 自己的 tools/ 目录内，sys.path 注入即可解析，无需改动它们。
"""

import importlib.util
import os
import sys


def _default_repo_root():
    """源码场景：仓库根 = 本文件( unpacker/labs.py )上一级。"""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


REPO_ROOT = _default_repo_root()
LABS = {
    '360jiagu':     os.path.join(REPO_ROOT, '360jiagu'),
    'upx_practice': os.path.join(REPO_ROOT, 'upx_practice'),
    'ajiami':       os.path.join(REPO_ROOT, 'ajiami'),
}

# 每个 lab 的 tools/ 里可能存在与本桥模块重名的文件（如都有 reset_lab.py），
# 因此**不用包式 import**，而是按「模块名 → 文件路径」逐个 spec 加载，互不污染。
_SPEC_CACHE = {}


def _load(module_name, rel_path):
    """按文件路径加载一个 lab 模块（带缓存）。rel_path 相对仓库根，如 '360jiagu/tools/detect_360.py'。"""
    key = (module_name, rel_path)
    if key in _SPEC_CACHE:
        return _SPEC_CACHE[key]
    path = os.path.join(REPO_ROOT, rel_path)
    if not os.path.exists(path):
        raise FileNotFoundError('lab 模块不存在: %s（仓库根=%s）' % (rel_path, REPO_ROOT))
    spec = importlib.util.spec_from_file_location(module_name, path)
    mod = importlib.util.module_from_spec(spec)
    # lab 模块内部如有 `sys.path.insert(0, 自身tools目录)` 的自举，exec 前先把它
    # lab 的 tools/ 注入 sys.path，保证其兄弟 import（apkutil 等）可解析。
    lab_tools = os.path.dirname(path)
    if lab_tools not in sys.path:
        sys.path.insert(0, lab_tools)
    spec.loader.exec_module(mod)
    _SPEC_CACHE[key] = mod
    return mod


# ---------------------------------------------------------------- 360jiagu
def load_360_detect():
    return _load('lab360_detect', os.path.join('360jiagu', 'tools', 'detect_360.py'))


def load_360_solve():
    return _load('lab360_solve', os.path.join('360jiagu', 'tools', 'solve_360.py'))


# ------------------------------------------------------------ upx_practice
def load_upx_detect():
    return _load('labupx_detect', os.path.join('upx_practice', 'tools', 'detect_packer.py'))


def load_upx_solve():
    return _load('labupx_solve', os.path.join('upx_practice', 'tools', 'solve_variant.py'))


# ------------------------------------------------------------------ ajiami
def load_ajiami_detect():
    return _load('labajm_detect', os.path.join('ajiami', 'tools', 'detect.py'))


def load_ajiami_unpack_v1():
    return _load('labajm_unpack_v1', os.path.join('ajiami', 'tools', 'unpack_v1.py'))


def load_ajiami_unpack_v2():
    return _load('labajm_unpack_v2', os.path.join('ajiami', 'tools', 'unpack_v2.py'))


def load_ajiami_verify():
    return _load('labajm_verify', os.path.join('ajiami', 'tools', 'verify.py'))


def lab_path(lab, *parts):
    """lab 内路径（跟随 REPO_ROOT，exe 场景 REPO_ROOT 可被 main.py 运行时改写）。"""
    base = os.path.join(REPO_ROOT, lab)
    return os.path.join(base, *parts) if parts else base
