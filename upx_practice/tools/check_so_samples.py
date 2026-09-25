#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
check_so_samples.py — 双向回归断言（专治"只拿自己造的样本验证自己做的检测器"的循环论证）

  · 正向：libtarget_stripped.so 必须被判为 B13（疑似 SO 加壳 / 自实现 Linker）
  · 负向：libtarget_orig.so     不得触发 B13（干净 NDK .so，节头完整）
  · 防回归：libtarget_upx.so / libtarget_upx_variant.so 仍须判为加壳
            （确认 B13 改造没有破坏原有的 UPX 判定）

用法： python tools/check_so_samples.py
失败以非 0 退出；全部通过退出 0。
"""
import contextlib
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import detect_packer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(name):
    """调用 detect 但吞掉它的详细打印，只取返回的结构化结果。"""
    path = os.path.join(ROOT, name)
    if not os.path.exists(path):
        return None
    with contextlib.redirect_stdout(io.StringIO()):
        return detect_packer.detect(path, brief=True)


def main():
    fails = 0

    # 正向：剥离节头的样本必须触发 B13
    r = _run("libtarget_stripped.so")
    if r is None:
        print("[SKIP] libtarget_stripped.so 不存在（先 bash build/build_android.sh && bash build/pack.sh）")
    elif r["b13"]:
        print("[PASS] libtarget_stripped.so   b13=True  -> %s" % r["verdict"])
    else:
        print("[FAIL] libtarget_stripped.so   b13=False (期望 True)  verdict=%s" % r["verdict"])
        fails += 1

    # 负向：原始 NDK .so 不得触发 B13（节头完整）
    r = _run("libtarget_orig.so")
    if r is None:
        print("[SKIP] libtarget_orig.so 不存在（先 bash build/build_android.sh）")
    elif not r["b13"]:
        print("[PASS] libtarget_orig.so       b13=False -> %s" % r["verdict"])
    else:
        print("[FAIL] libtarget_orig.so       b13=True (期望 False，正常 NDK .so 不该触发)")
        fails += 1

    # 防回归：UPX / 变种 UPX 仍须判为加壳，且不得被 B13 改动破坏
    for name in ("libtarget_upx.so", "libtarget_upx_variant.so"):
        r = _run(name)
        if r is None:
            print("[SKIP] %s 不存在（先 bash build/pack.sh）" % name)
            continue
        if r["is_packed"]:
            print("[PASS] %-26s 仍为加壳判定: %s" % (name, r["verdict"]))
        else:
            print("[FAIL] %-26s 加壳判定丢失: %s" % (name, r["verdict"]))
            fails += 1

    print("\n%d 项失败" % fails)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
