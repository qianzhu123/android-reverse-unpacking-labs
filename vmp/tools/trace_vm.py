#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
trace_vm.py — 动态路线入口：把 frida 脚本挂到样本上跑一段，回收输出。

设计：
  · 与 uncrackable/tools/hook_run.py 同构（spawn -> attach -> load script -> resume ->
    等 N 秒 -> detach/kill），只是把「设备」也做成可选项（--device usb|ip:port）。
  · 不把 frida 硬绑进本 lab：frida 从环境里找（PATH 或 <repo>/.venv/Scripts）。
  · 只做「跑脚本 + 打印消息」，不解释结果 —— 解释在文档与 devirt_* 工具里。

⚠️ 提醒：本工具会**在连接的设备上安装并启动目标 app**。请在你有权操作的设备/模拟器上
   使用（本仓推荐用本地模拟器 n4tive_lab，见 build/env.sh.example）。

用法：
    python tools/trace_vm.py --package com.demo.calc --script frida/oracle_run.js --seconds 8
    python tools/trace_vm.py --package com.demo.calc --script frida/trace_dispatch.js --device 127.0.0.1:5555
"""

import argparse
import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _find_frida_python():
    """优先仓内 .venv（frida 16.5.9 钉在那边），否则用当前解释器。"""
    venv = os.path.join(os.path.dirname(ROOT), '.venv', 'Scripts', 'python.exe')
    if os.path.exists(venv):
        return venv
    venv = os.path.join(os.path.dirname(ROOT), '.venv', 'bin', 'python')
    if os.path.exists(venv):
        return venv
    return sys.executable


_RUNNER = r'''
import sys, time
import frida
pkg, script_path, seconds, device_id = sys.argv[1], sys.argv[2], float(sys.argv[3]), sys.argv[4]
dev = frida.get_usb_device(5) if device_id == "usb" else frida.get_device(device_id, 5)
print("[device] %s" % dev)
pid = dev.spawn([pkg])
print("[spawn] pid=%s" % pid)
sess = dev.attach(pid)
with open(script_path, "r", encoding="utf-8") as f:
    src = f.read()
script = sess.create_script(src)
script.on("message", lambda m, d: print(("[%s] %s" % (m["type"], m.get("description") or m.get("payload")))))
script.load()
dev.resume(pid)
time.sleep(seconds)
sess.detach()
dev.kill(pid)
print("[done]")
'''


def main():
    ap = argparse.ArgumentParser(description='frida 动态路线入口')
    ap.add_argument('--package', required=True, help='目标包名，如 com.demo.calc')
    ap.add_argument('--script', required=True, help='frida 脚本路径（相对 lab 根或绝对）')
    ap.add_argument('--seconds', type=float, default=8.0)
    ap.add_argument('--device', default='usb', help='"usb" 或 "ip:port"')
    a = ap.parse_args()

    script = a.script if os.path.isabs(a.script) else os.path.join(ROOT, a.script)
    if not os.path.exists(script):
        print('[!] script not found: %s' % script)
        return 1
    py = _find_frida_python()
    print('[info] using python: %s' % py)
    try:
        import importlib
        subprocess.run([py, '-c', 'import frida'], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        print('[!] frida not importable by %s' % py)
        print('    本仓把 frida 钉在仓库根的 .venv（16.5.9）。若缺失：')
        print('    python -m venv .venv && .venv/Scripts/python -m pip install "frida==16.5.9" "frida-tools==13.7.0"')
        return 1
    code = subprocess.run([py, '-c', _RUNNER, a.package, script, str(a.seconds), a.device]).returncode
    return code


if __name__ == '__main__':
    sys.exit(main())
