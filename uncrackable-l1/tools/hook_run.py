#!/usr/bin/env python3
"""uncrackable-l1 lab · dynamic runner (real-target route, see PROMPT-REAL.md)

Spawns the target under Frida, loads frida/hook.js, prints hook output for a bounded
window, then detaches. Bounded by design — a real-target session must not hang.

Usage:
    python tools/hook_run.py --package owasp.mstg.uncrackable1 --script frida/hook.js --seconds 12

Venv: run with the repo-local interpreter (../.venv/Scripts/python.exe) — frida is
installed per-repo, never globally.
"""
import argparse
import os
import sys
import time

import frida


def on_message(message, data):
    if message.get("type") == "send":
        print("[send]", message["payload"])
    elif message.get("type") == "error":
        print("[error]", message.get("description"))
        print(message.get("stack", ""))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--package", required=True, help="target package name")
    ap.add_argument("--script", required=True, help="path to hook .js")
    ap.add_argument("--seconds", type=float, default=10.0, help="capture window")
    ap.add_argument("--device", default="usb", help="frida device id (default usb/adb)")
    args = ap.parse_args()

    lab_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    script_path = args.script
    if not os.path.isabs(script_path):
        script_path = os.path.join(lab_root, script_path)

    device = frida.get_usb_device(5) if args.device == "usb" else frida.get_device(args.device, 5)
    print(f"[*] device: {device.name}  package: {args.package}  script: {script_path}")

    pid = device.spawn([args.package])
    print(f"[*] spawned pid={pid}")
    session = device.attach(pid)
    with open(script_path, "r", encoding="utf-8") as fh:
        script = session.create_script(fh.read())
    script.on("message", on_message)
    script.load()
    device.resume(pid)
    print(f"[*] resumed; capturing {args.seconds}s of hook output ...")

    time.sleep(args.seconds)
    session.detach()
    device.kill(pid)
    print("[*] done")


if __name__ == "__main__":
    sys.exit(main())
