#!/usr/bin/env python
# reset_lab.py — 备份 / 恢复练习环境，让你能反复练习
#
#   python tools/reset_lab.py backup [文件 ...]   建立（或刷新）"初始状态"备份到 pristine/
#   python tools/reset_lab.py status              查看当前状态与初始状态的差异
#   python tools/reset_lab.py restore             恢复初始状态（还原样本 + 清理练习产物）
#
# 【可复用·samples 容器版】样本一律住 samples/（如 samples/apks/*.apk），工程根不放样本：
#   - backup 不带文件名时，递归把 samples/ 下所有文件纳入基线
#     （相对路径以 samples/ 为根，如 'apks/app-debug.apk'，作为 manifest 的 key）
#     也可显式指定: python reset_lab.py backup apks/app-debug.apk
#   - pristine/ 内镜像 samples/ 的子目录结构（如 pristine/apks/app-debug.apk）
#   - 练习产物用目录级清理：analysis_output/ 整体清空（ollvm 的产物都在这里）
#   - 输出目录默认 analysis_output，用 --clean-dir 改
#   - 根目录默认取脚本的上级目录，用 --root 改
import os, sys, shutil, hashlib, json

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ROOT = os.path.dirname(HERE)

DEFAULT_CLEAN_DIR = "analysis_output"

def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(65536), b""): h.update(c)
    return h.hexdigest()

def samples_dir(root):      return os.path.join(root, "samples")
def manifest_path(root):    return os.path.join(root, "pristine", "manifest.json")
def pristine_dir(root):     return os.path.join(root, "pristine")

def discover(root):
    """递归遍历 samples/ 下所有文件，返回相对路径列表（以 samples/ 为根，如 'apks/x.apk'）。"""
    out = []
    sdir = samples_dir(root)
    for dirpath, _dirnames, filenames in os.walk(sdir):
        for fn in sorted(filenames):
            rel = os.path.relpath(os.path.join(dirpath, fn), sdir)
            out.append(rel.replace(os.sep, "/"))
    return sorted(out)

def load_manifest(root):
    """兼容两种格式：新版 {"files":..., "config":...} 与旧版扁平 {文件名: {...}}"""
    mp = manifest_path(root)
    if not os.path.exists(mp): return None, {}
    m = json.load(open(mp))
    if isinstance(m, dict) and "files" in m:
        return m["files"], m.get("config", {})
    return m, {}

def save_manifest(root, files, cfg):
    d = pristine_dir(root)
    os.makedirs(d, exist_ok=True)
    json.dump({"files": files, "config": cfg}, open(manifest_path(root), "w"), indent=2)

def get_cfg(root, clean_dir_cmd):
    """合并"命令行指定"与"已存清单里的配置"。命令行优先，未给的用默认。"""
    _, saved = load_manifest(root)
    clean_dir = clean_dir_cmd or saved.get("clean_dir") or DEFAULT_CLEAN_DIR
    return {"clean_dir": clean_dir}

def cmd_backup(root, files, cfg):
    if not files:
        files = discover(root)
        if not files:
            print("[!] samples/ 下没有样本文件，请先放入（或显式指定: python reset_lab.py backup apks/x.apk）")
            return
        print("[*] 自动发现 samples/ 下 %d 个样本文件（可用 backup <相对路径...> 显式指定）" % len(files))
    pristine = pristine_dir(root)
    man = {}
    for f in files:
        src = os.path.join(samples_dir(root), f)
        if not os.path.exists(src):
            print("  [skip] samples/%s 不存在" % f); continue
        dst = os.path.join(pristine, f)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
        man[f] = {"sha256": sha(src), "size": os.path.getsize(src)}
        print("  [backup] %-40s %8d bytes" % (f, man[f]["size"]))
    save_manifest(root, man, cfg)
    print("\n[+] 初始状态已备份到 pristine/  (manifest: %d 个文件)" % len(man))

def cmd_status(root, cfg):
    man, _ = load_manifest(root)
    if man is None:
        print("[!] 还没有备份，请先执行: python tools/reset_lab.py backup"); return
    print("样本状态对比:")
    for f, info in man.items():
        p = os.path.join(samples_dir(root), f)
        if not os.path.exists(p):
            print("  [缺失]   %s" % f); continue
        cur = sha(p)
        if cur == info["sha256"]:
            print("  [一致]   %-40s %8d bytes" % (f, os.path.getsize(p)))
        else:
            print("  [已改动] %-40s %8d bytes (原始 %d)" % (f, os.path.getsize(p), info["size"]))
    ao = os.path.join(root, cfg["clean_dir"])
    if os.path.isdir(ao):
        fs = os.listdir(ao)
        print("\n输出目录 %s/: %s" % (cfg["clean_dir"], "%d 个条目" % len(fs) if fs else "空"))
    else:
        print("\n输出目录 %s/: 不存在（尚未跑过分析脚本）" % cfg["clean_dir"])
    clean = all(
        os.path.exists(os.path.join(samples_dir(root), f)) and sha(os.path.join(samples_dir(root), f)) == i["sha256"]
        for f, i in man.items())
    print("\n当前环境: %s" % ("干净，可直接开始练习" if clean else "有练习残留，可执行 restore 回归"))

def cmd_restore(root, cfg):
    man, _ = load_manifest(root)
    if man is None:
        print("[!] 还没有备份，请先执行: python tools/reset_lab.py backup"); return
    pristine = pristine_dir(root)
    print("还原样本:")
    for f in man:
        src = os.path.join(pristine, f)
        dst = os.path.join(samples_dir(root), f)
        if os.path.exists(src):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            print("  [还原] %-40s %8d bytes" % (f, os.path.getsize(dst)))
        else:
            print("  [SKIP] %s（pristine/ 无副本）" % f)
    print("清理练习产物:")
    ao = os.path.join(root, cfg["clean_dir"])
    n = 0
    if os.path.isdir(ao):
        for x in os.listdir(ao):
            p = os.path.join(ao, x)
            if os.path.isfile(p):
                os.remove(p); n += 1
            else:
                shutil.rmtree(p); n += 1
        print("  [清空] %s/ (%d 个条目)" % (cfg["clean_dir"], n))
    else:
        print("  (无残留)")
    print("\n[+] 已回到初始状态，可以重新开始练习")

def parse(argv):
    cmd = None; files = []; root = None; clean_dir = None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--root" and i + 1 < len(argv):         root = argv[i + 1]; i += 2
        elif a == "--clean-dir" and i + 1 < len(argv):  clean_dir = argv[i + 1]; i += 2
        elif a.startswith("--"):                        i += 1
        else:
            if cmd is None: cmd = a
            else: files.append(a)
            i += 1
    return cmd, files, root, clean_dir

if __name__ == "__main__":
    cmd, files, root_arg, clean_dir = parse(sys.argv[1:])
    root = os.path.abspath(root_arg) if root_arg else DEFAULT_ROOT
    if not cmd: cmd = "status"
    if cmd not in ("backup", "status", "restore"):
        print("用法: python tools/reset_lab.py [backup|status|restore] [相对路径 ...]\n"
              "      [--root DIR] [--clean-dir NAME]")
        sys.exit(1)
    cfg = get_cfg(root, clean_dir)
    print("[*] 练习根目录: %s" % root)
    if cmd == "backup":  cmd_backup(root, files, cfg)
    elif cmd == "status": cmd_status(root, cfg)
    else:                 cmd_restore(root, cfg)
