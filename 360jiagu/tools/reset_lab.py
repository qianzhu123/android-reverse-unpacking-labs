#!/usr/bin/env python
# reset_lab.py — 备份 / 恢复练习环境，让你能反复练习
#
#   python tools/reset_lab.py backup [文件 ...]   建立（或刷新）"初始状态"备份到 pristine/
#   python tools/reset_lab.py status              查看当前状态与初始状态的差异
#   python tools/reset_lab.py restore             恢复初始状态（还原样本 + 清理练习产物）
#
# 【可复用】本脚本不含任何项目专属文件名：
#   - backup 不带文件名时，自动把"项目根目录下的样本文件"纳入基线
#     （跳过 tools/ src/ docs/ build/ pristine/ 等目录，以及 .md/.py/.sh/.exe 等非样本文件）
#     也可显式指定: python reset_lab.py backup a.so b.bin
#   - 练习产物用 glob 模式识别，默认值见 DEFAULT_ARTIFACT_GLOBS；
#     可用 --artifact-glob '*.xxx' 追加模式、--artifact 文件名 指定确切文件
#   - 输出目录默认 analysis_output，用 --clean-dir 改
#   - 根目录默认取脚本的上级目录，用 --root 改
import os, sys, shutil, hashlib, json, fnmatch

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ROOT = os.path.dirname(HERE)

# 自动发现基线时要跳过的目录
PROTECTED_DIRS = {"tools", "src", "docs", "build", "pristine",
                  ".git", ".workbuddy", ".idea", "__pycache__"}
# 自动发现基线时要跳过的文件后缀（文档/脚本/工具不是样本）
NON_SAMPLE_EXTS = {".md", ".txt", ".json", ".py", ".sh", ".bat", ".ps1",
                   ".exe", ".dll", ".yaml", ".yml", ".toml", ".ini", ".cfg"}
# 默认识别为"练习产物"的 glob 模式
# 注意 *unpacked.so 同时覆盖 "unpacked.so" 与 "xxx_unpacked.so"（如 README 示例的输出名）
DEFAULT_ARTIFACT_GLOBS = ["*unpacked.so", "*_repaired.so",
                          "*_probe.so", "_tmp_*.so", "*.fixed.so"]
DEFAULT_CLEAN_DIR = "analysis_output"

def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(65536), b""): h.update(c)
    return h.hexdigest()

def is_artifact(name, globs, exact):
    if name in exact: return True
    return any(fnmatch.fnmatch(name, g) for g in globs)

def discover(root, clean_dir, globs, exact):
    """自动发现"项目根目录下的样本文件"（不递归）。"""
    out = []
    for name in sorted(os.listdir(root)):
        p = os.path.join(root, name)
        if not os.path.isfile(p): continue
        if name in PROTECTED_DIRS: continue
        if os.path.splitext(name)[1].lower() in NON_SAMPLE_EXTS: continue
        if is_artifact(name, globs, exact): continue
        out.append(name)
    return out

def manifest_path(root): return os.path.join(root, "pristine", "manifest.json")
def pristine_dir(root):  return os.path.join(root, "pristine")

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

def get_cfg(root, clean_dir_cmd, globs_cmd, exact_cmd):
    """合并"命令行指定"与"已存清单里的配置"。命令行优先，未给的用默认。"""
    _, saved = load_manifest(root)
    clean_dir = clean_dir_cmd or saved.get("clean_dir") or DEFAULT_CLEAN_DIR
    globs = list(DEFAULT_ARTIFACT_GLOBS)
    for g in (saved.get("artifact_globs") or []):
        if g not in globs: globs.append(g)
    for g in globs_cmd:
        if g not in globs: globs.append(g)
    exact = list(saved.get("artifacts") or [])
    for e in exact_cmd:
        if e not in exact: exact.append(e)
    return {"clean_dir": clean_dir, "artifact_globs": globs, "artifacts": exact}

def cmd_backup(root, files, cfg):
    pristine = pristine_dir(root)
    os.makedirs(pristine, exist_ok=True)
    if not files:
        files = discover(root, cfg["clean_dir"], cfg["artifact_globs"], cfg["artifacts"])
        if not files:
            print("[!] 没发现可纳入基线的样本文件，请显式指定: python reset_lab.py backup a.so b.so")
            return
        print("[*] 自动发现 %d 个样本文件（可用 backup <文件...> 显式指定）" % len(files))
    man = {}
    for f in files:
        src = os.path.join(root, f)
        if not os.path.exists(src):
            print("  [skip] %s 不存在" % f); continue
        shutil.copy2(src, os.path.join(pristine, f))
        man[f] = {"sha256": sha(src), "size": os.path.getsize(src)}
        print("  [backup] %-32s %8d bytes" % (f, man[f]["size"]))
    save_manifest(root, man, cfg)
    print("\n[+] 初始状态已备份到 pristine/  (manifest: %d 个文件)" % len(man))

def cmd_status(root, cfg):
    man, _ = load_manifest(root)
    if man is None:
        print("[!] 还没有备份，请先执行: python tools/reset_lab.py backup"); return
    print("样本状态对比:")
    for f, info in man.items():
        p = os.path.join(root, f)
        if not os.path.exists(p):
            print("  [缺失]   %s" % f); continue
        cur = sha(p)
        if cur == info["sha256"]:
            print("  [一致]   %-32s %8d bytes" % (f, os.path.getsize(p)))
        else:
            print("  [已改动] %-32s %8d bytes (原始 %d)" % (f, os.path.getsize(p), info["size"]))
    art = [n for n in os.listdir(root)
           if os.path.isfile(os.path.join(root, n))
           and is_artifact(n, cfg["artifact_globs"], cfg["artifacts"])]
    print("\n练习产物: %s" % (art if art else "无（环境干净）"))
    ao = os.path.join(root, cfg["clean_dir"])
    if os.path.isdir(ao):
        fs = os.listdir(ao)
        print("输出目录 %s/: %s" % (cfg["clean_dir"], "%d 个文件" % len(fs) if fs else "空"))
    clean = (not art) and all(
        os.path.exists(os.path.join(root, f)) and sha(os.path.join(root, f)) == i["sha256"]
        for f, i in man.items())
    print("\n当前环境: %s" % ("干净，可直接开始练习" if clean else "有练习残留，可执行 restore 回归"))

def cmd_restore(root, cfg):
    man, _ = load_manifest(root)
    if man is None:
        print("[!] 还没有备份，请先执行: python tools/reset_lab.py backup"); return
    pristine = pristine_dir(root)
    print("还原样本:")
    for f in man:
        src = os.path.join(pristine, f); dst = os.path.join(root, f)
        if os.path.exists(src):
            shutil.copy2(src, dst)
            print("  [还原] %-32s %8d bytes" % (f, os.path.getsize(dst)))
    print("清理练习产物:")
    n = 0
    for name in sorted(os.listdir(root)):
        p = os.path.join(root, name)
        if not os.path.isfile(p): continue
        if name in man: continue          # 基线里的样本不删
        if is_artifact(name, cfg["artifact_globs"], cfg["artifacts"]):
            os.remove(p); print("  [删除] %s" % name); n += 1
    ao = os.path.join(root, cfg["clean_dir"])
    if os.path.isdir(ao):
        for x in os.listdir(ao):
            p = os.path.join(ao, x)
            if os.path.isfile(p): os.remove(p); n += 1
        print("  [清空] %s/" % cfg["clean_dir"])
    if n == 0: print("  (无残留)")
    print("\n[+] 已回到初始状态，可以重新开始练习")

def parse(argv):
    cmd = None; files = []; root = None; clean_dir = None
    globs = []; exact = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--root" and i + 1 < len(argv):           root = argv[i + 1]; i += 2
        elif a == "--clean-dir" and i + 1 < len(argv):    clean_dir = argv[i + 1]; i += 2
        elif a == "--artifact-glob" and i + 1 < len(argv): globs.append(argv[i + 1]); i += 2
        elif a == "--artifact" and i + 1 < len(argv):      exact.append(argv[i + 1]); i += 2
        elif a.startswith("--"):                           i += 1
        else:
            if cmd is None: cmd = a
            else: files.append(a)
            i += 1
    return cmd, files, root, clean_dir, globs, exact

if __name__ == "__main__":
    cmd, files, root_arg, clean_dir, globs, exact = parse(sys.argv[1:])
    root = os.path.abspath(root_arg) if root_arg else DEFAULT_ROOT
    if not cmd: cmd = "status"
    if cmd not in ("backup", "status", "restore"):
        print("用法: python tools/reset_lab.py [backup|status|restore] [文件 ...]\n"
              "      [--root DIR] [--clean-dir NAME] [--artifact-glob PATTERN] [--artifact NAME]")
        sys.exit(1)
    cfg = get_cfg(root, clean_dir, globs, exact)
    print("[*] 练习根目录: %s" % root)
    if cmd == "backup":  cmd_backup(root, files, cfg)
    elif cmd == "status": cmd_status(root, cfg)
    else:                 cmd_restore(root, cfg)
