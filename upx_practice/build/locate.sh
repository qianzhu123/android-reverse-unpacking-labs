#!/usr/bin/env bash
# locate.sh — 工具链自动探测（第四档）
#
# 四档优先级（本脚本只负责最后一档）：
#   ① 命令行参数（--ndk / --upx / --python ...）
#   ② 环境变量（NDK_ROOT / ANDROID_NDK_HOME / ANDROID_HOME / UPX / PYTHON ...）
#   ③ 项目配置（可选，需要钉版本时自己 export 后再 source 本文件）
#   ④ 本脚本：环境变量 → PATH → SDK/NDK 标准布局 → 工程根自带二进制
#
# 用法：
#   source build/locate.sh
#   locate_require NDK PY UPX        # 缺什么就报错并说明怎么配
#   bash build/locate.sh --dump      # 机器可读输出，给 Python 侧复用
#
# 【零绝对路径】本文件不含任何盘符路径与用户目录，全部靠环境变量与 PATH 推导。

# ---------- 工程根目录（由脚本自身位置推导，不依赖 CWD） ----------
_LOCATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$_LOCATE_DIR/.." && pwd)"
if command -v cygpath >/dev/null 2>&1; then
  ROOT_W="$(cygpath -w "$ROOT")"
else
  ROOT_W="$ROOT"
fi
ROOT_W="${ROOT_W//\\//}"

# ---------- 小工具 ----------
_win_path() {     # 统一成 X:/a/b 盘符风格：Windows 程序（java / aapt2 / upx.exe）最认这种
  local p="$1"
  case "$p" in
    /*) command -v cygpath >/dev/null 2>&1 && p="$(cygpath -w "$p" 2>/dev/null || echo "$p")" ;;
  esac
  echo "${p//\\//}"
}

_latest_dir() {   # 取某目录下"名字最大"的子目录（build-tools / ndk 取最新版）
  local base="$1" best="" d
  [ -d "$base" ] || return 1
  for d in "$base"/*; do
    [ -d "$d" ] || continue
    best="$d"
  done
  [ -n "$best" ] || return 1
  echo "$best"
}

# ---------- python ----------
find_python() {
  if [ -n "$PYTHON" ] && command -v "$PYTHON" >/dev/null 2>&1; then echo "$PYTHON"; return 0; fi
  local c
  for c in python python3 py; do
    if command -v "$c" >/dev/null 2>&1; then echo "$c"; return 0; fi
  done
  return 1
}

# ---------- Android SDK（只为从 <SDK>/ndk 找 NDK，找不到也不致命）----------
find_sdk() {
  local d j
  for d in "$ANDROID_HOME" "$ANDROID_SDK_ROOT" "$ANDROID_USER_HOME"; do
    [ -n "$d" ] && [ -d "$d/platforms" ] && { echo "$d"; return 0; }
  done
  j="$(command -v aapt2 2>/dev/null || true)"
  if [ -n "$j" ]; then
    d="$(cd "$(dirname "$j")/../.." 2>/dev/null && pwd)"
    [ -n "$d" ] && [ -d "$d/platforms" ] && { echo "$d"; return 0; }
  fi
  j="$(command -v adb 2>/dev/null || true)"
  if [ -n "$j" ]; then
    d="$(cd "$(dirname "$j")/.." 2>/dev/null && pwd)"
    [ -n "$d" ] && [ -d "$d/platforms" ] && { echo "$d"; return 0; }
  fi
  for d in "$HOME/Android/Sdk" "$HOME/AppData/Local/Android/Sdk" "$LOCALAPPDATA/Android/Sdk"; do
    [ -n "$d" ] && [ -d "$d/platforms" ] && { echo "$d"; return 0; }
  done
  return 1
}

# ---------- Android NDK ----------
find_ndk() {
  local d
  for d in "$ANDROID_NDK_HOME" "$NDK_ROOT" "$ANDROID_NDK_ROOT"; do
    [ -n "$d" ] && [ -x "$d/toolchains/llvm/prebuilt/windows-x86_64/bin/clang" ] && { echo "$d"; return 0; }
  done
  if [ -n "$SDK" ] && [ -d "$SDK/ndk" ]; then
    for d in "$SDK"/ndk/*; do
      [ -x "$d/toolchains/llvm/prebuilt/windows-x86_64/bin/clang" ] && { echo "$d"; return 0; }
    done
  fi
  return 1
}

# ---------- UPX ----------
# 顺序：环境变量 UPX（或 --upx） > 工程根自带的 upx.exe > PATH > tools/upx396.exe
# 为什么工程根优先于 PATH：本 lab 的所有实测数值都基于工程根那份版本（4.2.4），
# 换成别的版本可能打不出同样的样本；要换版本就显式设 UPX=<路径>，别靠 PATH 偷偷切。
find_upx() {
  local c p
  [ -n "$UPX" ] && [ -x "$UPX" ] && { echo "$UPX"; return 0; }
  for p in "$ROOT/upx.exe" "$ROOT/upx"; do
    [ -x "$p" ] && { echo "$p"; return 0; }
  done
  for c in upx.exe upx; do
    p="$(command -v "$c" 2>/dev/null || true)"
    [ -n "$p" ] && { echo "$p"; return 0; }
  done
  [ -x "$ROOT/tools/upx396.exe" ] && { echo "$ROOT/tools/upx396.exe"; return 0; }
  return 1
}

# ---------- 执行探测 ----------
PY="$(find_python || true)"
SDK="$(_win_path "$(find_sdk || true)")"
NDK="$(_win_path "$(find_ndk || true)")"
UPX="$(find_upx || true)"

if [ -n "$NDK" ]; then
  CLANG="$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin/clang"
  [ -x "$CLANG" ] || CLANG="$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe"
else
  CLANG=""
fi

# ---------- 缺失检查 ----------
# 用法：locate_require NDK PY UPX
locate_require() {
  local miss=() name var hint
  for name in "$@"; do
    case "$name" in
      PY)   var="$PY";   hint="python：PATH 里加 python，或 PYTHON=<解释器路径>" ;;
      NDK)  var="$NDK";  hint="Android NDK：设 ANDROID_NDK_HOME 或 NDK_ROOT=<NDK 根目录>，或放进 <SDK>/ndk/<版本>" ;;
      CLANG) var="$CLANG"; hint="NDK clang：确认 NDK 下有 toolchains/llvm/prebuilt/windows-x86_64/bin/clang" ;;
      UPX)  var="$UPX";  hint="UPX：把 upx 加进 PATH，或 UPX=<upx.exe 路径>；工程根自带 upx.exe 仅作兜底" ;;
      *)    var="$name"; hint="$name" ;;
    esac
    [ -n "$var" ] || miss+=("$hint")
  done
  if [ ${#miss[@]} -gt 0 ]; then
    echo "[!] 工具链未就绪，缺以下依赖：" >&2
    local m
    for m in "${miss[@]}"; do echo "    - $m" >&2; done
    echo "    配好后重跑；命令行参数 > 环境变量 > 自动探测，任一档配好即可。" >&2
    exit 1
  fi
}

# ---------- 机器可读输出（给 Python 侧复用）----------
if [ "${BASH_SOURCE[0]}" = "$0" ] && [ "${1:-}" = "--dump" ]; then
  for _v in ROOT ROOT_W PY SDK NDK CLANG UPX; do
    printf '%s=%s\n' "$_v" "${!_v}"
  done
fi
