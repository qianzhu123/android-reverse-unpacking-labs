#!/usr/bin/env bash
# locate.sh — 工具链自动探测（第四档）
#
# 四档优先级（本脚本只负责最后一档）：
#   ① 命令行参数（--ndk / --aapt2 / --python ...）
#   ② 环境变量（NDK_ROOT / ANDROID_NDK_HOME / ANDROID_HOME / JAVA_HOME / PYTHON ...）
#   ③ 项目配置 build/env.sh（可选，存在才 source，可在里面 export 覆盖）
#   ④ 本脚本：环境变量 → PATH → SDK/NDK 标准布局 → 版本号取最新
#
# 用法（被 build/env.sh 或 build/*.sh source）：
#   source build/locate.sh
#   locate_require JAVA SDK NDK PY        # 缺什么就报错并说明怎么配
#
# 【零绝对路径】本文件不含任何盘符路径与用户目录，全部靠环境变量与 PATH 推导。

# ---------- 工程根目录（由脚本自身位置推导，不依赖 CWD） ----------
_LOCATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$_LOCATE_DIR/.." && pwd)"

# 给 Windows 程序（java/javac/aapt2）用的盘符风格路径；无 cygpath 时降级
if command -v cygpath >/dev/null 2>&1; then
  ROOT_W="$(cygpath -w "$ROOT")"
else
  ROOT_W="$ROOT"
fi
ROOT_W="${ROOT_W//\\//}"   # 统一成正斜杠：Windows 程序与 Git Bash 都认

# ---------- 小工具 ----------
_win_path() {     # 统一成 X:/a/b 盘符风格：Windows 程序（java / aapt2）最认这种，
                  # Git Bash 也能正确把它转换后传给它们
  local p="$1"
  case "$p" in
    /*) command -v cygpath >/dev/null 2>&1 && p="$(cygpath -w "$p" 2>/dev/null || echo "$p")" ;;
  esac
  echo "${p//\\//}"
}

_latest_dir() {   # 取某目录下"名字最大"的子目录（用于 build-tools / platforms 取最新版）
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

# ---------- java ----------
find_java_home() {
  if [ -n "$JAVA_HOME" ] && [ -x "$JAVA_HOME/bin/javac" ]; then echo "$JAVA_HOME"; return 0; fi
  local j d
  j="$(command -v javac 2>/dev/null || true)"
  [ -n "$j" ] || j="$(command -v java 2>/dev/null || true)"
  if [ -n "$j" ]; then
    d="$(cd "$(dirname "$j")/.." 2>/dev/null && pwd)"
    if [ -n "$d" ] && [ -x "$d/bin/javac" ]; then echo "$d"; return 0; fi
  fi
  return 1
}

# ---------- Android SDK ----------
find_sdk() {
  local d j
  for d in "$ANDROID_HOME" "$ANDROID_SDK_ROOT" "$ANDROID_USER_HOME"; do
    [ -n "$d" ] && [ -d "$d/platforms" ] && { echo "$d"; return 0; }
  done
  # 从 PATH 里的 aapt2 / adb 反推：.../build-tools/<ver>/aapt2、.../platform-tools/adb
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
  # 最后兜底：Android Studio 的默认安装位置（由 $HOME / $LOCALAPPDATA 推导，非写死）
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
    d="$(_latest_dir "$SDK/ndk")"
    [ -n "$d" ] && [ -x "$d/toolchains/llvm/prebuilt/windows-x86_64/bin/clang" ] && { echo "$d"; return 0; }
  fi
  return 1
}

# ---------- aapt2（Python 侧也会用；这里只探测，不强制） ----------
find_aapt2() {
  [ -n "$AJ_AAPT2" ] && [ -x "$AJ_AAPT2" ] && { echo "$AJ_AAPT2"; return 0; }
  command -v aapt2 2>/dev/null && return 0
  [ -n "$BT" ] && [ -x "$BT/aapt2.exe" ] && { echo "$BT/aapt2.exe"; return 0; }
  [ -n "$BT" ] && [ -x "$BT/aapt2" ] && { echo "$BT/aapt2"; return 0; }
  return 1
}

# ---------- 执行探测 ----------
PY="$(find_python || true)"
JAVA_HOME="$(_win_path "$(find_java_home || true)")"
SDK="$(_win_path "$(find_sdk || true)")"
NDK="$(_win_path "$(find_ndk || true)")"

if [ -n "$JAVA_HOME" ]; then
  JAVAC="$JAVA_HOME/bin/javac"
  JAVA="$JAVA_HOME/bin/java"
  KEYTOOL="$JAVA_HOME/bin/keytool"
else
  JAVAC=""; JAVA=""; KEYTOOL=""
fi

if [ -n "$SDK" ]; then
  BT="$(_latest_dir "$SDK/build-tools" || true)"
  PLATFORM="$(_latest_dir "$SDK/platforms" || true)"
  ANDROID_JAR="${PLATFORM:+$PLATFORM/android.jar}"
  D8_JAR="${BT:+$BT/lib/d8.jar}"
  APK_SIGNER_JAR="${BT:+$BT/lib/apksigner.jar}"
  AAPT2="${BT:+$BT/aapt2.exe}"
  [ -x "$AAPT2" ] || AAPT2="${BT:+$BT/aapt2}"
  ZIPALIGN="${BT:+$BT/zipalign.exe}"
  [ -x "$ZIPALIGN" ] || ZIPALIGN="${BT:+$BT/zipalign}"
else
  BT=""; PLATFORM=""; ANDROID_JAR=""; D8_JAR=""; APK_SIGNER_JAR=""; AAPT2=""; ZIPALIGN=""
fi
AAPT2="$(find_aapt2 || true)"

if [ -n "$NDK" ]; then
  CLANG="$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin/clang"
  [ -x "$CLANG" ] || CLANG="$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe"
else
  CLANG=""
fi

D8() { "$JAVA" -cp "$D8_JAR" com.android.tools.r8.D8 "$@"; }
APK_SIGNER() { "$JAVA" -jar "$APK_SIGNER_JAR" "$@"; }

MIN_SDK=24
TARGET_SDK=36

# ---------- 缺失检查 ----------
# 用法：locate_require JAVA SDK NDK PY
# 缺什么就打印「缺什么 / 通常装在哪 / 该设哪个环境变量 / 用哪个参数覆盖」并 exit 1
locate_require() {
  local miss=() name var hint
  for name in "$@"; do
    case "$name" in
      PY)   var="$PY";   hint="python：PATH 里加 python，或 PYTHON=<解释器路径>" ;;
      JAVA) var="$JAVA"; hint="JDK：设 JAVA_HOME=<JDK 根目录>，或把 <JDK>/bin 加进 PATH" ;;
      SDK)  var="$SDK";  hint="Android SDK：设 ANDROID_HOME=<SDK 根目录>（或 ANDROID_SDK_ROOT），也可由 PATH 里的 aapt2/adb 反推" ;;
      NDK)  var="$NDK";  hint="Android NDK：设 ANDROID_NDK_HOME 或 NDK_ROOT=<NDK 根目录>，或放进 <SDK>/ndk/<版本>" ;;
      AAPT2) var="$AAPT2"; hint="aapt2：把 <SDK>/build-tools/<版本> 加进 PATH，或 AJ_AAPT2=<aapt2 路径>" ;;
      *)    var="$name"; hint="$name" ;;
    esac
    [ -n "$var" ] || miss+=("$hint")
  done
  if [ ${#miss[@]} -gt 0 ]; then
    echo "[!] 工具链未就绪，缺以下依赖：" >&2
    local m
    for m in "${miss[@]}"; do echo "    - $m" >&2; done
    echo "    配好后重跑；也可以在 build/env.sh（从 build/env.sh.example 复制）里写死覆盖。" >&2
    exit 1
  fi
}

# ---------- 机器可读输出（给 Python 侧 tools/envload.py 用，避免它去解析 bash）----------
# 只在被直接执行（而非 source）且带 --dump 时输出：bash build/locate.sh --dump
if [ "${BASH_SOURCE[0]}" = "$0" ] && [ "${1:-}" = "--dump" ]; then
  for _v in ROOT ROOT_W PY JAVA_HOME SDK NDK BT PLATFORM ANDROID_JAR JAVAC JAVA \
            KEYTOOL D8_JAR APK_SIGNER_JAR AAPT2 ZIPALIGN CLANG; do
    printf '%s=%s\n' "$_v" "${!_v}"
  done
fi
