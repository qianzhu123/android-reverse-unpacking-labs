# uncrackable-l2 · CLI 路线（通用命令）

> 遵循 `PROMPT-REAL.md`。只用**通用命令**（adb / frida / unzip / llvm-*）。
> **不调用 tools/*.py**（那是 SCRIPT.md 的路线）。目标：`owasp.mstg.uncrackable2`。

## §0 概览

- **定位**：纯命令行复现「装目标 → 起 frida → 静态逆 .so → 动态绕过反调试验证」。
- **目标清单**：同 SCRIPT.md §0。

## §1 Lab 布局

同 SCRIPT.md §1。

## §2 知识点

- CLI 路线用 `frida -l solve.js`（通用 frida 命令）注入，等价于 SCRIPT 的 Python 运行器。

## §3 静态侦察

```bash
# llvm-* 已在 PATH（随 NDK 下发）
BIN=$(dirname "$(command -v llvm-objdump)")

unzip -o -j samples/apks/UnCrackable-Level2.apk "lib/x86_64/libfoo.so" -d samples/native/
"$BIN/llvm-nm" -D samples/native/libfoo.so | grep Java_
"$BIN/llvm-objdump" -d --no-show-raw-insn samples/native/libfoo.so | sed -n '/CodeCheck_bar/,/retq/p'
"$BIN/llvm-objdump" -s -j .rodata samples/native/libfoo.so | head -5
#   => 11c0 ... "Thanks for all t"   (密钥前缀)
```

## §4 动态分析（通用命令）

```bash
# ADB 四级解析（ANDROID_HOME / ANDROID_SDK_ROOT 已设）
ADB="${ANDROID_HOME:-$ANDROID_SDK_ROOT}/platform-tools/adb"

# 环境（模拟器 + frida-server 已在跑，见 uncrackable-l1/CLI.md §4）
"$ADB" install -r samples/apks/UnCrackable-Level2.apk      # => Success

# 注入解题脚本（frida CLI；solve.js 内含 init stub + 门限位写入）
frida -U -f owasp.mstg.uncrackable2 -l frida/solve.js
#   => [bypass] libfoo.so base=0x... gate[+0x400c]=1
#   => [oracle] CodeCheck.bar("Thanks for all the fish") = true
#   => [oracle-neg] CodeCheck.bar("nope-not-it") = false
```

## §5 验证标准

同 SCRIPT.md §5：artifact（`.rodata`=密钥）+ algorithm（`bar` 真/假）双 oracle。

## §6 决策流

同 SCRIPT.md §6。

## §7 可重复练习

指纹见 `pristine/provenance.json`；重跑 §4 的 `frida -U -f ...`。

## §8 坑与速查

| 坑 | 根因 | 修法 |
|---|---|---|
| 无 bypass 时进程 abort（`Bad file descriptor`） | native 反调试 | `frida -f` 在 onCreate 前注入 solve.js（spawn 门控） |
| `frida` 与 server 版本不一致报错 | host 17.x vs server 16.5.9 | 两端统一 16.5.9 |
| Git Bash 路径被改写 | `/data/...` 被当 Windows 路径 | `MSYS_NO_PATHCONV=1` |
