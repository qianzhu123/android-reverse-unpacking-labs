# uncrackable-l3 · CLI 路线（通用命令）

> 遵循 `PROMPT-REAL.md`。只用**通用命令**（adb / frida / unzip / llvm-*）。
> ⚠️ 本 lab **动态路线未通过**（见 SCRIPT.md §4）；本文件记录通用的静态侦察与环境命令，动态部分给出可复现的失败路径。

## §0 概览

- 目标 `owasp.mstg.uncrackable3`。与 L2 同属 native 校验，但多了**构造函数级反篡改看门狗**。

## §1 Lab 布局

同 SCRIPT.md §1。

## §2 知识点

- 本关的反篡改在**构造函数**里起线程，早于任何 Java 代码 —— CLI 路线里 `frida -f` 的注入时机就是关键变量。

## §3 静态侦察

```bash
BIN=$(dirname "$(command -v llvm-objdump)")
unzip -o -j samples/apks/UnCrackable-Level3.apk "lib/x86_64/libfoo.so" -d samples/native/
"$BIN/llvm-nm" -D samples/native/libfoo.so | grep Java_
"$BIN/llvm-objdump" -d --no-show-raw-insn samples/native/libfoo.so | sed -n '/CodeCheck_bar/,/retq/p'
#   => 门限 cmpl $2,[0x705c]；callq 运行期解密；逐字节 xor 比较
```

## §4 动态分析（通用命令 · 可复现失败路径）

```bash
ADB="${ANDROID_HOME:-$ANDROID_SDK_ROOT}/platform-tools/adb"
"$ADB" install -r samples/apks/UnCrackable-Level3.apk

# 用 frida CLI 注入（与 SCRIPT 的 Python 运行器等价）
frida -U -f owasp.mstg.uncrackable3 -l frida/solve.js
#   => [bypass] pthread_create(libfoo+0x37c0) -> stub
#   => 进程随后 SIGSEGV（反篡改未完全清除）—— 未达成 oracle
```

## §5 验证标准

同 SCRIPT.md §5：**未满足**（无 oracle）。

## §6 决策流

同 SCRIPT.md §6。

## §7 可重复练习

指纹与前置条件见 `../README.md`「Real-target lab environment setup」；`frida/solve.js` 可重放卡点。

## §8 坑与速查

| 坑 | 根因 | 修法方向 |
|---|---|---|
| `frida` 版本不符 | host/server 必须一致 | 统一 16.5.9（见 README setup） |
| 早崩、backtrace 在 frida-agent | 主动反 Frida | 见 SCRIPT.md §8 的四条方向 |
