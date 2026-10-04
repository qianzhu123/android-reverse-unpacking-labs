# uncrackable-l2 · GUI 路线（图形化工具理解）

> 遵循 `PROMPT-REAL.md`。只用**图形化工具**（Ghidra / IDA / jadx），不调用 tools/*.py。
> 目标：`owasp.mstg.uncrackable2`。**本 lab 的重点在 native**，故 Ghidra/IDA 是主线。

## §0 概览

- **定位**：用 Ghidra/IDA 看懂 `libfoo.so` 的 `CodeCheck.bar` 与反调试逻辑，解释脚本路线的 bypass 为何必要。
- **目标清单**：同 SCRIPT.md §0。

## §1 Lab 布局

同 SCRIPT.md §1。

## §2 知识点

- **native 关要用反编译器**（Ghidra/IDA），jadx 只覆盖 Java 层（这里 Java 层基本是空壳）。

## §3 静态侦察（GUI）

**Ghidra（首选，native）**

1. `File → Import File` 打开 `samples/native/libfoo.so`；`Analysis → Auto Analyze`（默认 x86_64:LE:64:default）。
2. Symbol Tree → Exports，定位两个 JNI 入口：
   - `Java_sg_vantagepoint_uncrackable2_CodeCheck_bar`
   - `Java_sg_vantagepoint_uncrackable2_MainActivity_init`
3. 反编译 `CodeCheck_bar`，**关键读点**：
   - 开头 `if (*(char*)0x400c != 1) return 0;` ← **门限位**（.bss），这是"理解 bypass 为什么必须写它"的根据。
   - `GetStringUTFChars` → `GetStringUTFLength == 23` → `strncmp(s, "Thanks for all the fish", 23)`。
   - 相等 → `return 1`。
4. 反编译 `MainActivity_init`，**关键读点**：`fork()` + `ptrace(PTRACE_TRACEME)` + `waitpid` 组成的**反调试**（也是"为什么在 Frida 下 onCreate 抛 Bad file descriptor"的解释）。
5. `Window → Bytes` 跳到 `0x11c0`，右键 → Data，可见字符串 `Thanks for all the fish`。

**IDA Pro（等价）**：同样看 Exports、`bar` 的门限位分支与 `strncmp`、`init` 的 `fork/ptrace`。

**jadx（Java 层，辅助）**：打开 APK，可见 `CodeCheck` 是 native 方法声明（`native boolean bar(byte[])`），`MainActivity.onCreate` 调 `init` —— 呼应 native 侧。

## §4 动态分析（GUI）

GUI 路线不做注入；动态验证交给 SCRIPT/CLI。

## §5 验证标准

GUI 产出是**理解**：① `bar` 有 `.bss` 门限位（0x400c）；② 密钥 = `.rodata 0x11c0` 的 23 字节；
③ `init` 是 fork/ptrace 反调试。这三点解释了 SCRIPT/CLI 的 bypass 设计。

## §6 决策流

```
Ghidra 导入 libfoo.so → 反编译 bar（见门限位 + strncmp + .rodata 串）
  → 反编译 init（见 fork/ptrace）→ 理解无 bypass 必 abort
  → 回到 SCRIPT/CLI 路线：stub init + 写 0x400c=1 → 验证 bar==true
```

## §7 可重复练习

- Ghidra 项目可存 `analysis_output/ghidra/`（可清）；指纹同 `pristine/provenance.json`。

## §8 坑与速查

| 坑 | 根因 | 修法 |
|---|---|---|
| 反编译 `init` 看不到明显逻辑 | fork/ptrace 经 PLT 调用 | 看 Symbol Tree 的 Imports（fork/waitpid/ptrace）与 `_exit` |
| `bar` 看起来恒返回 0 | 忽略了开头的 `.bss` 门限位分支 | 重点看 `0x400c` 那个 `cmp/movzx` 分支 |
| 以为 Java 层有算法 | 算法全在 `.so` | 本关 jadx 只作声明对照 |
