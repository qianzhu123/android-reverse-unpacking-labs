# uncrackable-l3 · SCRIPT 路线（本仓库工具）

> 遵循 `PROMPT-REAL.md`。目标：**OWASP MASTG UnCrackable Level 3**，包名 `owasp.mstg.uncrackable3`。
>
> **⚠️ 状态：静态已完成并实证；动态 oracle 未达成（本 lab 为 WIP，未提交）。**
> 本文件如实记录进度与卡点，不虚构成功。

## §0 概览

- **定位**：L1（Java+AES）→ L2（native check + fork/ptrace 反调试）→ **L3（native check + 反篡改看门狗线程 + 反调试 + 完整性校验 + 运行期解密）**。难度阶梯的最后一跳，也是唯一没跑通的一关。
- **结论**：`bar()` 的校验算法（静态）已逆清；密钥在运行期由 `init([B)` 写入，明文由 `bar` 运行期在栈上解密。**动态绕过被 L3 的"看门狗线程 + 完整性校验"组合挡住**——见 §4、§8。
- **目标清单**：

| 文件 | 说明 | 是否入库 |
|---|---|---|
| `samples/apks/UnCrackable-Level3.apk` | 目标 APK | 否（gitignored） |
| `samples/native/libfoo.so` | 提取的 x86_64 native 库 | 否（gitignored） |
| `samples/dex/classes.dex` | 提取的 dex | 否（gitignored） |

## §1 Lab 布局

```
uncrackable-l3/
├── SCRIPT.md / CLI.md / GUI.md   # 三路线文档
├── samples/{apks,native,dex}/…    # 目标 & 提取物（gitignored）
├── analysis_output/{libfoo.disasm.txt, classes.dump.txt}
├── (runner: ../tools/hook_run.py, shared)
├── frida/{probe.js, recon.js, solve.js}
└── logs/
```

## §2 知识点（本关新增）

- **构造函数级反篡改**：`libfoo.so` 的构造函数直接 `pthread_create(start=libfoo+0x37c0)` 起一个**看门狗线程**，检到 Frida/篡改就打 `"Tampering detected! Terminating..."` 并 `raise(SIGABRT)` / `_exit`。**它在 Java 代码跑之前就在跑**——这是它比 L2 难的原因。
- **fork + ptrace 反调试**：另一处 `pthread_create(start=0x3900)` 的线程里 `fork()`，子进程自 `ptrace`。
- **完整性校验**：Java 侧 `MainActivity.verifyLibs()` + native `init([B)` 做 CRC 校验（logcat 打 `CRC[lib/x86_64/libfoo.so] = …`）；在 Android 14(targetSdk28) 上 `init` 自身抛 `Bad file descriptor`。
- **门限 + 运行期解密**：`bar()` 先查全局计数 `[0x705c]==2`（门限位），再 `callq` 一个**运行期解密函数**（0x12c0，内部还有 linear-congruential PRNG 生成器）把明文解到栈上，逐字节 `input[i] == keyTable[0x7040][i] ^ plaintext[i]`。密钥表由 `init([B)` 写入（Java 传下 `xorkey`）。

## §3 静态侦察（已完成，实证）

```bash
BIN=$(dirname "$(command -v llvm-objdump)")
unzip -o -j samples/apks/UnCrackable-Level3.apk "lib/x86_64/libfoo.so" -d samples/native/
"$BIN/llvm-nm" -D samples/native/libfoo.so | grep Java_
#   => Java_sg_vantagepoint_uncrackable3_CodeCheck_bar        ([B)Z
#   => Java_sg_vantagepoint_uncrackable3_MainActivity_init    ([B)V   ← 装 xorkey
#   => Java_sg_vantagepoint_uncrackable3_MainActivity_baz     ()J     ← 常数 0x18110E3

"$BIN/llvm-objdump" -d --no-show-raw-insn samples/native/libfoo.so > analysis_output/libfoo.disasm.txt
#   bar：cmpl $2, [0x705c] → 门限；callq 0x12c0（运行期解密到栈）；逐字节 xor 比较
#   init：[0x3910]（含 fork/ptrace）+ 写 0x7040 密钥表 + [0x705c]++
#   构造：[0x38a0] pthread_create(0x37c0 看门狗) + [0x705c]++；[0x3910] pthread_create(fork/ptrace)
```

**静态已确定**：`bar = (input[i] == keyTable[i] ^ plaintext[i])`，`keyTable` 来自 Java `xorkey`，`plaintext` 由 `bar` 运行期解到栈上（`bar+0x3a` 处 `rsp`）。

## §4 动态分析（**未达成** — 卡点实证）

已尝试的绕过（`frida/solve.js`，均未通过）：

1. **pthread_create 钩子**（脚本预加载，构造函数前生效）：把落在 `libfoo` 文本段内的 start_routine（含看门狗 0x37c0）换成 no-op。→ 日志见到 `[bypass] pthread_create(libfoo+0x37c0) -> stub`，但**进程仍在启动早期 SIGSEGV**（`fault addr 0xa`，backtrace 落在 `frida-agent` 线程里）——说明还有别的路径触发崩溃。
2. **fork/ptrace 中和**：`Interceptor.replace(fork, -> -1)`、`ptrace -> 0`。→ 未消除崩溃。
3. **Java 侧全量绕过**：stub `init([B)` / `verifyLibs()` / `showDialog`、`isDebuggable->false`、`checkRoot1/2/3->false`、trap `System.exit`/`killProcess`。→ 均命中（有日志），仍崩。
4. **门限位**：`Memory.writeU32(libfoo+0x705c, 2)` 置门限，尝试 `CodeCheck.$new().bar(24B)` 触发解密并抓栈明文。→ 未到达该点，进程已先崩。

**核心卡点**：L3 的反篡改是**构造函数级线程**，在内存中注入/替换其启动例程的成本高，且替换后进程仍在早期崩溃（backtrace 在 `frida-agent` 线程）——属于"**反 Frida 的主动检测**"范畴，常规 Interceptor 绕过不足以清除。

## §5 验证标准（**尚未满足**）

| 断言 | 期望 | 实际 |
|---|---|---|
| `CodeCheck.bar(plaintext)` | `true` | ❌ 未达成（进程早崩，未到调用） |
| 静态：`bar` 算法 = `keyTable ^ plaintext` | 成立 | ✅ 静态已证 |

**本 lab 不声称成功。** 按 `PROMPT-REAL.md`，无 oracle 的结论只能标 hypothesis —— 故此处结论为 **hypothesis：明文即"输入使逐字节 xor 比较成立"的串，值未取到**。

## §6 决策流（本关实际路径）

```
静态 bar/init 逆清 → 动态：构造函数看门狗先崩
  → 尝试 pthread_create 钩子灭看门狗 → 仍早崩（另有路径）
  → ★ 卡点：需更强的反-反调试（见 §8）
```

## §7 可重复练习

- 环境指纹同 L1/L2（Android Emulator x86_64 / SDK34 / frida-server 16.5.9）。
- 当前 `frida/solve.js` 可重放，但**不通过**——保留作为"卡点复现脚本"。

## §8 坑与速查（本关教训）

| 现象 | 根因 | 方向 |
|---|---|---|
| 构造函数线程先崩 | `pthread_create` 在 Java 前执行 | 钩子须**脚本预加载期**装好（已做） |
| 灭看门狗后仍 SIGSEGV | 还有其他反篡改路径 / 或看门狗被唤醒 | 需 dump 崩溃线程栈、逐路径定位 |
| backtrace 落在 `frida-agent` 线程 | 反调试可能直接针对 frida 的线程/内存 | 需要**改 frida-server 或外部反-反调试工具**（Anti-Anti-Frida 类），而非仅 Java/native hook |
| `init([B)` 抛 Bad file descriptor | 完整性校验在 A14 不自洽 | stub 它（已做）但不解决看门狗 |
| 下一步建议 | — | ① 用 `frida -f` + `--enable-jit` 或 spawngating 更早注入；② 给 frida-server **改名/打补丁**规避字符串与线程检测；③ 换真机/低版本 Android 使完整性校验自洽；④ 先在 GUI（Ghidra）把构造函数完整反编译，列出**所有**反篡改路径再逐条灭 |
