# uncrackable-l2 · SCRIPT 路线（本仓库工具）

> 遵循 `PROMPT-REAL.md`。目标：**OWASP MASTG UnCrackable Level 2**（公开教学 crackme），
> 包名 `owasp.mstg.uncrackable2`。相比 L1，本关是 **native `.so` 校验 + 反调试**。
> 验证方式：**算法 oracle + 产物 oracle**（无源码、无 golden）。

## §0 概览

- **定位**：在 L1（纯 Java + AES）基础上，进入 **native 层**：静态逆 `.so` 拿算法，动态 patch `.bss` 门限绕过反调试。
- **目标清单**：

| 文件 | 说明 | 是否入库 |
|---|---|---|
| `samples/apks/UnCrackable-Level2.apk` | 目标 APK（第三方） | 否（gitignored） |
| `samples/native/libfoo.so` | 提取的 x86_64 native 库 | 否（gitignored） |
| `samples/dex/classes.dex` | 提取的 dex | 否（gitignored） |
| `pristine/provenance.json` | 来源 + 授权 + 环境指纹 + 结论 | 是 |

## §1 Lab 布局

```
uncrackable-l2/
├── SCRIPT.md / CLI.md / GUI.md
├── samples/{apks,native,dex}/…          # 目标 & 提取物（gitignored）
├── pristine/provenance.json             # 来源+授权+环境指纹+结论
├── analysis_output/                     # 反汇编/反编译产物（可清）
├── (runner: ../tools/hook_run.py, shared)
├── frida/{enumerate,probe,solve}.js     # 动态 hook
└── logs/solve-run.txt                   # 设备侧证据
```

## §2 知识点

- **真实目标的反调试会破坏插桩本身**：`libfoo.so` 的 `init()` 用 `fork`+`ptrace` 反调试；
  在 Frida 下 `onCreate` 直接抛 `Bad file descriptor` 并 abort。**绕过反调试是动态分析的前提**，不是附加项。
- **native 校验常藏在 .bss 门限位后面**：`bar()` 首指令 `cmpb $1, 0x400c` —— 门限位不为 1 直接返回 false。
  门限位由 `init()` 在反调试通过后才写 —— 所以 stub 掉 `init` 后必须**自己把门限位写回 1**。

## §3 静态侦察

```bash
# ① 提取 native 库（x86_64 匹配模拟器）
unzip -o -j samples/apks/UnCrackable-Level2.apk "lib/x86_64/libfoo.so" -d samples/native/

# ② 工具链四级解析：llvm-* 已在 PATH（随 NDK 下发，裸 nm/objdump/strings 不存在）
BIN=$(dirname "$(command -v llvm-objdump)")

# ③ 导出表：拿到两个 JNI 入口
"$BIN/llvm-nm" -D samples/native/libfoo.so | grep Java_
#   => Java_sg_vantagepoint_uncrackable2_MainActivity_init   (返回 void)
#   => Java_sg_vantagepoint_uncrackable2_CodeCheck_bar       (返回 boolean-ish)

# ④ 反汇编 bar：strncmp(input, secret, 23)
"$BIN/llvm-objdump" -d --no-show-raw-insn samples/native/libfoo.so | sed -n '/CodeCheck_bar/,/retq/p'
#   => cmpb $0x1, 0x2ed8(%rip)      # 门限位 0x400c
#   => callq JavaString->GetStringUTFChars
#   => callq JavaString->GetStringUTFLength ; cmpl $0x17(23)
#   => callq strncmp(input, rsp, 23) ; je 0x11b6 -> movb $1,%al   (true)
```

```bash
# ⑤ 读 .rodata 直接拿密钥字节（vaddr 0x11c0 是文件偏移）
"$BIN/llvm-objdump" -s -j .rodata samples/native/libfoo.so | head -5
#   => 11c0 5468616e 6b732066 6f722061 6c6c2074  Thanks for all t
```
**密钥 = "Thanks for all the fish"**（23 字节）。这是 **artifact oracle**：静态即可确定密钥。

## §4 动态分析（脚本路线）

```bash
# ① 枚举/存活探测（确认 Java bridge 与目标类）
../../.venv/Scripts/python.exe ../tools/hook_run.py \
    --package owasp.mstg.uncrackable2 --script frida/probe.js --seconds 5

# ② 解题：stub 反调试 + 写门限位 + 调用目标自身 bar()
../../.venv/Scripts/python.exe ../tools/hook_run.py \
    --package owasp.mstg.uncrackable2 --script frida/solve.js --seconds 7
#   => [+] stubbed MainActivity.init()
#   => [bypass] libfoo.so base=0x7b4db1adc000 gate[+0x400c]=1
#   => [oracle] CodeCheck.bar("Thanks for all the fish") = true
#   => [oracle-neg] CodeCheck.bar("nope-not-it") = false
```

## §5 验证标准

| 断言 | 期望 | 实际 |
|---|---|---|
| 静态：`.rodata` 密钥 = 23 字节串 | `Thanks for all the fish` | ✅ |
| `CodeCheck.bar(secret)` | `true` | ✅ true |
| `CodeCheck.bar("nope-not-it")` | `false` | ✅ false |
| 无 bypass 时 | `init` 反调试使 onCreate 抛 `Bad file descriptor` | ✅ 实测 |

**双 oracle**：artifact（静态 .rodata = 密钥）+ algorithm（bar 返回 true/false 有区分度）。**关键 bypass**：门限位 `0x400c` 必须写 1，否则 `bar` 恒 false —— 这是本关的核心。

## §6 决策流

```
静态 nm 拿 JNI 入口 → objdump bar 见 strncmp + 门限位判据 → objdump .rodata 拿密钥
  → 动态：无 bypass 时 onCreate Bad file descriptor（反调试）→ stub init
  → stub 后 bar 恒 false（门限位未置）→ 写 .bss[0x400c]=1
  → oracle 翻转 true
```

## §7 可重复练习

- 环境指纹见 `pristine/provenance.json`；重跑只需 §4 的 ②。
- 清理：删 `analysis_output/*`；样本从 provenance.url 重下核对 sha256。

## §8 坑与速查

| 坑 | 根因 | 修法 |
|---|---|---|
| onCreate `Bad file descriptor` + abort | native `init()` 的 fork/ptrace 反调试 | 动态：stub `init()`；或用 frida `-f` 配合 (见 CLI) |
| stub 后 `bar` 恒 false | 全局门限位 `.bss 0x400c` 未置 1 | `Memory.writeU8(base+0x400c, 1)` |
| `init: expected return value compatible with void` | init 返回 void，stub 里 `return 0` 非法 | stub 里不 return 值 |
| `bar: argument types do not match .overload('[B')` | bar 收 `byte[]`，传了 JS string | `Java.array('byte', [...])` |
| `bar: cannot call instance method without an instance` | bar 是实例方法 | `Java.choose(...)` 拿实例再 `inst.bar()` |
| 枚举输出全空（L2） | 目标在 Java 层就因反调试 abort，类未到位 | 先 probe 存活，再带 bypass 枚举 |
