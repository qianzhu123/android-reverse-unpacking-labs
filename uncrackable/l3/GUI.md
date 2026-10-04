# uncrackable-l3 · GUI 路线（图形化工具理解）

> 遵循 `PROMPT-REAL.md`。只用**图形化工具**（Ghidra / IDA / jadx）。
> ⚠️ 本 lab 动态路线未通过（见 SCRIPT.md §4）。GUI 路线在这里**尤其重要**：下一步攻关应在 Ghidra 里把构造函数完整反编译，列出所有反篡改路径。

## §0 概览

- 目标 `owasp.mstg.uncrackable3`；重点是构造函数与 `bar`/`init` 的控制流。

## §1 Lab 布局

同 SCRIPT.md §1。

## §2 知识点

- 本关每条反篡改路径都藏在构造函数与 `.init_array` 指向的函数里；GUI 反编译器是把它们**列全**的最快方式。

## §3 静态侦察（GUI）

**Ghidra（主线）**

1. 导入 `samples/native/libfoo.so`，Auto Analyze。
2. `.init_array`（`llvm-readelf -x .init_array` 显示指向 `0x38a0`）→ 在 Ghidra 跳到 `0x38a0` 反编译：
   - `pthread_create(&t, NULL, 0x37c0, NULL)` ← **看门狗线程**（0x37c0 内打 `"Tampering detected!"` 后 `raise`/`_exit`）。
   - `pthread_create(&t2, NULL, 0x3900, NULL)` ← 线程体 `fork()` → 子进程 `ptrace`。
3. Exports → 反编译 `Java_..._CodeCheck_bar`（0x3a70）：门限 `[0x705c]==2` → `callq 0x12c0`（运行期解密到栈）→ 逐字节 `input[i] == keyTable[0x7040][i] ^ plaintext[i]`。
4. 反编译 `Java_..._MainActivity_init`（0x3a00）：`[0x3910]`（反调试）+ 写 `0x7040` 密钥表 + `[0x705c]++`。
5. **攻关用**：对 `0x38a0` 与其调用链做 xref，把**所有**反篡改副作用（写内存、起线程、`_exit`）列成清单 —— 这是 SCRIPT §8「逐条灭」的输入。

**jadx（Java 层对照）**：`MainActivity` 有 `verifyLibs()`（CRC 校验）、`init([B)`（装 xorkey）、`baz()`、static `xorkey/tampered/check/crc` 字段。

## §4 动态分析（GUI）

GUI 不做注入。

## §5 验证标准

GUI 产出是**理解**：建构函数反篡改清单。判定的达成仍需 SCRIPT/CLI 的 oracle（**当前未达成**）。

## §6 决策流

```
Ghidra 反编译 .init_array 目标 → 列全反篡改路径（看门狗线程/fork+ptrace/内存写）
  → 是 SCRIPT §8「逐条灭」的攻关输入
```

## §7 可重复练习

Ghidra 工程可存 `analysis_output/ghidra/`。

## §8 坑与速查

| 坑 | 根因 | 修法 |
|---|---|---|
| 找不到构造函数 | `llvm-readelf -x .init_array` 才知指向 0x38a0 | 先 dump `.init_array` |
| 认为只有一处反篡改 | 至少两处 pthread_create + 内存写 | 用 xref 列全 |
