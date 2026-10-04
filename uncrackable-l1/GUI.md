# uncrackable-l1 · GUI 路线（图形化工具理解）

> 遵循 `PROMPT-REAL.md`。本文件只用**图形化工具**（jadx / Ghidra / IDA），
> **不调用 tools/*.py，也不用 frida CLI**。目标：`owasp.mstg.uncrackable1`。
> GUI 路线给"看懂结构"，判决仍来自 SCRIPT/CLI。

## §0 概览

- **定位**：用反编译器看懂 `sg.vantagepoint.*` 的调用关系，理解脚本路线为什么那样写。
- **目标清单**：同 SCRIPT.md §0。

## §1 Lab 布局

同 SCRIPT.md §1。

## §2 知识点

- **jadx 直接把 smali 还原成 Java**，让 AES 调用链一眼可见——这是脚本路线"验证"，GUI 路线"理解"的分工。

## §3 静态侦察（GUI）

**jadx（首选，Java 反编译）**

1. `File → Open` 打开 `samples/apks/UnCrackable-Level1.apk`。
2. 左树定位到 `sg.vantagepoint.uncrackable1 → MainActivity`。
3. **看 `a(String)`**：这就是校验函数（`verify(View)` 只是按钮回调）。
   - 关键读点：内部 `a.a.a(keyBytes, Base64.decode(...))` → AES 解密 → `String.equals`。
4. 看 `sg.vantagepoint.a.a.a(byte[],byte[])`：`SecretKeySpec` + `Cipher.getInstance("AES/ECB/...")`，确认是 AES。
5. 看 `sg.vantagepoint.a.c` / `a.b`：`/system/bin/.ext/.su`、`/system/xbin/daemonsu` 检查，`Root detected!` → `System.exit`。

**Ghidra / IDA（如需看 native）**：本目标**无 `.so`**（纯 Java），Ghidra/IDA 此处无内容可看——这正是"先看有没有 native"的意义。若换成含 `.so` 的样本（如 Level 3），才切到 Ghidra 看 `JNI_OnLoad`/导出函数。

## §4 动态分析（GUI）

GUI 路线不做注入；动态验证交给 SCRIPT/CLI。

## §5 验证标准

GUI 路线不下判决。它的产出是**理解**：确认
① 校验本体是 `a.a(String)`；② 解密用的是 AES；③ root 检测会 `System.exit`。
这三点解释并支撑了 SCRIPT/CLI 路线的三行结论。

## §6 决策流

```
jadx 打开 → 定位 MainActivity.a(String) → 确认 AES 解密链
  → 确认 root 检测会 exit → 理解为何必须 spawn 门控 + bypass
  → 回到 SCRIPT/CLI 路线执行验证
```

## §7 可重复练习

- jadx 输出可 `File → Save All` 到 `analysis_output/jadx/`（可清）。
- 指纹同 `pristine/provenance.json`。

## §8 坑与速查

| 坑 | 根因 | 修法 |
|---|---|---|
| jadx 里找不到"secret"明文字符串 | 密文/密钥二次编码 | 看 `a.a(String)` 的调用链而非搜字符串 |
| 以为要逆 native | 本样本纯 Java | 先 `unzip -l` 看有没有 `lib/*/*.so` |
