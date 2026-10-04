# uncrackable-l1 · SCRIPT 路线（本仓库工具）

> 本 lab 遵循 `PROMPT-REAL.md`（外部真实目标分析），非 `PROMPT.md`（自建样本）。
> 目标：**OWASP MASTG UnCrackable Level 1**（公开教学 crackme），包名 `owasp.mstg.uncrackable1`。
> 验证方式：**行为/算法 oracle**（无源码、无 golden，不做 byte-for-byte 对比）。

## §0 概览

- **定位**：用本仓库工具（Python + Frida）对一个**外部真实目标**完成「静态侦察 → 动态 hook → oracle 验证」闭环。
- **为什么选它**：OWASP 公开教学靶场，授权清晰、体积小（66 KB）、目标单一（一个 AES 密钥校验），适合作为真实目标路线的第一个样板。
- **目标清单**：

| 文件 | 说明 | 是否入库 |
|---|---|---|
| `samples/apks/UnCrackable-Level1.apk` | 目标 APK（第三方） | 否（gitignored，仅记 sha256） |
| `samples/dex/classes.dex` | 从 APK 提取的 dex | 否（gitignored） |
| `pristine/provenance.json` | 来源 + 授权 + 环境指纹 + 结论 | 是 |

## §1 Lab 布局

```
uncrackable-l1/
├── SCRIPT.md / CLI.md / GUI.md   # 三路线文档
├── samples/apks/UnCrackable-Level1.apk   # 外部目标（gitignored）
├── samples/dex/classes.dex               # 提取产物（gitignored）
├── pristine/provenance.json              # 来源+授权+环境指纹+结论（PROMPT-REAL 的 pristine）
├── analysis_output/classes.dump.txt      # dexdump 产物（可清）
├── (runner: ../tools/hook_run.py, shared)
├── build/                                # 环境脚本（四级工具链解析）
├── frida/{enumerate,hook,solve}.js       # 动态 hook（一等公民）
└── logs/solve-run.txt                    # 设备侧证据（gitignored，可重跑再生）
```

相比 `PROMPT.md` 的布局：**无 `src/` `shell/`**（无源码）；`pristine/` 从「金样本」改为「来源+完整性记录」；`frida/` `logs/` 为主力。

## §2 知识点

- **静态侦察给的是假设，不是判决**。`llvm-strings` 命中 `Root detected!` / `/system/bin/.ext/.su`，说明"有 root 检测"，但**判不出校验算法**（字符串已被 Base64/hex 二次编码）。真正的密钥逻辑只在 smali 里。
- **真实目标里方法名会被混淆**：`MainActivity.a(String)` 才是校验函数，`verify(View)` 只是 onClick。靠 `dexdump -d` 的 `type`/调用链定性，不靠名字。

## §3 静态侦察

```bash
# ① 工具链四级解析：llvm-* 已在 PATH（随 NDK 下发；裸 strings 不存在）；dexdump 随 build-tools
LS=$(command -v llvm-strings)
DD="$ANDROID_HOME/build-tools/$(ls "$ANDROID_HOME/build-tools" | sort -V | tail -1)/dexdump"

# ② 提取 dex 并扫字符串（只做定位，不做判决）
unzip -o -j samples/apks/UnCrackable-Level1.apk classes.dex -d samples/dex/
"$LS" samples/dex/classes.dex | grep -iE "root|magisk|frida|secret|system/bin"
#   => /system/bin/.ext/.su
#   => /system/xbin/daemonsu
#   => Root detected!
#   => This is the correct secret.        ← 校验相关的 UI 文案
```

```bash
# ③ 定性：反汇编看调用链形状（dexdump 随 build-tools 下发，四级解析取最新版）
"$DD" -d samples/dex/classes.dex > analysis_output/classes.dump.txt
# 找到真正的校验函数：sg.vantagepoint.uncrackable1.a.a(String) -> boolean
#   它内部：Base64.decode(密文) → a.b(hex密钥) → a.a.a(key,enc) AES → input.equals(明文)
```

## §4 动态分析（脚本路线）

```bash
# 前置：模拟器已起、frida-server 已跑、APK 已装（见 CLI.md §4 的通用步骤）
# 用本仓库的 venv 解释器（frida 装在 repo 本地，非全局）

# ① 枚举真实方法签名（先拿 ground truth，别猜 overload）
../../.venv/Scripts/python.exe ../tools/hook_run.py \
    --package owasp.mstg.uncrackable1 --script frida/enumerate.js --seconds 7
#   => sg.vantagepoint.uncrackable1.MainActivity.a(java.lang.String) -> void
#   => sg.vantagepoint.a.b.a(android.content.Context) -> boolean  [static]   ← root 检测
#   => sg.vantagepoint.a.c.a()/.b()/.c() -> boolean  [static]

# ② 跑解题脚本（bypass 守卫 + 主动调用目标自身解密 + oracle）
../../.venv/Scripts/python.exe ../tools/hook_run.py \
    --package owasp.mstg.uncrackable1 --script frida/solve.js --seconds 8
#   => [+] bypass a.b.a(Context)
#   => [+] bypass a.c.a()/.b()/.c()
#   => [recovered] secret = "I want to believe"
#   => [oracle] uncrackable1.a.a(secret) = true
#   => [oracle-neg] uncrackable1.a.a("definitely-not-the-secret") = false
```

## §5 验证标准（行为 oracle）

本 lab 无 golden，用**算法 oracle + 负控**：

| 断言 | 期望 | 实际 |
|---|---|---|
| `A.a(secret)` | `true` | ✅ true |
| `A.a("definitely-not-the-secret")` | `false` | ✅ false |
| 恢复值 | 与 APP 自己解密结果一致 | ✅ 由 APP 自身 `AES.a()` 产出，非 JS 移植 |

**关键设计**：不把常量搬进 JS 重算，而是**用 APP 自己的函数**（`A.b` hex→bytes、`AES.a` 解密）算出明文——证明理解的是**调用关系**，不是抄常数。负控证明 oracle 有区分度，不是恒真。

## §6 决策流

```
静态 strings 命中 root 检测 → 需要动态绕过（否则 APP 检测到 root 即 System.exit）
  → dexdump 定位校验函数 a.a(String)
  → frida enumerate 拿真实签名
  → spawn 门控：resume 前装好 bypass（否则 exit 先发生）
  → 主动调用 APP 解密 → 喂回校验 → oracle 翻转 true
```

## §7 可重复练习

- 环境指纹固定在 `pristine/provenance.json`：设备=Android Emulator x86_64 / Android 14 (SDK 34)、frida-server 16.5.9、host frida 16.5.9 / frida-tools 13.7.0。
- 快速重跑：`../../.venv/Scripts/python.exe ../tools/hook_run.py --package owasp.mstg.uncrackable1 --script frida/solve.js`
- 清理：删除 `analysis_output/*` 即可；`samples/` 重下见 `pristine/provenance.json` 的 provenance.url。

## §8 坑与速查

| 坑 | 根因 | 修法 |
|---|---|---|
| `Java is not defined` | host frida 17.x 的 Java bridge 与 frida-server 17.22 不匹配 | host 与 server 同步到 **16.5.9** |
| `.overload('[B','[B')` 猜错 | 方法名被混淆，overload 靠猜必错 | 先用 `enumerate.js` 打印 `getDeclaredMethods()` 真实签名 |
| `java is not defined` | Frida 无 `java.lang.reflect` 全局 | 用 `Java.use('java.lang.reflect.Modifier')` |
| root 检测先于 hook | `System.exit` 在 onCreate 早期 | `spawn`+`resume` 门控，bypass 在 resume 前装好 |
| 低熵字符串搜不到密钥 | 密钥/密文均二次编码 | 密钥 = `uncrackable1.a.b()` 里 `Character.digit` 解析的 hex（见 SCRIPT §3 ③） |
