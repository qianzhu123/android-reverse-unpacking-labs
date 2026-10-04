# uncrackable · 导学（TUTORIAL）

> 这是 `uncrackable/` 的**课程线**：把 l1 → l2 → l3 串成一条有先后的学习路径。
> 每关各自的**操作手册**在 `l*/SCRIPT.md`（脚本）/ `CLI.md`（命令）/ `GUI.md`（图形化）；
> 本文件只回答"**先学什么、每关练什么、按什么顺序读**"，不重复操作细节。
> 环境怎么搭 → 仓库根 `README.md` 的「Real-target lab environment setup」。

---

## 0. 这条线在练什么

你仓库原有的 4 个 lab（360jiagu / upx_practice / ajiami / ollvm）练的是
**静态、自建样本、可复现的"拆壳"**。`uncrackable/` 是补上另一半：
**外部真实目标 → 动态分析 → 用 oracle 验证**（`PROMPT-REAL.md` 路线）。

三关不是"三个无关题"，而是**同一条能力链上的三级台阶**：

| 关 | 新增的能力 | 一句话 |
|---|---|---|
| l1 | Java 层动态绕过 + **主动调用**目标函数 | 先把"动态"的基础动作练熟 |
| l2 | **native 校验** + 反调试绕过 + 内存写（门限位） | 从 Java 跨到 `.so` |
| l3 | **反篡改（构造函数级线程）** + 完整性校验 | 对抗"主动反 Frida"，最硬 |

---

## 1. 前置知识（没有就先补，否则会卡在"看不懂"而非"做不出"）

不是硬性，但缺哪块补哪块。每块只给"够用"的最小范围：

- **JNI 调用约定**：`JNIEnv*` / `jobject` / `jclass`；native 方法如何收到参数（`[B` = `byte[]`）；
  `GetStringUTFChars` / `GetStringUTFLength` 的用途。→ 只在 **l2/l3** 才真正用得上。
- **ARM/RISC 汇编基础**：读 `push/sub/mov/call`、看比较分支（`cmp`/`je`）、认 PLT 调用（`@plt`）。
  ⚠️ **本机模拟器是 x86_64**，所以你在 `llvm-objdump` 看到的是 **x86_64 反汇编**，
  但样本本身也带 arm64/armv7 的 `.so`——理解"同一份 C 编译到不同 ABI"这件事即可。
- **Frida 生命周期**：`spawn`（在进程启动前注入）vs `attach`；`Java.perform`；类/实例方法区别。
  → 三关都要用，**l1 就是拿来练这个的**。
- **ELF / `.so` 结构基础**：节区（`.rodata`/`.bss`）、导出符号（`llvm-nm -D`）、
  `file offset` 与 `vaddr` 的关系。→ l2/l3 静态侦察要用。
- **反调试/反篡改的常见形态**（术语即可，细节在 l2/l3 现学）：
  `TracerPid`、`ptrace`、`fork` 反调试、Frida 检测、CRC 完整性校验、看门狗线程。

---

## 2. 学习路径（按顺序走，别跳）

### 第 0 步：把环境跑起来（必做）
照仓库根 `README.md`「Real-target lab environment setup」起模拟器 + frida-server。
**这一步不跳过**——三关都依赖它，且卡在环境上最容易劝退。

### 第 1 关 · l1（纯 Java + AES + root 检测）— 打基础
- **目标**：拿到密钥 `"I want to believe"`，并让它通过目标自己的校验。
- **练的核心动作**（三关通用）：
  1. `enumerate.js` —— **先问活着的 JVM 要真实签名**，别猜 `.overload`；
  2. `spawn` 门控 —— 绕过检测要在目标"动手"之前装好；
  3. **主动调用** —— 借目标自己的 `AES.a()` / `a.b()` 解密，而不是把常数抄进 JS；
  4. **oracle + 负控** —— 正确输入得 `true`，错误输入必须得 `false`。
- **读法**：先读 `l1/SCRIPT.md`（有真实输出，建立全貌）→ 再 `l1/CLI.md` 看每条命令
  → 想理解 Java 结构看 `l1/GUI.md`（jadx）。
- **验收**：`[oracle] uncrackable1.a.a(secret) = true` 且 `[oracle-neg] ... = false`。

### 第 2 关 · l2（native `strncmp` + fork/ptrace 反调试）— 跨到 native
- **目标**：拿到 `"Thanks for all the fish"`。
- **新增的三件事**（本关的教学重点）：
  1. **静态逆 native**：`llvm-nm` 找 JNI 导出、`llvm-objdump` 读 `bar` 的算法、
     `-s -j .rodata` 直接读密钥（**artifact oracle**）；
  2. **绕反调试**：目标 `init()` 的 `fork`+`ptrace` 在 Frida 下让 `onCreate` 抛
     `Bad file descriptor` —— 要 stub 掉它；
  3. **门限位**：stub 之后校验仍恒 false，因为 native 把"通过反调试"这个事实记在一个
     `.bss` 字节里（`libfoo+0x400c`）—— **要自己把它写回 1**。这是"hook 不够、要动内存"的第一课。
- **读法**：`l2/SCRIPT.md` §3（静态）→ §4（动态）→ `l2/GUI.md`（Ghidra 看 `bar` 的门限分支）。
- **验收**：`CodeCheck.bar("Thanks for all the fish") = true`。

### 第 3 关 · l3（native + 构造函数级反篡改）— 进阶挑战（**当前 WIP**）
- **目标**：逆清算法**并**在动态下拿到明文——**动态部分尚未通过**。
- **本关的教学价值恰恰在"没做出来"**：它把真实保护里的**主动反 Frida** 暴露出来——
  一个在**库构造函数**里 `pthread_create` 起的**看门狗线程**，在 Java 代码之前就运行，
  检测到篡改就 `raise(SIGABRT)`。常规 `Interceptor` 绕过不够。
- **静态已确定**：`bar = input[i] == keyTable[i] ^ plaintext[i]`（`keyTable` 来自 Java 的 `xorkey`，
  `plaintext` 由目标运行期解到栈上）。
- **读法**：`l3/SCRIPT.md` **§4（尝试过的 4 条路）与 §8（卡点与 4 个攻关方向）**，
  再 `l3/GUI.md`（下一步攻关应从 Ghidra 把构造函数完整反编译、列全所有反篡改路径开始）。
- **验收（未达成）**：`CodeCheck.bar(plaintext) = true`。当前结论按 `PROMPT-REAL.md`
  只能标 **hypothesis**。

---

## 3. 每关的"三件套"怎么读（通用的文档用法）

| 你想干什么 | 读哪份 | 为什么 |
|---|---|---|
| 最快跑通、看清全貌 | `SCRIPT.md` | 有真实输出，先给答案再解释 |
| 搞清每条命令在干嘛 | `CLI.md` | 纯通用命令，逐条解释 |
| 练反编译器、理解结构 | `GUI.md` | jadx/Ghidra 的"看哪里、怎么判" |

三份是**同一骨架的三种手法**，不互相抄结论：判决看 SCRIPT/CLI，理解看 GUI。

---

## 4. 一条"能力自查"清单（走完这条线你应该会）

- [ ] 能用 `enumerate` 拿到混淆类/方法的真实签名，写出正确的 `.overload`
- [ ] 知道 `spawn` 与 `attach` 的区别，知道**为什么绕检测要用 spawn**
- [ ] 会用 `Java.choose` / `$new()` 拿到实例，并**主动调用**目标方法
- [ ] 会用 `llvm-nm` / `llvm-objdump` / `llvm-strings` 在 `.so` 里找导出、算法与常量
- [ ] 理解"**hook 不够时要写内存**"（l2 的门限位）
- [ ] 会写**带负控的 oracle** 来验证真实目标上的结论（无 golden 时）
- [ ] 见过"**构造函数级看门狗线程**"这种主动反 Frida 手段，并知道它的攻关方向（l3）

---

## 5. 做完之后去哪

- **回到主线**：`METHODS.md` 的「动态分析通用方法集」把这些经验沉淀成了可复用方法。
- **自建更难的靶场**：`INJUREDANDROID` / `Frida-Labs` 分级题 / 各加固厂商的脱壳样本
  （仅限已授权目标，遵守 `PROMPT-REAL.md` 的授权与不重分发红线）。
- **把 l3 拿下**：按 `l3/SCRIPT.md` §8 的四条方向攻关（frida-server 改名/补丁、
  spawngate 更早注入、换低版本 Android 让完整性校验自洽、GUI 列全反篡改路径）。
