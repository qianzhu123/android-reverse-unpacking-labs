# GUI.md — 图形工具路线：用 jadx-gui / IDA·Ghidra / 010 Editor 看懂每一步

> 本文件与 `SCRIPT.md`、`CLI.md` **结构完全平行**（同一套章节骨架一一对应），只讲「图形工具怎么看」。
>
> **路线纯度（硬）**：本路线的工具**必须是图形应用**：
> · 反编译读 Java / dex → **jadx-gui**（打开 APK/dex，出可浏览的包树与方法体）；
> · SO 结构、反汇编、调用图 → **IDA** 或 **Ghidra**（打开 `.so`，看 段视图/函数图/反汇编）；
> · 十六进制读字节 → **010 Editor**（或 HxD / ImHex），打开文件、跳到偏移、读原始字节；
> · APK 结构浏览 → **GDA / JEB**（打开 APK 看 AndroidManifest、dex 列表、资源）。
>
> **命令行工具不属于本路线**：`dexdump -d`、`llvm-objdump`、`unzip -l`、`aapt2 dump`、`xxd`
> 都是命令 —— 它们属于 `CLI.md`。本文件只**读取**这些命令导出的产物，或在图形应用里做等价操作。
> `python tools/*.py` 属于 `SCRIPT.md`，本文件不调用。
>
> **路线分工**：判定靠 SCRIPT/CLI（可量化、可写进判据），看懂靠 GUI（jadx-gui 出可浏览的 Java、
> IDA/Ghidra 出反汇编与函数图、010 Editor 出可编辑的十六进制视图）。图形工具给的是「可读形态」，
> 不替代量化判据；每节都写清「点哪里 / 看什么 / 怎么判」。

---

## 概述

**项目定位**：同 `SCRIPT.md` —— 用自造样本把虚拟化保护铺成 L1→L5 / S1→S3 的阶梯，
图形工具的价值在于**把「方法体塌缩为调解释器」这件抽象的事看见**。

**为什么自造样本**：同 `SCRIPT.md`。

### 文件与样本索引

| 图形工具 | 用在哪一步 | 本文档对应章节 |
|---|---|---|
| jadx-gui | 打开样本 APK，看业务方法体只剩一行、看解释器 switch | 「判定 · DEX」「脱壳 · DEX」 |
| IDA / Ghidra | 打开 `libcalc_*.so`，看分派函数、case 块、间接跳转 | 「判定 · SO」「脱壳 · SO」 |
| 010 Editor | 打开 `assets/core_a.dat` / 打开 dex 跳 `fill-array-data`，手工读字节 | 「脱壳 · L1/L2」 |
| GDA / JEB | 打开 APK，看 AndroidManifest / dex 列表 / 资源清单 | 「判定 · 概览」 |

`samples/` 清单与 `SCRIPT.md`「文件与样本索引」完全相同。

---

## 工程结构与样本

```text
vmp/
├── samples/apks/     app_golden.apk · app_l1..l5.apk · app_s1..s3.apk · neg_*.apk
├── samples/dex/      golden.dex · level_L1..L5.dex · level_S1..S3.dex · neg_*.dex
├── samples/payloads/ golden_ops.json · level_*.bin · level_*.map.json
├── samples/native/   libcalc_s{1,2,3}_{arm64,x86_64}.so
├── analysis_output/  （GUI 工具导出的产物建议放这里，或用系统临时目录）
└── src/ tools/ build/ frida/ neg/
```

---

## 知识点总览（图形工具能看到什么）

原理与判据代号见 `SCRIPT.md`「知识点总览」。本表只给「判据 → 在 GUI 里长什么样」：

| 判据 | 在图形工具里的**可读形态** |
|---|---|
| V1 汇聚调用 | jadx-gui 里点开 `CalcLogic`：`mix/twist/digest` 三个方法体**都只有一行** `return Core.run(...)` |
| V3 载荷外置 | GDA/JEB 的资源树里 `assets/` 下有一个小编号资源；010 Editor 打开它是高熵字节 |
| V4 解释器 | jadx-gui 里 `Core.run` 是个**大方法**，含 `switch` + `while` 循环 |
| V5 内联 VM | jadx-gui 里**没有** `Core` 类，但 `CalcLogic` 的每个方法体内都有一份**相同的 switch** |
| V6 随机 opcode | jadx-gui 的 switch 显示为 `sparse-switch`，case 值是大而不连续的字节值 |
| VN1 SO 内嵌表 | IDA/Ghidra 里 `.rodata` 很小；跳过去看是紧凑字节表 |
| VN2 分派非中心 | IDA/Ghidra 的**函数图**里没有单一 switch 汇聚，而是一堆 `blr xN` / `br xN` |
| B13 节头剥离 | IDA/Ghidra 打开后**只有段（Segments）没有节名（Sections）** |

### 判据代号总表

代号与量化阈值见 `SCRIPT.md`「判据代号总表」，GUI 只补「可读形态」一列（见上表）。
**一句话记法**：`V*` 是 DEX 层、`VN*` 是 SO 层、`B13` 是结构性加壳。

### VM 原理在 GUI 里的样子（对照 `SCRIPT.md`「虚拟机是怎么运转的」）

虚拟机就是「取指 → 译码 → 执行」一个循环。图形工具把它**画出来**：

| VM 概念 | jadx-gui（DEX） | IDA / Ghidra（SO） |
|---|---|---|
| **主循环** | `Core.run` 是个大方法，里面 `while (i < code.length)` | `vmr` 是个大函数，尾部 `b <loop_head>` 回边 |
| **取指** | `code[i++] & 0xFF`（一行 Java） | `ldrb wN, [xN, xN]` + `add xN, xN, #1` |
| **译码/分派** | `switch (op)`（jadx 会标成 packed/sparse） | 一长串 `cmp/subs wN,wN,#imm` + `b.eq`（比较级联） |
| **栈（求值栈）** | `STACK[sp++]` / `STACK[--sp]` | `ldr/str wN, [xN, #0x14]` + `lsl #2` |
| **opcode 表** | switch 的 `case` 值 | 比较级联里的 `#imm` |
| **字节码** | jadx 点开 `P_MIX` 看到 `byte[]`（有符号十进制） | IDA 跳到 `.rodata` 看紧凑字节 |

**怎么判**：在 jadx-gui 里，**一个方法体内同时出现 `while` + `switch` + `数组[指针++]`**，就是
一台 VM 的解释器；在 IDA 里，**一个函数体内同时出现 `ldrb` + 一串 `cmp/b.eq` + 回边**，就是
native 解释器。**看到这个骨架，就知道样本用了虚拟化保护**（不必依赖任何字符串）。

---

## 判定：这是虚拟化保护吗（图形工具）

### 概览 · 用 GDA / JEB 打开 APK

1. GDA / JEB 里 `File → Open`，选 `samples/apks/app_l2.apk`；
2. 左侧看 **AndroidManifest**：包名 `com.demo.calc`、入口 `CalcActivity`；
3. 看 **dex 列表**：只有一个 `classes.dex`；
4. 看 **资源树**：`assets/` 下有一个 `core_a.dat`。

**怎么判**：包名/入口是中性名（不含任何加固字样）；`assets/` 里那个**既小又不像资源**的条目
就是第一个嫌疑。**但注意：名字本身不是判据** —— 判据是「它在 dex 里被引用、体积小、内容不透明」，
这一点要到 jadx-gui 里看代码引用（或 `CLI.md` 的 `dexdump`）才能坐实。

### 判定 · DEX（jadx-gui）

1. jadx-gui `File → Open`，选 `samples/apks/app_l1.apk`；
2. 展开包树到 `com.demo.calc → CalcLogic`；
3. 看 `mix` / `twist` / `digest` 三个方法。

**你会看到**（这是本 lab 最核心的「一眼」）：

```java
public static int mix(int a, int b) { return Core.run(0, new int[]{a, b}); }
public static int twist(int a)      { return Core.run(1, new int[]{a}); }
public static int digest(int a, int b) { return Core.run(2, new int[]{a, b}); }
```

**怎么判（V1）**：三个业务方法的**方法体都只有一行**，且都调用**同一个** `Core.run`。
正常业务方法的实现不会被整体抽走 —— 这就是「方法体塌缩为调解释器」。

4. 再点开 `Core → run`。

**你会看到**：

```java
public static int run(int id, int[] args) {
    byte[] code = (id == 0) ? P_MIX : (id == 1) ? P_TWIST : P_DIGEST;
    int sp = 0, i = 0;
    while (i < code.length) {
        int op = code[i++] & 0xFF;
        switch (op) {
            case 0x01: STACK[sp++] = args[code[i++] & 0xFF]; break;
            ...
            case 0xFF: return STACK[--sp];
        }
    }
}
```

**怎么判（V4）**：一个**大方法**，含 `while` 循环 + `switch`（jadx 会把它标成分派）。
`P_MIX/P_TWIST/P_DIGEST` 是静态 `byte[]` —— 点它们能跳过去看内容（jadx 会显示成
`{-1, 0, -1, ...}` 之类的有符号十进制数组，那是**自定义字节码**，不是合法 dalvik 指令）。

> **jadx 看不到什么**：它**看不到原始操作逻辑**。`P_MIX` 那串数字的语义，要结合
> `Core.run` 的 switch 分支人工对照才推得出来 —— 这就是「jadx 能看到类 ≠ 能恢复原始逻辑」。

### 判定 · L5 内联 VM（jadx-gui）

打开 `samples/apks/app_l5.apk`。

**你会看到**：包树里**没有 `Core` 类**；`CalcLogic` 的 `mix/twist/digest` 各自是一个**大方法**，
每个方法体里都内嵌了**一模一样的 `while + switch`**。

**怎么判（V5）**：这就是「内联 VM」—— 没有 hub 可抓，只能靠「多个方法体内含同一组 case」来
识别。**聚拢类判据（V1）在这里失效**，这是本 lab 刻意设置来提醒「判据有边界」的一档。

### 判定 · L4 随机 opcode（jadx-gui）

打开 `samples/apks/app_l4.apk`，看 `Core.run` 的 switch。

**你会看到**：jadx 把它显示成 **`sparse-switch`**，`case` 值形如
`0x22, 0x3E, 0x57, 0x65, 0x78, 0x9A, 0xA3, 0xCA, 0xCB, 0xD2, 0xD4` —— 大、跳、不连续。

**怎么判（V6）**：`sparse-switch` 本身说明 case 值不连续；再看到每个 case 体里是
`add-int/lit16` 这类**带内联立即数**的算术（一条顶两条基础指令），就是「融合算子 + 随机 opcode」。

### 判定 · SO 样本（IDA / Ghidra）

1. 用 IDA 打开 `samples/native/libcalc_s1_arm64.so`（或 Ghidra 里 `File → Import`）；
2. 看 **Segments / Sections 窗口**。

**你会看到（S1）**：
- 有正常的节名（`.text` / `.rodata` / `.dynsym` …），`.rodata` **很小**（约 0x24 字节）；
- 跳到 `.rodata`：是一串紧凑字节（`01 00 01 01 03 02 11 04 …`）—— **自定义字节码**；
- 反汇编窗口里 `vmr`（或 `call`）是个大函数，分派是**一长串 `subs w8,w8,#imm` + `b.eq`**。

**怎么判（VN1）**：`.rodata` 异常小 + 有 `Java_*` 导出（native 业务入口）= SO 里内嵌了表。

**你会看到（S2 / S3，打开 `libcalc_s2/s3_arm64.so`）**：
- S2：反汇编里最大函数的分派处是 **`blr x8`（间接调用）** —— 目标是运行期才算出的地址；
  交叉引用（xref）看不到一个固定的函数表；
- S3：**函数图（Function graph）里没有中心函数** —— 一堆小块通过 `br x8` 互相跳。

**怎么判（VN2）**：分派不是「一个大 switch」，而是间接调用 / 块网 → 静态难解，需动态。

> **IDA/Ghidra 看不到什么**：S2 的 handler 表是**运行期装配**的，静态只能看到「有一张表被填」；
> S3 是 computed-goto，被优化成一堆块。两者的 opcode→handler 映射**静态拿不到**。

---

## 脱壳：图形工具参与方式

### 图形工具版「去虚拟化五步」（对照 `SCRIPT.md` §A）

`SCRIPT.md` 讲了通用五步；在图形工具里它们长这样：

| 步 | jadx-gui / IDA 里怎么做 |
|---|---|
| **① 定位解释器** | jadx-gui：点开业务类，找**方法体里带 `while`+`switch` 的那个大方法**；IDA：找**最大的函数**，看它的比较级联/跳转表 |
| **② 找字节码** | jadx-gui：点 `P_MIX` 之类的静态 `byte[]` 跳过去；或看 `Core.load` 读哪个 assets；010 Editor：跳到该文件/偏移看字节 |
| **③ 反推 opmap** | jadx-gui：**逐个 `case` 点开，读它内部做了什么运算**（点 `case 0x03:` 那段，看是 `xor-int`）；IDA：逐个 case 地址（按 `G` 跳）看 `eor/add/mul/sub` |
| **④ 解码** | 拿 010 Editor 里的字节码 + ③ 的表，一条条翻译（纸笔 / 记事本） |
| **⑤ 验证** | jadx-gui 里点黄金类 `CalcLogic.mix`，把你翻译的表达式与它对照；或在设备上跑 `frida/oracle_run.js` |

**图形工具卡在哪**（与 `SCRIPT.md` §A 的「卡住」一一对应）：① 卡住 = jadx 里 `Core.run` 没有
`switch` 而是 `invoke Method`（L3）；③ 卡住 = case 体里是 `add-int/lit16`（融合算子，立即数
编在指令里，GUI 也拆不开，L4）；SO 侧 ① 卡住 = IDA 里没有中心函数，只有 `blr`/`br`（S2/S3）。

---

### L1 · 用 010 Editor 手工读「自定义字节码」

> 这一步是 `CLI.md`「L1 · 从 fill-array-data 取字节码」的**图形版**：同一个产物，用 GUI 读。

1. 010 Editor `File → Open`，选 `samples/dex/level_L1.dex`（或直接开 APK 里的 `classes.dex`）；
2. 在 jadx-gui 里先定位：点开 `Core → <clinit>`，看到 `P_MIX` 由 `fill-array-data` 初始化 ——
   jadx 会把 `fill-array-data` 的偏移显示出来（形如 `+0x0000001e`）；把 `Core.<clinit>` 起始地址
   加上该偏移，就是数据区；
3. 在 010 Editor 里按 `Ctrl+G` 跳到该偏移，看到：
   `00 03 | 01 00 | 0c 00 00 00 | 01 00 01 01 03 02 11 04 02 03 05 07`：
   - `00 03` = ident（`0x0300`，表示 fill-array-data）；
   - `01 00` = element width = 1（字节数组）；
   - `0c 00 00 00` = size = 12；
   - 后面 12 字节就是 `P_MIX` 的内容。
4. 回到 jadx-gui，**逐个点开 `Core.run` 的 `case`**，读它的语义（这是 ③ 的关键）：

```java
switch (op) {
    case 0x01: STACK[sp++] = args[code[i++] & 0xFF]; break;   // ← 点进来看到这个 = LOADARG
    case 0x02: STACK[sp++] = code[i++] & 0xFF; break;          // ← 少了 args[...] = PUSH
    case 0x03: { int b = STACK[--sp], a = STACK[--sp]; STACK[sp++] = a ^ b; break; }  // XOR
    case 0x04: ... a + b ...   // ADD ; case 0x05: MUL ; case 0x06: SUB
    case 0xFF: return STACK[--sp];                             // RET
}
```

**怎么判**：这 12 字节 `01 00 01 01 03 02 11 04 02 03 05 07` 与上面读到的 case 语义对照：
`01`=LOADARG、`00`=参数 0、`01`=LOADARG、`01`=参数 1、`03`=XOR、`02`=PUSH、`11`=0x11、
`04`=ADD、`02`=PUSH、`03`=3、`05`=MUL、`07`=RET → **`((a ^ b) + 0x11) * 3`**。

> **jadx 显示 `byte[]` 是有符号十进制**（`-1` 其实是 `0xFF`、`17` 就是 `0x11`）——
> 对照时先把负数换算回无符号，否则 opmap 会整体错位（`AGENTS.md` §12.12）。
>
> 同样的操作也能在 `samples/payloads/level_L1.bin` 上做（那是「长度头 + 三段字节码」的导出件）。

### L2 · 用 010 Editor 读密文载荷

1. 010 Editor 打开 `samples/payloads/level_L2.bin`（等价于 APK 里的 `assets/core_a.dat`）；
2. 你会看到高熵字节（`d5 6a cc e5 6c 0a 42 fb …`）；
3. 在 jadx-gui 里打开 `app_l2.apk`、点开 `Core` 的 `KEY` 数组，看到 16 字节密钥
   （jadx 显示为有符号十进制：`-39, 99, -61, …` = `d9 63 c3 …`）；
4. 回到 010 Editor，用 `Tools → Convert → XOR`（或手算第一个字节 `d5 ^ d9 = 0c = 12`）验证：
   解密后第一个字节 `0c` 正好是 `P_MIX` 的长度 12 → 载荷 = `[12,9,15] + 三段字节码`。

**怎么判**：解出来的前 3 字节是各段长度，之后按 L1 的方法读字节码（case 语义从 jadx 的
`Core.run` 读）。**关键点**：L2 与 L1 的 switch 分支**完全一样**（都是 `case 0x01..0xFF` 那套），
差别只在「字节码从哪来」。

### L3 / L4 / L5 · 图形工具能看，但解不完整

- **L3**：jadx-gui 里 `Core.run` **没有 switch**，而是 `Method[]` + `for` 循环 + `invoke`
  （反射）。**opcode→handler 的映射静态看不全**（映射在 `int[] DISPATCH` 里，但反射目标的分派
  关系要靠动态 —— 不过可以**人工**把 `h0..h6` 六个小方法的字节码各读一遍，得到语义）；
  → 转 `SCRIPT.md` / `frida`。
- **L4**：jadx-gui 能看 `sparse-switch` 与各 case 体，但**融合算子把立即数编进了指令**
  （case 体里是 `v8 = v8 + 0x11` 这种），图形界面也拆不开 → 静态只能部分还原。
- **L5**：jadx-gui 里**没有 `Core` 类**，但 `CalcLogic` 的 `mix/twist/digest` **每个方法体内
  都有一份相同的 switch** —— 对**每个方法**重复 L1 的第 3、4 步即可人工还原
  （opmap 是同一套，字节码是每个方法各自的那一段）。

### SO · 用 IDA/Ghidra 看 case 块并人工还原（S1）

1. IDA/Ghidra 打开 `libcalc_s1_arm64.so`；
2. 找到 `vmr`（最大值函数 —— Ghidra 里按 Function 大小排序），看它的比较级联
   `subs w8,w8,#0x1 / b.eq <case1>`；
3. 依次跳到每个 `case` 目标地址（IDA 里按 `G` 输入地址），看块内的**数据运算**：
   - 有 `eor w8,w8,w9` → XOR；有 `add w8,w8,w9`（**两个 w 寄存器**）→ ADD；`mul` → MUL；`sub` → SUB；
   - 只有 `ldrb` → PUSH；`ldrb` + 带缩放的 `ldr`（`lsl #2`）→ LOADARG；从栈数组弹元素 → RET。
4. 得到 opmap 后，对照 `.rodata` 的字节（用 010 Editor 打开 `.so`，跳到 `llvm-readelf -S`
   给出的 `.rodata` 偏移 `0x548`）人工解码：`01 00 01 01 03 02 11 04 02 03 05 ff`
   → `((a ^ b) + 0x11) * 3`。

**怎么判**：解出来应与黄金逻辑一致（`((a ^ b) + 0x11) * 3` 等）。**注意**：`add x9,x9,#0x14`
是**指针簿记**（不是 VM 语义），别把它当成 ADD —— 这是本 lab 踩过的坑（`AGENTS.md` §12.9），
IDA 里看着也很像。**只有两个 `w` 寄存器的 `add/sub` 才算数据运算。**

> **S2/S3 在 IDA 里**：S2 的 `vmr` 里只有一句 `blr x8`（间接调用，目标运行期才算）；S3 里是
> 一串 `br x8` 互相跳（函数图里没有中心节点）。**图形工具到此为止**，要还原 opcode 表必须动态。


---

## 验证判据（图形工具视角）

图形工具**不产生**量化判据，只做**可读性验证**：

| 判据 | 图形验证 |
|---|---|
| 还原的操作流对不对 | jadx-gui 里点 `CalcLogic.mix`，把它与手工解出的 `((a^b)+0x11)*3` 对照 |
| 样本与黄金是否同一业务 | 两边的 `CalcActivity.onCreate` 与锚点串 `ANCHOR-0001:LOGIC-MIX` 完全一致 |
| SO 内嵌表是否就是字节码 | 010 Editor 打开 `.so` 跳到 `.rodata`，字节序列与 jadx 里 `P_MIX` 一致 |

**量化验证（`sha256sum` / `cmp` / 语义 oracle）见 `SCRIPT.md` 与 `CLI.md`。**

---

## 动态路线（图形工具的下一步）

静态 GUI 到不了的地方（L3 反射分派 / L4 融合算子 / S2 运行期装配 / S3 threaded），
真值只在运行期。GUI 路线在这里**不自己跑脚本**，而是：先看 `SCRIPT.md`「脱壳」章拿到的
动态输出，再回到图形工具里**核对**：

| 动态拿到的东西 | 回 GUI 核对什么 |
|---|---|
| L3 的 `opcode → h0..h6` 表 | jadx-gui 里点开 `h0..h6`，逐个确认语义（`h2` 内有 `xor` → XOR） |
| L4 的本机字节码（含 `0x11` 等明文立即数） | jadx-gui 里看 `sparse-switch` 的 case 体，确认「`0x3E` 是加法类」 |
| S2 的 `handler 地址` | IDA/Ghidra 里按 `G` 跳到该地址，看是 `op_load`/`op_xor`，并对照符号名 |
| S1/S3 的 `.rodata` 字节码 | 010 Editor 打开 `.so` 跳到 `.rodata` 偏移，与 dump 的字节逐字节对照 |

**前置**：动态要在 **dyn 版**样本上跑（`samples/apks/app_lN_dbg.apk`）——
它比正式样本多一个一次性探针（`CalcActivity.peek/wipe`）。

> 本 lab 的 frida 版本钉在 **16.5.9**（host 与设备 frida-server 必须同版本）。图形工具本身
> 不参与 frida，只负责「读懂动态取到的东西」。

---

## 决策流程（图形工具版）

```text
GDA/JEB 打开 APK          → 包名/入口/资源清单（找可疑的 assets）
jadx-gui 点开业务类        → 方法体是不是只有一行 invoke？(V1)
jadx-gui 点开被调的大方法   → 有没有 while+switch？(V4)  sparse-switch？(V6)
                           → 没有 Core 但每个方法都有 switch？(V5)
IDA/Ghidra 打开 .so        → .rodata 是否异常小？(VN1)
                           → 分派是中心级联 / blr xN / br xN？(VN2)
010 Editor                 → 读 fill-array-data / assets 载荷的字节，人工解码
```

---

## 复位

图形工具在 `analysis_output/` 或系统临时目录产生产物；复位（清空产物、还原 samples/ 基线）
见 `SCRIPT.md` 的 `tools/reset_lab.py`。

---

## 踩坑

1. **jadx-gui 打开「抽取态 dex」会装载失败**（本 lab 的 `neg_extract` 是 nop 抽取态）——
   报 `Load failed! No classes for decompile!`。**注意**：本 lab 的 VM 样本**不会**这样
   （方法体不为空，只是变成了一句调用），能正常打开 —— 这正是 VMP 与「抽取」的区别。
2. **jadx-gui 显示的 `byte[]` 是有符号十进制**（如 `-1` 其实是 `0xFF`）。读 opcode 时要把
   负数换算回无符号（`-1 → 0xFF`），否则 opmap 会整体对不上。
3. **IDA/Ghidra 对 `-O0` 的 SO 反汇编最友好**。本 lab 的 S1 刻意用 `-O0` 编译（分派保持
   比较级联 + 独立 case 体），S2/S3 用 `-O2`（分派被优化，正是难档）。如果你在 S2/S3 里
   找不到「一个干净的 switch」，那是**设计如此**，不是工具坏了。
4. **Ghidra 首次导入要跑自动分析**（可能几分钟），别以为卡死了。
5. **图形工具不给出判据**。`jadx-gui` 里看到「方法体只有一行」是**证据**；把它变成
   带阈值、带边界的**判据**，是 `detect_vm.py` 的活。
6. **不要用 GUI 的「导出/反编译成源码」当结论**。虚拟化保护的意义就是「反编译不出原始逻辑」
   —— jadx 给出的是「调用解释器」这一层的 Java，真实逻辑在字节码里，要靠对照 switch 分支还原。
