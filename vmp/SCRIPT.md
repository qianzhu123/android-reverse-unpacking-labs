# SCRIPT.md — 脚本路线：用本仓 `tools/` 的 Python 工具做判定、去虚拟化与验证

> 本文件与 `CLI.md`、`GUI.md` **结构完全平行**（同一套章节骨架一一对应），只讲「脚本怎么做」。
> **路线分工**：di 本 lab 的判定与还原**结论**全部来自脚本（可量化、可复现）；`CLI.md` 用通用命令
> 逐步复现同一过程；`GUI.md` 用图形工具**看懂**结构（jadx-gui / IDA·Ghidra / 010 Editor）。
>
> 本 lab 主题：**VMP（Virtual Machine Protection，虚拟化保护）的解壳**。
> 「解壳」在这里指：从「方法体只剩一句调用解释器」的样本，还原出**原始运算逻辑**
> （本 lab 用一套可读的「规范操作流」表示），并**验证**还原结果与黄金逻辑语义等价。

---

## 概述

### 一句话定位

用**自造样本**把「虚拟化保护」从最简单的解释器到最难的分派形态铺成一条 **L1→L5 / S1→S3**
的阶梯，配一套**只读结构判定 + 静态去虚拟化**工具；判据全部落在方法体形状、分派形态、载荷
结构与 ELF 结构上，**不靠文件名、不靠类名、不靠可见字符串**。

### 为什么自造样本（建模说明）

真实商业虚拟化保护器（VMProtect / Themida 等）无法在本机离线复现，跑到 Arm 上更是拿不到
可比对的黄金结果。本 lab 因此**从源码编译**每一档样本，并且让**全部样本与黄金样本共享同一份
「表达式规范」**（`tools/vmlang.py` 的 `PROGRAMS`）：

```text
表达式规范（唯一真源）
   ├── src/com/demo/calc/CalcLogic.java   黄金逻辑（明文表达式）
   ├── 各档样本的自定义字节码              由规范 assemble 出来
   └── samples/payloads/golden_ops.json    规范操作流 + 测试向量 + 黄金答案
```

于是「受保护样本 == 黄金逻辑」是**结构性保证**，而不是靠肉眼比对 —— 这也是本 lab 的
**语义 oracle**（见「验证」章）。

### 文件与样本索引

| 工具（`tools/`） | 作用 | 对应章节 |
|---|---|---|
| `vmlang.py` | 表达式虚拟机语言内核：汇编 / 反汇编 / 参考解释器 | 知识点 |
| `vmgen.py` | 规范 → 黄金 Java + `golden_ops.json` | 概述 / 验证 |
| `build_levels.py` `build_so_levels.py` `build_negatives.py` | 生成各档样本源码与载荷 | 工程结构 |
| `dexscan.py` | DEX 方法体形状 / switch 分派扫描（判定与去虚拟化共用） | 判定 / 脱壳 |
| `detect_vm.py` | **只读结构判定**：V1..V6 / VN1·VN2 / B13 + 认知边界 | 判定 |
| `devirt_dex.py` | DEX 层**静态去虚拟化**（还原 opcode 映射 + 反汇编 + 验证） | 脱壳 |
| `devirt_so.py` | SO 层**静态分析**（定位解释器、判读分派、还原 S1 opmap） | 脱壳 |
| `nop_methods.py` | 造 `neg_extract`（旧式函数抽取）负样本 | 判定 |
| `verify_gen.py` | **语义 oracle**：样本字节码回放 == 黄金答案 | 验证 |
| `check_negatives.py` | **双向回归断言**（正向必中 / 负向必不中） | 判定 / 反复练习 |
| `trace_vm.py` `frida/*.js` | 动态路线（静态搞不定时兜底） | 脱壳 |

**样本阶梯**（`samples/`）：

| 样本 | 层 | 分派形态（难度递进） | 关键判据 |
|---|---|---|---|
| `app_golden.apk` | 基线 | 明文，无虚拟机 | （无） |
| `app_l1.apk` | L1 | 字节码在源码数组 + 规则 `packed-switch` | V1 + V4 |
| `app_l2.apk` | L2 | 字节码外置 `assets/` + XOR 加密 | V1 + V3 + V4 |
| `app_l3.apk` | L3 | **无 switch**：opcode 经 int[] 表 → `Method[]` 反射 invoke | V1 |
| `app_l4.apk` | L4 | **融合算子** + opcode 随机且不连续（`sparse-switch`） | V1 + V4 + V6 |
| `app_l5.apk` | L5 | **内联 VM**：三个业务方法各内嵌一份解释器，无 hub | V4 + V5 |
| `app_s1.apk` + `libcalc_s1_arm64.so` | S1 | native 解释器，中心比较级联 | VN1 |
| `app_s2.apk` + `libcalc_s2_arm64.so` | S2 | native 分派运行期装配（间接调用） | VN1 + VN2 |
| `app_s3.apk` + `libcalc_s3_arm64.so` | S3 | native **threaded** 分派（basic block 网） | VN1 + VN2 |
| `neg_plain / neg_bigswitch / neg_hub / neg_extract` | 负样本 | 干净 / 大状态机 / 汇聚调用但非解释器 / 旧式抽取 | **必须不报 VM** |

> **命名约束**：所有样本的包名（`com.demo.calc`）、类名（`CalcLogic`/`Core`）、资源名
> （`core_a.dat`）、签名别名（`CALC`）与锚点串（`ANCHOR-0001:LOGIC-MIX`）**都不含**
> `vmp` / `protect` / 厂商名等判别词 —— 识别只能靠结构。唯一带层号的是 `samples/` 下的
> **文件名**，而文件名不是判据。

---

## 工程结构与样本

```text
vmp/
├── SCRIPT.md  CLI.md  GUI.md           # 三份教学文档（中文，同一骨架）
├── AGENTS.md                           # agent 用 ground-truth（英文）
├── src/                                # 黄金业务源码（明文，无虚拟机）
│   ├── AndroidManifest.xml
│   └── com/demo/calc/{CalcLogic.java, CalcActivity.java}
├── vmp/                                # （本 lab 无独立 vmp/src —— 受保护样本源码由
│                                       #   build_levels.py / build_so_levels.py 生成到 build/gen/）
├── neg/                                # （负样本源码同样由 build_negatives.py 生成）
├── samples/
│   ├── apks/     app_golden.apk · app_l1..l5.apk · app_s1..s3.apk · neg_*.apk
│   ├── dex/      golden.dex · level_L1..L5.dex · level_S1..S3.dex · neg_*.dex
│   ├── payloads/ golden_ops.json · level_*.bin · level_*.map.json · so_*.map.json
│   └── native/   libcalc_s{1,2,3}_{arm64,x86_64}.so
├── pristine/     samples/ 的 sha256 基线（reset_lab.py 用）
├── analysis_output/
├── tools/        （见上表）+ 复用自 ajiami 的 apkutil/dexlib/elfinspect/envload/reset_lab
├── build/        locate.sh · env.sh.example · build_{golden,vm,so,neg}.sh
├── frida/        trace_dispatch.js · so_vm_trace.js · oracle_run.js
└── logs/
```

**受保护样本源码在哪**：`src/` 只放**黄金**业务；每一档样本的源码由 `build_levels.py`
（DEX 层）与 `build_so_levels.py`（SO 层）**生成**到 `build/gen/`，再交给
`build/build_*.sh` 编译。改动只发生在「规范」和生成器里，样本天生可复现。

---

## 知识点总览（VMP 分类学）

### 什么是「虚拟化保护」

把原始逻辑（本 lab 是几个整数表达式）**编译成一套自定义字节码**，再用一个**解释器**
在运行时还原执行。DEX / SO 里留下的只是：

- 业务方法体变成一句「调用解释器」；
- 真实逻辑变成一段**非 dalvik / 非 ARM** 的自定义字节码；
- 一个规模不小的解释器（分派循环 + handler）。

**五要素**（每档都一样，只是形态不同）：

| 要素 | 说明 | 怎么看出来 |
|---|---|---|
| 字节码载体 | 自定义字节码放在哪 | 源码 `byte[]` 常量 / `fill-array-data` / `assets` / `.rodata` |
| 分派形态 | 解释器怎么选 handler | `packed/sparse-switch` / 比较级联 / 反射 `Method[]` / 函数指针表 / threaded |
| opcode 表 | opcode 字节 → 语义的映射 | 规则小集合、随机不连续、或运行期才装配 |
| handler 粒度 | 一条 opcode 顶几条逻辑指令 | 基础指令（一对一）/ 融合算子（一对多） |
| 一致性 oracle | 怎么证明还原对了 | 规范操作流回放 == 黄金答案（本 lab 用这个） |

### 各档位 **[可验证]**

| 档 | 核心难点 | 静态能解决吗 |
|---|---|---|
| L1 | 抄 switch 分支即可解 | ✅ 完全（`devirt_dex.py` 全还原） |
| L2 | 先找到并解密外置载荷 | ✅ 完全（载荷 → opmap → 反汇编） |
| L3 | 没有 switch，靠反射分派 | ❌ opcode 映射要**动态 trace** |
| L4 | 融合算子 + 随机 opcode | ❌ 静态只能部分（映射能恢复，融合算子的立即数拆不开） |
| L5 | 无 hub，形状判据失效 | ✅ 完全（靠 V5 找到内联解释器，再按 L1 方法解） |
| S1 | native 中心分派 | ✅ 完全（比较级联符号化模拟） |
| S2 | native 运行期装配分派 | ❌ 需动态 trace |
| S3 | native threaded 分派 | ❌ 需动态 trace |

### DEX VMP vs SO VMP vs Java2CPP **[知识框架]**

- **DEX VMP**：解释器在 dex 里（Java 字节码）。判据 V1/V4/V5/V6。
- **SO VMP**：解释器在 `.so` 里（native）。判据 VN1/VN2 —— 静态只能判「形态」，
  真正还原必须反汇编 + 动态。
- **Java2CPP**：业务整体挪到 native（`native` 声明 + JNI 实现），**没有**自定义字节码。
  与 SO VMP 的区别：Java2CPP 的 native 代码是普通编译产物（有稳定调用图），SO VMP 里
  有一个「取指-译码-执行」的循环。本 lab 只覆盖后者的形态判定。

### 判据代号总表（先看这张，再看「判定」）

DEX 侧（形状来自 `dexscan.py`）：

| 代号 | 判据（结构 / 统计） | 阈值/依据 | 指向 |
|---|---|---|---|
| **V1** | ≥2 个「极短方法体」invoke 同一个「大方法」 | 极短 ≤ `TINY_UNITS=24` 单位；大 ≥ `HUB_UNITS=30`；调用者 ≥ `MIN_CALLERS=2` | 疑似 DEX VM（方法体塌缩为调 hub） |
| V2 | 极短方法里「只有调用、无 switch、无回边」的数量（统计量） | 辅助计数，不单独定性 | 业务方法体被退化 |
| **V3** | 代码里引用了的小体积「不透明」资源 | 命中 dex 字符串池 + 8..4096 B + 熵 > 4.2 | 字节码/载荷外置（L2） |
| **V4** | 某大方法含 `switch` + 回边 | 有 packed/sparse-switch 且 `has_backbranch` 且 units ≥ 30 | 解释器定位 |
| **V5** | ≥2 个方法内含**同一组 switch case** | case 集合完全相同的方法 ≥2 | 内联 VM（L5，无 hub 时唯一抓手） |
| **V6** | switch 的 case 值不构成 0..N 连续小集合 | 去掉 `0xFF` 哨兵后 `is_dense_small()` 判否 | 随机 opcode（L4） |

SO 侧：

| 代号 | 判据 | 指向 |
|---|---|---|
| **VN1** | 有 `Java_*` 导出（native 业务入口）+ 紧凑数据段（`.rodata`/`.data` 8..4096 B） | SO 里有业务 + 内嵌表 |
| **VN2** | 最大函数的分派形态是 `indirect`（间接调用）或 `threaded`（>4 条 `br xN`） | 分派不是中心 switch |
| **B13** | `ET_DYN` 且节头表被剥离（自实现 Linker / 加壳） | SO 加壳（沿用本仓通用判据） |

> **V4/V6 不是定性判据**：合法的大 `switch` 状态机同样「有 switch + 循环」「case 不连续」。
> 本 lab 的负样本 `neg_bigswitch.apk` 就是专门来当场挖这个误报的（见「判定」章的实跑）。

### 保护方式 → 处理思路

| 形态 | 静态 | 动态 |
|---|---|---|
| 规则 switch 解释器（L1/L2/L5、S1） | 还原 opmap → 反汇编字节码 | 可省 |
| 反射 / 运行期装配分派（L3/S2） | 只能定位解释器 | trace 分派目标 → 反推映射 |
| 融合算子 + 随机 opcode（L4） | 恢复 opmap，但拆不开立即数 | trace handler 入参 |
| threaded 分派（S3） | 只能定位形态 | trace basic block 转移 |

---

## 判定：这是虚拟化保护吗、哪一档（脚本 · `detect_vm.py`）

```bash
# 判定一个 DEX 样本（只读结构；不改文件、不看文件名）
python tools/detect_vm.py samples/apks/app_l4.apk
#   => codes  : V1, V4, V6
#   => verdict: suspected DEX virtual machine — business methods collapse to a hub
#               method (V1); corroborated by V4/V6 when present
```

**这条命令做了什么**：打开 APK → 逐个 `classes*.dex` → 走每个方法的 dalvik 指令
（`dexscan.scan`）→ 统计「极短方法」「hub 汇聚」「switch+循环」「同签名 switch」→ 汇总判据
→ 给出**带认知边界**的结论。

**逐行读输出**：

- `dex classes.dex methods=11 tiny=8 | V1 hubs=1 ...` —— 本 dex 有 11 个带码方法，其中 8 个
  是「极短」（≤24 单位）；V1 命中 1 处、V4 命中 1 处。
- `V1: Lcom/demo/calc/Core;->run (296 units) <- 3 tiny callers: ...` —— 解释器是 `Core.run`
  （296 单位），有 3 个极短方法（`mix/twist/digest`）汇聚调用它。**这是虚拟化的最强信号**：
  正常的一个业务方法不会「只有一句调用另一个大方法」。
- `codes / verdict / boundary` —— 判据、结论、以及**静态判不了的那几类**。

**失败判读**：若输出 `codes: (none)` + `no known hardening signature observed (≠ none)`，
表示**没看到已知形态** —— 这**不等于**「没被保护」（认知边界，见下）。

```bash
# 判定一个 SO 样本（native 解释器）
python tools/detect_vm.py samples/native/libcalc_s1_arm64.so
#   => dispatch shape: switch  {...'cmp': 18, 'blr': 0, 'br': 0 ...}
#   => codes  : VN1
#   => verdict: suspected native (SO) VM — central-switch interpreter over an embedded table
```

```bash
# 判定 SO 的「难档」：S2 运行期装配 / S3 threaded
python tools/detect_vm.py samples/native/libcalc_s2_arm64.so samples/native/libcalc_s3_arm64.so
#   => s2: dispatch shape: indirect  codes: VN1, VN2
#   => s3: dispatch shape: threaded  codes: VN1, VN2
```

**怎么读**：`dispatch shape` 由 `llvm-objdump` 反汇编最大函数后统计 `cmp` / `blr` / `br` 得出。
`switch` = 有 5 条以上带立即数的比较（比较级联）；`indirect` = 有间接调用（运行期装配的
函数指针表）；`threaded` = 有 4 条以上 `br xN`（computed-goto 块网）。

### 阈值设计的坑（都踩过）

1. **`TINY_UNITS` / `HUB_UNITS` 不能凭感觉定**。最初用 16/30，结果 `mix` 方法体（10 单位）
   正好落在边界，误伤。实测后定为 24/30：业务方法「构造 int[] + invoke + return」稳定在
   8–12 单位，解释器循环稳定在 80 单位以上，两个区间之间有充裕余量。
2. **V6 的 `0xFF` 哨兵**。第一版的 `RET` opcode 用 `0xFF`，于是「case 集合 = {1..6, 0xFF}」
   看起来不连续 → L1/L2 全部误报 V6。修正：判定前**剔除 `0xFF` 哨兵**再判连续性。
3. **V3 不能用「高熵」当唯一信号**。L2 的载荷只有 39 字节，XOR 后熵只有 5.18 —— 按
   `熵 > 7.5` 直接漏掉。修正：主信号改成「**资源名出现在 dex 字符串池里** + 体积小」，
   熵退为辅助（> 4.2）。
4. **V1 的 `invoked` 是 method_idx，不是方法名**。必须过 `dexlib.method_at(idx)` 反查
   「调用者是不是极短方法、被调者是不是大方法」，否则同一个 idx 在不同 dex 里含义不同。

### 认知边界（**必须一起读**）

`detect_vm.py` 每次都会打印这三条，它只回答「样本**呈现出**哪一种虚拟化形态」，
**不回答**「它一定被 VMP / 一定没被保护」：

```text
boundary (static cannot decide):
  - hub-less / fully-inlined custom VM can still evade V1 (V5 is the fallback)
  - runtime-assembled dispatch and opcode maps are invisible statically
  - handler semantics are data-driven — shape alone cannot prove VMP
```

**「未见已知特征」永远不等于「未加固」。**

---

## 脱壳（去虚拟化）

### DEX 层：`devirt_dex.py`

```bash
# L1：字节码在源码里 + 规则 switch —— 全自动还原
python tools/devirt_dex.py samples/apks/app_l1.apk
#   => recovered opmap (7 entries): 1=LOADARG, 2=PUSH, 3=XOR, 4=ADD, 5=MUL, 6=SUB, 7=RET
#   => prog0  12 bytes ->  8 ops  => semantics == golden mix
#            LOADARG:0 LOADARG:1 XOR PUSH:17 ADD PUSH:3 MUL RET
#   => prog1   9 bytes ->  6 ops  => semantics == golden twist
#   => prog2  15 bytes -> 10 ops  => semantics == golden digest
```

**它做的四步**（全部只读结构）：

1. **定位解释器**：找含 switch 的大方法（V4 形态）；
2. **还原 opmap**：把 switch 每个 case 体切出来做**指纹** —— 体内用 `eor` 就是 XOR、
   用 `mul` 就是 MUL、读一字节索引到数组就是 LOADARG……（`dexscan.fingerprint`）；
3. **取字节码**：从 `fill-array-data` 抽静态 `byte[]`；若载荷外置，则用那个小 `byte[]`
   作 key **解密 assets**；
4. **反汇编 + 验证**：用还原出的 opmap 反汇编字节码，用测试向量跑一遍，比对黄金答案。

```bash
# L2：载荷外置 + XOR —— 自动定位并解密
python tools/devirt_dex.py samples/apks/app_l2.apk
#   => note: payload assets/core_a.dat decrypted with 16-byte key from static field
#   => (之后与 L1 相同：opmap + 三段操作流 + semantics == golden)
```

```bash
# L5：内联 VM —— 没有 Core.run，工具从「多个方法含同一 switch」入手
python tools/devirt_dex.py samples/apks/app_l5.apk
#   => note: opmap recovered from switch in Lcom/demo/calc/CalcLogic;->digest
#   => prog0..prog5  -> semantics == golden mix / twist / digest
```

```bash
# L3：反射分派 —— 静态不足，工具**明确报告**并指向动态路线
python tools/devirt_dex.py samples/apks/app_l3.apk
#   => note: no packed-switch interpreter found -> reflection/dispatch needs dynamic tracing
#   => (static devirtualization insufficient — dynamic route required)
```

```bash
# L4：融合算子 + 随机 opcode —— 静态部分还原，融合算子的立即数拆不开
python tools/devirt_dex.py samples/apks/app_l4.apk
#   => recovered opmap (11 entries): 34=XOR, 62=ADD, 87=RET, 101=LOADARG, ...
#   => (disassembly incomplete: 未知 opcode 0x3E @0x5)
#   => ! fused/inline-immediate opcodes present -> static devirtualization is PARTIAL;
#      dynamic trace required
```

**怎么读**：`opmap` 是「还原出的 opcode → 语义」；`semantics == golden <方法名>` 是**关键一行**
—— 它表示还原出的操作流跑测试向量后**与黄金答案完全一致**。若显示 `?` 或
`(disassembly incomplete)`，说明该档静态不够，需转动态。

### SO 层：`devirt_so.py`

```bash
# S1：native 中心比较级联 —— 符号化模拟分派，7/7 全部还原
python tools/devirt_so.py samples/native/libcalc_s1_arm64.so
#   => note: interpreter = vmr (214 insns, dispatch=switch)
#   => note: switch opmap: 7/7 cases fingerprinted via comparison-chain simulation
#   => switch opmap: 1=LOADARG, 2=PUSH, 3=XOR, 4=ADD, 5=MUL, 6=SUB, 255=RET
```

**它怎么做到的**：先认「比较级联」`subs wR,wR,#imm / b.eq <case> / b <next>`，写一个**小解释器**
沿标志位走比较树，走到叶子就是 case 体；再对 case 体做**数据运算指纹** —— 这里有个关键区分：
`add w8, w8, w9`（寄存器对寄存器 = **数据运算**）和 `add x9, x9, #0x14`（带立即数 = **指针簿记**）
必须分开，否则每个 case 都会被误认成 ADD。

```bash
# S2：运行期装配分派 —— 静态没有稳定 case 边界
python tools/devirt_so.py samples/native/libcalc_s2_arm64.so
#   => note: dispatch is indirect -> need dynamic tracing ...
#   => ! static devirtualization not sufficient for this dispatch shape
```

### 动态路线（静态不够时）

```bash
# 行为 oracle：主动调目标方法，比对黄金值（并在设备上，见下方红字提醒）
python tools/trace_vm.py --package com.demo.calc --script frida/oracle_run.js --seconds 8
#   => [oracle] mix(7,3)   = 63   (expect 63)
#   => [oracle] twist(7)   = 44   (expect 44)
#   => [oracle] digest(7,3)= 121  (expect 121)
#   => [oracle-neg] mix(0,0)= 51  (expect 51 ≠ 63，负控)
```

> ⚠️ **`trace_vm.py` 会在连接的设备上安装并启动目标 app。** 请只在**你有权操作**的设备或
> **本地模拟器**上运行（本仓推荐 `n4tive_lab` AVD，见 `build/env.sh.example` 与根 `README.md`
> 的 frida 环境段）。绝不针对他人的真机。

---

## 验证

本 lab 的验证分三层，全部实测通过：

### ① 语义 oracle（不需要设备）：`verify_gen.py`

```bash
python tools/verify_gen.py
#   => mix  args=[7, 3]  expect=63  got=63  OK
#   => ...
#   => 2. DEX 层字节码 -> 反汇编 -> 语义   L1..L5 全部 OK
#   => 3. SO 层字节码 -> 反汇编 -> 语义    S1..S3 全部 OK
#   => ALL OK
```

**这是本 lab 的核心验证**：把每一档样本的字节码解密/取出 → 按该档 opmap 反汇编 → 用参考
解释器跑测试向量 → 必须等于 `golden_ops.json` 里的黄金答案。任何一档语义跑偏，这里就会红。

### ② 双向回归断言：`check_negatives.py`

```bash
python tools/check_negatives.py
#   => 正向：L1..L5 / S1..S3 必须判为 VM 且命中代号   —— 8 项 PASS
#   => 负向：neg_plain/bigswitch/hub/extract 必须 NOT 判 VM —— 4 项 PASS
#   => 基线：app_golden 必须「未见已知特征」           —— 1 项 PASS
#   => 13/13 ALL PASS
```

**为什么要双向**：只测正向，判据可能宽到把正常程序判成 VMP（`neg_bigswitch` 就是来抓这个的）；
只测负向，判据可能窄到漏掉真样本。**单边通过一律判失败**。

### ③ 真机/模拟器行为 oracle（可选，需设备）

样本自己会往 logcat 打一行 `CALC`：

```bash
adb install -r samples/apks/app_golden.apk
adb shell am force-stop com.demo.calc && adb shell am start -n com.demo.calc/.CalcActivity
adb logcat -s CALC
#   => mix(7,3)=63 twist(7)=44 digest(7,3)=121 anchor=ANCHOR-0001:LOGIC-MIX
```

**判据**：`app_golden` 与 `app_l1..l5`、`app_s1..s3` 在设备上必须打印**完全相同的这一行**。
（本 lab 已在 arm64 真机上实测 9/9 一致；请在你有权操作的设备上复现。）

### 量化验证清单

| 项 | 判据 |
|---|---|
| 语义 | 每档 opmap 反汇编 → 测试向量 → == 黄金答案（`verify_gen.py` ALL OK） |
| 判定 | 每档命中其代号；负样本不报 VM（`check_negatives.py` 13/13） |
| 还原 | L1/L2/L5 与 S1 的 opmap 与 `level_*.map.json` / `so_*.map.json` 逐项一致 |
| 行为 | 设备上各样本 logcat 行与黄金**逐字符相同** |
| 完整性 | `python tools/reset_lab.py status` 全部 OK |

---

## 决策流程（拿到一个陌生样本先走这张图）

```text
① 这是什么形态？  python tools/detect_vm.py <样本>
   ├─ codes 里没有 V*/VN*  -> 「未见已知特征（≠ none）」，别急着下"没保护"的结论
   ├─ V1 (hub 汇聚)       -> DEX VM，hub 方法就是解释器
   ├─ V5（无 hub 但同 switch）-> 内联 DEX VM（L5 形态）
   ├─ VN1/VN2             -> SO VM
   └─ B13                 -> SO 加壳 / 自实现 Linker（先解决装载，再谈 VM）

② 分派是哪种？（决定能不能静态解）
   ├─ 规则 packed-switch / native 比较级联       -> devirt_dex / devirt_so 静态全解
   ├─ 反射 Method[] / native 间接调用（间接）     -> 静态只能定位，转 ③
   ├─ 随机 opcode + 融合算子                      -> 静态部分还原，转 ③
   └─ native threaded（computed-goto）           -> 转 ③

③ 动态兜底
   python tools/trace_vm.py --package <pkg> --script frida/trace_dispatch.js
   （在你有权操作的设备/模拟器上；trace 出 opcode→handler 映射后回到 ② 的名字做还原）

④ 验证
   python tools/verify_gen.py         # 语义 oracle（静态）
   adb logcat -s CALC                 # 行为 oracle（设备）
```

---

## 反复练习

```bash
# 看当前状态：samples/ 与 pristine/ 基线逐文件比对
python tools/reset_lab.py status
#   => OK / DIFF / MISSING / EXTRA 逐条列出

# 把当前 samples/ 快照成新基线（改过生成器、重跑过构建后用）
python tools/reset_lab.py backup

# 复位：用 pristine/ 覆盖 samples/，清空练习产物
python tools/reset_lab.py restore --force
```

**推荐练习循环**：`reset_lab.py restore` → 改 `tools/vmlang.py` 的 `PROGRAMS`（换一组表达式）
→ `python tools/vmgen.py emit` → 重跑 `build/*.sh` → `verify_gen.py` 必须仍 ALL OK。

---

## 踩坑 / 速查

### 最容易写错的结论

1. **「没看到 V1」≠「不是 VMP」**。L5 的内联 VM **故意**没有 hub，V1 恒不命中 —— 靠 V5 兜。
   判据是活的，边界是死的：永远把 `boundary` 三条一起读。
2. **「有 switch + 循环」≠「是解释器」**。`neg_bigswitch.apk` 是合法状态机，V4/V6 都会亮，
   但它不是 VM。**V4/V6 是辅助信号，定性要看 V1/V5。**
3. **「能还原 opmap」≠「还原完了」**。L4 的融合算子（`add-int/lit16` 直接把立即数编进指令）
   静态可以认出「这里是 XOR」，但**拆不出那个立即数** —— 工具会明说 `PARTIAL`，别把它当成
   完整答案。

### 脚本与环境坑（实测）

1. **DEX `packed-switch-payload` 的偏移布局**：`u2 ident | u2 size | s4 first_key |
   s4 targets[]`（targets 从 `+4` 个 code unit 起，不是 `+2`）。踩过一次：把 size 当
   first_key，切出来的 case 全是垃圾。
2. **DEX `sparse-switch-payload` 是「两个数组」不是「键值对交错」**：`u2 ident | u2 size |
   s4 keys[size] | s4 targets[size]`。踩过一次：按交错读，case 目标全部错位。
3. **DEX 里 `packed-switch` 会指向一个 256 项的跳转表**（编译器为密集连续 case 生成的），
   表首是 ident `0x0100`，别把它当成 case 数量。
4. **`ldrb` + 带缩放的 `ldr` 才是 LOADARG**；只有 `ldrb` 是 PUSH；两者都无但有带缩放的 `ldr`
   是 RET（从栈数组弹）。区分错了，opmap 会整体错位。
5. **重跑构建必须清干净中间目录**。`build_levels.py` 与 `build_vm.sh` 现在都会 `rmtree`
   层目录 —— 否则改形态后**旧 `.class` 会一起编进 dex**（L5 曾把旧 `Core.class` 带进去，
   导致「内联 VM 里居然有 hub」）。
6. **`-O0` vs `-O2` 决定 SO 能不能静态解**。S1 用 `-O0`：比较级联与独立 case 体都还在；
   S2/S3 用 `-O2`：分派被优化成跳转表/回调，正是它们「难」的原因。这是刻意的，不是偷懒。
7. **assets 读取不能用 `in.available()` 当长度**。Android 的 `AssetManager` 解压流上
   `available()` 可能返回 0，读出来是空的 —— 表现为「同一份样本时好时坏（0 或正确值）」。
   必须读到 EOF（本 lab 的 L2 `Core.load` 已改成 `ByteArrayOutputStream` 循环读）。

### 速查

```bash
# 判定（可传多个样本；只看结构，不改文件）
python tools/detect_vm.py samples/apks/app_l4.apk
python tools/detect_vm.py samples/native/libcalc_s1_arm64.so

# 去虚拟化
python tools/devirt_dex.py samples/apks/app_l1.apk
python tools/devirt_dex.py samples/apks/app_l4.apk --json
python tools/devirt_so.py samples/native/libcalc_s1_arm64.so --json

# 语义 oracle + 双向回归
python tools/verify_gen.py
python tools/check_negatives.py

# 复位
python tools/reset_lab.py status
python tools/reset_lab.py restore --force
```
