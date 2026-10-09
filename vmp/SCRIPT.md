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

### 虚拟机是怎么运转的（VM 原理，本 lab 的 VM 就是一个栈式解释器）

**虚拟机 = 一段能执行「自定义指令」的程序**。它有三个数据结构、一个循环：

```text
VM 状态：  pc（取指指针）  sp（栈顶指针）  stack[64]（求值栈）  args（业务入参）
主循环：   while pc < code.length:
               op = code[pc++]          # 取指：读一个字节，就是「opcode」
               switch op:               # 译码 + 执行：跳到对应 handler
                   case 0x01:  stack[sp++] = args[code[pc++]]   # LOADARG：把第 k 个参数入栈
                   case 0x02:  stack[sp++] = code[pc++]         # PUSH：把立即数入栈
                   case 0x03:  { b=pop; a=pop; push(a ^ b) }    # XOR
                   case 0x04:  ... ADD / 0x05 MUL / 0x06 SUB ...
                   case 0xFF:  return pop                      # RET：返回栈顶
```

**指令集就是「一份约定」**：每个字节值对应一个动作。本 lab 的 VM 指令集（`tools/vmlang.py:BASE_OPS`）：

| opcode 名 | 动作 | 栈效果（`…` 表示栈上原有内容） |
|---|---|---|
| `LOADARG k` | 把第 k 个入参入栈 | `…` → `…, args[k]` |
| `PUSH v` | 把立即数 v 入栈 | `…` → `…, v` |
| `XOR` / `ADD` / `MUL` / `SUB` | 弹两个、算、压回（顺序：`a op b`，先弹的是 b） | `…, a, b` → `…, a op b` |
| `RET` | 返回栈顶 | `…, x` → 返回 x |

**「虚拟化保护」为什么能保护**：这段自定义字节码**不是一个能直接执行的东西** —— dalvik/ARM
里没有这些 opcode。要还原业务逻辑，必须先知道：

1. **哪段字节是字节码**（载体，可能被外置/加密）；
2. **每个 opcode 字节代表什么动作**（opcode 表 —— 可以随机化、运行期才装配）；
3. **分派怎么走**（switch / 反射 / 函数指针表 / threaded —— 决定能不能静态读取）。

这三件事里任何一件被藏住，静态分析就难。本 lab 的 L1→L5 / S1→S3 就是**逐条把这三件事逐级
藏起来**（见下）。

**「虚拟化」相对「加壳/加密」的本质区别**：加密是「把数据锁起来，解开就是原文」；虚拟化是
「把指令**换了一套机器**」—— 解开之后拿到的不是原指令，而是一段**别家的字节码**，必须再
理解那台虚拟机的指令集。所以解 VMP 的核心动作是**把解释器读懂 → 反推 opcode 表 → 再解码
字节码**（本 lab 的 `devirt_*` 工具就干这个）。这也是为什么 VMP 的静态判定**不看字符串**：
真正的线索是「解释器在不在、字节码在不在、分派是不是中心化的」。

### VMP 对抗技术的分类学 **[知识框架 + 部分可验证]**

真实保护器在这三件事上做文章，本 lab 逐项对应实现了一档：

| 对抗手段 | 藏住的是 | 真实保护器怎么做 | 本 lab 对应档 |
|---|---|---|---|
| 字节码外置 + 加密 | ① 载体 | 载荷放 assets/资源，运行期解密 | **L2**（assets + XOR）/ 真货常用自定义加密 |
| 分派去中心化 | ③ 分派 | 反射 / 函数指针表 / 计算跳转 | **L3**（反射 `Method[]`）/ **S2**（运行期装配函数表） |
| opcode 随机化 | ② opcode 表 | 每次加固换一套 opcode 映射（官方明说「可随机」） | **L4**（随机不连续 opcode） |
| 指令融合（超算子） | ② + 粒度 | 一条 handler 顶多条逻辑指令，抬高语义分析成本 | **L4**（`ADDK/MULK/…`） |
| 内联（去掉 hub） | 解释器形状 | 分派内联进每个方法，破坏「汇聚」特征 | **L5** |
| threaded / computed-goto | ③ 分派 | handler 之间直接互相跳，没有中心 switch | **S3** |
| 多层 VM（VM 套 VM） | —— | 解释器自身也被虚拟化；官方称「双层 VMP」 | 未实现（列入认知边界） |
| 混淆/垃圾指令 / 花指令 | 分析成本 | 塞无效 handler、假分派、不透明谓词 | 未实现（属 `ollvm` 主题） |

> **诚实边界**：本 lab 只做了「形态」的阶梯；真实保护器还会叠加**反调试、完整性校验、
> 环境检测、多层嵌套**。这些**不在本 lab 覆盖范围**（本 lab 无设备依赖），但它们**不影响
> 本 lab 的方法论**：无论外面套多少层，解 VMP 的内核始终是「读解释器 → 反推 opcode →
> 解码字节码」这三步。

### 各档位 **[可验证]**

| 档 | 核心难点 | 藏住了什么 | 静态能解决吗 |
|---|---|---|---|
| L1 | 抄 switch 分支即可解 | 什么都没藏（教学基线） | ✅ 完全（`devirt_dex.py` 全还原） |
| L2 | 先找到并解密外置载荷 | ① 载体 | ✅ 完全（载荷 → opmap → 反汇编） |
| L3 | 没有 switch，靠反射分派 | ③ 分派 | ❌ opcode 映射要**动态 trace** |
| L4 | 融合算子 + 随机 opcode | ② opcode 表 + 粒度 | ❌ 静态只能部分（映射能恢复，融合算子的立即数拆不开） |
| L5 | 无 hub，形状判据失效 | 解释器形状 | ✅ 完全（靠 V5 找到内联解释器，再按 L1 方法解） |
| S1 | native 中心分派 | ——（native 侧基线） | ✅ 完全（比较级联符号化模拟） |
| S2 | native 运行期装配分派 | ③ 分派 | ❌ 需动态 trace |
| S3 | native threaded 分派 | ③ 分派 | ❌ 需动态 trace |

**逐档的完整解壳演示见「脱壳」章**（`devirt_dex.py` / `devirt_so.py` 的实跑输出 + 逐行读法）。

### 判据为什么必须落在结构上（而不是名字/字符串）

- **类名、方法名、资源名一行配置就能改**：真实保护器普遍把 `ProxyApplication`→乱码、
  `Vmp.run`→`a.b.c`，字符串判据一改就全灭。本 lab 的样本**故意**把包名/类名全部中性化
  （`com.demo.calc`/`Core`/`core_a.dat`），就是为了逼着判据只看结构。
- **结构改不了**：只要它还是个虚拟机，就必然有「一个分派循环 + 一段自定义字节码 + 一批
  handler」。`switch` 可以被换成反射/函数表，但「方法体塌缩为调解释器」这件事藏不掉
  （L5 那种「内联」也只是把 hub 打散成多个小解释器，仍然能被 V5 抓到）。
- **可量化**：方法体大小（code unit 数）、调用者个数、case 集合形态、段体积、分派指令
  种类 —— 都是能从字节里数出来的数，能写进阈值、能做双向回归。

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

> **本章是核心。** 下面按「先给通用方法论 → 再逐档实证」组织：
> §A 讲**去虚拟化的五步通用流程**（任何 VM 都适用）；
> §B 起逐档给出**完整解壳演示**（真实工具输出 + 逐行读法 + 手工复现）。
> 想直接抄命令：见本章末尾「速查」与 `CLI.md`。
>
> **贯穿全章的一条铁律**：解完必须**验证**。本 lab 用「还原出的操作流跑测试向量 == 黄金
> 答案」当 oracle（`golden_ops.json`）。**没有验证的还原只是猜测**。

### §A 去虚拟化的五步通用流程（先建立方法论）

不管目标是什么形态，解一个 VM 都是这五步（`devirt_dex.py` / `devirt_so.py` 就是它的自动化）：

| 步 | 做什么 | 关键问题 | 本 lab 的判据/工具 |
|---|---|---|---|
| **① 定位解释器** | 在样本里找出「那个大循环」 | 哪个方法/函数是「取指-译码-执行」？ | V4（DEX 含 switch+回边）/ VN2（SO 分派形态） |
| **② 找字节码** | 找出「那段自定义字节码」 | 它在源码数组 / assets / `.rodata`？加没加密？ | V3（外置载荷）/ `xxd`、`llvm-objdump -s` |
| **③ 反推 opcode 表** | 确定「每个 opcode 字节 = 什么动作」 | switch 的每个 case 体干了什么？ | `dexscan.fingerprint` / SO 比较级联模拟 |
| **④ 解码字节码** | 用③的表把字节码翻译成操作流 | 每条指令的语义 + 立即数怎么取 | `vmlang.disassemble` |
| **⑤ 验证** | 证明还原对了 | 跑测试向量 == 黄金答案？ | `vmlang.interpret` vs `golden_ops.json` |

**每一步「卡住」意味着什么**（这就是各档难度的来源）：

- ① 卡住 → 分派被去中心化（L3 反射 / S2 运行期装配 / S3 threaded）→ 转动态 trace；
- ② 卡住 → 载体被外置+加密（L2）→ 找解密点（静态找 key，或动态 hook 解密函数）；
- ③ 卡住 → opcode 随机化 / 融合算子（L4）→ 静态只能认「算术种类」，立即数要动态；
- ④ 卡住 → 字节码里出现了③没覆盖的 opcode → 该 opcode 的 handler 没被识别，回头补③；
- ⑤ 失败 → 前四步有错（最常见是 ③ 认错 handler，比如把「指针簿记」当成了数据运算）。

**手工版对照**（不跑脚本时）：① 用 jadx-gui/IDA 看方法形状；② 用 010 Editor / `xxd` 读字节；
③ 用 `dexdump -d` / `llvm-objdump -d` 看 case 体做什么；④ 拿纸笔（或记事本）逐条翻译；
⑤ 把你的翻译与样本在设备上的行为对（logcat / `frida/oracle_run.js`）。**`CLI.md` 是这条路线的
完整手工脚本，`GUI.md` 是它的图形版。**

---

### §B L1 · 最简：规则 switch + 字节码在源码（完整演示）

```bash
# 一步到位（脚本路线）
python tools/devirt_dex.py samples/apks/app_l1.apk
#   => note: opmap recovered from switch in Lcom/demo/calc/Core;->run
#   => recovered opmap (7 entries): 1=LOADARG, 2=PUSH, 3=XOR, 4=ADD, 5=MUL, 6=SUB, 7=RET
#   => prog0  12 bytes ->  8 ops  => semantics == golden mix
#            LOADARG:0 LOADARG:1 XOR PUSH:17 ADD PUSH:3 MUL RET
#   => prog1   9 bytes ->  6 ops  => semantics == golden twist
#            LOADARG:0 PUSH:7 MUL PUSH:5 SUB RET
#   => prog2  15 bytes -> 10 ops  => semantics == golden digest
#            LOADARG:0 LOADARG:1 MUL LOADARG:0 LOADARG:1 ADD XOR PUSH:90 ADD RET
```

**它做的四步**（全部只读结构）：

1. **定位解释器**：找含 switch 的大方法（V4 形态）；
2. **还原 opmap**：把 switch 每个 case 体切出来做**指纹** —— 体内用 `eor` 就是 XOR、
   用 `mul` 就是 MUL、读一字节索引到数组就是 LOADARG……（`dexscan.fingerprint`）；
3. **取字节码**：从 `fill-array-data` 抽静态 `byte[]`；若载荷外置，则用那个小 `byte[]`
   作 key **解密 assets**；
4. **反汇编 + 验证**：用还原出的 opmap 反汇编字节码，用测试向量跑一遍，比对黄金答案。

#### 手工复现（关键：opcode 表是从 case 体**读出来**的，不是猜的）

**第 ① 步：看业务方法体塌缩**（`dexdump -d`，完整输出见 `CLI.md`）——

```text
    #4   name : 'mix'    type : '(II)I'   insns size : 10 16-bit code units
000488: 1200        |0000: const/4 v0, #int 0
00048a: 2420 1000 2100 |0001: filled-new-array {v1, v2}, [I
000490: 0c01        |0004: move-result-object v1
000492: 7120 1000 1000 |0005: invoke-static {v0, v1}, Lcom/demo/calc/Core;.run:(I[I)I
000498: 0a01        |0008: move-result v1
00049a: 0f01        |0009: return v1
```

**读**：`mix` 整个方法体就 6 条指令 —— 建数组 `{a,b}`、调 `Core.run(0, 数组)`、返回。
**业务逻辑一条都没有**。这是 V1 的直接证据。

**第 ②③ 步：看解释器怎么把 opcode 映射到动作** —— `Core.run` 里：

```text
00053e: d803 0101   |0013: add-int/lit8 v3, v1, #1     ← pc++
000542: 4801 0701   |0015: aget-byte v1, v7, v1        ← 取指：op = code[pc]
000546: d511 ff00   |0017: and-int/lit16 v1, v1, #255  ← op &= 0xFF（无符号化）
00054a: 2b01 8700 0000 |0019: packed-switch v1, 0xa0   ← 用它分派
```

**这就是主循环的取指 + 译码**。`packed-switch` 的跳转表在 `00a0` 处，表长 7（= 7 个 opcode）。

**第 ③ 步详解：怎么从 case 体反推 opmap** —— 看 `packed-switch-data` 的 targets，
每个 case 体做的事**直接读出来**（完整反汇编见 `CLI.md`「L1」节）：

| opcode | case 体（`dexdump` 里的实际指令） | 语义 |
|---|---|---|
| `0x07` | `sget STACK; sub v2,#-1; aget v7,STACK,v2; return v7` | **RET**（弹栈顶返回） |
| `0x01` | `sget STACK; add v4,v2,#1; add v5,v3,#1; aget-byte v3,code,v3; and v3,#255; aget v3,args,v3; aput v3,STACK,v2` | **LOADARG**（读 code[pc] 作下标，取 args[·] 入栈） |
| `0x02` | `sget STACK; add v4,v2,#1; add v5,v3,#1; aget-byte v3,code,v3; and v3,#255; aput v3,STACK,v2` | **PUSH**（读 code[pc] 作立即数入栈） |
| `0x06` | `sget STACK; … sub-int/2addr v4, v1` | **SUB**（弹两个、相减） |
| `0x05` | `… mul-int/2addr v4, v1` | **MUL** |
| `0x04` | `… add-int/2addr v4, v1` | **ADD** |
| `0x03` | `… xor-int/2addr v1, v4` | **XOR** |

**这就是 opmap**：`01=LOADARG 02=PUSH 03=XOR 04=ADD 05=MUL 06=SUB 07=RET`。
**注意 LOADARG 与 PUSH 的区别**：两者都「读 code[pc] 入栈」，但 LOADARG 多一步
`aget v3, args, v3` —— **用它当 args 的下标**。这一个 `aget` 就是两者的分水岭。

**第 ② 步取字节码**：`Core.<clinit>` 里 `P_MIX` 由 `fill-array-data` 初始化：

```text
0006d0: 0003 0100 0c00 0000 0100 0101 0302 1104  |0022: array-data (10 units)
         └ident┘└w=1┘└─size=12──┘└──── 12 字节数据 ────┘
```

**读**：头部 8 字节 = `ident(0x0300) | width(1) | size(12)`，之后 12 字节就是 `P_MIX`：
`01 00 01 01 03 02 11 04 02 03 05 07`。

**第 ④ 步：用 opmap 逐字节解码**（这就是「去虚拟化」的一刻）：

```text
01 00   -> LOADARG 0        (入栈 a)
01 01   -> LOADARG 1        (入栈 b)
03      -> XOR              (栈: a^b)
02 11   -> PUSH 0x11        (入栈 17)
04      -> ADD              (栈: (a^b)+17)
02 03   -> PUSH 3
05      -> MUL              (栈: ((a^b)+17)*3)
07      -> RET              (返回)
```

**结果**：`mix(a,b) = ((a ^ b) + 0x11) * 3` —— **与黄金 `CalcLogic.mix` 逐字符一致**。
`P_TWIST`（`01 00 02 07 05 02 05 06 07`）→ `(a*7)-5`；`P_DIGEST` 同法 → `((a*b)^(a+b))+0x5A`。

---

### §C L2 · 字节码被外置 + 加密（完整演示）

与 L1 **只有两点不同**：(a) 分派形态一模一样（还是 `packed-switch` + `case 0x01..0xFF`）；
(b) **字节码不在源码里** —— 挪到了 `assets/core_a.dat`，且 XOR 加密。

```bash
# 一步到位
python tools/devirt_dex.py samples/apks/app_l2.apk
#   => note: opmap recovered from switch in Lcom/demo/calc/Core;->run
#   => note: payload assets/core_a.dat decrypted with 16-byte key from static field
#   => (opmap 与三段操作流和 L1 完全相同，semantics == golden)
```

**手工复现**：

**① 找载体** —— `unzip -l` 里唯一那个「既小又不是文本」的条目：

```bash
unzip -l samples/apks/app_l2.apk
#   => assets/core_a.dat  39   ← 39 字节，比任何正常资源都小
xxd analysis_output/cli/assets/core_a.dat | head -2
#   => d56a cce5 6c0a 42fb 816c 6cee cad0 49f9 ...
#   => d961 c4e1 6e0e 45ff ...
```

**② 找解密点** —— `Core` 的 `load()`：

```text
    private static byte[] load(Context ctx) {
        InputStream in = ctx.getAssets().open(RES);   ← RES = "core_a.dat"（一个普通字面量）
        ...
        for (int i = 0; i < raw.length; i++)
            out[i] = (byte) (raw[i] ^ KEY[i % KEY.length]);   ← 就是这一步：逐字节 XOR
    }
    private static final byte[] KEY = {-39,99,-61,-28,108,11,67,-8,-125,125,104,-20,-55,-43,78,-8};
```

**③ 解密** —— KEY 的十六进制是 `d9 63 c3 e4 6c 0b 43 f8 83 7d 68 ec c9 d5 4e f8`。
逐字节 XOR 后得到明文：

```text
密文: d5 6a cc e5 6c 0a 42 fb 81 6c 6c ee ca d0 49 f9 d9 ...
明文: 0c 09 0f 01 00 01 01 03 02 11 ...
      └len┘ └───────── 三段字节码 ─────────
```

**读**：明文前 3 字节 `0c 09 0f` = `12, 9, 15` —— 正是三段字节码的长度。`0c=12` 与 L1 的
`P_MIX` 长度一致。之后 `01 00 01 01 03 02 11 …` **与 L1 的 `P_MIX` 逐字节相同** —— 证明
「同一份业务、同一套 opcode 表，只是换了载体」。

**④⑤ 反汇编 + 验证**：拿到字节码后，按 L1 的 opmap 解码、跑测试向量 —— 与黄金一致。

> **本档的教学点**：L1→L2 的变化**只发生在第 ② 步**（找载体）。这说明去虚拟化的能力是
> **可分解**的：先把①③④做好（L1 就练完），遇到 L2 只需补「怎么找+解密载荷」这一步。

---

### §D L3 · 无 switch，反射分派（静态到此为止）

L3 **没有 `switch`**。看 `Core.run`（`dexdump -d`，完整见 CLI）：

```text
00081c: 6205 0500   |002c: sget-object v5, Core;.HM:[Ljava/lang/reflect/Method;  ← handler 表（Method 数组）
000820: 6206 0400   |002e: sget-object v6, Core;.DISPATCH:[I                      ← opcode → 槽位 表
000824: 4404 0604   |0030: aget v4, v6, v4                                       ← slot = DISPATCH[op]
000828: 4604 0504   |0032: aget-object v4, v5, v4                                 ← Method m = HM[slot]
000830: 2440 1600 3785 |0036: filled-new-array {code, regs, STACK, args}         ← 拼 invoke 参数
00083a: 6e30 2000 6405 |003b: invoke-virtual {v4, v6, v5}, Method;.invoke(...)     ← 反射调用 handler
```

**读**：分派是「`DISPATCH[op]` → 在 `Method[]` 里取方法 → `invoke`」。**没有一个 switch
可以把 case 体切出来做指纹** —— opcode 表藏在 `DISPATCH` 数组的**运行期填充**里：

```text
Core.ensureInit()（运行期装配 [DISPATCH] 与 [HM]）：
000956: sget DISPATCH;  0x95e: aput v2=0 -> DISPATCH[1]   ← opcode 0x01 -> 槽位 0
000962: sget DISPATCH;  0x968: aput v3=1 -> DISPATCH[2]   ← opcode 0x02 -> 槽位 1
00096c: ...              一直到 aput v8=6 -> DISPATCH[7]   ← opcode 0x07 -> 槽位 6
00099e: new-array [Ljava/lang/Class;  ← 后面建 sig 数组
        HM = { getDeclaredMethod("h0",sig), ... "h6" }
```

而每个 handler 的语义在 `h0..h6` 里 —— 它们**只有二十来条指令**，能读：

```text
Core.h2:([B[I[I[I)I            ← 收 (code, regs, STACK, args)
0006a2: aget v6, v4, v3         ← 从栈弹一个
0006a6: sub-int/2addr v6, v3
0006ac: aget v6, v5, v6         ← 再弹一个
0006ca: xor-int v4, v0, v6      ← 异或
0006ce: aput v4, v5, v1         ← 压回
0006d2: return v3               ← 返回 1（继续循环）
=> 这就是 XOR
```

**所以这一档「静态能不能解」取决于你怎么定义「解」**：

- **要靠工具自动切 case（像 L1 那样）**：不行 —— 没有 switch 可切。`devirt_dex.py` 会
  明确报告「静态不够」；
- **要人工还原**：**可以** —— 读 `ensureInit` 的常量表（7 条 `aput`）得到 `opcode → 槽位`，
  再读 `HM` 的 `getDeclaredMethod("hN")` 顺序得到 `槽位 → handler`，最后读 `h0..h6` 得到语义。
  **但这是人读 20×7 条指令，不是工具一键完成**。

```bash
python tools/devirt_dex.py samples/apks/app_l3.apk
#   => note: no packed-switch interpreter found -> reflection/dispatch needs dynamic tracing
#   => (static devirtualization insufficient — dynamic route required)
```

**这就是本档的边界，而且它是「工具有边界」而不是「不可能」**：工具不做「反射目标 + 常量表 +
小方法」的三段拼接，所以如实报告；人做得到，动态也做得到。

- **静态半自动（人读）**：`ensureInit` 的 `aput` 序列 → `h0..h6` 的字节码（如上）；
- **动态（推荐）**：`frida/trace_dispatch.js` 在 `Method.invoke` 上下 hook，把每次
  `(op, handler名)` 打出来，一条命令直接得到 opcode 表。

---

### §E L4 · 融合算子 + 随机 opcode（静态部分还原）

L4 有**两个**难点：**(a) opcode 值随机且不连续**（`sparse-switch`）；
**(b) 融合算子** —— 一条 handler 顶好几条逻辑指令（`ADDK` 表示「栈顶 + 立即数」，一条顶
`PUSH v; ADD` 两条）。

```bash
python tools/devirt_dex.py samples/apks/app_l4.apk
#   => recovered opmap (11 entries): 34=XOR, 62=ADD, 87=RET, 101=LOADARG, 120=MUL,
#         154=XOR, 163=MUL, 202=PUSH, 203=MUL, 210=ADD, 212=SUB
#   => (disassembly incomplete: 未知 opcode 0x3E @0x5)
#   => ! fused/inline-immediate opcodes present -> static devirtualization is PARTIAL
```

**怎么读**：opmap 认出了 11 项 —— 但注意 **`62=ADD` 这类「名字叫 ADD」的项其实是融合算子
`ADDK`**（「栈顶 + 立即数」，源里写作 `STACK[sp-1] = STACK[sp-1] + (code[i++] & 0xFF)`）。
静态指纹只认得它用了 `add` 指令，**认不出那个内联立即数**，所以它落在 opmap 里却被**错标成
`ADD`**。反汇编时遇到这些 opcode 就卡住（`未知 opcode 0x3E`），于是**只能部分还原**。

**为什么立即数拆不开（本 lab 用真实 case 体实测）**：L4 一共 11 个 case，其中 **6 个是基础
指令、5 个是融合算子**，而**指纹把它们两两混淆了** —— 看真实的 case 体：

| opcode | 真实语义（源） | 指纹判成 | 混淆在哪里 |
|---|---|---|---|
| `0x9A` | **XOR**（`x ^ y`，弹两个） | XOR ✅ | —— |
| `0x22` | **XORK**（`[sp-1] ^= imm`） | XOR ❌ | 少了一个立即数 |
| `0xD2` | **ADD**（`x + y`） | ADD ✅ | —— |
| `0x3E` | **ADDK**（`[sp-1] += imm`） | ADD ❌ | 少了一个立即数 |
| `0xA3` | **MUL**（`x * y`） | MUL ✅ | —— |
| `0xCB` | **MULK**（`[sp-1] *= imm`） | MUL ❌ | 少了一个立即数 |
| `0x78` | **ADDMUL**（`(a*v)+c`，**两个**立即数） | MUL ❌ | 少了两个立即数 |

**根因**：指纹只看「case 体里出现了哪条算术指令」。融合算子用的是**同一个** `add`/`mul`/`xor`
指令，只是作用对象不同 —— `x + y` 是**两个寄存器**，`[sp-1] += imm` 是**寄存器 + 内联立即数**。
而那个立即数（`code[i++]`）在 dalvik 里编成了一条独立的 `aget-byte` + `and #255`，**看起来和
`PUSH` 的取立即数一模一样**。所以：「这里是加法」看得出，「这个加法吃的是栈上两个值、还是
栈顶一个值加一个立即数」**单看形状分不出** —— 必须按 handler 语义建模，超出「形状指纹」。

**后果**：opmap 里 `0x22` 和 `0x9A` 都标成 `XOR` → 反汇编时二义；用错的映射去解码，
字节码里出现 `0x3E`(ADDK) 时就没有正确解释 → **`未知 opcode` → 只能部分还原**。

**怎么补**：

- **静态（人读）**：逐个融合 case 读它是否「多读了一条 `aget-byte` 当立即数」——
  能分出 `ADD` vs `ADDK`，但要人做（本 lab 的工具不做这一步）；
- **动态（推荐）**：trace 每次 handler 的入参，**直接读那个内联立即数的值** —— 这是最省事的。

> **本档的教学点**：随机 opcode（V6）只是**抬高门槛**，真正卡住静态的是**融合算子**。
> 这也是真实保护器的主要手法之一 —— 不是「换成随机数」，而是「把多条指令合成一条」，
> 让「一条 VM 指令 = 一条 CPU 指令」这个隐含假设失效。

---

### §F L5 · 内联 VM（无 hub —— 形状判据失效后怎么解）

L5 **没有 `Core` 类**。三个业务方法各自内嵌了一份完整的解释器循环：

```java
public static int mix(int a, int b) {
    int[] args = new int[]{a, b};
    {  byte[] code = P_MIX;
       int[] st = new int[64]; int sp = 0, i = 0;
       while (i < code.length) {
           int op = code[i++] & 0xFF;
           switch (op) { case 0x01: ... case 0x07: return st[--sp]; }   ← 与 twist/digest 里的一模一样
       } }
}
```

```bash
python tools/devirt_dex.py samples/apks/app_l5.apk
#   => note: opmap recovered from switch in Lcom/demo/calc/CalcLogic;->digest
#   => prog0..prog5  -> semantics == golden mix / twist / digest
```

**怎么解**：**V1（汇聚调用）在这里恒不命中**（没有 hub）—— 但 **V5（多个方法含同一个
switch）命中**。工具于是改从「内联在 `CalcLogic` 里的那个 switch」入手，切 case 体、
还原 opmap、取每个方法自己的字节码、解码 —— 结果与 L1 一模一样的三段操作流。

**逐行读法**：`note: opmap recovered from switch in …CalcLogic;->digest` 说明工具**没有**
找到 `Core.run`（因为不存在），而是从内联在业务方法里的 switch 拿到的 opmap。
`prog0..prog5` 是 6 段（每个方法各一段字节码，工具按出现顺序编号），它们分别匹配黄金的
`mix/twist/digest`。

> **本档的教学点**：判据有边界（V1 会漏 L5），但**只要换个结构特征（V5）就还能抓**。
> 这就是「判据组合」而不是「单一特征」的意义。

---

### §G S1 · native 中心分派（完整演示）

SO 侧前先把「native 解释器长什么样」看清楚。S1 用 `-O0` 编译，比较级联**完整保留**：

```bash
python tools/devirt_so.py samples/native/libcalc_s1_arm64.so
#   => note: interpreter = vmr (214 insns, dispatch=switch)
#   => note: switch opmap: 7/7 cases fingerprinted via comparison-chain simulation
#   => switch opmap: 1=LOADARG, 2=PUSH, 3=XOR, 4=ADD, 5=MUL, 6=SUB, 255=RET
```

#### 手工复现

**① 找解释器** —— `llvm-objdump -d` 里最大的函数是 `vmr`（214 条指令）。它的分派是
**比较级联**（clang 未优化的 switch 形态）：

```text
subs w8, w8, #0x1     b.eq 0x1980 <vmr+0xc0>     ← op==1 -> case 体 @0x1980
                      b    0x1920 <vmr+0x60>     ← 否则下一个比较节点
subs w8, w8, #0x2     b.eq 0x19d0 <vmr+0x110>
                      b    0x1930
subs w8, w8, #0x3     b.eq 0x1a14 <vmr+0x154>
...
subs w8, w8, #0xff    b.eq 0x1bd4 <vmr+0x314>
```

**读**：`subs w8,w8,#imm / b.eq <case> / b <next>` 是一个**比较节点**；`next` 指向下一个
节点。`devirt_so.py` 的 `_simulate_chain` 就是一个小解释器：沿这个链走，命中就落到 case 体。

**② 找字节码** —— `.rodata` 只有 36 字节：

```bash
"$NDBIN/llvm-objdump.exe" -s -j .rodata samples/native/libcalc_s1_arm64.so
#   => 0548 01000101 03021104 020305ff 01000207 ...
```

**③ 反推 opmap** —— 对每个 case 体做「**数据运算**指纹」。这里有个**必须分清**的陷阱：

```text
case 0x3 体 (@0x1a14):
    1a5c: 4a090108   eor w8, w8, w9     ← 两个 w 寄存器运算 = DATA 运算 = XOR ✅
    1a60: f9401be9   ldr x9, [sp, #0x30]
    1a64: 91005129   add x9, x9, #0x14  ← 带立即数 = 指针簿记，不是 VM 运算 ❌（必须排除）
    ...
    1a80: 14000060   b 0x1c00           ← 回循环尾 = case 体结束
```

**如果不过滤**：每个 case 体都有 `add x9,x9,#0x14`（那是「`&stack[sp++]`」的地址计算），
不过滤就会把**每一个** case 都判成 ADD —— 这正是本 lab 踩过的坑（`AGENTS.md` §12.9）。
正确做法：**只有 `add/sub` 的两个操作数都是 w 寄存器（reg,reg）才算数据运算**。

所以：

| opcode | case 体里的决定性指令 | 语义 |
|---|---|---|
| `0x1` | `ldrb w9,[x9,x10]`（读 code[pc]）+ `ldr w8,[x8,w9,lsl #2]`（按它索引 args） | **LOADARG** |
| `0x2` | 只有 `ldrb`（读 code[pc]） | **PUSH** |
| `0x3` | `eor w8,w8,w9` | **XOR** |
| `0x4` | `add w8,w8,w9` | **ADD** |
| `0x5` | `mul w8,w8,w9` | **MUL** |
| `0x6` | `sub w8,w8,w9` | **SUB** |
| `0xff` | 从栈数组弹元素（无 ldrb，有带缩放的 `ldr`） | **RET** |

**④⑤ 解码 + 验证**：用该表解 `.rodata` 的 36 字节：

```text
01 00   -> LOADARG 0
01 01   -> LOADARG 1
03      -> XOR
02 11   -> PUSH 0x11
04      -> ADD
02 03   -> PUSH 3
05      -> MUL
ff      -> RET
=> ((a ^ b) + 0x11) * 3    ✓ 与黄金一致
```

> **注意 `RET` 的 opcode 在 SO 是 `0xFF`，在 DEX 是 `0x07`** —— 两套样本用不同的 opcode 表
> （`SO_OPMAP` vs `vmgen.level_opmap`）。这本身也是个知识点：**opcode 表是每套 VM 自己的约定**。

---

### §H S2 / S3 · native 分派被去中心化（静态到此为止）

```bash
python tools/devirt_so.py samples/native/libcalc_s2_arm64.so
#   => note: interpreter = Java_com_demo_calc_CalcLogic_mix (106 insns, dispatch=indirect)
#   => note: dispatch is indirect -> need dynamic tracing ...
#   => ! static devirtualization not sufficient for this dispatch shape

python tools/devirt_so.py samples/native/libcalc_s3_arm64.so
#   => note: interpreter = vmr (123 insns, dispatch=threaded)
#   => ! static devirtualization not sufficient for this dispatch shape
```

**S2（运行期装配）**：handler 表 `SLOT[]` 和 opcode 映射 `OPMAP[]` 都在 `assemble()` 里
**运行期算出来**。静态只能看到一句 `blr x8`（间接调用）——**目标地址运行期才确定**，
没有稳定的 case 边界可切。

**S3（threaded / computed-goto）**：每个 handler 以 `goto *LBL[op]` 直接跳下一个 handler，
形成一张 basic block 网。静态看到的是**一堆 `br x8` 互相跳**，**没有中心函数**可切。

**两者的下一步都是动态**：

- S2：`frida/so_vm_trace.js` 在 `blr xN` 处 hook，记录每次跳到的 handler 地址 → 得到
  `opcode → handler` 映射 → 再回 `llvm-objdump` 看那个 handler 体做什么；
- S3：trace basic block 的转移序列（`Stalker`），还原控制流图。

> **本档的诚实边界**：S2/S3 是本 lab 的 **WIP**（像 `uncrackable/l3` 那样如实记录），
> 不假装已解。它们的价值是**证明「静态有边界」**：分派一去中心化，形状判据就只剩「定位」，
> 真值必须从运行期取。

---

### §I 动态路线（静态不够时的统一兜底）

```bash
# 行为 oracle：主动调目标方法，比对黄金值（会在设备上安装并启动 app，见下方红字提醒）
python tools/trace_vm.py --package com.demo.calc --script frida/oracle_run.js --seconds 8
#   => [oracle] mix(7,3)   = 63   (expect 63)
#   => [oracle] twist(7)   = 44   (expect 44)
#   => [oracle] digest(7,3)= 121  (expect 121)
#   => [oracle-neg] mix(0,0)= 51  (expect 51 ≠ 63，负控)
```

**为什么动态能兜住静态的缺口**（对照 §A 五步）：

| 静态卡在 | 动态怎么补 |
|---|---|
| ① 分派去中心化 | hook 分派指令（`Method.invoke` / `blr xN`），直接读「这次用了哪个 handler」 |
| ② 载荷加密 | hook 解密函数出口，直接拿到明文字节码 |
| ③ 融合算子 | hook handler 入参，直接读那个拆不开的立即数 |
| ④⑤ | 静态④⑤通常还能做；动态结果回来做交叉验证 |

**动态的纪律**（沿用本仓 `METHODS.md` 的「动态分析通用方法集」）：

- **先拿签名再 hook**：`.overload(...)` 靠猜必错，先枚举；
- **oracle 必配负控**：`oracle_run.js` 里的 `mix(0,0)=51` 就是负控（证明 oracle 有区分度）；
- **调目标自身的函数**，别把常量抄回 JS 重算 —— 那证明不了你理解了调用关系；
- **记环境指纹**：设备/Android/frida 版本必须记（本仓钉 frida **16.5.9**，17.x 去掉了 `Java` 全局）。

> ⚠️ **`trace_vm.py` 会在连接的设备上安装并启动目标 app。** 请只在**你有权操作**的设备或
> **本地模拟器**上运行（本仓推荐 `n4tive_lab` AVD，见 `build/env.sh.example` 与根 `README.md`
> 的 frida 环境段）。绝不针对他人的真机。

---

### §J 去虚拟化工作流总图（把 §A..§I 串起来）

```text
              ┌─ ① 定位解释器 ──────────────┐
detect_vm ────┤                              │
   │          └─ ② 找字节码 ─────────────────┤
   │                                          ├─ 全成功 → ④ 解码 → ⑤ 验证 → 完成
   │          ┌─ ③ 反推 opcode 表 ───────────┘
   │          │
   └─ 任一步失败 │
              ↓
        ┌──────────────────────────────────────────────┐
        │ L3：反射分派        → trace Method.invoke     │
        │ L4：融合算子        → trace handler 入参       │
        │ S2：运行期装配      → trace blr 目标          │
        │ S3：threaded        → trace basic block 转移   │
        └──────────────────────────────────────────────┘
              ↓
        动态拿到映射 → 回到 ④ 解码 → ⑤ 验证
```


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
