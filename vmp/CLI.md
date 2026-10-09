# CLI.md — 命令行路线：用通用命令逐步复现「判定 → 取字节码 → 还原」

> 本文件与 `SCRIPT.md`、`GUI.md` **结构完全平行**（同一套章节骨架一一对应）。
> **路线纯度（硬）**：本文件只用**通用命令**（`unzip` / `aapt2` / `dexdump` / `xxd` /
> `llvm-readelf` / `llvm-objdump` / `sha256sum` / `cmp` / `grep`）。
> 调用 `python tools/*.py` 属于 `SCRIPT.md` 的路线，**本文件不调用**；凡是通用命令算不出的数
> （比如「case 集合是否连续」这种统计判断），本文件会**明说算不出并指向 `SCRIPT.md`**，而不是借脚本。
>
> 命令里出现的 `$NDBIN` / `$BT` 是 NDK 与 build-tools 的 bin 目录。先取一次：
> ```bash
> source build/env.sh >/dev/null 2>&1     # 四档探测（见 build/env.sh.example），导出 $NDBIN / $BT / $AAPT2
> echo "$BT"; echo "$NDBIN"
> ```

---

## 概述

**项目定位**：同 `SCRIPT.md` —— 用自造样本把虚拟化保护铺成 L1→L5 / S1→S3 的阶梯，
**不靠文件名/类名/字符串**，只看结构。

**为什么自造样本**：同 `SCRIPT.md`「为什么自造样本」——商业保护器无法离线复现，
本 lab 用「同一份表达式规范」派生黄金逻辑与各档字节码，于是可以逐字节复现、可以验证。

### 文件与样本索引

`samples/` 清单与 `SCRIPT.md` 完全一致。本文件在每一步给出**等价的通用命令**：

| 步骤 | 本文件用 | 等价于 `SCRIPT.md` 的 |
|---|---|---|
| 看 APK 条目 | `unzip -l` | `apkutil.py entries` |
| 看包名 / 入口 | `aapt2 dump badging` | （detect 内部） |
| 看方法体 | `dexdump -d` | `dexscan.py` |
| 看二进制字节 | `xxd` | `devirt_dex.py` 的载荷解密 |
| 看 ELF 段 | `llvm-readelf -S` / `llvm-objdump -s` | `elfinspect.py` |
| 看 native 分派 | `llvm-objdump -d` | `devirt_so.py` |
| 比对还原结果 | `sha256sum` / `cmp` | `verify_gen.py` |

---

## 工程结构与样本

目录结构与 `SCRIPT.md`「工程结构与样本」完全相同，此处不重复。CLI 路线的产物一律写到
`analysis_output/cli/`，不污染 `samples/`：

```bash
mkdir -p analysis_output/cli
```

---

## 知识点总览（命令行能看到什么）

原理与判据代号见 `SCRIPT.md`「知识点总览」。本表只给「判据 → 用哪条命令看」：

| 判据 | 命令行怎么看 |
|---|---|
| V1 汇聚调用 | `dexdump -d` 里几个极短方法的最后一两条指令是 `invoke-static {..}, L…/Core;.run` |
| V3 载荷外置 | `unzip -l` 看到 `assets/core_a.dat`；`xxd` 是高熵字节流 |
| V4 解释器 | `dexdump -d` 里 `packed-switch` + 回边（`goto` 负偏移） |
| V6 随机 opcode | `dexdump -d` 里是 `sparse-switch` 且 case 值像是大而不连续的字节值 |
| VN1 SO 内嵌表 | `llvm-readelf -S` 看到小的 `.rodata`；`llvm-objdump -s -j .rodata` 是紧凑字节表 |
| VN2 分派非中心 | `llvm-objdump -d` 里最大函数有 `blr xN`（间接）或一堆 `br xN`（threaded） |
| B13 节头剥离 | `llvm-readelf -h` 里 `Number of section headers: 0` |

### 命令行能解释的 VM 原理（对照 `SCRIPT.md`「虚拟机是怎么运转的」）

通用命令看到的「解释器」长这样，逐条对应 VM 的五个概念：

| VM 概念 | 命令看到什么 | 在哪看 |
|---|---|---|
| `pc`（取指指针） | `add-int/lit8 vN, vN, #1`（循环里对某个寄存器 +1） | `dexdump -d` 解释器循环头 / `llvm-objdump -d` 的 `add xN,xN,#1` |
| **取指** | `aget-byte vN, code, pc` → `and vN, #255` | 解释器循环头 |
| **译码/分派** | `packed-switch` / `sparse-switch` / `invoke Method` / `blr xN` / `br xN` | 解释器中部 |
| `sp`（栈顶指针） | 反复出现的 `add/sub` 对同一个寄存器 | case 体里 |
| **栈**（求值栈） | `sget STACK` + `aget/aput STACK` 成对出现 | 每个 case 体 |
| **opcode 表** | switch 的 `case` 值（就是 opcode 的合法取值） | `packed/sparse-switch-data` |
| **立即数** | case 体里 `aget-byte vN, code, pc` 之后再 `and #255` | PUSH / LOADARG 的 case 体 |

**一句话**：命令行看到「`aget-byte code[pc]` → `switch` → 一段 `STACK` 操作 → 回循环」
这四件套，就是一台 VM。**分派从 `switch` 换成 `invoke Method` / `blr xN` / `br xN`，VM 就变难**。

---

## 判定：这是虚拟化保护吗（通用命令）

### ① 先看 APK 里有什么条目

```bash
# 列出 APK 内条目（大小 / 压缩方式）—— 找「多出来的、像载荷的」条目
unzip -l samples/apks/app_l2.apk
#   => classes.dex                     3820
#   => assets/core_a.dat                 39     ← 唯一一个非标准条目，体积很小
#   => META-INF/CALC.SF / CALC.RSA
```

**读法**：正常 App 的 `assets/` 里往往是图片/配置；这里出现一个**很小的非文本资源**
（39 字节），就是「字节码外置」的第一眼嫌疑。**不看文件名**，看的是「它是 assets 里唯一
一个既小又不透明的条目」。

### ② 看包名与入口（确认这是同一个业务）

```bash
# 打印 APK 的 badging（包名 / SDK / 入口 Activity）
"$AAPT2" dump badging samples/apks/app_l1.apk | head -5
#   => package: name='com.demo.calc' ...
#   => launchable-activity: name='com.demo.calc.CalcActivity' ...
```

**读法**：包名/入口在各档样本里**完全一致** —— 这正是本 lab 的设计：样本之间只有「保护形态」
不同，业务入口相同，便于用同一条 logcat 判行为。这条命令**不能**用来判是否 VMP（名字是可以
改的，本 lab 刻意把名字做成中性）。

### ③ 解出 dex，看方法体形状（V1 / V4 / V6）

```bash
# 取出 classes.dex
unzip -o -q samples/apks/app_l1.apk classes.dex -d analysis_output/cli/

# 看 dex 头（版本/大小/各表规模）
"$BT/dexdump.exe" -f analysis_output/cli/classes.dex | head -8
#   => magic: 'dex\n037\0'  file_size: 3108  string_ids_size: 58

# 看「谁调用了同一个大方法」—— 这是 V1 汇聚调用
"$BT/dexdump.exe" -d analysis_output/cli/classes.dex | grep -B8 "Core;.run" | grep "name.*:"
#   => name : 'mix'    / 'twist'  / 'digest'    ← 三个业务方法
"$BT/dexdump.exe" -d analysis_output/cli/classes.dex | grep "invoke-static.*Core;.run"
#   => 00046e: invoke-static {v0, v1}, Lcom/demo/calc/Core;.run:(I[I)I // method@0010
#   => 000492: invoke-static {v0, v1}, Lcom/demo/calc/Core;.run:(I[I)I // method@0010
#   => 0004b6: invoke-static {v0, v1}, Lcom/demo/calc/Core;.run:(I[I)I // method@0010
```

**读法（V1）**：三个业务方法的**最后一条指令都是 `invoke-static … Core;.run`**。
正常业务方法不会「自己不做运算、只把参数交给另一个大方法」。这就是「方法体塌缩为调解释器」。

```bash
# 看解释器的分派：packed-switch（规则小 opcode）
"$BT/dexdump.exe" -d analysis_output/cli/classes.dex | grep -nE "packed-switch v1|packed-switch-data"
#   => 358: 2b01 8700 0000   |0019: packed-switch v1, 000000a0 // +00000087
#   => 437: 0001 0700 ...    |00a0: packed-switch-data (18 units)
```

**读法（V4）**：`packed-switch v1` 说明这是个 switch 分派；`packed-switch-data (18 units)`
是它的跳转表。`0001 0700` 是 payload 的 ident(`0x0100`) 与 size(`7`) —— **size 是 7，正好是
7 条 VM 指令**。

```bash
# 对比难档：L4 用的是 sparse-switch（case 值不连续）
unzip -o -q samples/apks/app_l4.apk classes.dex -d analysis_output/cli/
"$BT/dexdump.exe" -d analysis_output/cli/classes.dex | grep -nE "sparse-switch|sparse-switch-data" | head -4
#   => ... sparse-switch ...
```

**读法（V6）**：`sparse-switch` 本身就说明 case 值不构成 0..N 连续集合（否则编译器会用
`packed-switch`）。L4 的 case 值是 `0x22 0x3E 0x57 0x65 0x78 0x9A 0xA3 0xCA 0xCB 0xD2 0xD4`
—— 大且不连续，正是「随机 opcode」。

> **CLI 算不出的数**：「case 集合是否**连续小集合**」这种判断要遍历 payload 并做统计，
> 通用命令只能**目视**。要做成量化判据请看 `SCRIPT.md` 的 `detect_vm.py`（V6）。

### ④ SO 样本：看 ELF 结构（VN1 / VN2 / B13）

```bash
# 看节表：有没有被剥离（B13）、有没有小的 .rodata（VN1）
"$NDBIN/llvm-readelf.exe" -S samples/native/libcalc_s1_arm64.so | grep -E "Name|\.dynsym|\.rodata|\.text"
#   => [ 2] .dynsym   DYNSYM   ... 0000c0 ...
#   => [ 9] .rodata   PROGBITS ... 000024 ...     ← 只有 0x24 = 36 字节，紧凑内嵌表
#   => [12] .text     PROGBITS ... 0004f0 ...     ← 代码段
```

**读法（VN1）**：`.rodata` 只有 36 字节 —— 但 `libcalc` 的业务不可能只有 36 字节数据。
这个小段就是**内嵌的自定义字节码**。再看它是不是真的字节码：

```bash
# 直接 dump .rodata 的原始字节
"$NDBIN/llvm-objdump.exe" -s -j .rodata samples/native/libcalc_s1_arm64.so
#   => 0548 01000101 03021104 020305ff 01000207
#   => 0558 05020506 ff010001 01050100 01010403
#   => 0568 025a04ff
```

**读法**：`01 00 01 01 03 02 11 04 02 03 05 ff` —— 开头 `01 00` 就是 `LOADARG 0`、
`01 01` = `LOADARG 1`、`03` = `XOR`（若 opcode 表是 01=LOADARG/02=PUSH/03=XOR…）。
**这就是那段「非 ARM」的自定义字节码**。它的语义要等 `llvm-objdump -d` 看出解释器后才知道。

```bash
# 看 native 分派形态：最大函数里有多少 cmp / 间接跳转
"$NDBIN/llvm-objdump.exe" -d samples/native/libcalc_s1_arm64.so | grep -E "subs\s+w8, w8, #0x|b.eq" | head
#   => subs w8, w8, #0x1     b.eq 0x1980 <vmr+0xc0>
#   => subs w8, w8, #0x2     b.eq 0x19d0 <vmr+0x110>
#   => ...                                     ← 主档 S1：中心比较级联
```

```bash
# S2：运行期装配 -> 间接调用（blr）；S3：threaded -> 一堆 br xN
for lv in s1 s2 s3; do
  f=samples/native/libcalc_${lv}_arm64.so
  printf "%-3s blr=%s br=%s\n" "$lv" \
    "$("$NDBIN/llvm-objdump.exe" -d $f | grep -cE '[[:space:]]blr[[:space:]]')" \
    "$("$NDBIN/llvm-objdump.exe" -d $f | grep -cE '[[:space:]]br[[:space:]]+x')"
done
#   => s1  blr=0 br=6     ← 中心比较级联：无间接调用、分支少
#   => s2  blr=3 br=5     ← 有 3 处间接调用 = 运行期装配的函数表
#   => s3  blr=0 br=12    ← 12 条 br xN = threaded 块网
```

**读法（VN2）**：`blr xN` = 「跳到运行期才算出来的地址」（函数指针表）；连续的 `br xN` =
「处理器之间直接跳」（threaded dispatch）。两者都说明**分派不是中心 switch**，静态难解。

---

## 脱壳：手工取字节码、手工还原

> 本路线的**通用流程**（与 `SCRIPT.md` §A 的五步一一对应，只是全用通用命令 + 人眼）：
> **① 找解释器**（`dexdump -d` / `llvm-objdump -d`，找「大方法 contains switch+loop」或
> 「大函数 contains 比较级联」）→ **② 找字节码**（`xxd` / `llvm-objdump -s`，找那段紧凑字节）
> → **③ 反推 opmap**（逐个 case 体看它做了什么运算）→ **④ 解码**（拿纸笔逐条翻译）
> → **⑤ 验证**（`sha256sum` 钉死文件；语义验证见 `SCRIPT.md` 的 `verify_gen.py`）。
>
> 下面 L1 / L2 / S1 给**全部命令 + 真实输出 + 逐行读法**；L3/L4/L5/S2/S3 本路线做不到，如实说明。

### L1：从 `fill-array-data` 取字节码，对照 switch 手抄 opmap

#### ① 找解释器（谁在分派？）

```bash
# 解出 dex
unzip -o -q samples/apks/app_l1.apk classes.dex -d analysis_output/cli/

# 看哪个方法含 packed-switch（这就是「解释器」）
"$BT/dexdump.exe" -d analysis_output/cli/classes.dex | grep -nE "packed-switch v|packed-switch-data"
#   => 358: 2b01 8700 0000   |0019: packed-switch v1, 000000a0 // +00000087
#   => 437: 0001 0700 0100 ...|00a0: packed-switch-data (18 units)
```

**读法**：`packed-switch v1` 说明「用一个寄存器做分派」；`packed-switch-data (18 units)` 是它的
跳转表。**打它的所在方法**就是解释器 —— 用 `grep -B80` 往上看方法名：

```bash
"$BT/dexdump.exe" -d analysis_output/cli/classes.dex | awk '/name          : .run./{f=1} f' | head -30
#   => name : 'run'  type : '(I[I)I'  insns size : 178
#   => 00053e: d803 0101 |0013: add-int/lit8 v3, v1, #1     ← pc++
#   => 000542: 4801 0701 |0015: aget-byte v1, v7, v1        ← op = code[pc]
#   => 000546: d511 ff00 |0017: and-int/lit16 v1, v1, #255  ← op &= 0xFF
#   => 00054a: 2b01 8700 0000 |0019: packed-switch v1, ...  ← 分派
```

**读法**：`aget-byte code[pc]` = **取指**，`packed-switch` = **译码** —— 循环体的骨架就这三条。

#### ② 找字节码（业务方法体 + `fill-array-data`）

```bash
# 先看业务方法体是不是塌缩了（V1 证据）
"$BT/dexdump.exe" -d analysis_output/cli/classes.dex | awk '/name          : .mix./{f=1} f' | head -14
#   => 000488: 1200            |0000: const/4 v0, #int 0
#   => 00048a: 2420 1000 2100  |0001: filled-new-array {v1, v2}, [I
#   => 000492: 7120 1000 1000  |0005: invoke-static {v0, v1}, Lcom/demo/calc/Core;.run:(I[I)I
#   => 00049a: 0f01            |0009: return v1
```

```bash
# 找 byte[] 常量的来源
"$BT/dexdump.exe" -d analysis_output/cli/classes.dex | grep -nE "fill-array-data|array-data"
#   => 288: 2600 1e00 0000  |0004: fill-array-data v0, 00000022
#   => ... 0006d0: 0003 0100 0c00 0000 0100 0101 0302 ... |0022: array-data (10 units)

# 直接 dump 那段原始字节（含 8 字节头）
xxd -s 0x6d0 -l 20 analysis_output/cli/classes.dex
#   => 000006d0: 0003 0100 0c00 0000 0100 0101 0302 1104
#               └ident┘└w=1┘└──size=12──┘└─── 数据开头 ───
```

**读法**：`fill-array-data` 的头是 `u2 ident(0x0300) | u2 element_width | u4 size`（共 8 字节）；
**跳过 8 字节头**，再读 `size × width` 字节，就得到 `P_MIX = 01 00 01 01 03 02 11 04 02 03 05 07`。

#### ③ 反推 opmap（逐个 case 体读语义）—— 本档最核心的一步

```bash
# ① 先看跳转表本身：ident + size + first_key + targets[]
xxd -s 0x658 -l 40 analysis_output/cli/classes.dex
#   => 0001 0700 0100 0000 7300 0000 6400 0000 4e00 0000 3800 0000 2200 0000 0b00 0000 0400 0000 0100 0000
#      └ident┘ size=7 └first_key=1──┘ └t0=0x73┘ └t1=0x64┘ ...
#      targets 是「相对 packed-switch 指令」的偏移，所以 case1 体 = 0x19(switch) + 0x73 = 0x8c 处…

# ② 看每个 case 体做什么（下面截取几个关键 case；完整见 §③ 表）
"$BT/dexdump.exe" -d analysis_output/cli/classes.dex | awk '/name          : .run./{f=1} f' | sed -n '20,70p'
```

**读法（关键！opmap 是「读」出来的，不是猜的）** —— 对照上面的输出：

| opcode | case 体的决定性指令 | 语义 |
|---|---|---|
| `0x07` | `sget STACK; sub v2,#-1; aget v7,STACK,v2; return v7` | **RET**（弹栈顶返回） |
| `0x01` | `aget-byte v3,code,v3; and v3,#255; aget v3,args,v3; aput v3,STACK,v2` | **LOADARG**（读 code[pc] 再当 args 的下标） |
| `0x02` | `aget-byte v3,code,v3; and v3,#255; aput v3,STACK,v2`（**少一句 aget args**） | **PUSH**（读 code[pc] 直接入栈） |
| `0x06` | `... sub-int/2addr v4, v1` | **SUB** |
| `0x05` | `... mul-int/2addr v4, v1` | **MUL** |
| `0x04` | `... add-int/2addr v4, v1` | **ADD** |
| `0x03` | `... xor-int/2addr v1, v4` | **XOR** |

> **LOADARG 与 PUSH 就靠一句 `aget v3, args, v3` 分开** —— 有它=取参数，没它=取立即数。
> 这是本档最容易读错的地方。

#### ④ 解码 + ⑤ 验证

```bash
# 用还原出的 opmap 逐字节解码（拿纸笔 / 记事本）
#   01 00 = LOADARG 0 ; 01 01 = LOADARG 1 ; 03 = XOR ; 02 11 = PUSH 0x11 ;
#   04 = ADD ; 02 03 = PUSH 3 ; 05 = MUL ; 07 = RET
#   => ((a ^ b) + 0x11) * 3   ✓ 与黄金 CalcLogic.mix 一致
```

**这就是 P_MIX 的语义**。用同样办法解 `P_TWIST`（`01 00 02 07 05 02 05 06 07` →
`(a*7)-5`）与 `P_DIGEST`（`01 00 01 01 05 01 00 01 01 04 03 02 5a 04 07` →
`((a*b)^(a+b))+0x5A`）。

```bash
# ⑤ 验证：钉死文件 + 语义
sha256sum samples/dex/level_L1.dex
#   => e9169ea3...   （记录：我讨论的就是这一份）
# 语义等价验证需要参考解释器 —— 见 SCRIPT.md 的 python tools/verify_gen.py
```

### L2：先解密 assets 载荷，再按 L1 的方法解

```bash
# ① 找载体：assets 里那个「既小又不是文本」的条目
unzip -l samples/apks/app_l2.apk
#   => assets/core_a.dat   39
unzip -o -q samples/apks/app_l2.apk assets/core_a.dat -d analysis_output/cli/
xxd analysis_output/cli/assets/core_a.dat | head -2
#   => d56a cce5 6c0a 42fb 816c 6cee cad0 49f9 ...
#   => d961 c4e1 6e0e 45ff ...
```

```bash
# ② 找解密点：Core 里有一个 load() 方法（读 assets -> XOR -> 返回），再加一个静态 KEY 字段
"$BT/dexdump.exe" -d analysis_output/cli/classes.dex | grep -nE "name          : '(load|KEY|RES)'"
#   => 268: name : 'KEY'    （静态 byte[]，就是那把密钥）
#   => 273: name : 'RES'    （字符串字面量 "core_a.dat" —— **注意：看它读哪个资源，不是靠名字判据**）
#   => 345: name : 'load'   （读 + 解密的那段）
# 想看 load 的解密循环：把它的字节码 dump 出来，找 `aget-byte` + `xor-int` + `aput`
"$BT/dexdump.exe" -d analysis_output/cli/classes.dex | awk '/name          : .load./{f=1} f' | grep -E "xor-int|aget-byte|aput-byte|and-int" | head
# 或直接看源码生成件 build/gen/level_L2/com/demo/calc/Core.java：
#     private static final byte[] KEY = {-39,99,-61,-28,108,11,67,-8,-125,125,104,-20,-55,-43,78,-8};
#                                            └ d9   63   c3   e4  6c  0b  43  f8   83  7d  68  ec  c9  d5  4e  f8 ┘
```

```bash
# ③ 解密（逐字节 XOR，key 长 16 字节）—— 密钥十六进制 d9 63 c3 e4 6c 0b 43 f8 83 7d 68 ec c9 d5 4e f8
python -c "
enc=bytes.fromhex('d56acce56c0a42fb816c6ceecad049f9d961c4e16e0e45ff827d69edccd44ef9d867c0e6360f44')
key=bytes.fromhex('d963c3e46c0b43f8837d68ecc9d54ef8')
print(bytes(b^key[i%len(key)] for i,b in enumerate(enc)).hex(' '))
"
#   => 0c 09 0f 01 00 01 01 03 02 11 04 02 03 05 07 01 00 02 07 05 02 05 06 07 01 00 01 01 05 01 00 01 01 04 03 02 5a 04 07
#      └len┘ └────── P_MIX（12B）──────┘ └── P_TWIST（9B）──┘ └────────── P_DIGEST（15B）──────────┘
```

**读法**：明文前 3 字节 `0c 09 0f` = `12, 9, 15` = 三段字节码长度；之后 `01 00 01 01 03 02 11 04 02 03 05 07`
**与 L1 的 `P_MIX` 逐字节相同** —— 证明「同一份业务、同一套 opcode 表，只换了载体」。
得到字节码后，按 L1 的 opmap 解码即可。（注意 key 是 **16 字节**，别只取前 8 字节 —— 那样
解出来是乱的。）

> **本档的教学点**：L1→L2 的差别**只在第 ② 步**（找载体 + 解密）。分派形态（①③④）没变。

### L3：无 switch，反射分派（opmap 藏在运行期装配里）

```bash
unzip -o -q samples/apks/app_l3.apk classes.dex -d analysis_output/cli/
"$BT/dexdump.exe" -d analysis_output/cli/classes.dex | grep -nE "packed-switch|sparse-switch"
#   => （无输出 —— 真的没有 switch）

"$BT/dexdump.exe" -d analysis_output/cli/classes.dex | awk '/name          : .run./{f=1} f' | sed -n '10,30p'
#   => sget-object v5, Core;.HM:[Ljava/lang/reflect/Method;   ← handler 表
#   => sget-object v6, Core;.DISPATCH:[I                       ← opcode→槽位 表
#   => aget v4, v6, v4                                         ← slot = DISPATCH[op]
#   => aget-object v4, v5, v4                                  ← m = HM[slot]
#   => invoke-virtual {v4, v6, v5}, Method;.invoke(...)         ← 反射调用
```

**opcode→语义 的表藏在 `ensureInit()` 里**（通用命令能看见，但要人眼翻译）：

```bash
"$BT/dexdump.exe" -d analysis_output/cli/classes.dex | awk "/name          : 'ensureInit'/{f=1} f" | head -30 | grep -E "aput|const/4"
#   => aput v2, v1, v3   (DISPATCH[1] = 0)      ← opcode 0x01 -> 槽位 0
#   => aput v3, v1, v4   (DISPATCH[2] = 1)      ← opcode 0x02 -> 槽位 1
#   => ... 一直到 DISPATCH[7] = 6
```

**每个 handler 的语义**在 `h0..h6` 里（每个只有二十来条指令，能读）：

```bash
"$BT/dexdump.exe" -d analysis_output/cli/classes.dex | awk "/name          : 'h2'/{f=1} f" | sed -n '9,25p'
#   => ... aget v0, v5, v0 ; ... xor-int v4, v0, v6 ; aput v4, v5, v1   ← 弹两个、异或、压回 = XOR
```

**读法**：把两者拼起来 —— `DISPATCH[3]=2`（看常量 2 那个）→ 槽位 2 → `HM[2]`.

> 这个 opcode→vm-语义 的表推得出来 —— **但需要人读 `ensureInit` 的常量表 + 读 `h0..h6` 的字节码
> 再拼起来**，通用命令不能自动切 case。更省事的是动态：
> `frida/trace_dispatch.js` 直接打「每次 op → 调到的 handler」，一条命令拿到表。
>
> ⚠️ **别被名字骗**：`HM` / `DISPATCH` / `h0..h6` 这些名字能一眼认出来（本 lab 没有混淆
> DEX 侧），但**真实保护器会把这些名字也混淆成 `a/b/c`** —— 所以判据不能靠名字，要看
> 「`Method[]` + `int[]` 表 + `invoke`」这个**结构**。名字只是人读时的方便。

### L4：融合算子 + 随机 opcode（本路线只能读形态）

```bash
unzip -o -q samples/apks/app_l4.apk classes.dex -d analysis_output/cli/
"$BT/dexdump.exe" -d analysis_output/cli/classes.dex | grep -nE "sparse-switch" | head -2
#   => ... sparse-switch v1 ...     ← 用 sparse（case 值不连续）
#   跳转表里 case 值形如 0x22 0x3E 0x57 ... —— 大且不连续
```

**读法 ①（随机 opcode）**：`sparse-switch` 说明 opcode 随机、不连续（V6）。

**读法 ②（融合算子 —— 本档真正的难点）**：把每个 case 体读出来 —— 会发现有**两种**形状：

```bash
# 基础指令（作用在两个栈元素上）：
"$BT/dexdump.exe" -d analysis_output/cli/classes.dex | awk '/name          : .run./{f=1} f' | grep -B2 "xor-int/2addr"
#   => sget STACK; ... aget ...; aget ...; xor-int/2addr ...; aput    ← XOR（弹 2 压 1）

# 融合算子（只作用在栈顶 + 一个内联立即数上）—— 同一条 xor 指令：
"$BT/dexdump.exe" -d analysis_output/cli/classes.dex | awk '/name          : .run./{f=1} f' | grep -B3 "aget-byte" | grep -A3 "// #11"
#   => ... aget-byte vN, code, pc; and #255; xor-int/lit8 v8, v8    ← XORK（栈顶 ^= 立即数）
```

**为什么拆不开（关键）**：融合算子用的是**同一条** `xor`/`add`/`mul` 指令 —— 差别只在
「**两个寄存器**」还是「**寄存器 + 内联立即数**」。而那个立即数的取法（`aget-byte code[pc]`
+ `and #255`）**与 `PUSH` 的取立即数一模一样**。所以通用命令能看出「这里是异或」，但
**分不出**「异或的是栈上两个值、还是栈顶一个值异或一个立即数」→ 映射二义性 → **转动态**
（trace handler 入参，直接读那个立即数）。

### L5：内联 VM（本路线可人工解，但逐个方法做）

```bash
unzip -o -q samples/apks/app_l5.apk classes.dex -d analysis_output/cli/
"$BT/dexdump.exe" -d analysis_output/cli/classes.dex | grep -nE "Class descriptor|packed-switch"
#   => 'Lcom/demo/calc/CalcActivity;' / 'Lcom/demo/calc/CalcLogic;'   ← 没有 Core 类
#   => 三个方法（mix/twist/digest）各自含一个 packed-switch
```

**读法**：没有 `Core`，但 `mix/twist/digest` **每个方法体内都有一份相同的 switch**（case 值
都是 `1..7`）。对**每一个**方法重复 L1 的第 ③④ 步即可（opmap 是同一套）。本路线能做，只是
要手工做三遍。

### S1：从 `.rodata` 取字节码，对照比较级联手抄 opmap

#### ① 找解释器 + ② 找字节码

```bash
# ① 找最大函数 + 它的比较级联
"$NDBIN/llvm-objdump.exe" -d samples/native/libcalc_s1_arm64.so | grep -E "subs\s+w8, w8, #0x|b.eq" | head -8
#   => subs w8, w8, #0x1    b.eq 0x1980 <vmr+0xc0>
#   => subs w8, w8, #0x2    b.eq 0x19d0 <vmr+0x110>
#   => subs w8, w8, #0x3    b.eq 0x1a14 <vmr+0x154>
#   => ...

# ② 找字节码：.rodata 只有 36 字节
"$NDBIN/llvm-readelf.exe" -S samples/native/libcalc_s1_arm64.so | grep -E "Name|rodata"
#   => [ 9] .rodata  PROGBITS  ... 000024 ...   ← 0x24 = 36 字节
"$NDBIN/llvm-objdump.exe" -s -j .rodata samples/native/libcalc_s1_arm64.so
#   => 0548 01000101 03021104 020305ff 01000207  ...
#   => 0568 025a04ff
```

#### ③ 反推 opmap（看 case 体的「数据运算」）—— 与 DEX 侧同样重要的一步

```bash
# 看 LOADARG case（0x1980）与 XOR case（0x1a14）
"$NDBIN/llvm-objdump.exe" -d samples/native/libcalc_s1_arm64.so --start-address=0x1980 --stop-address=0x19d0 | tail -14
#   => ldrb  w9, [x9, x10]          ← 读 code[pc]
#   => ldr   w8, [x8, w9, lsl #2]   ← 按它索引 args（带缩放）→ LOADARG
"$NDBIN/llvm-objdump.exe" -d samples/native/libcalc_s1_arm64.so --start-address=0x1a14 --stop-address=0x1a84 | tail -14
#   => eor   w8, w8, w9             ← 两个 w 寄存器运算 = XOR
#   => add   x9, x9, #0x14          ← 带立即数 = 指针簿记（**不是** VM 运算，必须排除！）
#   => b     0x1c00                 ← 回循环尾 = case 体结束
```

**读法（关键陷阱！）**：每个 case 体里都有 `add x9,x9,#0x14`（那是 `&stack[sp++]` 的地址计算），
**如果不区分就会被误判成 ADD**。正确规则：

```text
add/sub/mul/eor wA, wA, wB     ← 两个 **w 寄存器** = 数据运算（ADD/SUB/MUL/XOR）
add        xA, xA, #imm        ← 带立即数 = 指针/下标簿记，跳过
ldrb       wA, [..]            ← 读一字节
ldrb + ldr wA,[.., lsl #2]     ← 读字节再按它索引 = LOADARG
只有 ldrb                      ← = PUSH
带缩放的 ldr，无 ldrb           ← 从栈数组弹元素 = RET
```

| opcode | case 体决定性指令 | 语义 |
|---|---|---|
| `0x1` | `ldrb` + `ldr ...,lsl #2`（索引 args） | **LOADARG** |
| `0x2` | 只有 `ldrb` | **PUSH** |
| `0x3` | `eor w8,w8,w9` | **XOR** |
| `0x4` | `add w8,w8,w9` | **ADD** |
| `0x5` | `mul w8,w8,w9` | **MUL** |
| `0x6` | `sub w8,w8,w9` | **SUB** |
| `0xff` | 带缩放的 `ldr`，无 `ldrb` | **RET** |

#### ④ 解码 + ⑤ 验证

```bash
# 用该表解码 .rodata 的 36 字节
#   01 00 = LOADARG 0 ; 01 01 = LOADARG 1 ; 03 = XOR ; 02 11 = PUSH 0x11 ;
#   04 = ADD ; 02 03 = PUSH 3 ; 05 = MUL ; ff = RET
#   => ((a ^ b) + 0x11) * 3   ✓ 与黄金一致
sha256sum samples/native/libcalc_s1_arm64.so
#   => 2ad21875...   （钉死文件）
```

> **注意 `RET` 的 opcode：SO 是 `0xFF`，DEX 是 `0x07`** —— 两套 VM 各自的约定。

### S2 / S3：分派在运行期才装配 —— 通用命令到此为止，改走动态取真值

> ⚠️ 下面的 `frida` 属**动态工具**；本文件（CLI）平时只讲通用命令，这一节是**例外**，
> 因为 S2/S3 的 opcode→handler 映射**只存在于运行期**，没有任何静态命令能读出来。
> 用本 lab 的 runner 跑（等价于 `frida -U -f com.demo.calc -l <脚本>`）：
>
> ```bash
> # L3（反射分派）：取「本机字节码」+「opcode→slot→handler」表
> python tools/trace_vm.py --package com.demo.calc --script frida/trace_dispatch.js
> #   => [prog] id=0 len=12 hex=010001010302110402030507
> #   => [opmap] opcode=0x01 -> slot=0 -> h0
> #   => [opmap] opcode=0x03 -> slot=2 -> h2      （再读 Core.h2 的字节码 -> XOR）
>
> # S2（运行期装配 handler 表）：读 OPMAP[]/SLOT[] 两个静态表
> python tools/trace_vm.py --package com.demo.calc --script frida/so_vm_trace.js
> #   => [so] opcode=0x01 -> slot=3
> #   => [so] slot=3 -> handler=0x1d54
> ```
>
> 前置：目标须是 **dyn 版**（`samples/apks/app_lN_dbg.apk`，见 `build/build_dyn.sh`）。
> 细节与逐行读法见 `SCRIPT.md`「脱壳 · §D/§H」。

### S2 / S3：本文件**做不到**，如实说明

```bash
# S2：分派是间接调用（blr xN）—— 目标地址运行期才确定
"$NDBIN/llvm-objdump.exe" -d samples/native/libcalc_s2_arm64.so | grep -nE '[[:space:]]blr[[:space:]]'
#   =>  1988: blr x8   /   1b30: blr x8   /   1cd8: blr x8     ← 三处间接调用

# S3：threaded 分派（computed-goto）—— 一堆 br xN 互相跳
"$NDBIN/llvm-objdump.exe" -d samples/native/libcalc_s3_arm64.so | grep -cE '[[:space:]]br[[:space:]]+x'
#   => 12
```

**读法**：S2 的 handler 表在**运行期装配**、S3 的 handler 之间**直接互跳**（没有中心函数）——
通用命令只能定位形态，**拿不到 opcode→handler 映射**。要还原必须：

- 看 `SCRIPT.md` 的 `devirt_so.py`（静态能解的部分它解）；
- 或走动态路线（`frida/so_vm_trace.js`），把运行期的分派目标 trace 出来。

这是本 lab 刻意保留的**诚实边界**，不是文档偷懒。

---


## 验证（通用命令）

```bash
# ① 逐字节比对两段字节码/载荷（一致则 "no differences"）
cmp samples/dex/golden.dex samples/dex/level_L1.dex
#   => （不同，这是预期的 —— 受保护 dex 本来就与黄金 dex 不同）
cmp samples/payloads/level_L2.bin samples/payloads/level_L2.plain.bin
#   => （不同 —— 一个是密文一个是明文）

# ② 用 sha256 记录「我处理的就是这个文件」（可复现的锚点）
sha256sum samples/dex/golden.dex samples/native/libcalc_s1_arm64.so samples/payloads/golden_ops.json
#   => 6acf80fe...  golden.dex
#   => 2ad21875...  libcalc_s1_arm64.so
#   => 69f6e19e...  golden_ops.json
```

**读法**：CLI 路线能给出「文件级一致/不同」，但**给不出「语义是否等价」** —— 语义判据需要
一个参考解释器，那是 `SCRIPT.md` 的 `verify_gen.py`。CLI 路线在这里的职责是：把**还原出的
字节码/操作流**与原文件用 `sha256sum` 钉死，保证「我讨论的就是这一份」。

---

## 决策流程（命令行版）

```text
unzip -l               → 有没有像载荷的 assets 条目？
aapt2 dump badging     → 只是确认业务入口（不用于判定）
dexdump -f / -d        → 方法体是否「只有一句 invoke 到同一个大方法」？(V1)
                       → 有 packed-switch + 回边？(V4)  sparse-switch？(V6)
llvm-readelf -S        → .rodata 是否异常小？(VN1) 节头是否被剥离？(B13)
llvm-objdump -d        → 最大函数是中心比较级联 / 间接调用 / threaded？(VN2)
                       └─ 中心级联 → 手工抄 opmap（本文件可做）
                         间接/threaded → 转动态（SCRIPT.md / frida）
xxd / llvm-objdump -s  → 取到字节码，解码
sha256sum / cmp        → 钉死「讨论的文件」
```

---

## 反复练习

```bash
# 复位（通用命令能做的那部分：清空本路线的产物目录）
rm -rf analysis_output/cli
# 完整的复位（含 samples/ 基线）见 SCRIPT.md 的 tools/reset_lab.py
```

---

## 踩坑（命令行 / 工具侧）

1. **`dexdump` 在本机是 `$BT/dexdump.exe`，不在 PATH 上**。直接写 `dexdump` 会
   「command not found」（Git Bash 找不到 `.exe` 后缀也要靠路径）。要么用全路径，
   要么先把 `$BT` 加进 PATH。**本机 build-tools 37.0.0 里确实有 `dexdump.exe`**（已核实）。
2. **`apktool` 本机没有装**。本文件因此全程用 `unzip` + `aapt2` + `dexdump` 组合，
   没有引用 `apktool d`（写文档时若写它就等于给读者一个跑不了的命令）。
3. **`readelf`/`objdump`/`strings` 这些裸 GNU 名在本机不存在**。NDK 的 binutils 全是
   `llvm-` 前缀：`llvm-readelf` / `llvm-objdump` / `llvm-strings`。写裸名 = 命令跑不了。
4. **`xxd` 看的是 dex 的原始字节，不是「语义」**。`fill-array-data` 的数组在 dex 里是
   紧凑存放的，手工时要跳过 `ident(2) + width(2) + size(4)` 这 8 字节头。
5. **`.rodata` 的地址与文件偏移在这份 SO 里相同**（`Address 000548 / Off 000548`）——
   这是最常见的情形，但**不保证**：`llvm-readelf -S` 会各自列出，别想当然。
6. **`--start-address/--stop-address` 用的是虚拟地址**（`llvm-objdump -d` 显示的地址列），
   不是文件偏移。用错了会 dump 到空区域。
7. **CLI 路线**不**给出「是否 VMP」的量化结论**。`unzip`/`xxd`/`llvm-objdump` 只能给出
   「有 switch」「有间接跳转」「有个小 .rodata」这些**形态证据**；把证据收成判据、并给出
   认知边界，是 `detect_vm.py` 的活（`SCRIPT.md`）。

## 速查

```bash
# 解包 / 看结构
unzip -l samples/apks/app_l2.apk
unzip -o -q samples/apks/app_l1.apk classes.dex -d analysis_output/cli/
"$AAPT2" dump badging samples/apks/app_l1.apk | head -5
"$BT/dexdump.exe" -f analysis_output/cli/classes.dex | head -8
"$BT/dexdump.exe" -d analysis_output/cli/classes.dex | grep "invoke-static.*Core;.run"
"$BT/dexdump.exe" -d analysis_output/cli/classes.dex | grep -nE "packed-switch|sparse-switch"

# 看 ELF / native 分派
"$NDBIN/llvm-readelf.exe" -S samples/native/libcalc_s1_arm64.so | grep -E "Name|rodata|text"
"$NDBIN/llvm-objdump.exe" -s -j .rodata samples/native/libcalc_s1_arm64.so
"$NDBIN/llvm-objdump.exe" -d samples/native/libcalc_s1_arm64.so | grep -E "subs\s+w8, w8, #0x|b.eq"

# 看字节 / 钉死文件
xxd analysis_output/cli/assets/core_a.dat | head -3
sha256sum samples/dex/golden.dex samples/native/libcalc_s1_arm64.so
```
