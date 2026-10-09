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
# S2：运行期装配 -> 间接调用；S3：threaded -> 一堆 br xN
"$NDBIN/llvm-objdump.exe" -d samples/native/libcalc_s2_arm64.so | grep -c "blr\s*x"
"$NDBIN/llvm-objdump.exe" -d samples/native/libcalc_s3_arm64.so | grep -cE "^\s+[0-9a-f]+:\s+[0-9a-f]{8}\s+br\s+x"
#   => s2 有 blr x8（间接）；s3 有 7 条 br xN（computed-goto）
```

**读法（VN2）**：`blr xN` = 「跳到运行期才算出来的地址」（函数指针表）；连续的 `br xN` =
「处理器之间直接跳」（threaded dispatch）。两者都说明**分派不是中心 switch**，静态难解。

---

## 脱壳：手工取字节码、手工还原

### L1：从 `fill-array-data` 取字节码，对照 switch 手抄 opmap

```bash
# ① 在解释器里找 byte[] 常量的来源：fill-array-data
"$BT/dexdump.exe" -d analysis_output/cli/classes.dex | grep -nE "fill-array-data|packed-switch-data" 
#   => 288: fill-array-data v0, 00000022   ← P_MIX
#   => 292: fill-array-data v0, 0000002c   ← P_TWIST
#   => 296: fill-array-data v0, 00000036   ← P_DIGEST
#   => 437: packed-switch-data (18 units)

# ② 把 fill-array-data 之后的原始字节 dump 出来（这是 dex 的字节，不是源码）
xxd -s 0x6b0 -l 48 analysis_output/cli/classes.dex
#   => 相邻区域能看到 0c 09 0f 01 00 01 01 03 02 11 04  ... （各段前面还有 width/size 头）
```

**读法**：`fill-array-data` 把静态 `byte[]` 从 dex 的数据区拷进数组。**头是
`u2 ident(0x0300) | u2 element_width | u4 size`**，随后才是数据。手工时先跳过 8 字节头，
再读 `size × width` 字节 —— 得到的就是 `P_MIX = 01 00 01 01 03 02 11 04 02 03 05 07`。

```bash
# ③ 抄 switch 映射：packed-switch-data 的 first_key + size 给出 case 集合
"$BT/dexdump.exe" -d analysis_output/cli/classes.dex | sed -n '350,440p' | grep -E "packed-switch|cmp-|goto|invoke|return"
```

**读法**：逐个 `case` 体能看出语义 ——
`case 0x01` 里是「读 args 的一个元素入栈」= **LOADARG**；
`case 0x02` 里是「把下一字节当立即数入栈」= **PUSH**；
`case 0x03` 里是 `xor-int` = **XOR**；`0x04`=`add-int`；`0x05`=`mul-int`；`0x06`=`sub-int`；
`case 0x07` 是 `return` = **RET**。

```bash
# ④ 用还原出的 opmap，手工解码字节码
#   01 00 = LOADARG 0 ; 01 01 = LOADARG 1 ; 03 = XOR ; 02 11 = PUSH 0x11 ;
#   04 = ADD ; 02 03 = PUSH 3 ; 05 = MUL ; 07 = RET
#   => ((a ^ b) + 0x11) * 3
```

**这就是 P_MIX 的语义**。用同样办法解 `P_TWIST`（`01 00 02 07 05 02 05 06 07` →
`(a*7)-5`）与 `P_DIGEST`。

### L2：先解密 assets 载荷，再按 L1 的方法解

```bash
# ① 取载荷并看它是不是密文
unzip -o -q samples/apks/app_l2.apk assets/core_a.dat -d analysis_output/cli/
xxd analysis_output/cli/assets/core_a.dat | head -3
#   => d56a cce5 6c0a 42fb 816c 6cee cad0 49f9 ...
#   => d961 c4e1 6e0e 45ff ...
```

```bash
# ② 在 dex 里找那把 16 字节 key（它是 Core 的一个静态 byte[] 常量）
"$BT/dexdump.exe" -d analysis_output/cli/classes.dex 2>/dev/null | grep -A2 "KEY" | head
#   （或直接从源码 build/gen/level_L2/com/demo/calc/Core.java 里看到 KEY 数组）
```

```bash
# ③ 手工 XOR：第一个字节 d5 ^ d9 = 0x0c = 12 —— 正好是 P_MIX 的长度
python -c "print(0xd5 ^ 0xd9)"     # （这里只是算一个数，不是调用本 lab 的脚本）
#   => 12
```

**读法**：解出来的明文是 `[len_mix, len_twist, len_digest] + 三段字节码`。得到字节码后，
按 L1 的方法解 —— 用 `xxd` 看不到语义，语义靠解释器的 case 体。

### S1：从 `.rodata` 取字节码，对照比较级联手抄 opmap

```bash
# ① 取 .rodata（上面已 dump）：01 00 01 01 03 02 11 04 02 03 05 ff ...
# ② 看比较级联（上面已 dump）：subs w8,w8,#0x1 -> b.eq 0x1980 ; #0x2 -> 0x19d0 ; ...
# ③ 逐个 case 体看它做了什么数据运算
"$NDBIN/llvm-objdump.exe" -d samples/native/libcalc_s1_arm64.so --start-address=0x1980 --stop-address=0x19d0
#   => 里面对 w8/w9 做 eor / add / mul / sub ... 对应 XOR / ADD / MUL / SUB
```

**读法**：`case 0x1` 体里有 `ldrb`（读一字节）+ 带缩放的 `ldr`（按它索引 args）→ **LOADARG**；
`case 0x2` 只有 `ldrb` → **PUSH**；`case 0x3` 有 `eor` → **XOR**；`#0x4` 有 `add` → **ADD**；
`#0x5` 有 `mul` → **MUL**；`#0x6` 有 `sub` → **SUB**；`#0xff` 从栈数组弹元素 → **RET**。

```bash
# ④ 用该表解码 .rodata 字节码（与 L1 同样的流程）
#   01 00 = LOADARG 0 ; 01 01 = LOADARG 1 ; 03 = XOR ; 02 11 = PUSH 0x11 ;
#   04 = ADD ; 02 03 = PUSH 3 ; 05 = MUL ; ff = RET
#   => ((a ^ b) + 0x11) * 3
```

### L3 / S2 / S3：本文件**做不到**，如实说明

L3 没有 `switch`（用反射 `Method[]` invoke），S2/S3 的分派在运行期才装配 ——
**通用命令只能定位到解释器，拿不到 opcode→handler 的映射**。要还原必须：

- 看 `SCRIPT.md` 的 `devirt_dex.py` / `devirt_so.py`（静态能解的部分它解）；
- 或走动态路线（`frida/trace_dispatch.js` / `so_vm_trace.js`），把运行期的分派目标 trace 出来。

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
