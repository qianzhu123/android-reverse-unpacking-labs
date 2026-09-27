# SCRIPT.md — 脚本路线：用 detect / solve / dump 工具完成判定与脱壳

> 本文件与 `CLI.md`、`GUI.md` **结构完全平行**（同一套章节骨架一一对应），只讲「脚本怎么做」。
> 所有判定与脱壳都靠 `tools/` 下的 Python 脚本（纯标准库，无外部依赖），不依赖任何大模型。
> 想亲手用 xxd / readelf / sha256sum 逐字节复现每一步，去读 `CLI.md`；
> 想用 010 Editor / IDA / binwalk 看懂每一步，去读 `GUI.md`。
>
> **路线分工**：判定靠 SCRIPT/CLI（可量化、可写进判据），看懂靠 GUI（IDA 出调用链、binwalk 出熵曲线）。
> 阅读顺序建议：先跑「三分钟跑一遍」（知道「能解开」），再看「判定」「脱壳」的原理展开。

---

## 概述与三分钟跑一遍

### 一句话定位

把「360 加固 native 层 = 改版 UPX」的判定与脱壳做成一个**证据可复核**的练习工程：每个结论都落在可量化的结构特征上，每一步都能用脚本或通用命令亲手复现，脱壳结果可与黄金 `.so` **逐字节对照**。

### 为什么自造样本（建模说明）

本机没有真实的 360 加固商业工具，本工程把 360 加固的 **native（.so）层**建模为「**改版 UPX**」——这在历史上是准确的（360 早期 native 保护即基于 UPX 改写）。脱壳机制（运行期解压 → 跳 OEP → 恢复原始代码 → ELF Fix）与真实 360 完全一致；区别只在「被改写的特征」（魔数 `UPX!` → `JG!!`、明文 `360 4.24` 标记）。dex 层加固不在本工程范围。
样本由本机 NDK 从同一份源码编译，加壳前后代码与字符串完全一致；自造样本天然有「循环论证」风险（样本=需求=测试集，检测器在自己设计的样本上必然全对），所以强制配 **B13 双向回归断言**（`check_so_samples.py`，见「反复练习」）。

### 样本清单

| 文件 | 大小 | e_type | `UPX!` | `JG!!` | `upx -t` | 用途 |
|---|---|---|---|---|---|---|
| `samples/so/libtarget_orig.so` | 43888 | ET_DYN(3) | 0 | 0 | FAIL | 原始 SO，黄金对照 |
| `samples/so/libtarget_360.so` | 17916 | ET_EXEC(2) | **4** | 0 | **OK** | 标准 360：可自动解包 |
| `samples/so/libtarget_360_variant.so` | 17916 | ET_EXEC(2) | 0 | **4** | **FAIL** | 变种 360：需手工/动态脱壳 |
| `samples/so/libtarget_stripped.so` | 43888 | ET_DYN(3) | 0 | 0 | — | **B13 正样本**：节头表被剥离，触发「疑似 SO 加壳 / 自实现 Linker」 |
| `samples/so/libtarget_orig_arm64.so` | 45848 | ET_DYN(3) | 0 | 0 | — | ARM64 原始 `.so`（架构对照，检测器自动识别 64 位） |

> **重要前提**：官方 UPX 4.2.4 **不能直接打包 Android 的 `ET_DYN` `.so`**（见「踩坑」）。
> 本工程标准/变种样本以 `linux/arm ET_EXEC` 形式打包——**脱壳机制完全相同**（同样的 Stub、
> 解压缓冲、OEP 概念），仅 `e_type` 字段不同。原始 `.so` 仍是货真价实的 ARM32 Android `ET_DYN`。

### 三分钟跑一遍（脚本版 · 全部样本形态）

```bash
cd 360jiagu

# ① 判定 4 个样本（不看文件名，只看结构特征；一次覆盖 orig/标准/变种/B13 四种形态）
python tools/detect_360.py samples/so/libtarget_orig.so            # => 综合得分 0  · 未见已知加固特征（≠未加壳）
python tools/detect_360.py samples/so/libtarget_360.so             # => 综合得分 16 · 标准 360（UPX! 保留，可自动解包）
python tools/detect_360.py samples/so/libtarget_360_variant.so     # => 综合得分 16 · ★ 变种 360（UPX! 被改写，结构仍在）
python tools/detect_360.py samples/so/libtarget_stripped.so        # => 综合得分 2  · B13：疑似 SO 加壳 / 自实现 Linker（节头被剥离）

# ② 标准 360：直接官方解包（-t 先验证能解，-d 再解出；out.so 应为 43888 字节）
./upx.exe -t samples/so/libtarget_360.so && ./upx.exe -d samples/so/libtarget_360.so -o out.so
#   => Unpacked 1 file.   out.so = 43888 字节

# ③ 变种 360：先实证确认真魔数，再修复解包
python tools/detect_360.py samples/so/libtarget_360_variant.so --verify
#   => b'JG!!' x4 -> upx -t OK   <= 这就是被篡改的真魔数（其余候选是巧合项）
python tools/solve_360.py samples/so/libtarget_360_variant.so unpacked.so --orig samples/so/libtarget_orig.so
#                └ 输入变种样本         └ 输出   └ 黄金样本：解完立刻比对，应报「除 e_type 外差异 0 字节」

# ④ 解法 B 演练（无真机也能跑通内存 dump + ELF Fix）
python tools/simulate_dump.py samples/so/libtarget_orig.so analysis_output/sim_dump.bin
python tools/dump_fix.py analysis_output/sim_dump.bin 0x0 analysis_output/dump_fixed.so --arch arm
#   => wrote analysis_output/dump_fixed.so: base=0x0 size=53408 arch=arm entry=0x0

# ⑤ 回归 + 练完还原，下次重练
python tools/check_so_samples.py                        # => 0 项失败（B13 正/负向 + 既有判定防回归）
python tools/reset_lab.py restore                       # => 还原样本 + 删练习产物 + 清空 analysis_output/
```

**五步分别干什么**：`detect_360.py` 只做**结构体检**（不修改文件），看 F1–F8 哪几条被点亮；
`--verify` 会把每个"疑似被篡改的 4 字节 token"打补丁后跑一次 `upx -t` **实证**（静态候选必有巧合项）；
`solve_360.py` 是解法 A 的完整自动化：定位 token → 全部还原为 `UPX!` → `upx -d` → 锚点校验 → 与黄金样本逐字节比对；
`simulate_dump`/`dump_fix` 是解法 B 的本地演练；`check_so_samples.py` 是双向回归断言（负样本工程的"心跳"）。

---

## 工程结构

```
360jiagu/
├── upx.exe                    UPX 4.2.4（默认用它；可用 UPX=<路径> 覆盖）
├── src/
│   ├── target.c               样本源码（JNI_OnLoad/RegisterNatives/check_license/blob_selfcheck + 锚点）
│   └── policy_inc.h           AUTO-GENERATED 策略表（体积锚点，勿手改）
├── build/
│   ├── locate.sh              ★ 工具链自动探测（NDK / UPX / python，四档优先级）
│   ├── build_android.sh       NDK 编译原始 .so（先跑 gen_policy.py）
│   ├── gen_policy.py          生成 policy_inc.h（提供可压缩体积）
│   └── pack.sh                生成标准 + 变种样本
├── tools/
│   ├── detect_360.py          ★ 结构特征判定（加壳/标准360/变种360，--verify 实证）
│   ├── solve_360.py           解法 A 自动化（特征修复 + upx -d + 锚点校验）
│   ├── simulate_dump.py       生成模拟内存镜像
│   ├── dump_fix.py            解法 B：内存 dump → 重建 ELF
│   ├── make_360_variant.py    由标准包生成变种（UPX! → JG!!）
│   ├── make_stripped_so.py    生成 B13 样本（剥离节头表，模拟自实现 Linker）
│   ├── check_so_samples.py    ★ B13 双向回归断言
│   ├── elf_scan.py            无依赖 ELF 解析 + UPX 指纹
│   ├── upx_probe.py           批量 upx -t/-l/-d
│   ├── reset_lab.py           ★ 备份 / 状态 / 回归
│   ├── anchors.txt            脱壳后应找回的锚点
│   └── upx396.exe             UPX 3.96（对照用）
├── samples/so/                ★ 样本栏（SO 工程的 samples 容器；分析对象一律住这里，不平铺工程根）
│   ├── libtarget_orig.so          【原始 SO】ET_DYN ARM32
│   ├── libtarget_360.so           【标准 360】upx -d 可解
│   ├── libtarget_360_variant.so   【变种 360】upx -d 失败
│   ├── libtarget_stripped.so      【B13 样本】节头剥离
│   └── libtarget_orig_arm64.so    ARM64 原始 .so（对照）
├── pristine/so/               samples/ 的镜像备份 + manifest.json（勿手改）
└── analysis_output/           脚本产出（detect*.txt / solve.txt / sim_dump.bin / dump_fixed.so ...）
```

> 配置全部外置：`build/locate.sh` 四档探测（参数 > 环境变量 > 项目配置 > 自动探测），工程根由脚本自身位置推导，脚本内无写死路径。

---

## 知识点

> 每节固定五件套：是什么 / 怎么看（结构特征+阈值）/ 验证手段 / 实测输出 / 失效边界。有样本标 **[可验证]**，纯理论标 **[知识框架]**。

### 360 native 层 = 改版 UPX **[可验证]**

- **是什么**：360 早期 native 保护基于 UPX 改写——同样的 Stub、解压缓冲、OEP 概念；区别只在被改写的特征（魔数、版本串）。
- **怎么看**：加壳前后结构对照——

```
正常 .so                     360 加固后（改版 UPX）
ELF                           ELF
├── ELF Header                ├── 360/UPX Loader / Stub   ← 入口先到这里
├── Program Headers           ├── 压缩后的原始数据
├── .text / .rodata / .data   └── 相关 ELF 信息（l_info / p_info / b_info）
├── .dynamic
```

- **运行时流程（分析的关键）**：

```
System.loadLibrary → linker → 映射 PT_LOAD → 360 Stub → 运行期解压
   → 原始 Native 代码 → JNI_OnLoad → RegisterNatives → 业务代码
```

- **验证手段**：`detect_360.py` 特征对照（见「判定」）；`solve_360.py` 脱壳后与黄金样本逐字节对照（见「脱壳」）。
- **实测输出**：标准壳综合得分 16，`upx -t` 直接通过；变种壳同分但魔数 `JG!!`，须修复后解包。
- **失效边界**：本建模只覆盖「改特征」这一档；若 360 改了 Stub/控制流/压缩参数，解法 A 失效，须走解法 B（内存 dump）。

### Entry vs OEP **[可验证]**

- **是什么**：Entry Point 是当前 ELF 入口（加壳后指向 Stub）；OEP（Original Entry Point）是原始程序入口。
- **怎么看**：加壳样本 `e_entry` 落在 stub 段内（本例 `0x11684` 落在 `PT_LOAD[1] vaddr=0xE000`），原始样本 `e_entry=0x0`（段首）。
- **验证手段**：`elf_scan.py` 打印 e_entry 与 PT_LOAD 布局，肉眼对照。
- **失效边界**：判断"到达 OEP"必须**综合判断，不靠单一指标**——代码在原始映射区 / 控制流脱离 Stub / 出现正常函数结构 / 出现 `JNI_OnLoad`·`RegisterNatives`。
- **核心警示**：❌ 搜索 `UPX!` → 固定地址找 OEP（对魔改样本不可靠）；✅ 看的是「运行过程中原始代码在哪里被恢复并开始执行」。

### B13：节头表剥离（自实现 Linker 形态） **[可验证]**

- **是什么**：`e_type==ET_DYN(3)` 且 `e_shnum==0` 且存在可执行 PT_LOAD 的形态。正常 NDK `.so` 永远带完整节头；自定义 Linker 自行按 Program Header 装载、不写标准节头。
- **怎么看**：结构体检里 F1 命中 + e_type 仍为 ET_DYN 即触发 B13 专属结论（与"未加壳"严格区分）。
- **验证手段**：`check_so_samples.py` 双向断言——`samples/so/libtarget_stripped.so` 必触发、`samples/so/libtarget_orig.so`（节头完整）必不触发。
- **实测输出**：

```
[B13 · SO 加壳 / 自实现 Linker] e_type=ET_DYN 但 e_shnum=0（节头表被剥离）：自定义 Linker 通常
自己按 Program Header 装载，不写标准节头。这是可靠的强信号——正常 NDK .so 永远带完整节头，不会误伤。
判定结果: 疑似 SO 加壳 / 自实现 Linker（ELF 节头被剥离）— 需人工进 ELF 层确认
```

- **失效边界**：B13 是"疑似"信号，不得写确定结论；`samples/so/libtarget_stripped.so` **没有任何 UPX 特征**，仅靠这一条信号被检出——证明 B13 能抓到 UPX 类壳抓不到的自定义 Linker。

### 认知边界：静态不可定性的方案 **[知识框架]**

「未见已知特征」**绝不等于「未加固」**。以下场景仍须动态 trace 才能定性：

1. **SO VMP** —— VMP 解释器在 SO 里只是普通大函数，ELF 结构正常则静态不可确认；
2. **不走「汇聚调用」形态的自定义 VMP** —— 普通启发式对其失效；
3. **精巧的字符串加密** —— 字符串根本不在常量池里，无结构性异常。

**可跑的检查**：对任何一个"判为未见已知特征"的文件，重跑 `python tools/detect_360.py <file>` 看结尾的认知边界输出——工具显式列出这三条不覆盖方案；`detect_360.py` 的兜底永远写「未见已知加固特征（≠未加壳）」，绝不写"未加固/没问题"。

---

## 判定

### 特征对照表（本工程实跑）

| 特征 | 未加壳 orig | 标准 360 | 变种 360 | B13 stripped | 原理 |
|---|---|---|---|---|---|
| 节区头 `e_shnum` | 24 | **0** | **0** | **0** | 加壳/剥节头，IDA 看不到 `.text/.rodata` |
| 整文件熵 | 5.011 | **7.598** | **7.598** | 5.010 | 正常代码 4~6.5；>7.0 = 压缩/加密 |
| 大解压缓冲段 | 无 | **0x1000→0xD0A0（13.0x）** | **0x1000→0xD0A0（13.0x）** | 无 | UPX0：文件近空、内存很大；要求 memsz≥32KB 排除 `.bss` |
| `e_entry` 位置 | 0x0（段首） | **0x11684（stub 段内）** | **0x11684（stub 段内）** | 0x0 | 入口先跑解压代码 |
| 总 memsz / 文件大小 | 1.03x | **3.90x** | **3.90x** | 1.03x | 运行期解压出远多于文件的内容 |
| `UPX!` 魔数 | 0 | **4** | 0 | 0 | 变种把魔数改写掉 |
| 尾部 `sz_unc` 字段 | 0 | **43888** | **43888** | 0 | UPX 尾部记录解压后大小，远大于文件 |
| 明文 `360` 标记 | payload（脱壳后） | **文件内 `360 4.24`** | **文件内 `360 4.24`** | 无 | 360 标记（lab 注入，仅用于命名） |

### 实跑输出（节选）

标准 360（`python tools/detect_360.py samples/so/libtarget_360.so`）：

```
目标: samples/so/libtarget_360.so   (17916 bytes)
  架构: 32-bit  e_type=2  e_entry=0x11684
  [命中] F1 节区头数量         e_shnum=0                      (+2)
  [命中] F2 整文件熵          7.598 bits/byte                (+2)
  [命中] F3 大解压缓冲段        PT_LOAD[0] filesz=0x1000 -> memsz=0xD0A0 (13.0x)  (+3)
  [命中] F4 入口位置          e_entry=0x11684 落在 PT_LOAD[1] (vaddr=0xE000, size=0x40A2)  (+2)
  [命中] F5 内存/文件体积比      3.90x (memsz=0x11142)        (+2)
  [命中] F6 'UPX!' 魔数     出现 4 次                         (+3)
  [命中] F7 尾部 sz_unc 字段  0xAB70 = 43888                  (+2)
综合得分: 16
判定结果: 标准 360 加固（改版 UPX，UPX! 保留，可自动解包）
```

变种 360（`python tools/detect_360.py samples/so/libtarget_360_variant.so`）：

```
目标: samples/so/libtarget_360_variant.so   (17916 bytes)
  [命中] F1 节区头数量         e_shnum=0                      (+2)
  [命中] F2 整文件熵          7.598 bits/byte                (+2)
  [命中] F3 大解压缓冲段        PT_LOAD[0] filesz=0x1000 -> memsz=0xD0A0 (13.0x)  (+3)
  [命中] F4 入口位置          e_entry=0x11684 落在 PT_LOAD[1] (vaddr=0xE000, size=0x40A2)  (+2)
  [命中] F5 内存/文件体积比      3.90x (memsz=0x11142)        (+2)
  [  - ] F6 'UPX!' 魔数     出现 0 次                         (+0)
  [命中] F7 尾部 sz_unc 字段  0xAB70 = 43888                  (+2)
  [命中] F8 疑似被篡改魔数       候选 b'JG!!' 出现 4 次 @ ['0x98', '0x3cfb', '0x45cf', '0x45d8']  (+3)
综合得分: 16
判定结果: ★ 变种 360 加固（UPX! 被 360 改写，结构仍在）
```

B13 样本（`python tools/detect_360.py samples/so/libtarget_stripped.so`，关键行）：

```
  [命中] F1 节区头数量         e_shnum=0
  [  - ] F2 整文件熵          5.010 bits/byte        ← 无压缩，熵正常
[B13 · SO 加壳 / 自实现 Linker] e_type=ET_DYN 但 e_shnum=0（节头表被剥离）
综合得分: 2
判定结果: 疑似 SO 加壳 / 自实现 Linker（ELF 节头被剥离）— 需人工进 ELF 层确认
```

### 判定逻辑与阈值设计踩过的坑

判定逻辑（在 `tools/detect_360.py` 的 `detect()` 内）：结构特征 F1–F7 打分；**`UPX!` 在 + 总分≥6 → 标准壳**；**`UPX!` 不在 + 总分≥6 + 有被改写魔数候选 → 变种**。「是否 360」由两路明文标记确认（变种魔数 `JG!!` / `360jiagu` / `360 4.24`），**仅用于命名**，不改变「是否加壳」的判定（避免被 payload 里的 360 标记误判成「已加壳」）。

| 坑 | 现象 | 修正 |
|---|---|---|
| 解压缓冲段不加下限 | 普通 `.bss`（0xEC→0x9E0）被误判成 UPX 解压区 | 要求 `memsz ≥ 32KB` |
| 魔数候选排除「4 字节全同」 | 真实占位符被自己误杀 | 只排除 `00`/`FF` 纯填充 |
| 只用静态候选 | 出现 `\x00\x00p\xab` 这类巧合项 | 必须 `--verify` 打补丁跑 `upx -t` 实证 |
| 原始 .so 太小 | UPX 报 `NotCompressibleException` | 加策略表体积（见「踩坑」），让 UPX 有净收益 |

`--verify` 实证（实跑输出）：

```
[实证验证] 逐个候选打补丁后用 upx -t 检验:  (upx = upx.exe)
   b'JG!!' x4   -> upx -t OK   <= 这就是被篡改的真魔数
   b'\x00\x00p\xab' x2   -> upx -t FAIL
   b'\x00p\xab\x00' x2   -> upx -t FAIL
   b'\x00\x00\x00\t' x2   -> upx -t FAIL
   b'\x00\x00\t\xff' x2   -> upx -t FAIL
```

---

## 脱壳

### 解法 A：solve_360.py（变种只抹特征，Stub 与控制流未动）

```bash
python tools/solve_360.py samples/so/libtarget_360_variant.so unpacked.so --orig samples/so/libtarget_orig.so
```

实跑输出（节选）：

```
[*] 样本: samples/so/libtarget_360_variant.so (17916 bytes)
[*] 现有 'UPX!' 数量: 0
[*] 使用的 upx: upx.exe
    候选 token b'\x00\x00\x00\x00' x37 -> upx -t FAIL
    候选 token b'JG!!' x4 -> upx -t OK
[+] 确定被篡改的 token: b'JG!!' -> 还原为 'UPX!'（共 4 处）
[+] 解包成功: unpacked.so (43888 bytes)

[*] 校验：脱壳后应找回的锚点
    360jiagu_lab_payload_marker_v1 OK 找到
    JiaguLab-2026-SECRET-KEY       OK 找到
    flag{jiagu_unpacking_is_fun}   OK 找到
    com/aegis/NativeLib            OK 找到
    getFlag                        OK 找到
    JNI_OnLoad                     OK 找到
    check_license                  OK 找到
    blob_selfcheck                 OK 找到

[*] 与原始 SO 对比: samples/so/libtarget_orig.so (43888 bytes)
    大小: 43888 vs 43888  一致
    除 e_type 外差异字节数: 0  => 内容一致，脱壳成功
```

**逐行判读**：脚本扫描 4 字节重复 token → 逐个打补丁用 `upx -t` 实证 → `JG!!` 通过即真魔数 → 全部还原为 `UPX!` → `upx -d` 解出 43888 字节 → 8 个锚点全部找回 → 与原始 `.so` **除 `e_type` 外 0 字节差异**。

**⚠️ 必须 4 处全改（本题核心）**：4 处偏移是 `0x98 / 0x3cfb / 0x45cf / 0x45d8`——只改任意单独一处 `upx -t` 必 FAIL（实测 `NotPackedException: not packed by UPX`），4 处全改才 OK。原因：UPX/360 校验和覆盖所有内嵌魔数。手动逐字节复现见 `CLI.md`「脱壳」，010 Editor 操作见 `GUI.md`「脱壳」。

**何时失效**：若 4 处全改后 `upx -t` 仍失败 → 说明不止改了特征（Stub/控制流/压缩参数被改）→ **转解法 B**。

### 解法 B：内存 Dump + ELF Fix（通用主力路线）

完全不依赖 360 的特征与校验和。思路：`让程序跑起来 → 等 Stub 解压完 → dump 进程内存 → 重建 ELF → 载入 IDA`。

真机 Frida 步骤：把 `.so` 放进 APK 的 `lib/armeabi-v7a/`，安装运行，Frida 附加：

```javascript
// 等模块加载完成后 dump（此时内存里已是解压后的原始代码）
const lib = "samples/so/libtarget_360_variant.so";
const t = setInterval(() => {
  try {
    const m = Process.getModuleByName(lib);
    clearInterval(t);
    m.enumerateRanges('r--').forEach((r, i) => {
      const f = new File(`/data/local/tmp/dump_${i}.bin`, 'wb');
      f.write(r.base.readByteArray(r.size)); f.close();
    });
    console.log("[+] dumped, base=" + m.base);
  } catch (e) {}
}, 200);
```

要点：**加载完成后**才是解压后的代码，别在 `JNI_OnLoad` 之前 dump；最稳时机是 hook `libart.so` 的 `RegisterNatives` 被调用后；导出表没 `JNI_OnLoad`（被壳隐藏）时，改用 linker 映射完 PT_LOAD / 执行 init_array 时 dump。

本工程演练（无真机也能跑通）：

```bash
python tools/simulate_dump.py samples/so/libtarget_orig.so analysis_output/sim_dump.bin
python tools/dump_fix.py analysis_output/sim_dump.bin 0x0 analysis_output/dump_fixed.so --arch arm
```

实跑输出：

```
[+] simulated dump -> analysis_output/sim_dump.bin  base=0x0 size=53408 (from 4 PT_LOAD, 32-bit)
[+] wrote analysis_output/dump_fixed.so: base=0x0 size=53408 arch=arm entry=0x0
```

锚点复核：`dump_fixed.so` 内 `360jiagu` / `JiaguLab` / `getFlag` / `JNI_OnLoad` 均可搜到（`check_license`/`blob_selfcheck` 两个字符串只存在于静态符号表 `.strtab`，不进任何 PT_LOAD，运行时内存里本来就没有——这本身就是"dump 拿到的是运行态"的旁证）。
真机用法：`dump_fix.py <dump.bin> <模块基址> <out.so> --arch arm [--entry-rva HEX]`。

**OEP 定位**：Stub 解压完跳回原始入口。观察 PC 何时离开 stub 段（本例 stub 在 `vaddr=0xE000`），进入第一个 PT_LOAD（`0x0` 起）。实用替代：在 `RegisterNatives` / `JNI_OnLoad` 下断或 hook——被调用即已在真实代码里。

**Dump ≠ 完成脱壳**：内存里的 ELF 缺节区表/符号，需 ELF Fix（重建 Section Header）。`dump_fix.py` 是最小可用版（单 PT_LOAD + `.text`）；真实对抗需补 `.dynamic`/`.dynsym`/重定位 → 用 `elf-dump-fix` / `elf-dump-fix-x` 或手工补全。

---

## 验证

三条判据（每条都实跑过）：

1. **体积恢复**：`unpacked.so = 43888` == `samples/so/libtarget_orig.so = 43888`
2. **锚点找回**：`tools/anchors.txt` 的 8 个锚点全部可见（solve 输出逐条 `OK 找到`）
3. **字节一致**：与 `samples/so/libtarget_orig.so` 除偏移 16 的 `e_type` 外 **0 字节差异**（解出 ET_EXEC=2，原始 ET_DYN=3；代码内容完全一致）。`cmp -l` 实测全文件仅 1 处差异：

```
$ cmp -l samples/so/libtarget_orig.so unpacked.so
   17   3   2        ← 1-based 第 17 字节 = 0 偏移 16 的 e_type：03(ET_DYN) vs 02(ET_EXEC)
```

IDA 打开脱壳产物应看到调用链：`JNI_OnLoad → RegisterNatives → getFlag → check_license` + 锚点字符串（操作见 `GUI.md`「验证」）。

---

## 决策流程

```
拿到 .so
 ├─ upx -t 通过 ─────────────► 直接 upx -d（标准 360，不必手脱）
 └─ upx -t 失败
      ├─ 结构仍像 360/UPX（无节区表/高熵/大解压缓冲/入口在 stub）
      │    └─► 解法 A：还原全部魔数 → upx -d
      │         失败 → 说明 Stub/校验被改，转下一条
      └─ 完全不像 / 解法 A 无效 / B13（节头被剥离）
           └─► 解法 B：Frida dump → dump_fix.py → IDA
```

---

## 反复练习

原始样本已备份到 `pristine/`（含 sha256 清单）：

```bash
python tools/reset_lab.py status     # 环境是否被练脏
python tools/reset_lab.py restore    # 还原 4 个样本 + 删练习产物 + 清空 analysis_output/
python tools/reset_lab.py backup     # 改过源码后刷新基线
```

`status` 实跑（干净态）：

```
[*] 练习根目录: D:\code\android\reverse\360jiagu
样本状态对比:
  [一致]   so/libtarget_360.so                         17916 bytes
  [一致]   so/libtarget_360_variant.so                 17916 bytes
  [一致]   so/libtarget_orig.so                        43888 bytes
  [一致]   so/libtarget_orig_arm64.so                  45848 bytes
  [一致]   so/libtarget_stripped.so                    43888 bytes

练习产物: 无（环境干净）
输出目录 analysis_output/: 空

当前环境: 干净，可直接开始练习
```

建议每轮从 `restore` 开始：

1. `detect_360.py` 判定 4 个样本（不看文件名）
2. hexdump 自己找出 4 处 `JG!!`（`CLI.md`「判定」）
3. 十六进制编辑器手改 4 处 → `upx -t` → `upx -d`（`GUI.md`「脱壳」）
4. 三条判据验证
5. 进阶：故意只改 1~3 处，体会校验和
6. 进阶：跑通解法 B 的 dump + ELF Fix

**回归断言（负样本工程的心跳，双向都要过）**：

```bash
python tools/check_so_samples.py
```

实跑输出：

```
[PASS] samples/so/libtarget_stripped.so   b13=True  -> 疑似 SO 加壳 / 自实现 Linker（ELF 节头被剥离）— 需人工进 ELF 层确认
[PASS] samples/so/libtarget_orig.so       b13=False -> 未见已知加固特征（≠未加壳）
[PASS] samples/so/libtarget_360.so           仍为加壳判定: 标准 360 加固（改版 UPX，UPX! 保留，可自动解包）
[PASS] samples/so/libtarget_360_variant.so   仍为加壳判定: ★ 变种 360 加固（UPX! 被 360 改写，结构仍在）

0 项失败
```

三条断言的含义：正向——剥节头样本必触发 B13；负向——原始 NDK `.so`（节头完整）必不触发；防回归——既有的 360 判定不得被 B13 改造破坏。

---

## 踩坑与速查

### 踩坑（工具链 / 环境 / 阈值 / 误判 / 失效边界）

1. **官方 UPX 不能直接打包 Android `ET_DYN` `.so`**：UPX 4.2.4 打 ET_DYN 报 `NotCompressibleException`；改 `e_type=2` 后打包成功 43888→17916（40.82%）；打包后把 e_type 改回 DYN 则 `upx -t` 报 `ElfXX_Ehdr corrupted`。本工程标准/变种样本因此是 `ET_EXEC`，脱壳机制与真实 ET_DYN 完全一致。
2. **原始 .so 太小 → UPX 拒绝压缩**：UPX 自带 ~3.5KB stub，原始 `.so` 太小时「压缩后 + stub」≥ 原文件触发 `NotCompressibleException`。解决：`build/gen_policy.py` 生成 `src/policy_inc.h`（1000 条策略/签名表，约 45KB 文本），让原始 `.so` 达到 ~44KB 稳定打包。`policy_inc.h` 同时是脱壳后的真实数据锚点。
3. **校验和覆盖全部内嵌魔数**：只改一处必失败（见「脱壳」）。变种 360 的 `JG!!` 出现在 4 处（stub 2 + 尾部 2），必须全部还原。
4. **静态候选必有巧合项**：`\x00\x00p\xab` 等巧合 token 必须用 `--verify` 实证排除。
5. **360 明文标记可安全注入**：把 stub 版本串 `UPX 4.24` 改为 `360 4.24`（同长度 8 字节）后 `upx -t` 仍通过。注意**尾部追加任何字节都会破坏 UPX**（`upx -t` 报 `not packed by UPX`），故不能用「尾部追加标记」。这是本 lab 的建模标记，真实 360 未必有此串。
6. **尾部 `sz_unc` 字段不要当唯一判据**：它只是 UPX 尾部结构里的一个 4 字节值，真实样本里正常文件也可能在尾部碰巧出现大数值——所以它只是 F7（+2 分），须与其他特征互相印证。
7. **中文乱码**：Windows 控制台跑本仓 Python 脚本输出中文乱码时设 `PYTHONIOENCODING=utf-8`（PowerShell `$env:PYTHONIOENCODING='utf-8'`）。
8. **本机只有 `python` 无 `python3`**（全局约定）。

### 速查

```bash
# 判定
python tools/detect_360.py <file> [--brief] [--verify]
python tools/elf_scan.py   samples/so/libtarget_orig.so samples/so/libtarget_360.so samples/so/libtarget_360_variant.so
python tools/upx_probe.py  samples/so/libtarget_orig.so samples/so/libtarget_360.so samples/so/libtarget_360_variant.so

# 解法 A
python tools/solve_360.py samples/so/libtarget_360_variant.so unpacked.so --orig samples/so/libtarget_orig.so

# 解法 B
python tools/simulate_dump.py samples/so/libtarget_orig.so analysis_output/sim_dump.bin
python tools/dump_fix.py analysis_output/sim_dump.bin 0x0 analysis_output/dump_fixed.so --arch arm

# 重新生成样本
bash build/build_android.sh    # NDK 编译原始 .so（含 gen_policy.py 生成策略表）
bash build/pack.sh             # 生成标准 + 变种
python tools/make_stripped_so.py samples/so/libtarget_orig.so samples/so/libtarget_stripped.so   # 生成 B13 样本

# 回归
python tools/check_so_samples.py    # B13 双向断言（0 失败才算过）
python tools/reset_lab.py restore
```

**外部工具怎么定位（都不写死路径）**——见 `build/locate.sh`：

| 工具 | 优先级（从高到低） |
|---|---|
| UPX | `--upx <路径>` > 环境变量 `UPX` > 工程根 `upx.exe` > PATH > `tools/upx396.exe` |
| NDK | 环境变量 `NDK_ROOT` / `ANDROID_NDK_HOME` > `<SDK>/ndk/<最新版>` |
| python | 环境变量 `PYTHON` > PATH 里的 `python` |

工程根自带的 `upx.exe` 优先于 PATH：本工程所有实测数值都基于它，换版本可能复现不出同样样本。要换版本请显式 `UPX=<路径>`，别靠 PATH 偷偷切。任何一档都拿不到时脚本会直接报错，并告诉你该配哪一项。

---

## 一句话记住

> **判断 360 不靠字符串，靠「运行时原始代码在哪里恢复并开始执行」。**
> 标准 360 用 `upx -d`；只抹魔数用**特征修复（必须全部还原）**；Stub 被改就**内存 dump + ELF Fix**。
