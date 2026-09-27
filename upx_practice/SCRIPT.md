# SCRIPT.md — 脚本路线：用 detect / solve / dump 工具完成判定与脱壳

> 本文件与 `CLI.md`、`GUI.md` **结构完全平行**（同一套章节骨架一一对应），只讲「脚本怎么做」。
> 所有判定与脱壳都靠 `tools/` 下的 Python 脚本（纯标准库，无外部依赖），不依赖任何大模型。
> 想亲手用 xxd / llvm-readelf / sha256sum 逐字节复现每一步，去读 `CLI.md`；
> 想用 010 Editor / IDA / binwalk 看懂每一步，去读 `GUI.md`。
>
> **路线分工**：判定靠 SCRIPT/CLI（可量化、可写进判据），看懂靠 GUI（IDA 出调用链、binwalk 出熵曲线）。
> 阅读顺序建议：先跑「判定」拿到结论（知道「是什么壳」），再看「脱壳」的手法展开。

---

## 概述

### 一句话定位

把「UPX 壳与其变种」的判定与脱壳做成一个**证据可复核**的练习工程：每个结论都落在可量化的结构特征上，每一步都能用脚本或通用命令亲手复现，脱壳结果可与黄金 `.so` **逐字节对照**。

### 为什么自造样本（建模说明）

UPX 是开源壳，但其**变种**（改 Stub / 抹特征 / 改控制流）是真实对抗的常态。本工程从同一份源码用本机 NDK 编译原始 `.so`，官方 UPX 4.2.4 打包成标准壳，再用 `make_variant.py` 把 `UPX!` 魔数整体替换成 `XXXX` 得到变种——加壳前后代码与字符串完全一致，脱壳结果可与黄金 `.so` 逐字节对照。
自造样本天然有「循环论证」风险（样本=需求=测试集，检测器在自己设计的样本上必然全对），所以强制配 **B13 双向回归断言**（`check_so_samples.py`，见「反复练习」）。

### 样本清单

| 文件 | 大小 | e_type | `UPX!` | `XXXX` | `upx -t` | 用途 |
|---|---|---|---|---|---|---|
| `samples/so/libtarget_orig.so` | 70012 | ET_DYN(3) | 0 | 0 | FAIL | 原始 SO，黄金对照 |
| `samples/so/libtarget_upx.so` | 5348 | ET_EXEC(2) | **4** | 0 | **OK** | 标准 UPX：可自动解包 |
| `samples/so/libtarget_upx_variant.so` | 5348 | ET_EXEC(2) | 0 | **4** | **FAIL** | 变种 UPX：需手工/动态脱壳 |
| `samples/so/libtarget_stripped.so` | 70012 | ET_DYN(3) | 0 | 0 | — | **B13 正样本**：节头表被剥离，触发「疑似 SO 加壳 / 自实现 Linker」 |
| `samples/so/libtarget_orig_arm64.so` | 71848 | ET_DYN(3) | 0 | 0 | — | ARM64 原始 `.so`（架构对照，检测器自动识别 64 位） |

> **重要前提**：官方 UPX 4.2.4 **不能直接打包 Android 的 `ET_DYN` `.so`**（见「踩坑」）。
> 本工程标准/变种样本以 `linux/arm ET_EXEC` 形式打包——**脱壳机制完全相同**（同样的 Stub、
> UPX0 段、OEP 概念），仅 `e_type` 字段不同。原始 `.so` 仍是货真价实的 ARM32 Android `ET_DYN`。

---

## 工程结构

```
upx_practice/
├── upx.exe                    UPX 4.2.4（默认用它；可用 UPX=<路径> 覆盖）
├── src/
│   └── target.c               样本源码（JNI_OnLoad/RegisterNatives/check_license/blob_selfcheck + 锚点）
├── build/
│   ├── locate.sh              ★ 工具链自动探测（NDK / UPX / python，四档优先级）
│   ├── build_android.sh       NDK 编译原始 .so
│   └── pack.sh                生成标准 + 变种样本
├── tools/
│   ├── detect_packer.py       ★ 结构特征判定（加壳/标准UPX/变种，--verify 实证）
│   ├── solve_variant.py       解法 A 自动化（特征修复 + upx -d + 锚点校验）
│   ├── simulate_dump.py       生成模拟内存镜像
│   ├── dump_fix.py            解法 B：内存 dump → 重建 ELF
│   ├── make_variant.py        由标准包生成变种（UPX! → XXXX）
│   ├── make_stripped_so.py    生成 B13 正样本（剥节头表：自实现 Linker 形态）
│   ├── check_so_samples.py    ★ 双向回归（B13 正/负样本 + 防 UPX 判定回归）
│   ├── elf_scan.py            无依赖 ELF 解析 + UPX 指纹
│   ├── upx_probe.py           批量 upx -t/-l/-d
│   ├── reset_lab.py           ★ 备份 / 状态 / 回归
│   ├── anchors.txt            脱壳后应找回的锚点
│   └── upx396.exe             UPX 3.96（带 --android-shlib，对照用）
├── samples/so/                ★ 样本栏（SO 工程的 samples 容器；分析对象一律住这里，不平铺工程根）
│   ├── libtarget_orig.so          【原始 SO】ET_DYN ARM32
│   ├── libtarget_upx.so           【标准 UPX】upx -d 可解
│   ├── libtarget_upx_variant.so   【变种 UPX】upx -d 失败
│   ├── libtarget_stripped.so      【B13 正样本】节头表剥离
│   └── libtarget_orig_arm64.so    ARM64 原始 .so（对照）
├── pristine/so/               samples/ 的镜像备份 + manifest.json（勿手改）
└── analysis_output/           脚本产出（detect*.txt / solve.txt / sim_dump.bin / dump_fixed.so ...）
```

> 配置全部外置：`build/locate.sh` 四档探测（参数 > 环境变量 > 项目配置 > 自动探测），工程根由脚本自身位置推导，脚本内无写死路径。

---

## 知识点

> 每节固定五件套：是什么 / 怎么看（结构特征+阈值）/ 验证手段 / 实测输出 / 失效边界。有样本标 **[可验证]**，纯理论标 **[知识框架]**。

### UPX 与变种 **[可验证]**

- **是什么**：UPX 是开源压缩壳——运行期由 Stub 解压原始程序并跳 OEP 继续执行。**变种**不是官方壳，而是以 UPX 为基础修改 Stub / 文件结构 / 特征 / 流程后的样本：

```
标准 UPX → 修改 Stub → 删除明显特征 → 加入额外代码 → 改变控制流 → 加反调试 → 变种
```

- **怎么看**：加壳前后结构对照——

```
正常 .so                     UPX 加壳后
ELF                           ELF
├── ELF Header                ├── UPX Loader / Stub   ← 入口先到这里
├── Program Headers           ├── 压缩后的原始数据
├── .text / .rodata / .data   └── 相关 ELF 信息（l_info / p_info / b_info）
├── .dynamic
```

- **运行时流程（分析的关键）**：

```
System.loadLibrary → linker → 映射 PT_LOAD → UPX Stub → 运行时解压
   → 原始 Native 代码 → JNI_OnLoad → RegisterNatives → 业务代码
```

- **验证手段**：`detect_packer.py` 特征对照（见「判定」）；`solve_variant.py` 脱壳后与黄金样本逐字节对照（见「脱壳」）。
- **实测输出**：标准壳综合得分 16、`upx -t` 直接通过；变种壳同分但魔数被替换成 `XXXX`，须修复后解包。
- **失效边界**：本工程的变种只做「抹特征」（`UPX!`→`XXXX`）这一档；若 Stub/控制流/压缩参数也被改，解法 A 失效，须走解法 B（内存 dump）。

### Entry vs OEP **[可验证]**

- **是什么**：Entry Point 是当前 ELF 入口（加壳后指向 Stub）；OEP（Original Entry Point）是原始程序入口。
- **怎么看**：加壳样本 `e_entry` 落在 stub 段内（本例 `0x1358C` 落在 `PT_LOAD[1] vaddr=0x13000`），原始样本 `e_entry=0x0`（段首）。
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

**可跑的检查**：对任何一个"判为未见已知特征"的文件，重跑 `python tools/detect_packer.py <file>` 看结尾的认知边界输出——工具显式列出这三条不覆盖方案；`detect_packer.py` 的兜底永远写「未见已知加固特征（≠未加壳）」，绝不写"未加固/没问题"。

---

## 判定

### 特征对照表（本工程实跑）

| 特征 | 未加壳 orig | 标准 UPX | 变种 UPX | B13 stripped | 原理 |
|---|---|---|---|---|---|
| 节区头 `e_shnum` | 23 | **0** | **0** | **0** | 加壳/剥节头，IDA 看不到 `.text/.rodata` |
| 整文件熵 | 4.470 | **7.309** | **7.308** | 4.469 | 正常代码 4~6.5；>7.0 = 压缩/加密 |
| 大解压缓冲段 | 无 | **0x1000→0x13000（19.0x）** | **0x1000→0x13000（19.0x）** | 无 | UPX0：文件近空、内存很大；要求 memsz≥32KB 排除 `.bss` |
| `e_entry` 位置 | 0x0（段首） | **0x1358C（stub 段内）** | **0x1358C（stub 段内）** | 0x0 | 入口先跑解压代码 |
| 总 memsz / 文件大小 | 0.99x | **15.30x** | **15.30x** | 0.99x | 运行期解压出远多于文件的内容 |
| `UPX!` 魔数 | 0 | **4** | 0 | 0 | 变种把魔数替换掉 |
| 尾部 `sz_unc` 字段 | 0 | **70012** | **70012** | 0 | UPX 尾部记录解压后大小，远大于文件 |
| `XXXX` 替换魔数 | 0 | 0 | **4** | 0 | 变种的替换 token（F8） |

### 实跑输出（节选）

标准 UPX（`python tools/detect_packer.py samples/so/libtarget_upx.so`）：

```
目标: samples/so/libtarget_upx.so   (5348 bytes)
  架构: 32-bit  e_type=2  e_entry=0x1358C
  [命中] F1 节区头数量         e_shnum=0                      (+2)
  [命中] F2 整文件熵          7.309 bits/byte                (+2)
  [命中] F3 大解压缓冲段        PT_LOAD[0] filesz=0x1000 -> memsz=0x13000 (19.0x)  (+3)
  [命中] F4 入口位置          e_entry=0x1358C 落在 PT_LOAD[1] (vaddr=0x13000, size=0xFAA)  (+2)
  [命中] F5 内存/文件体积比      15.30x (memsz=0x13FAA)        (+2)
  [命中] F6 'UPX!' 魔数     出现 4 次                         (+3)
  [命中] F7 尾部 sz_unc 字段  0x1117C = 70012                 (+2)
综合得分: 16
判定结果: 标准 UPX 壳（特征完整）
```

变种 UPX（`python tools/detect_packer.py samples/so/libtarget_upx_variant.so`）：

```
目标: samples/so/libtarget_upx_variant.so   (5348 bytes)
  [命中] F1 节区头数量         e_shnum=0                      (+2)
  [命中] F2 整文件熵          7.308 bits/byte                (+2)
  [命中] F3 大解压缓冲段        PT_LOAD[0] filesz=0x1000 -> memsz=0x13000 (19.0x)  (+3)
  [命中] F4 入口位置          e_entry=0x1358C 落在 PT_LOAD[1] (vaddr=0x13000, size=0xFAA)  (+2)
  [命中] F5 内存/文件体积比      15.30x (memsz=0x13FAA)        (+2)
  [  - ] F6 'UPX!' 魔数     出现 0 次                         (+0)
  [命中] F7 尾部 sz_unc 字段  0x1117C = 70012                 (+2)
  [命中] F8 疑似被篡改魔数       候选 b'XXXX' 出现 4 次 @ ['0x98', '0xc03', '0x14b8', '0x14c0']  (+3)
综合得分: 16
判定结果: ★ 变种 UPX 壳（UPX 特征被抹掉，但结构仍在）
```

B13 样本（`python tools/detect_packer.py samples/so/libtarget_stripped.so`，关键行）：

```
  [命中] F1 节区头数量         e_shnum=0
  [  - ] F2 整文件熵          4.469 bits/byte        ← 无压缩，熵正常
[B13 · SO 加壳 / 自实现 Linker] e_type=ET_DYN 但 e_shnum=0（节头表被剥离）
综合得分: 2
判定结果: 疑似 SO 加壳 / 自实现 Linker（ELF 节头被剥离）— 需人工进 ELF 层确认
```

### 判定逻辑与阈值设计踩过的坑

判定逻辑（在 `tools/detect_packer.py` 的 `detect()` 内）：结构特征 F1–F7 打分；**`UPX!` 在 + 总分≥6 → 标准壳**；**`UPX!` 不在 + 总分≥6 + 有被改写魔数候选 → 变种**。

| 坑 | 现象 | 修正 |
|---|---|---|
| 解压缓冲段不加下限 | 普通 `.bss`（0xEC→0x9E0）被误判成 UPX 解压区 | 要求 `memsz ≥ 32KB` |
| 魔数候选排除「4 字节全同」 | 真实占位符 `XXXX` 被自己误杀 | 只排除 `00`/`FF` 纯填充 |
| 只用静态候选 | 出现 `\x00\x00|\x11` 这类巧合项 | 必须 `--verify` 打补丁跑 `upx -t` 实证 |

`--verify` 实证（实跑输出）：

```
[实证验证] 逐个候选打补丁后用 upx -t 检验:  (upx = upx.exe)
   b'XXXX' x4   -> upx -t OK   <= 这就是被篡改的真魔数
   b'\x00\x00|\x11' x2   -> upx -t FAIL
   b'\x00|\x11\x01' x2   -> upx -t FAIL
   b'\x00\x00\x04\x80' x2   -> upx -t FAIL
   b'\x00\x04\x80\xff' x2   -> upx -t FAIL
```

---

## 脱壳

### 解法 A：solve_variant.py（变种只抹特征，Stub 与控制流未动）

```bash
python tools/solve_variant.py samples/so/libtarget_upx_variant.so unpacked.so --orig samples/so/libtarget_orig.so
```

实跑输出（每一行对应脚本内部的一步）：

```
[*] 样本: samples/so/libtarget_upx_variant.so (5348 bytes)
[*] 现有 'UPX!' 数量: 0
[*] 使用的 upx: upx.exe
    候选 token b'\x00\x00\x00\x00' x34 -> upx -t FAIL
    候选 token b'\x01\x00\x00\x00' x7 -> upx -t FAIL
    候选 token b'XXXX' x4 -> upx -t OK
[+] 确定被篡改的 token: b'XXXX' -> 还原为 'UPX!'（共 4 处）
[+] 解包成功: unpacked.so (70012 bytes)

[*] 校验：脱壳后应找回的锚点
    AegisDroid-2026-SECRET-KEY     OK 找到
    flag{upx_unpacking_is_fun}     OK 找到
    com/aegis/NativeLib            OK 找到
    getFlag                        OK 找到
    JNI_OnLoad                     OK 找到
    check_license                  OK 找到
    blob_selfcheck                 OK 找到

[*] 与原始 SO 对比: samples/so/libtarget_orig.so (70012 bytes)
    大小: 70012 vs 70012  一致
    除 e_type 外差异字节数: 0  => 内容一致，脱壳成功
```

**逐行判读**：脚本枚举"重复出现的 4 字节 token"当候选 → 逐个打补丁用 `upx -t` **实证** → `XXXX` 通过即真魔数（静态候选必有巧合项，必须实证）→ 全部还原为 `UPX!` → `upx -d` 解出 70012 字节 → 7 个锚点全部找回 → 与原始 `.so` **除 `e_type` 外 0 字节差异**。`使用的 upx` 一行：upx 由 `--upx > 环境变量 UPX > 工程根 upx.exe > PATH` 定位；日志只显示文件名，**不落绝对路径**。

**⚠️ 必须 4 处全改（本题核心）**：4 处偏移是 `0x98 / 0xc03 / 0x14b8 / 0x14c0`——只改任意单独一处 `upx -t` 必 FAIL（实测 `NotPackedException: not packed by UPX`），4 处全改才 OK。原因：UPX 校验和覆盖所有内嵌魔数。手动逐字节复现见 `CLI.md`「脱壳」，010 Editor 操作见 `GUI.md`「脱壳」。

**何时失效**：若 4 处全改后 `upx -t` 仍失败 → 说明不止改了特征（Stub/控制流/压缩参数被改）→ **转解法 B**。

### 解法 B：内存 Dump + ELF Fix（通用主力路线）

完全不依赖 UPX 的特征与校验和。思路：`让程序跑起来 → 等 Stub 解压完 → dump 进程内存 → 重建 ELF → 载入 IDA`。

真机 Frida 步骤：把 `.so` 放进 APK 的 `lib/armeabi-v7a/`，安装运行，Frida 附加：

```javascript
// 等模块加载完成后 dump（此时内存里已是解压后的原始代码）
const lib = "samples/so/libtarget_upx_variant.so";
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
[+] simulated dump -> analysis_output/sim_dump.bin  base=0x0 size=77824 (from 3 PT_LOAD, 32-bit)
[+] wrote analysis_output/dump_fixed.so: base=0x0 size=77824 arch=arm entry=0x0
```

锚点复核：`dump_fixed.so` 内 `AegisDroid` / `flag{upx_unpacking_is_fun}` / `getFlag` / `JNI_OnLoad` / `check_license` / `blob_selfcheck` 均可搜到（本工程源码把这些符号串放进了 PT_LOAD 覆盖的 `.rodata`，运行态镜像里都在）。
真机用法：`dump_fix.py <dump.bin> <模块基址> <out.so> --arch arm [--entry-rva HEX]`。

**OEP 定位**：Stub 解压完跳回原始入口。观察 PC 何时离开 stub 段（本例 stub 在 `vaddr=0x13000`），进入第一个 PT_LOAD（`0x0` 起）。实用替代：在 `RegisterNatives` / `JNI_OnLoad` 下断或 hook——被调用即已在真实代码里。

**Dump ≠ 完成脱壳**：内存里的 ELF 缺节区表/符号，需 ELF Fix（重建 Section Header）。`dump_fix.py` 是最小可用版（单 PT_LOAD + `.text`）；真实对抗需补 `.dynamic`/`.dynsym`/重定位 → 用 `elf-dump-fix` / `elf-dump-fix-x` 或手工补全。

---

## 验证

三条判据（每条都实跑过）：

1. **体积恢复**：`unpacked.so = 70012` == `samples/so/libtarget_orig.so = 70012`
2. **锚点找回**：`tools/anchors.txt` 的 7 个锚点全部可见（solve 输出逐条 `OK 找到`）
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
 ├─ upx -t 通过 ─────────────► 直接 upx -d（标准壳，不必手脱）
 └─ upx -t 失败
      ├─ 结构仍像 UPX（无节区表/高熵/大解压缓冲/入口在 stub）
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
[*] 练习根目录: D:\code\android\reverse\upx_practice
样本状态对比:
  [一致]   so/libtarget_orig.so                        70012 bytes
  [一致]   so/libtarget_orig_arm64.so                  71848 bytes
  [一致]   so/libtarget_stripped.so                    70012 bytes
  [一致]   so/libtarget_upx.so                          5348 bytes
  [一致]   so/libtarget_upx_variant.so                  5348 bytes

练习产物: 无（环境干净）
输出目录 analysis_output/: 4 个文件

当前环境: 干净，可直接开始练习
```

建议每轮从 `restore` 开始：

1. `detect_packer.py` 判定 4 个样本（不看文件名）
2. hexdump 自己找出 4 处魔数（`CLI.md`「判定」）
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
[PASS] samples/so/libtarget_upx.so           仍为加壳判定: 标准 UPX 壳（特征完整）
[PASS] samples/so/libtarget_upx_variant.so   仍为加壳判定: ★ 变种 UPX 壳（UPX 特征被抹掉，但结构仍在）

0 项失败
```

三条断言的含义：正向——剥节头样本必触发 B13；负向——原始 NDK `.so`（节头完整）必不触发；防回归——既有的 UPX 判定不得被 B13 改造破坏。

---

## 踩坑与速查

### 踩坑（工具链 / 环境 / 阈值 / 误判 / 失效边界）

1. **官方 UPX 不能直接打包 Android `ET_DYN` `.so`**：UPX 4.2.4 对 ET_DYN 报 `NotCompressibleException`；改 `e_type=2` 后打包成功 70012→5348（7.64%）。**UPX 3.96 的 `--android-shlib` 同样失败**（实测 `NotCompressibleException`）——本工程原始 `.so` 已有 70KB，说明**不是体积问题，是结构问题**（ET_DYN 的装载语义 UPX 不支持）。打包后把 e_type 改回 DYN 则 `upx -t` 报 `ElfXX_Ehdr corrupted`。另注：UPX 4.2.4 已移除 `--android-shlib`。
2. **校验和覆盖全部内嵌魔数**：只改一处必失败（见「脱壳」）。变种的 `XXXX` 出现在 4 处（stub 2 + 尾部 2），必须全部还原。
3. **静态候选必有巧合项**：`\x00\x00|\x11` 等巧合 token 必须用 `--verify` 实证排除。
4. **make_variant 的 UPX0/1/2 段名改写在本构建里不生效**：`make_variant.py` 会同时把段名 `UPX0/UPX1/UPX2` 改成 `SEC0/SEC1/SEC2`，但本 UPX 4.2.4 生成的包里根本没有这些段名字符串（实测替换 0 处）——变种与标准的全部差异只有 4 处 `XXXX`（12 字节）。判据设计不能依赖"段名改写"这个动作存在。
5. **尾部 `sz_unc` 字段不要当唯一判据**：它只是 UPX 尾部结构里的一个 4 字节值，正常文件也可能在尾部碰巧出现大数值——所以它只是 F7（+2 分），须与其他特征互相印证。
6. **中文乱码**：Windows 控制台跑本仓 Python 脚本输出中文乱码时设 `PYTHONIOENCODING=utf-8`（PowerShell `$env:PYTHONIOENCODING='utf-8'`）。
7. **本机只有 `python` 无 `python3`**（全局约定）。

### 速查

```bash
# 判定
python tools/detect_packer.py <file> [--brief] [--verify]
python tools/elf_scan.py   samples/so/libtarget_orig.so samples/so/libtarget_upx.so samples/so/libtarget_upx_variant.so
python tools/upx_probe.py  samples/so/libtarget_orig.so samples/so/libtarget_upx.so samples/so/libtarget_upx_variant.so

# 解法 A
python tools/solve_variant.py samples/so/libtarget_upx_variant.so unpacked.so --orig samples/so/libtarget_orig.so

# 解法 B
python tools/simulate_dump.py samples/so/libtarget_orig.so analysis_output/sim_dump.bin
python tools/dump_fix.py analysis_output/sim_dump.bin 0x0 analysis_output/dump_fixed.so --arch arm

# 重新生成样本
bash build/build_android.sh    # NDK 编译原始 .so
bash build/pack.sh             # 生成标准 + 变种
python tools/make_stripped_so.py samples/so/libtarget_orig.so samples/so/libtarget_stripped.so   # 生成 B13 正样本

# 回归
python tools/check_so_samples.py        # B13 双向断言：stripped 必触发 / orig 必不触发 / UPX 判定不丢
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

> **判断 UPX 不靠字符串，靠「运行时原始代码在哪里恢复并开始执行」。**
> 标准壳用 `upx -d`；只抹特征用**特征修复（必须全部还原）**；Stub 被改就**内存 dump + ELF Fix**。
