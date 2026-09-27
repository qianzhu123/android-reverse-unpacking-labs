# GUI.md — 图形工具路线：用 010 Editor / IDA / binwalk 看懂每一步

> 本文件与 `SCRIPT.md`、`CLI.md` **结构完全平行**（同一套章节骨架一一对应），只讲「图形工具怎么做」。
> 工具按步骤就近取用：十六进制改字节用 **010 Editor**（本机实装 010 Editor，`Tools` 目录下）；
> SO 逆向/调用链用 **IDA 或 Ghidra**；熵分布曲线用 **binwalk -E**（本机实装 binwalk 3.1.1）；
> GDA/JEB 主要面向 APK 结构浏览，本工程样本是 `.so` 非其主场，只在文末一句带过。
> **路线分工**：判定靠 SCRIPT/CLI（可量化、可写进判据），看懂靠 GUI——图形工具给出「可读形态」，
> 不替代量化判据；每节都写清「点哪里 / 看什么 / 怎么判」。
> 所有命令与工具行为先实跑/实开再写（010 Editor / binwalk 3.1.1，Windows 11 实测）。
>
> 工具定位（四档解析，无写死路径）：命令行参数 > 环境变量 > 项目配置 > 自动探测。
> 本文出现的 GUI 工具路径均为"本机说明性文字"的例外位置——可复制执行，但不是工程脚本的一部分。

---

## 概述

**项目定位 / 建模说明**：同 `SCRIPT.md`。

---

## 工程结构

同 `SCRIPT.md`——样本一律住 `samples/so/`；GUI 产物（010 Editor 另存的 `fixed.so`、IDA 数据库）放工程根或 `analysis_output/`，不污染 `samples/so/` 与 `pristine/`；`reset_lab.py` 会把 `fixed.so`/`unpacked.so` 这类练习产物识别并清理。

---

## 知识点

> 原理与失效边界见 `SCRIPT.md`「知识点」；本表只给「判据 → GUI 可读形态」的映射。

| 判据 | 量化值（SCRIPT/CLI 的事） | 在 GUI 里长什么样 |
|---|---|---|
| F1/B13 节头剥离 | `e_shnum=0` | IDA/Ghidra 打开壳样本：Sections 窗口**为空**；010 Editor ELF 模板里 `e_shoff=0` 异常高亮 |
| F2 整文件熵 | orig 5.011 / 壳 7.598 | binwalk -E 曲线：壳全程贴高位，orig 在 5 上下 |
| F3 大解压缓冲 | `0x1000→0xD0A0` | 010 Editor ELF 模板 PT_LOAD 表：MemSiz 列远大于 FileSiz |
| F6/F8 魔数 | `UPX!`×4 / `JG!!`×4 | 010 Editor 十六进制视图 4 处偏移肉眼可见 |
| 脱壳验证 | 除 e_type 外 0 差异 | IDA 打开脱壳产物：锚点字符串可搜、调用链完整 |

---

## 判定

### 010 Editor 读结构（对应 CLI 的 llvm-readelf / xxd）

1. **打开**：010 Editor 拖入 `samples/so/libtarget_360.so`（或 File → Open）。
2. **跑 ELF 模板**：菜单 `Templates → File Templates...` 选 `ELF/EXE (ELF64.bt / ELF.bt)`，`Run Template`（32 位样本选 ELF）。
3. **看什么**：模板解析结果窗口（`Results` 面板 / `Template Results`）里展开 `elf_header`：
   - `e_type = 2 (ET_EXEC)`——加壳样本被 pack 成 ET_EXEC（正常 Android `.so` 应为 3 ET_DYN）；
   - `e_entry = 0x11684`——入口不在段首（orig 是 0x0）；
   - `e_shnum = 0` / `e_shoff = 0`——**节头表被整体剥离**，正常 NDK `.so` 这里应是 24 和 42928 量级的偏移。
4. **怎么判**：`e_shnum=0` + 入口非段首联读即 F1/F4 命中的 GUI 形态。对 `samples/so/libtarget_stripped.so` 重复同样操作：`e_type=3 (ET_DYN)` **且** `e_shnum=0`——这就是 B13（自实现 Linker）的形态，与"未加壳"的区分点全在这两个字段联读上。

### binwalk -E 熵曲线（F2 的可视化）

```bash
# 整文件熵曲线：加壳 vs 原始，两条曲线一对比，F2 一目了然
binwalk -E samples/so/libtarget_360.so
#   => Plotly 交互图（浏览器打开）：整条曲线贴着高位走（≈7.6）= 主体是压缩数据
binwalk -E samples/so/libtarget_orig.so
#   => 曲线在 5 上下波动 = 正常代码/数据
binwalk -E samples/so/libtarget_stripped.so
#   => 曲线与 orig 几乎重合（≈5.0）——B13 样本没压缩，异常在"结构"不在"熵"
```

**怎么判**：曲线回答"哪里高哪里低"，数值（7.598 / 5.011）归 `SCRIPT.md`/`CLI.md` 的量化判据——两条路线互补。B13 这条尤其值得看：**熵完全正常但节头被剥**，单靠熵曲线必然漏判，这就是"判定靠结构特征、多证据互相印证"的直观教材。
**本机坑**：`-p <png>` 存 PNG 在本机失败（binwalk 3.1.1 的 Kaleido 组件缺 `mf.dll`，详见「踩坑」）——`-E` 的交互图不受影响，需要留档就截图。

---

## 脱壳

### 010 Editor 改魔数（解法 A 的 GUI 版；对应 `SCRIPT.md` solve_360.py / `CLI.md` 手改字节）

前提：`detect_360.py --verify` 已实证真魔数是 `JG!!`，4 处偏移 `0x98 / 0x3cfb / 0x45cf / 0x45d8`（每处 4 字节）。

1. **打开**：010 Editor 打开 `samples/so/libtarget_360_variant.so`。
2. **跳偏移**：`Ctrl+G`（Go To）输入 `0x98` 回车——光标落在十六进制视图的该偏移上；你会看到 `4A 47 21 21`（`JG!!`）。
3. **改字节**：直接在十六进制列把 `4A 47 21 21` 改成 `55 50 58 21`（`UPX!`）；或者右键该选区用编辑功能，或直接键盘输入。
4. **重复**：`Ctrl+G` 依次跳 `0x3cfb`、`0x45cf`、`0x45d8`，每处同样 4 字节改成 `55 50 58 21`。
5. **另存**：`File → Save As...` 存为 `fixed.so`（不要覆盖原样本——`reset_lab.py` 靠原始样本做回归）。
6. **验证**：

```bash
./upx.exe -t fixed.so && ./upx.exe -d fixed.so -o unpacked.so
#   => testing fixed.so [OK] / Unpacked 1 file.
```

**看什么 / 怎么判**：改之前先 `Ctrl+F`（Find）搜十六进制 `4A 47 21 21`——应命中且仅命中 4 处，与 `detect_360.py` F8 给的偏移列表一一对应；改完后同搜索应 0 命中，改搜 `55 50 58 21` 应 4 命中。**只改任意一处不灵**（`upx -t` 仍报 `not packed by UPX`，校验和覆盖全部内嵌魔数——实测过，见 `CLI.md`）。
**对照**：010 Editor 里同时打开 `samples/so/libtarget_360.so`（标准样本），`Ctrl+G` 跳同样 4 处偏移——那里本来就是 `55 50 58 21`。这就是"变种与标准的唯一区别是魔数被改写"的肉眼证明。

### 解法 B：IDA/Ghidra 看调用链（dump 之后的"看懂"环节）

解法 B 的 dump + ELF Fix 本身是脚本/真机操作（`SCRIPT.md`「脱壳」）；GUI 的参与点在**产物复核**。

**载入 IDA**（Ghidra 同理，操作名不同）：

1. **打开**：IDA 拖入脱壳产物（如 `analysis_output/solve_unpacked.so` 或解法 B 的 `analysis_output/dump_fixed.so`），按 ARM/ARM32 处理器载入。
2. **看导出**：`View → Open subviews → Exports`（或 Exports 标签页）——应有 `JNI_OnLoad`。
3. **看调用链**：双击 `JNI_OnLoad` 进反汇编；函数体内依次可见
   - `FindClass`（JNI 调用，参数是 `com/aegis/NativeLib`）；
   - `RegisterNatives`——它注册的方法表 `gMethods` 里有三个函数指针；
   - 顺着指针分别到 `getFlag`（回传 `flag{jiagu_unpacking_is_fun}`）、`check_license`（比对 `JiaguLab-2026-SECRET-KEY`）、`blob_selfcheck`。
   即完整链：`JNI_OnLoad → RegisterNatives → getFlag → check_license`。
4. **看锚点**：`Shift+F12` 打开 Strings 窗口——`360jiagu_lab_payload_marker_v1`、`JiaguLab-2026-SECRET-KEY`、`flag{jiagu_unpacking_is_fun}` 等锚点全部可见；双击任一锚点跳到 `.rodata`，再按 `X`（交叉引用）能看到哪些函数在用它。
5. **怎么判**：调用链完整 + 锚点可搜 = 脱壳真的还原了原始代码（对应 `SCRIPT.md`「验证」判据 2 的 GUI 形态）。

**壳样本的判读点（对照实验，值得做一次）**：用 IDA 直接打开**加壳样本** `samples/so/libtarget_360.so`——
- `View → Open subviews → Sections`（节视图）**是空的**：因为 `e_shnum=0`，IDA 只能按 Program Header 建段（Segments 有、Sections 无）——**正常 NDK `.so` 打开后 Sections 窗口是一长串 `.text/.rodata/.dynsym`，壳样本一个都没有**。这就是 F1「加壳剥离节区表，IDA 看不到 .text/.rodata」的字面形态；
- 入口点（`e_entry=0x11684`）落在 stub 段里，反汇编是解压 stub 代码，看不到任何业务函数；Strings 窗口里搜不到 `getFlag`/`check_license` 的函数名（它们在压缩数据里）。
两相对照，"脱壳前看不见、脱壳后全看见"就是 GUI 路线对判定/验证两章的可视化佐证。

**失效边界**：IDA 对剥了节头的文件（B13 样本、加壳样本）仍可按段装载分析，但失去节级导航；dump 产物（`dump_fixed.so`）是最小重建版，`.dynamic`/`.dynsym` 未修复，部分交叉引用/导入表功能不可用——真实对抗须用完整的 ELF Fix 工具补齐（见 `SCRIPT.md`「脱壳」）。IDA 只是"看懂"，不是判定；量化结论永远来自 `SCRIPT.md`/`CLI.md`。

### GDA / JEB（一句带过）

这两工程样本是 `.so`（native 层），GDA/JEB 的主场是 APK（dex/资源/Manifest）结构浏览——对本工程仅在对** APK 外壳**做整体浏览时顺带用一下，native 分析还是 IDA/Ghidra；此处不展开。

---

## 验证

SCRIPT「验证」的三条判据（体积/锚点/字节差）都是量化的事；GUI 视角只有一个动作：**IDA 同时打开脱壳产物与黄金样本 `samples/so/libtarget_orig.so`**——

- 两边 `Shift+F12` 搜锚点，命中同样的字符串、同样的交叉引用出处；
- `JNI_OnLoad` 的反汇编两边逐行一致（唯一不同：脱壳产物 `e_type=ET_EXEC`，黄金样本 `ET_DYN`，不影响反汇编视图）；
- 010 Editor 里 `Ctrl+G` 跳偏移 16（`0x10`）：一边 `03`、一边 `02`，其余字节肉眼扫过去无差异。

**怎么判**：GUI 对照是**直观复核**，不是判据本身——最终结论仍以 `solve_360.py` 的「除 e_type 外差异 0 字节」为准。

---

## 决策流程

```
图形工具在流程里的位置（判定结论永远来自 SCRIPT/CLI 的量化判据）：
  SCRIPT/CLI 判定 ──► 是哪种形态？
       │
       ├─ 标准 360 ──► 不必开 GUI：upx -d 直接解
       ├─ 变种 360 ──► 010 Editor 手改 4 处魔数（本档「脱壳」）→ upx -t/d
       ├─ B13 ──────► IDA/Ghidra 节视图为空（可读形态）；010 Editor 模板高亮 e_shnum=0
       └─ Stub 被改 ─► 解法 B dump 之后，IDA 看调用链 + 锚点（本档「脱壳 · 解法 B」）
```

---

## 反复练习

复位仍用 `SCRIPT.md` 的 `reset_lab.py`（status / restore / backup）；GUI 侧的增量练习：

1. 010 Editor 打开变种样本，`Ctrl+F` 自己搜出 4 处 `JG!!`（不看 detect 给的偏移），与工具输出对照；
2. 手改 4 处 → 另存 `fixed.so` → `upx -t`：先故意只改 1 处体会失败，再补齐 4 处；
3. IDA 分别打开加壳样本与脱壳产物，看 Sections 空与非空、Strings 有无锚点——两个视图各截一张心的图（用截图，别指望 binwalk 存 PNG，见踩坑）。

---

## 踩坑与速查

### 踩坑（GUI / 工具侧）

1. **binwalk 3.1.1 存 PNG 依赖 Kaleido**：本机 `-p <png>` 实测失败，报
   `plotly_kaleido ... couldn't write to Kaleido stdin: Os { code: 109, kind: BrokenPipe }`——
   本机 Kaleido 缺 `mf.dll`。`-E` 的交互图（浏览器打开的 Plotly 页）**不受影响**，能正常看曲线；要留档就截图，或修 Kaleido 环境（补 mf.dll 后重试 `-p`）。
2. **010 Editor 改完别覆盖原样本**：直接 Save 会改掉 `samples/so/libtarget_360_variant.so`，`reset_lab.py status` 会立刻标红，回归也可能被破坏——一律 Save As 到 `fixed.so` 等练习产物名。
3. **010 Editor 的 Ctrl+G 输入是十六进制**：`G` 对话框默认 Hex 模式，`0x98` 或 `98` 都行；输十进制想清楚再改 Base。
4. **IDA 打开壳样本可能不识别为 ARM**：剥节头的 ELF 有时需要手动选处理器（ARM little-endian）与入口；载不进去不等于文件坏——先跑 `detect_360.py` 确认结构，再回来载。
5. **IDA 对 dump 产物的交叉引用不全**：`dump_fix.py` 是最小重建（单 PT_LOAD + `.text`），`.dynamic`/`.dynsym` 缺失导致导入表为空、部分函数无法命名——这是重建器的边界，不是脱壳失败；判定以锚点字符串与调用链为准。
6. **中文乱码**：同 CLI 路线设 `PYTHONIOENCODING=utf-8`。
7. **GDA/JEB 别硬上 `.so`**：主场是 APK；native 分析用 IDA/Ghidra。

### 速查

```
010 Editor：改魔数（解法 A）
  打开 samples/so/libtarget_360_variant.so
  Ctrl+G -> 0x98 / 0x3cfb / 0x45cf / 0x45d8
  每处 4 字节：4A 47 21 21 -> 55 50 58 21
  Save As fixed.so -> ./upx.exe -t fixed.so 应 [OK]

IDA：看调用链（解法 B 验证）
  载入脱壳产物（ARM）-> Exports 找 JNI_OnLoad -> RegisterNatives
  -> getFlag / check_license / blob_selfcheck
  Shift+F12 搜锚点：360jiagu_lab_payload_marker_v1 / JiaguLab-2026-SECRET-KEY / flag{...}
  对照：打开 samples/so/libtarget_360.so 时 Sections 窗口为空（e_shnum=0 的可读形态）

binwalk：熵曲线（判定 F2 可视化）
  binwalk -E samples/so/libtarget_360.so          => 曲线全程高位（≈7.6）
  binwalk -E samples/so/libtarget_orig.so         => 曲线在 5 上下
  binwalk -E samples/so/libtarget_stripped.so     => 曲线正常（≈5.0）但节头被剥——熵曲线抓不到 B13
  （-p 存 PNG 本机失败：Kaleido 缺 mf.dll；用 -E 交互图或截图）

复检
  python tools/check_so_samples.py     => 0 项失败
  python tools/reset_lab.py status
```
