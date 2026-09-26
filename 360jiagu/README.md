# 加固（native 层）· 练习工程（完整手册）

> 工程根目录：`360jiagu`（本 README 所在目录；下文所有命令都在此执行）
> **这是本工程唯一的文档**：原理 / 判定 / 解法 / 踩坑 / 命令 / 练习回归全在这里，分级阅读。
> 样本由真实 NDK 从同一份源码编译，代码与字符串完全一致，脱壳后可逐字节对照。

> ⚠️ **建模说明（务必先读）**：本机没有真实的 360 加固商业工具，本工程把 360 加固的
> **native（.so）层**建模为「**改版 UPX**」——这在历史上是准确的（360 早期 native 保护即基于
> UPX 改写）。因此本工程的脱壳机制（运行期解压 → 跳 OEP → 恢复原始代码 → ELF Fix）与真实
> 360 完全一致；区别只在于「被改写的特征」（魔数 `UPX!` → `JG!!`、明文 `360 4.24` 标记）。
> dex 层加固不在本工程范围（主题是 Android 壳与脱壳，详见 `PROMPT.md`）。

---

## 快速上手

### 三分钟跑一遍

```bash
cd 360jiagu

# ① 判定（不看文件名，只看结构特征；--brief 只打印结论行）
python tools/detect_360.py libtarget_orig.so            # => 综合得分 0  · 未见已知加固特征（≠未加壳）
python tools/detect_360.py libtarget_360.so             # => 综合得分 16 · 标准 360（UPX! 保留，可自动解包）
python tools/detect_360.py libtarget_360_variant.so     # => 综合得分 16 · ★ 变种 360（UPX! 被改写，结构仍在）

# ② 标准 360：直接官方解包（-t 先验证能解，-d 再解出；out.so 应为 43888 字节）
./upx.exe -t libtarget_360.so && ./upx.exe -d libtarget_360.so -o out.so

# ③ 变种 360：先实证确认真魔数，再修复解包
python tools/detect_360.py libtarget_360_variant.so --verify   # => b'JG!!' x4 -> upx -t OK（其余候选是巧合项）
python tools/solve_360.py libtarget_360_variant.so unpacked.so --orig libtarget_orig.so
#                └ 输入变种样本         └ 输出   └ 黄金样本：解完立刻比对，应报「除 e_type 外差异 0 字节」

# ④ 练完回归，下次重练
python tools/reset_lab.py restore
```

**三条命令分别干什么**：`detect_360.py` 只做**结构体检**（不修改文件），看 F1–F8 哪几条被点亮；
`--verify` 会把每个"疑似被篡改的 4 字节 token"打补丁后跑一次 `upx -t` **实证**（静态候选必有巧合项）；
`solve_360.py` 则是解法 A 的完整自动化：定位 token → 全部还原为 `UPX!` → `upx -d` → 锚点校验 → 与黄金样本逐字节比对。

### 三个关键样本

| 文件 | 大小 | e_type | `UPX!` | `JG!!` | `360 4.24` | `upx -d` | 用途 |
|---|---|---|---|---|---|---|---|
| `libtarget_orig.so` | 43888 | ET_DYN(3) | 0 | 0 | 仅在 payload（脱壳后可见） | — | 原始 SO，黄金对照 |
| `libtarget_360.so` | 17916 | ET_EXEC(2) | **4** | 0 | **有**（文件内明文） | **OK** | 标准 360：可自动解包 |
| `libtarget_360_variant.so` | 17916 | ET_EXEC(2) | 0 | **4** | 有（文件内明文） | **FAIL** | 变种 360：需手工/动态脱壳 |
| `libtarget_stripped.so` | 43888 | ET_DYN(3) | 0 | 0 | 无 | — | **B13 正样本**：节头表被剥离，触发「疑似 SO 加壳 / 自实现 Linker」 |

> **重要前提**：官方 UPX 4.2.4 **不能直接打包 Android 的 `ET_DYN` `.so`**（见「踩坑结论汇总」节）。
> 本工程标准/变种样本以 `linux/arm ET_EXEC` 形式打包——**脱壳机制完全相同**（同样的 Stub、
> 解压缓冲、OEP 概念），仅 `e_type` 字段不同。原始 `.so` 仍是货真价实的 ARM32 Android `ET_DYN`。

> **认知边界（务必读）**：本工具覆盖 UPX/360 类壳（魔数/结构特征）与 **SO 加壳 / 自实现 Linker 的
> ELF 结构异常（节头剥离 B13）**。`libtarget_stripped.so` 即 B13 正样本——它**没有**任何 UPX 特征，
> 仅靠「节头被剥离」这一确定性信号被检出，证明 B13 能抓到 UPX 类壳抓不到的自定义 Linker。
> **仍须动态 trace 才能定性**的场景：① SO VMP（VMP 解释器在 SO 里只是普通大函数，ELF 结构正常则静态不可确认）；
> ② 不走「汇聚调用」形态的自定义 VMP；③ 精巧的字符串加密。故「未见已知特征」绝不等于「未加固」。

---

## 原理：360 native 层 = 改版 UPX

### 加壳前后结构

```
正常 .so                     360 加固后（改版 UPX）
ELF                           ELF
├── ELF Header                ├── 360/UPX Loader / Stub   ← 入口先到这里
├── Program Headers           ├── 压缩后的原始数据
├── .text / .rodata / .data   └── 相关 ELF 信息（l_info / p_info / b_info）
├── .dynamic
```

### 运行时流程（**分析的关键在这里**）

```
加载 SO → 进入 Stub → 初始化 → 解压原始内容 → 恢复代码/数据 → 跳到 OEP → 真实 Native 代码
```

> 核心：360/UPX 是「运行过程中恢复原始程序并继续执行」，
> 所以**运行时内存状态是分析变种 360 的关键依据**。

### Android 完整链路

```
System.loadLibrary → linker → 映射 PT_LOAD → 360 Stub → 运行期解压
   → 原始 Native 代码 → JNI_OnLoad → RegisterNatives → 业务代码
```

### 本工程的两种 360 状态（建模）

```
标准 360  = UPX 打包 + UPX! 保留 + 明文 "360 4.24" 标记   → upx -d 可解（可恢复配置）
变种 360  = UPX 打包 + UPX! 被改写成 JG!! + 明文 "360 4.24" → upx -d 失败（需手脱/动态）
```

> **关键认知**：360 native 层在「标准/可恢复」配置下，文件结构与标准 UPX **字节级无区别**
> （除了 payload 内容）。真正区分「标准 360 vs 变种 360」的是**魔数是否被改写**；
> 真正区分「是否加壳」的永远是**结构特征**（见「判定」节），不是文件名或某个字符串。

---

## 脱壳步骤法与 OEP

```
① 判断文件类型      ② 分析 ELF          ③ 判断 360 特征    ④ 尝试 upx -t / -d
⑤ 失败→不纠结特征    ⑥ Android 运行      ⑦ 动态观察 Stub     ⑧ 观察内存映射/执行流
⑨ 找原始代码恢复位置 ⑩ 定位 OEP          ⑪ Dump 内存 ELF     ⑫ ELF Fix
⑬ IDA/Ghidra 重分析  ⑭ JNI_OnLoad / RegisterNatives → 继续分析
```

### Entry vs OEP

| 概念 | 含义 |
|---|---|
| **Entry Point** | 当前 ELF 入口（加壳后指向 Stub） |
| **OEP** (Original Entry Point) | 原始程序入口 |

```
加壳 SO:  Entry → Stub → 解压 → OEP → 原始代码
```

判断到达 OEP（**综合判断，不靠单一指标**）：代码在原始映射区 / 控制流脱离 Stub /
出现正常函数结构 / 出现原始 `.text` / 开始访问原始 `.rodata` /
出现 `JNI_OnLoad`·`RegisterNatives`·正常调用关系。

### 核心警示：不要只依赖 `UPX!` 字符串

> ❌ 搜索 `UPX!` → 找 Stub → 固定地址找 OEP（对魔改样本不可靠）
> ✅ **不是「有没有 UPX 字符串」，而是「运行过程中原始代码在哪里被恢复并开始执行」**

重点观察：Stub 控制流 / 哪些内存区被写入 / 写入数据是否像 ELF / 哪些区随后执行 /
控制流何时离开 Stub / 是否出现原始函数结构。

---

## 判定：不看文件名，只看结构特征（实测值）

### 特征对照表（本工程实跑）

| 特征 | 未加壳 orig | 标准 360 | 变种 360 | 原理 |
|---|---|---|---|---|
| 节区头 `e_shnum` | 24 | **0** | **0** | 加壳剥离节区表，IDA 看不到 `.text/.rodata` |
| 整文件熵 | 5.011 | **7.598** | **7.598** | 正常代码 4~6.5；>7.0 = 压缩/加密 |
| 大解压缓冲段 | 无 | **0x1000→0xD0A0（13.0x）** | **0x1000→0xD0A0（13.0x）** | UPX0：文件近空、内存很大；要求 memsz≥32KB 排除 `.bss` |
| `e_entry` 位置 | 0x0（段首） | **0x11684（stub 段内）** | **0x11684（stub 段内）** | 入口先跑解压代码 |
| 总 memsz / 文件大小 | 1.03x | **3.90x** | **3.90x** | 运行期解压出远多于文件的内容 |
| `UPX!` 魔数 | 0 | 标准 4 / **变种 0（→JG!!×4）** | 0（→JG!!×4） | 变种把魔数改写掉 |
| 尾部 `sz_unc` 字段 | 0 | **43888** | **43888** | UPX 尾部记录解压后大小，远大于文件 |
| 明文 `360` 标记 | payload（脱壳后） | **文件内 `360 4.24`** | **文件内 `360 4.24`** | 360 标记（lab 注入，脱壳后仍可见 payload 标记） |

```bash
python tools/detect_360.py <file> [--brief] [--verify]
```

判定逻辑（在 `tools/detect_360.py` 的 `detect()` 内）：
- 结构特征 F1–F7 打分；**`UPX!` 在 + 总分≥6 → 标准壳**；**`UPX!` 不在 + 总分≥6 + 有被改写魔数候选 → 变种**；
- 「是否 360」由两路明文标记确认（变种魔数 `JG!!` / `360jiagu` / `360 4.24`），**仅用于命名**，
  不改变「是否加壳」的判定（避免被 payload 里的 360 标记误判成「已加壳」）。

### 标准 360 样本判定（实跑输出，节选）

```
目标: libtarget_360.so   (17916 bytes)
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

### 变种 360 样本判定（实跑输出，节选）

```
目标: libtarget_360_variant.so   (17916 bytes)
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

### 阈值设计踩过的坑（重要）

| 坑 | 现象 | 修正 |
|---|---|---|
| 解压缓冲段不加下限 | 普通 `.bss`（0xEC→0x9E0）被误判成 UPX 解压区 | 要求 `memsz ≥ 32KB` |
| 魔数候选排除「4 字节全同」 | 真实占位符 `XXXX` 被自己误杀 | 只排除 `00`/`FF` 纯填充 |
| 只用静态候选 | 出现 `\x00\x00p\xab` 这类巧合项 | 必须 `--verify` 打补丁跑 `upx -t` 实证 |
| 原始 .so 太小 | UPX 报 `NotCompressibleException` | 加策略表体积（见「踩坑结论汇总」节），让 UPX 有净收益 |

```bash
python tools/detect_360.py libtarget_360_variant.so --verify
# b'JG!!' x4   -> upx -t OK   <= 这就是被篡改的真魔数
# b'\x00\x00p\xab' x2 -> upx -t FAIL  (巧合项)
# b'\x00p\xab\x00' x2 -> upx -t FAIL  (巧合项)
```

---

## 解法 A：手工修复特征 → 官方解包

**适用**：变种只抹特征，Stub 与控制流未动。（脚本 `solve_360.py` 只是这些步骤的自动化）

### 脚本跑通（先给正确答案）

```bash
python tools/solve_360.py libtarget_360_variant.so unpacked.so --orig libtarget_orig.so
```

实跑输出（节选）：

```
[*] 样本: libtarget_360_variant.so (17916 bytes)
[*] 现有 'UPX!' 数量: 0
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
[*] 与原始 SO 对比: libtarget_orig.so (43888 bytes)
    大小: 43888 vs 43888  一致
    除 e_type 外差异字节数: 0  => 内容一致，脱壳成功
```

**逐行判读**：脚本扫描 4 字节重复 token → 逐个打补丁用 `upx -t` 实证 → `JG!!` 通过即真魔数
→ 全部还原为 `UPX!` → `upx -d` 解出 43888 字节 → 8 个锚点全部找回 → 与原始 `.so` **除 `e_type` 外 0 字节差异**。

### 手动复现（自己看字节定位）

检测已给出 4 个偏移：`0x98 / 0x3cfb / 0x45cf / 0x45d8`，各把 `JG!!` 改回 `UPX!`。

**十六进制编辑器**（HxD / 010 Editor / ImHex）：跳到上述 4 个偏移，各改成 `55 50 58 21`（`UPX!`），另存 `fixed.so`。

**命令行等价**：

```bash
python -c "
d=bytearray(open('libtarget_360_variant.so','rb').read())
for o in (0x98,0x3cfb,0x45cf,0x45d8): d[o:o+4]=b'UPX!'
open('fixed.so','wb').write(d)"
```

```bash
./upx.exe -t fixed.so && ./upx.exe -d fixed.so -o unpacked.so
```

### ⚠️ 必须 4 处全改（本题核心）

| 操作 | `upx -t` |
|---|---|
| 只改 `0x98` / `0x3cfb` / `0x45cf` / `0x45d8` **任意单独一处** | **FAIL** |
| **4 处全改** | **OK** |

**原因**：UPX/360 校验和覆盖所有内嵌魔数，只修一处其余仍让校验失败（报 `not packed by UPX`）。

### 三条验证判据

1. **体积恢复**：`unpacked.so = 43888` == `libtarget_orig.so = 43888`
2. **锚点找回**：`360jiagu_lab_payload_marker_v1`、`JiaguLab-2026-SECRET-KEY`、
   `flag{jiagu_unpacking_is_fun}`、`com/aegis/NativeLib`、`getFlag`、`JNI_OnLoad`、
   `check_license`、`blob_selfcheck` 全部可见
3. **字节一致**：与 `libtarget_orig.so` 除偏移 16 的 `e_type` 外 **0 字节差异**
   （解出 ET_EXEC=2，原始 ET_DYN=3；代码内容完全一致）

IDA 打开应看到调用链：`JNI_OnLoad → RegisterNatives → getFlag → check_license`

### 何时失效

若 4 处全改后 `upx -t` 仍失败 → 说明不止改了特征（Stub/控制流/压缩参数被改）→ **转解法 B**。

---

## 解法 B：内存 Dump + ELF Fix（通用）

**这是真实对抗的主力路线**，完全不依赖 360 的特征与校验和。

### 思路

```
让程序跑起来 → 等 Stub 解压完 → dump 进程内存 → 重建 ELF → 载入 IDA
```

### 真机 Frida 步骤

把 `.so` 放进 APK 的 `lib/armeabi-v7a/`，安装运行，Frida 附加：

```javascript
// 等模块加载完成后 dump（此时内存里已是解压后的原始代码）
const lib = "libtarget_360_variant.so";
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

要点：
- **加载完成后**才是解压后的代码，别在 `JNI_OnLoad` 之前 dump
- 最稳时机：hook `libart.so` 的 `RegisterNatives` 被调用后，或 `JNI_OnLoad` 返回后
- 导出表没 `JNI_OnLoad`（被壳隐藏）时，改用 linker 映射完 PT_LOAD / 执行 init_array 时 dump

### 本工程演练（无真机也能跑通）

```bash
python tools/simulate_dump.py libtarget_orig.so analysis_output/sim_dump.bin
python tools/dump_fix.py analysis_output/sim_dump.bin 0x0 analysis_output/dump_fixed.so --arch arm
# => ET_DYN / ARM，PT_LOAD + .text，锚点全部可回收
```

实跑输出：

```
[+] simulated dump -> analysis_output/sim_dump.bin  base=0x0 size=53408 (from 4 PT_LOAD, 32-bit)
[+] wrote analysis_output/dump_fixed.so: base=0x0 size=53408 arch=arm entry=0x0
```

锚点复核（`dump_fixed.so` 内 `360jiagu` / `JiaguLab` / `getFlag` 均 OK）。

真机用法：`dump_fix.py <dump.bin> <模块基址> <out.so> --arch arm [--entry-rva HEX]`

### OEP 定位

Stub 解压完跳转回原始入口。观察 PC 何时离开 stub 段（本例 stub 在 `vaddr=0xE000`），
进入第一个 PT_LOAD（`0x0` 起，即解压出的原始代码区）。
实用替代：在 `RegisterNatives` / `JNI_OnLoad` 下断或 hook —— 被调用即已在真实代码里。

### Dump ≠ 完成脱壳

内存里的 ELF 缺节区表/符号，需 ELF Fix（重建 Section Header）：

```
Dump → ELF Fix → Section Header 重建 → 载入 IDA
```

`dump_fix.py` 是最小可用版（单 PT_LOAD + `.text`）；真实对抗需补 `.dynamic`/`.dynsym`/重定位
→ 用 `elf-dump-fix` / `elf-dump-fix-x` 或手工补全。

---

## 决策流程

```
拿到 .so
 ├─ upx -t 通过 ─────────────► 直接 upx -d（标准 360，不必手脱）
 └─ upx -t 失败
      ├─ 结构仍像 360/UPX（无节区表/高熵/大解压缓冲/入口在 stub）
      │    └─► 解法 A：还原全部魔数 → upx -d
      │         失败 → 说明 Stub/校验被改，转下一条
      └─ 完全不像 / 解法 A 无效
           └─► 解法 B：Frida dump → dump_fix.py → IDA
```

---

## 踩坑结论汇总

### 官方 UPX 不能直接打包 Android `ET_DYN` `.so`

| 尝试 | 结果 |
|---|---|
| UPX 4.2.4 打包 ET_DYN | `NotCompressibleException` |
| UPX 4.2.4 打包 ET_EXEC（改 e_type=2） | **成功** 43888→17916（40.82%） |
| 打包后把 e_type 改回 DYN | `upx -t` 报 `ElfXX_Ehdr corrupted` |

> 注：本工程标准/变种样本是 `ET_EXEC`，仅为让 UPX 能打包；脱壳机制与真实 ET_DYN 完全一致。

### 原始 .so 太小 → UPX 拒绝压缩

UPX 自带 ~3.5KB stub，原始 `.so` 太小（如 4.5KB）时「压缩后 + stub」≥ 原文件，
触发 `NotCompressibleException`。

**解决**：`build/gen_policy.py` 生成 `src/policy_inc.h`（1000 条策略/签名表，约 42KB 文本），
让原始 `.so` 达到 ~44KB，UPX 稳定打包（17916 字节）。`policy_inc.h` 同时是脱壳后的真实数据锚点。

### 校验和覆盖全部内嵌魔数

见 「为什么必须全部还原」节 —— 只改一处必失败。变种 360 的 `JG!!` 出现在 4 处（stub 2 + 尾部 2），
必须全部还原为 `UPX!`。

### 静态候选必有巧合项

见 「实证真魔数」节 —— 用 `--verify` 实证。`JG!!` 通过 `upx -t`，其余 `\x00\x00p\xab` 等均为巧合。

### 360 明文标记可安全注入

把 stub 版本串 `UPX 4.24` 改为 `360 4.24`（同长度 8 字节）后 `upx -t` 仍通过，
标准/变种样本因此携带明文 `360 4.24` 标记（**这是本 lab 的建模标记，真实 360 未必有此串**）。
注意：**尾部追加任何字节都会破坏 UPX**（`upx -t` 报 `not packed by UPX`），故不能用「尾部追加标记」。

---

## 反复练习：备份与一键回归

原始样本已备份到 `pristine/`（含 sha256 清单）：

```bash
python tools/reset_lab.py status     # 环境是否被练脏
python tools/reset_lab.py restore    # 还原 3 个样本 + 删练习产物 + 清空 analysis_output/
python tools/reset_lab.py backup     # 改过源码后刷新基线
```

建议每轮从 `restore` 开始：
1. `detect_360.py` 判定三个样本（不看文件名）
2. hexdump 自己找出 4 处 `JG!!`
3. 十六进制编辑器手改 4 处 → `upx -t` → `upx -d`
4. 三条判据验证
5. 进阶：故意只改 1~3 处，体会校验和
6. 进阶：跑通解法 B 的 dump + ELF Fix

---

## 命令速查

```bash
# 判定
python tools/detect_360.py <file> [--brief] [--verify]
python tools/elf_scan.py   libtarget_orig.so libtarget_360.so libtarget_360_variant.so
python tools/upx_probe.py  libtarget_orig.so libtarget_360.so libtarget_360_variant.so

# 解法 A
python tools/solve_360.py libtarget_360_variant.so unpacked.so --orig libtarget_orig.so

# 解法 B
python tools/simulate_dump.py libtarget_orig.so analysis_output/sim_dump.bin
python tools/dump_fix.py analysis_output/sim_dump.bin 0x0 analysis_output/dump_fixed.so --arch arm

# 重新生成样本
bash build/build_android.sh    # NDK 编译原始 .so（含 gen_policy.py 生成策略表）
bash build/pack.sh             # 生成标准 + 变种
python tools/make_stripped_so.py libtarget_orig.so libtarget_stripped.so   # 生成 B13 样本（剥节头，模拟自实现 Linker）

# 回归
python tools/check_so_samples.py    # B13 双向断言（正向/负向/防回归，0 失败才算过）
python tools/reset_lab.py restore
```

**外部工具怎么定位（都不写死路径）**——见 `build/locate.sh`：

| 工具 | 优先级（从高到低） |
|---|---|
| UPX | `--upx <路径>` > 环境变量 `UPX` > 工程根 `upx.exe` > PATH > `tools/upx396.exe` |
| NDK | 环境变量 `NDK_ROOT` / `ANDROID_NDK_HOME` > `<SDK>/ndk/<最新版>` |
| python | 环境变量 `PYTHON` > PATH 里的 `python` |

工程根自带的 `upx.exe` 优先于 PATH：本工程所有实测数值都基于它，换版本可能复现不出同样样本。
要换版本请显式 `UPX=<路径>`，别靠 PATH 偷偷切。任何一档都拿不到时脚本会直接报错，并告诉你该配哪一项。

---

## 文件索引

```
360jiagu/
├── README.md                  ★ 本手册（唯一文档）
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
│   ├── reset_lab.py           ★ 备份 / 状态 / 回归
│   ├── check_so_samples.py    ★ B13 双向回归断言（stripped 必触发 / orig 必不触发 / 既有 360 判定防回归）
│   ├── solve_360.py           解法 A 自动化（特征修复 + upx -d + 锚点校验）
│   ├── make_360_variant.py    由标准包生成变种（UPX! → JG!!）
│   ├── make_stripped_so.py    生成 B13 样本（剥离节头表，模拟自实现 Linker）
│   ├── dump_fix.py            解法 B：内存 dump → 重建 ELF
│   ├── simulate_dump.py       生成模拟内存镜像
│   ├── elf_scan.py            无依赖 ELF 解析 + UPX 指纹
│   ├── upx_probe.py           批量 upx -t/-l/-d
│   ├── anchors.txt            脱壳后应找回的锚点（360jiagu/.../JNI_OnLoad 等）
│   └── upx396.exe             UPX 3.96（对照用）
├── pristine/                  原始样本备份 + sha256 清单（勿手改）
├── analysis_output/           脚本产出（detect*.txt / upx_probe.txt / solve.txt / sim_dump.bin / dump_fixed.so / solve_unpacked.so）
├── libtarget_orig.so          【原始 SO】ET_DYN ARM32
├── libtarget_orig_arm64.so    ARM64 原始 .so（对照）
├── libtarget_360.so           【标准 360】upx -d 可解
├── libtarget_360_variant.so   【变种 360】upx -d 失败
└── libtarget_stripped.so      【B13 样本】节头剥离（不触发 UPX 特征，只触发 B13）
```

---

## 一句话记住

> **判断 360 不靠字符串，靠「运行时原始代码在哪里恢复并开始执行」。**
> 标准 360 用 `upx -d`；只抹魔数用**特征修复（必须全部还原）**；Stub 被改就**内存 dump + ELF Fix**。
> 360 native 层本质是改版 UPX——结构特征与标准 UPX 完全一致，区别只在被改写的魔数。
