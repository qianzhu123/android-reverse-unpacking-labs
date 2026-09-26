# 变种 UPX 壳 · 练习工程（完整手册）

> 工程根目录：`upx_practice`（本 README 所在目录；下文所有命令都在此执行）
> **这是本工程唯一的文档**：原理 / 判定 / 解法 / 踩坑 / 命令 / 练习回归全在这里，分级阅读。
> 样本由真实 NDK 从同一份源码编译，代码与字符串完全一致，脱壳后可逐字节对照。

---

## 快速上手

### 三分钟跑一遍

```bash
cd upx_practice

# ① 判定（不看文件名，只看结构特征）
python tools/detect_packer.py libtarget_orig.so            # => 综合得分 0 · 未见已知加固特征（≠未加壳）
python tools/detect_packer.py libtarget_upx.so             # => 标准 UPX (16 分)
python tools/detect_packer.py libtarget_upx_variant.so     # => ★ 变种 UPX (16 分)
python tools/detect_packer.py libtarget_stripped.so        # => B13：疑似自实现 Linker（节头剥离，无 UPX 特征）

# ② 标准壳直接解（-t 先验证能解，-d 再解出，out.so 应为 70012 字节）
./upx.exe -t libtarget_upx.so && ./upx.exe -d libtarget_upx.so -o out.so

# ③ 变种壳：先实证确认真魔数，再修复解包
python tools/detect_packer.py libtarget_upx_variant.so --verify   # => b'XXXX' x4 -> upx -t OK（其余候选是巧合项）
python tools/solve_variant.py libtarget_upx_variant.so unpacked.so --orig libtarget_orig.so
#                  └ 输入变种样本          └ 输出   └ 黄金样本：解完立刻比对，应报「除 e_type 外差异 0 字节」

# ④ 练完回归，下次重练
python tools/reset_lab.py restore
```

**三条命令分别干什么**：`detect_packer.py` 只做**结构体检**（不修改文件），看 F1–F7 哪几条被点亮；
`--verify` 会把每个"疑似被篡改的 4 字节 token"打补丁后跑一次 `upx -t` **实证**（静态候选必有巧合项）；
`solve_variant.py` 是解法 A 的完整自动化：定位 token → 全部还原为 `UPX!` → `upx -d` → 锚点校验 → 与黄金样本逐字节比对。
`upx.exe` 的定位顺序是 `--upx > 环境变量 UPX > 工程根 upx.exe > PATH`（见 「命令速查」）。

### 三个关键样本

| 文件 | 大小 | e_type | `UPX!` | `upx -t` | 用途 |
|---|---|---|---|---|---|
| `libtarget_orig.so` | 70012 | ET_DYN | 0 | FAIL | 原始 SO，黄金对照 |
| `libtarget_upx.so` | 5348 | ET_EXEC | **4** | **OK** | 标准壳，`upx -d` 可解 |
| `libtarget_upx_variant.so` | 5348 | ET_EXEC | **0** | **FAIL** | 变种壳，需手工/动态 |
| `libtarget_stripped.so` | 70012 | ET_DYN | 0 | — | **B13 正样本**：节头表被剥离，触发「疑似 SO 加壳 / 自实现 Linker」 |

> **重要前提**：官方 UPX 4.2.4 **不能直接打包 Android 的 `ET_DYN` `.so`**（见「踩坑结论汇总」节）。
> 本工程标准样本以 `linux/arm ET_EXEC` 形式打包——**脱壳机制完全相同**（同样的 Stub、
> UPX0 段、OEP 概念），仅 `e_type` 字段不同。原始 `.so` 仍是货真价实的 ARM32 Android `ET_DYN`。

> **认知边界（务必读）**：本工具覆盖 UPX 类壳（魔数/结构特征）与 **SO 加壳 / 自实现 Linker 的
> ELF 结构异常（节头剥离 B13）**。`libtarget_stripped.so` 即 B13 正样本——它**没有**任何 UPX 特征，
> 仅靠「节头被剥离」这一确定性信号被检出，证明 B13 能抓到 UPX 类壳抓不到的自定义 Linker。
> **仍须动态 trace 才能定性**的场景：① SO VMP（VMP 解释器在 SO 里只是普通大函数，ELF 结构正常则静态不可确认）；
> ② 不走「汇聚调用」形态的自定义 VMP；③ 精巧的字符串加密。故「未见已知特征」绝不等于「未加固」。

---

## 原理：UPX 与变种

### 加壳前后结构

```
正常 .so                      UPX 加壳后
ELF                           ELF
├── ELF Header                ├── UPX Loader / Stub   ← 入口先到这里
├── Program Headers           ├── 压缩后的原始数据
├── .text / .rodata / .data   └── 相关 ELF 信息（l_info / p_info / b_info）
├── .dynamic
```

### 运行时流程（**分析的关键在这里**）

```
加载 SO → 进入 Stub → 初始化 → 解压原始内容 → 恢复代码/数据 → 跳到 OEP → 真实 Native 代码
```

> 核心：UPX 是"运行过程中恢复原始程序并继续执行"，
> 所以**运行时内存状态是分析变种 UPX 的关键依据**。

### Android 完整链路

```
System.loadLibrary → linker → 映射 PT_LOAD → UPX Stub → 运行时解压
   → 原始 Native 代码 → JNI_OnLoad → RegisterNatives → 业务代码
```

### 什么是变种 UPX

不是官方壳，而是以 UPX 为基础修改 Stub / 文件结构 / 特征 / 流程后的样本：

```
标准 UPX → 修改 Stub → 删除明显特征 → 加入额外代码 → 改变控制流 → 加反调试 → 变种
```

---

## 脱壳 14 步法与 OEP

```
① 判断文件类型      ② 分析 ELF          ③ 判断 UPX 特征     ④ 尝试 upx -t / -d
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

### 核心警示：不要只依赖 UPX 字符串

> ❌ 搜索 `UPX!` → 找 Stub → 固定地址找 OEP（对魔改样本不可靠）
> ✅ **不是"有没有 UPX 字符串"，而是"运行过程中原始代码在哪里被恢复并开始执行"**

重点观察：Stub 控制流 / 哪些内存区被写入 / 写入数据是否像 ELF / 哪些区随后执行 /
控制流何时离开 Stub / 是否出现原始函数结构。

---

## 判定：不看文件名，只看结构特征

### 特征对照（本工程实测）

| 特征 | 未加壳 | UPX 加壳 | 原理 |
|---|---|---|---|
| 节区头 `e_shnum` | 23 | **0** | 加壳剥离节区表，IDA 看不到 `.text/.rodata` |
| 整文件熵 | 4.470 | **7.31** | 正常代码 4~6.5；>7.0 = 压缩/加密 |
| 大解压缓冲段 | 无 | **0x1000→0x13000（19x）** | UPX 的 UPX0：文件里几乎空、内存中很大 |
| `e_entry` 位置 | 0x0（段首） | **0x1358C（小 stub 段内）** | 入口先跑解压代码 |
| 总 memsz / 文件大小 | 0.99x | **15.30x** | 运行时解压出远多于文件的内容 |
| 尾部 sz_unc 字段 | 无 | **70012** | UPX 尾部结构记录解压后大小 |
| `UPX!` 魔数 | 0 | 标准 4 / **变种 0** | 变种专门抹掉它 |

```bash
python tools/detect_packer.py <file> [--brief] [--verify]
```

判定：标准 = 有 `UPX!` 且分数高；**变种 = 搜不到 `UPX!` 但加壳特征全在**。

### 阈值设计踩过的坑（重要）

| 坑 | 现象 | 修正 |
|---|---|---|
| 解压缓冲段不加下限 | 普通 `.bss`（0xEC→0x9E0）被误判成 UPX 解压区 | 要求 `memsz ≥ 32KB` |
| 魔数候选排除"4 字节全同" | 真实占位符 `XXXX` 被自己误杀 | 只排除 `00`/`FF` 纯填充 |
| 只用静态候选 | 出现 `\x00\x00|\x11` 这类巧合项 | 必须 `--verify` 打补丁跑 `upx -t` 实证 |

```bash
python tools/detect_packer.py libtarget_upx_variant.so --verify
# b'XXXX' x4 @ 0x98/0xc03/0x14b8/0x14c0 -> upx -t OK   <= 真魔数
# b'\x00\x00|\x11' x2                   -> upx -t FAIL  (巧合项)
```

---

## 解法 A：修复特征 → 官方解包（脚本在前，手动在后）

**适用**：变种只抹特征，Stub 与控制流未动。（「手动复现」节 起的手动步骤 = 「脚本跑通」节 脚本所做之事的展开）

### 脚本跑通（先拿到正确答案）

```bash
python tools/solve_variant.py libtarget_upx_variant.so analysis_output/solve_unpacked.so --orig libtarget_orig.so
```

实跑输出（每一行对应脚本内部的一步）：

```
[*] 样本: libtarget_upx_variant.so (5348 bytes)
[*] 现有 'UPX!' 数量: 0
[*] 使用的 upx: upx.exe
    候选 token b'\x00\x00\x00\x00' x34 -> upx -t FAIL
    候选 token b'\x01\x00\x00\x00' x7 -> upx -t FAIL
    候选 token b'XXXX' x4 -> upx -t OK
[+] 确定被篡改的 token: b'XXXX' -> 还原为 'UPX!'（共 4 处）
[+] 解包成功: analysis_output/solve_unpacked.so (70012 bytes)

[*] 校验：脱壳后应找回的锚点
    AegisDroid-2026-SECRET-KEY     OK 找到
    flag{upx_unpacking_is_fun}     OK 找到
    com/aegis/NativeLib            OK 找到
    getFlag                        OK 找到
    JNI_OnLoad                     OK 找到
    check_license                  OK 找到
    blob_selfcheck                 OK 找到

[*] 与原始 SO 对比: libtarget_orig.so (70012 bytes)
    大小: 70012 vs 70012  一致
    除 e_type 外差异字节数: 0  => 内容一致，脱壳成功
```

**逐行判读**：
- 脚本枚举"重复出现的 4 字节 token"当候选 → 逐个打补丁用 `upx -t` **实证** → `XXXX` 通过即真魔数（静态候选必有巧合项，必须实证，见 「阈值设计踩过的坑」节）。
- `使用的 upx` 一行：upx 由 `--upx > 环境变量 UPX > 工程根 upx.exe > PATH` 定位；日志只显示文件名，**不落绝对路径**。
- 解包产物 70012 == 原始 SO、除 `e_type` 外 0 字节差异 → 脱壳成功（三条判据见 「判据」节）。

### 自己看字节定位（hexdump 对照）

stub 区：
```
xxd -s 0x90 -l 32 libtarget_upx.so
xxd -s 0x90 -l 32 libtarget_upx_variant.so

标准: 00000090: 0000 0000 5a64 6ac0 5550 5821 300a 0e17  ....Zdj.UPX!0...
变种: 00000090: 0000 0000 5a64 6ac0 5858 5858 300a 0e17  ....Zdj.XXXX0...
                               ^^^^^^^^^^^^ 5550 5821 -> 5858 5858
```

文件尾部（UPX 尾部结构在这里）：
```
xxd -s 0x14a0 -l 68 libtarget_upx.so

000014b0: 0004 80ff 0000 0000 5550 5821 0000 0000   ........UPX!....
000014c0: 5550 5821 0e17 0308 5412 1c42 e9b3 d4f9   UPX!....T..B....  ← 两处魔数+版本/格式
000014d0: 7c11 0100 c014 0000 7c11 0100 0000 006b   |.......|......k  ← 7c11 0100 = 70012
000014e0: a000 0000
```

尾部 `0x0001117C = 70012`（远大于文件 5348）→ 证明被压缩过。变种同样位置为 `5858 5858`。

### 被篡改的 4 处偏移

| 偏移 | 区域 | 标准字节 | 变种字节 |
|---|---|---|---|
| `0x98` | stub 代码区 | `55 50 58 21` | `58 58 58 58` |
| `0xC03` | stub 代码区 | `55 50 58 21` | `58 58 58 58` |
| `0x14B8` | 尾部结构 | `55 50 58 21` | `58 58 58 58` |
| `0x14C0` | 尾部结构 | `55 50 58 21` | `58 58 58 58` |

### 手改方法

**十六进制编辑器**（HxD / 010 Editor / ImHex）：跳到上述 4 个偏移，各改成 `55 50 58 21`，另存 `fixed.so`。

**命令行等价**：
```bash
python -c "
d=bytearray(open('libtarget_upx_variant.so','rb').read())
for o in (0x98,0xC03,0x14B8,0x14C0): d[o:o+4]=b'UPX!'
open('fixed.so','wb').write(d)"

python -c "open('fixed.so','wb').write(open('libtarget_upx_variant.so','rb').read().replace(b'XXXX',b'UPX!'))"
```

### ⚠️ 必须 4 处全改（本题核心）

| 操作 | `upx -t` |
|---|---|
| 只改 `0x98` / `0xC03` / `0x14B8` / `0x14C0` **任意单独一处** | **FAIL** |
| **4 处全改** | **OK** |

**原因**：UPX 内部校验和覆盖所有内嵌魔数，只修一处其余仍让校验失败（报 `not packed by UPX`）。

### 解包与三条验证判据

```bash
./upx.exe -t fixed.so && ./upx.exe -d fixed.so -o unpacked.so
```

1. **体积恢复**：`unpacked.so = 70012` == `libtarget_orig.so = 70012`
2. **锚点找回**：`AegisDroid-2026-SECRET-KEY`、`flag{upx_unpacking_is_fun}`、
   `com/aegis/NativeLib`、`getFlag`、`JNI_OnLoad`、`check_license`、`blob_selfcheck` 全部可见
3. **字节一致**：与 `libtarget_orig.so` 除偏移 16 的 `e_type` 外 **0 字节差异**
   （解出 ET_EXEC=2，原始 ET_DYN=3；代码内容完全一致）

IDA 打开应看到调用链：`JNI_OnLoad → RegisterNatives → getFlag → check_license`

### 何时失效

若 4 处全改后 `upx -t` 仍失败 → 说明不止改了特征（Stub/控制流/压缩参数被改）→ **转解法 B**。

---

## 解法 B：内存 Dump + ELF Fix（通用）

**这是真实对抗的主力路线**，完全不依赖 UPX 的特征与校验和。

### 思路

```
让程序跑起来 → 等 Stub 解压完 → dump 进程内存 → 重建 ELF → 载入 IDA
```

### 真机 Frida 步骤

把 `.so` 放进 APK 的 `lib/armeabi-v7a/`，安装运行，Frida 附加：

```javascript
// 等模块加载完成后 dump（此时内存里已是解压后的原始代码）
const lib = "libtarget_upx_variant.so";
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

真机用法：`dump_fix.py <dump.bin> <模块基址> <out.so> --arch arm [--entry-rva HEX]`

### OEP 定位

Stub 解压完跳转回原始入口。观察 PC 何时离开 stub 段（本例 stub 在 `vaddr=0x13000`），
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
 ├─ upx -t 通过 ─────────────► 直接 upx -d（标准壳，不必手脱）
 └─ upx -t 失败
      ├─ 结构仍像 UPX（无节区表/高熵/大解压缓冲/入口在 stub）
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
| UPX 4.2.4 打包 ET_EXEC（改 e_type=2） | **成功** 70012→5348（7.64%） |
| UPX 3.96 + `--android-shlib` | `NotCompressibleException` |
| 样本加大到 70KB 再打包 | 仍失败 → **不是体积问题，是结构问题** |
| 打包后把 e_type 改回 DYN | `upx -t` 报 `ElfXX_Ehdr corrupted` |

> 另注：UPX 4.2.4 已移除 `--android-shlib`，但仍会提示该选项（过时提示，别被误导）。

### 校验和覆盖全部内嵌魔数

见 「手动复现」节 —— 只改一处必失败。

### 静态候选必有巧合项

见 「阈值设计踩过的坑」节 —— 用 `--verify` 实证。

---

## 反复练习：备份与一键回归

原始样本已备份到 `pristine/`（含 sha256 清单）：

```bash
python tools/reset_lab.py status     # 环境是否被练脏
python tools/reset_lab.py restore    # 还原 4 个样本 + 删练习产物 + 清空 analysis_output/
python tools/reset_lab.py backup     # 改过源码后刷新基线
```

建议每轮从 `restore` 开始：
1. `detect_packer.py` 判定三个样本（不看文件名）
2. hexdump 自己找出 4 处魔数
3. 十六进制编辑器手改 4 处 → `upx -t` → `upx -d`
4. 三条判据验证
5. 进阶：故意只改 1~3 处，体会校验和
6. 进阶：跑通解法 B 的 dump + ELF Fix

---

## 命令速查

```bash
# 判定
python tools/detect_packer.py <file> [--brief] [--verify]

# 静态分析
python tools/elf_scan.py   libtarget_orig.so libtarget_upx.so libtarget_upx_variant.so
python tools/upx_probe.py  libtarget_orig.so libtarget_upx.so libtarget_upx_variant.so

# 解法 A
python tools/solve_variant.py libtarget_upx_variant.so unpacked.so --orig libtarget_orig.so

# 解法 B
python tools/simulate_dump.py libtarget_orig.so analysis_output/sim_dump.bin
python tools/dump_fix.py analysis_output/sim_dump.bin 0x0 analysis_output/dump_fixed.so --arch arm

# 重新生成样本
bash build/build_android.sh    # NDK 编译原始 .so
bash build/pack.sh             # 生成标准 + 变种

# 回归
python tools/reset_lab.py restore
python tools/check_so_samples.py        # B13 双向断言：stripped 必触发 / orig 必不触发 / UPX 判定不丢
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
upx_practice/
├── README.md                  ★ 本手册（唯一文档）
├── upx.exe                    UPX 4.2.4（默认用它；可用 UPX=<路径> 覆盖）
├── tools/
│   ├── detect_packer.py       ★ 结构特征判定（加壳/UPX/变种，--verify 实证）
│   ├── reset_lab.py           ★ 备份 / 状态 / 回归
│   ├── solve_variant.py       解法 A 自动化
│   ├── dump_fix.py            解法 B：内存 dump → 重建 ELF
│   ├── simulate_dump.py       生成模拟内存镜像
│   ├── elf_scan.py            无依赖 ELF 解析 + UPX 指纹
│   ├── upx_probe.py           批量 upx -t/-l/-d
│   ├── make_variant.py        由标准包生成变种
│   ├── make_stripped_so.py    生成 B13 正样本（剥节头表：自实现 Linker 形态）
│   ├── check_so_samples.py    双向回归（B13 正/负样本 + 防 UPX 判定回归）
│   └── upx396.exe             UPX 3.96（带 --android-shlib，对照用）
├── src/target.c               样本源码（JNI_OnLoad/RegisterNatives/check_license/blob_selfcheck）
├── build/
│   ├── locate.sh              ★ 工具链自动探测（NDK / UPX / python，四档优先级）
│   ├── build_android.sh       NDK 编译原始 .so
│   └── pack.sh                生成标准 + 变种样本
├── pristine/                  原始样本备份 + sha256 清单（勿手改）
├── analysis_output/           脚本产出（elf_scan.txt / upx_probe.txt / sim_dump.bin / dump_fixed.so）
├── libtarget_orig.so          【原始 SO】ET_DYN
├── libtarget_orig_arm64.so    ARM64 原始 .so（对照）
├── libtarget_upx.so           【标准 UPX】upx -d 可解
├── libtarget_upx_variant.so   【变种 UPX】upx -d 失败
└── libtarget_stripped.so      【B13 正样本】节头表剥离，触发「疑似自实现 Linker」
```

---

## 一句话记住

> **判断 UPX 不靠字符串，靠"运行时原始代码在哪里恢复并开始执行"。**
> 标准壳用 `upx -d`；只抹特征用**特征修复（必须全部还原）**；Stub 被改就**内存 dump + ELF Fix**。
