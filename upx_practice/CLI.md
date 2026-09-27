# CLI.md — 命令行路线：用 xxd / readelf / sha256sum 逐字节复现每一步

> 本文件与 `SCRIPT.md`、`GUI.md` **结构完全平行**（同一套章节骨架一一对应），只讲「命令行怎么做」。
> 命令行工具用 **xxd / readelf / upx / sha256sum / cmp / grep**——目的是**亲手走一遍脚本做的每一步**，
> 而不是只会跑脚本。配套的一键脚本见 `SCRIPT.md`；图形工具（010 Editor / IDA / binwalk）见 `GUI.md`。
>
> 所有命令单行书写、完整可复制，每行配行内注释 + `# =>` 预期输出；输出片段全部实跑后贴入。
> **路线分工**：判定靠命令（可量化、可写进判据），看懂靠 GUI（IDA 出调用链、binwalk 出曲线）。

---

## 概述与三分钟跑一遍

**项目定位 / 建模说明**：同 `SCRIPT.md`——标准 UPX 官方打包、变种由 `make_variant.py` 抹特征生成，样本自同一份源码 NDK 编译，可逐字节对照。

### 三分钟跑一遍（命令行版 · 全部样本形态）

```bash
cd upx_practice

# ① 判定入口：脚本给量化结论（数值依据就是下面的 xxd/readelf）
python tools/detect_packer.py samples/so/libtarget_orig.so samples/so/libtarget_upx.so samples/so/libtarget_upx_variant.so samples/so/libtarget_stripped.so
#   => orig 0 分 / 标准 16 分 / 变种 16 分 / stripped B13（逐项解读见「判定」）

# ② xxd 直接看魔数：标准样本 4 处 UPX!，变种同位置变成 XXXX
xxd -s 0x90 -l 32 samples/so/libtarget_upx.so
#   => 00000090: 0000 0000 5a64 6ac0 5550 5821 300a 0e17  ....Zdj.UPX!0...
xxd -s 0x90 -l 32 samples/so/libtarget_upx_variant.so
#   => 00000090: 0000 0000 5a64 6ac0 5858 5858 300a 0e17  ....Zdj.XXXX0...

# ③ readelf 看节头剥离（F1 / B13 的字节级事实）
readelf -h samples/so/libtarget_orig.so          # => Number of section headers: 23（正常 NDK .so）
readelf -h samples/so/libtarget_upx.so           # => Number of section headers: 0（加壳剥节头）
readelf -h samples/so/libtarget_stripped.so      # => Type: DYN + section headers: 0（B13 形态）

# ④ upx 直接操作：标准能解、变种不能
./upx.exe -t samples/so/libtarget_upx.so         # => testing samples/so/libtarget_upx.so [OK]
./upx.exe -d samples/so/libtarget_upx.so -o out.so && ./upx.exe -t samples/so/libtarget_upx_variant.so
#   => Unpacked 1 file.（out.so=70012）/ 变种: NotPackedException: not packed by UPX

# ⑤ 验证：与黄金样本逐字节对照
sha256sum samples/so/libtarget_orig.so out.so && cmp -l samples/so/libtarget_orig.so out.so
#   => 哈希不同（e_type 一处）；cmp 仅第 17 字节 1 处差异（03 vs 02）
```

五步走通就说明环境 OK：判定结论每一条都能落到 `xxd`/`readelf` 的字节读数上。`readelf` 在本机用 NDK 自带的 `llvm-readelf`（在 NDK 的 `toolchains/llvm/prebuilt/<host>/bin/` 下；`readelf` 名字同样可）。

---

## 工程结构

同 `SCRIPT.md`——样本一律住 `samples/so/`（分析对象），命令行产出的练习文件（`fixed.so` / `out.so` / `unpacked.so`）落在工程根、脚本报告落 `analysis_output/`；`reset_lab.py` 会识别并清理这些练习产物。

---

## 知识点

原理与失效边界见 `SCRIPT.md`「知识点」；本路线只给「判据 → 用哪条命令看哪个字节」的映射：

| 判据 | 量化值 | 命令行看法 |
|---|---|---|
| F1 节区头剥离 | `e_shnum=0` | `readelf -h` 看 `Number of section headers` |
| F2 整文件熵 | orig 4.470 / 壳 7.309 | detect 输出，或 python 一行手算（见「判定」） |
| F3 大解压缓冲 | `0x1000→0x13000` | `readelf -l` 看 PT_LOAD 的 FileSiz/MemSiz 列 |
| F4 入口在 stub | `e_entry=0x1358C` | `readelf -h` 的 Entry point + `readelf -l` 对照段范围 |
| F6/F8 魔数 | `UPX!`×4 / `XXXX`×4 | `xxd` 在 4 处偏移直接读字节 |
| B13 | ET_DYN + `e_shnum=0` | `readelf -h` 两行联读 |
| 验证 | 除 e_type 外 0 差异 | `sha256sum` + `cmp -l` |

---

## 判定

### readelf 看头部与段（F1 / F3 / F4 / B13 的字节级依据）

```bash
# 原始 .so：节头完整、入口在段首、3 个 PT_LOAD 尺寸正常
readelf -h samples/so/libtarget_orig.so
#   => Type: DYN / Entry point address: 0x0
#   => Start of section headers: 69092 / Number of section headers: 23   ← 正常 NDK .so
readelf -l samples/so/libtarget_orig.so
#   => LOAD 0x000000 0x00000000 ... 0x1043f 0x1043f R    ← filesz==memsz，无解压缓冲
#   => LOAD 0x010440 0x00011440 ... 0x001e0 0x001e0 R E

# 标准 UPX：3 个程序头、节头 0、入口在 stub 段、第一段 memsz 是 filesz 的 19 倍
readelf -h samples/so/libtarget_upx.so
#   => Type: EXEC / Entry point address: 0x1358c
#   => Number of section headers: 0     ← F1 命中
readelf -l samples/so/libtarget_upx.so
#   => LOAD 0x000000 0x00000000 ... 0x01000 0x13000 RW   ← F3：filesz 0x1000 -> memsz 0x13000（19.0x）
#   => LOAD 0x000000 0x00013000 ... 0x00faa 0x00faa R E   ← stub 段；0x1358C 落在它里面（F4）

# B13 样本：e_type 仍是 DYN，但节头表偏移与数量都被清零
readelf -h samples/so/libtarget_stripped.so
#   => Type: DYN (Shared object file)
#   => Start of section headers: 0 (bytes into file)   ← 与 orig 的 69092 对比
#   => Number of section headers: 0
readelf -S samples/so/libtarget_stripped.so
#   => There are no sections in this file.
readelf -S samples/so/libtarget_upx.so
#   => There are no sections in this file.              ← 加壳样本同样无节（F1 的另一面）
```

**逐行判读**：`readelf -h` 一次回答「是不是 DYN / 入口在哪 / 有没有节头」三件事；`readelf -l` 的 MemSiz 列远大于 FileSiz 即解压缓冲。注意 B13 与「UPX 加壳」的区分点：**B13 样本 e_type 仍是 ET_DYN**，加壳样本被 pack.sh 临时改成了 ET_EXEC——所以"无节头"要联读 e_type 才能分类。

### xxd 定位魔数（F6 / F8，4 处偏移）

```bash
# 偏移 0x98（stub 代码区）：标准 UPX! vs 变种 XXXX
xxd -s 0x90 -l 32 samples/so/libtarget_upx.so
#   00000090: 0000 0000 5a64 6ac0 5550 5821 300a 0e17  ....Zdj.UPX!0...
xxd -s 0x90 -l 32 samples/so/libtarget_upx_variant.so
#   00000090: 0000 0000 5a64 6ac0 5858 5858 300a 0e17  ....Zdj.XXXX0...
#                                  ^^^^^^^^^^^^ 5550 5821 -> 5858 5858（4 字节全改）

# 偏移 0xc03（stub 代码区第二处）
xxd -s 0xc00 -l 16 samples/so/libtarget_upx.so
#   00000c00: f0b7 7e55 5058 21f0 4f17 3f01 801d ff10  ..~UPX!.O.?.....
xxd -s 0xc00 -l 16 samples/so/libtarget_upx_variant.so
#   00000c00: f0b7 7e58 5858 58f0 4f17 3f01 801d ff10  ..~XXXX.O.?.....

# 偏移 0x14b8 / 0x14c0（尾部结构两处；连带看 sz_unc 字段）
xxd -s 0x14a0 -l 68 samples/so/libtarget_upx.so
#   000014b0: 0004 80ff 0000 0000 5550 5821 0000 0000  ........UPX!....
#   000014c0: 5550 5821 0e17 0308 5412 1c42 e9b3 d4f9   UPX!....T..B....
#   000014d0: 7c11 0100 c014 0000 7c11 0100 0000 006b   |.......|......k
xxd -s 0x14a0 -l 68 samples/so/libtarget_upx_variant.so
#   000014b0: 0004 80ff 0000 0000 5858 5858 0000 0000  ........XXXX....
#   000014c0: 5858 5858 0e17 0308 5412 1c42 e9b3 d4f9   XXXX....T..B....
#   000014d0: 7c11 0100 c014 0000 7c11 0100 0000 006b   |.......|......k
```

**逐行判读**：4 处魔数 = `0x98`、`0xc03`（stub 区）+ `0x14b8`、`0x14c0`（尾部结构）。标准样本这 4 处都是 `55 50 58 21`（`UPX!`），变种全被替换成 `58 58 58 58`（`XXXX`）——两文件逐字节对比全文件恰好 12 字节不同（每处 4 字节、第 3 字节 `58 21`→`58 58` 有重叠故计数为 12），都在这 4 处偏移内。
尾部 `7c 11 01 00`（`0x0001117C` 小端）= **70012**：UPX 尾部结构记录的解压后大小，远大于文件自身 5348 字节——F7 的字节级依据。

### 熵（F2）的一行手算版

```bash
# 纯标准库手算整文件熵，结果应与 detect_packer.py 输出一致（两者互为校验）
python -c "import math,collections;d=open('samples/so/libtarget_upx.so','rb').read();c=collections.Counter(d);n=len(d);print('entropy=%.3f'%(-sum(v/n*math.log2(v/n) for v in c.values())))"
#   => entropy=7.309
python -c "import math,collections;d=open('samples/so/libtarget_orig.so','rb').read();c=collections.Counter(d);n=len(d);print('entropy=%.3f'%(-sum(v/n*math.log2(v/n) for v in c.values())))"
#   => entropy=4.470
```

### upx 批量探测

```bash
# upx_probe.py = 批量 upx -t/-l/-d 的包装（一次看清四个样本谁可自动解包）
python tools/upx_probe.py samples/so/libtarget_orig.so samples/so/libtarget_upx.so samples/so/libtarget_upx_variant.so samples/so/libtarget_stripped.so
#   => orig:    upx -t FAIL (rc=2)   -- 需要手工/动态脱壳
#   => upx:     upx -t OK;  -l 显示 70012 -> 5348 7.64% linux/arm;  -d OK -> 70012 bytes
#   => variant: upx -t FAIL (rc=2)   -- 需要手工/动态脱壳
#   => stripped: upx -t FAIL (rc=2)  -- 需要手工/动态脱壳
```

---

## 脱壳

### 标准壳：upx -t / -d 直接操作

```bash
# -t 先验证可解（校验和过不过），-d 解出到指定文件
./upx.exe -t samples/so/libtarget_upx.so
#   => testing samples/so/libtarget_upx.so [OK]   /   Tested 1 file.
./upx.exe -d samples/so/libtarget_upx.so -o out.so
#   => 70012 <- 5348   7.64%   linux/arm   out.so /   Unpacked 1 file.
```

### 变种壳：命令行手改 4 处偏移（解法 A 的手动版）

```bash
# 先实证确认真魔数（静态候选有巧合项，必须 upx -t 实证）
python tools/detect_packer.py samples/so/libtarget_upx_variant.so --verify
#   => b'XXXX' x4 -> upx -t OK   <= 真魔数；其余 \x00\x00|\x11 等候选均 FAIL

# 命令行等价的"十六进制编辑器手改"：把 4 处偏移各 4 字节还原成 UPX!
python -c "
d=bytearray(open('samples/so/libtarget_upx_variant.so','rb').read())
for o in (0x98,0xc03,0x14b8,0x14c0): d[o:o+4]=b'UPX!'
open('fixed.so','wb').write(d)"
#   => 无输出；fixed.so = 5348 字节（体积不变）

# 也可整体替换（4 处 token 完全一致时两法等价）
python -c "open('fixed.so','wb').write(open('samples/so/libtarget_upx_variant.so','rb').read().replace(b'XXXX',b'UPX!'))"

# 验证 + 解包
./upx.exe -t fixed.so && ./upx.exe -d fixed.so -o unpacked.so
#   => testing fixed.so [OK] / Unpacked 1 file.
```

**⚠️ 必须 4 处全改**：只改 `0x98/0xc03/0x14b8/0x14c0` 任意单独一处，`upx -t` 实测报
`NotPackedException: not packed by UPX`——UPX 校验和覆盖所有内嵌魔数。
若 4 处全改后仍失败 → Stub/控制流/压缩参数也被改 → 转解法 B（`SCRIPT.md`「脱壳」）。

### 解法 B 的命令行演练

```bash
# simulate_dump 按 PT_LOAD 生成"运行态内存镜像"，dump_fix 重建可载入的 ELF
python tools/simulate_dump.py samples/so/libtarget_orig.so analysis_output/sim_dump.bin
#   => [+] simulated dump -> analysis_output/sim_dump.bin  base=0x0 size=77824 (from 3 PT_LOAD, 32-bit)
python tools/dump_fix.py analysis_output/sim_dump.bin 0x0 analysis_output/dump_fixed.so --arch arm
#   => [+] wrote analysis_output/dump_fixed.so: base=0x0 size=77824 arch=arm entry=0x0
```

---

## 验证

```bash
# 判据 1：体积恢复
ls -l samples/so/libtarget_orig.so unpacked.so
#   => 两边都是 70012 字节

# 判据 2：锚点找回（7 个锚点在脱壳产物里逐个 grep）
python -c "
d=open('unpacked.so','rb').read()
for a in ['AegisDroid-2026-SECRET-KEY','flag{upx_unpacking_is_fun}','com/aegis/NativeLib','getFlag','JNI_OnLoad','check_license','blob_selfcheck']:
    print(a, 'OK' if a.encode() in d else 'MISS')"
#   => 7 行全 OK

# 判据 3：字节一致（sha256 定变化、cmp 定位差异）
sha256sum samples/so/libtarget_orig.so unpacked.so
#   => 8905e1ab...  samples/so/libtarget_orig.so
#   => d3067c0c...  unpacked.so        ← 哈希不同：有 e_type 一处差异
cmp -l samples/so/libtarget_orig.so unpacked.so
#      17   3   2     ← 全文件唯一差异：1-based 第 17 字节 = 偏移 16 的 e_type（03=ET_DYN vs 02=ET_EXEC）
```

**逐行判读**：sha256 不同不要慌——`cmp -l` 精确指出**只有偏移 16 的 e_type 一处差异**（`upx -d` 解出的是打包时的临时 ET_EXEC 形态），代码与数据逐字节一致，脱壳成功。

---

## 决策流程

```
命令行版判定顺序（结论与 SCRIPT.md 相同，这里给出每步用的命令）：
  readelf -h <file>
 ├─ ET_DYN + 节头 23 完整 ──► 结构正常；再手算熵（≈4.5）确认 → 未见已知特征（≠未加壳）
 ├─ ET_EXEC + 节头 0 ────────► upx -t
 │     ├─ OK ───────────────► 标准 UPX：直接 upx -d
 │     └─ FAIL ─────────────► xxd 找 4 处魔数（UPX! 在？不在？）
 │           ├─ UPX! 在 ─────► 结构/校验被改 → 解法 B
 │           └─ 不在 ─────────► 实证候选（--verify）→ 4 处全改 → upx -t
 │                              ├─ OK → upx -d（解法 A 成）
 │                              └─ FAIL → 解法 B（内存 dump + ELF Fix）
 └─ ET_DYN + 节头 0 ─────────► B13：疑似 SO 加壳 / 自实现 Linker → 须人工 ELF 层确认
```

---

## 反复练习

复位与回归命令同 `SCRIPT.md`「反复练习」（`reset_lab.py` / `check_so_samples.py`）；命令行路线的增量只有一条：**练完自己用 `xxd` 找 4 处 `XXXX`，再用 `cmp` 验证你手改的 `fixed.so` 与脚本产物 `unpacked.so` 逐字节一致**——两个路线的产物完全可互换，互为校验。

```bash
# 练习产物判脏（out.so/fixed.so/unpacked.so 都会被 reset 识别为练习产物）
python tools/reset_lab.py status
#   => 列出练习产物；restore 一键清掉
```

---

## 踩坑与速查

### 踩坑（命令行 / 工具侧）

1. **本机没有独立 `readelf`**：用 NDK 自带的 `llvm-readelf`（`toolchains/llvm/prebuilt/<host>/bin/` 下），参数兼容 GNU readelf；四档探测见 `build/locate.sh`。
2. **`cmp -l` 是 1-based**：输出 `17` 对应 0 偏移 16（e_type），写文档/断言时别写成"第 16 字节"。
3. **`--android-shlib` 是 UPX 3.x 的旧选项**：4.2.4 已移除；本机实测 3.96 带 `--android-shlib` 打包 ET_DYN 仍报 `NotCompressibleException`——对 Android `.so` 别指望这个选项，正确姿势是 pack.sh 的「临时改 ET_EXEC」。
4. **xxd 的 `-s` 是十六进制**：`-s 0x14a0` 从偏移 5280 开始；等宽窗口（`-l 68`）对齐到 16 字节边界便于对照。
5. **Windows 下 `./upx.exe` 必须带 `.exe`**：`upx` 裸名可能撞上 PATH 里其他版本——工程根自带 `upx.exe` 优先级高于 PATH（`SCRIPT.md`「速查」的四档表），换版本要显式 `UPX=<路径>`。
6. **整体替换 `XXXX`→`UPX!` 只有在 4 处 token 全一致时才等价于按偏移改**：本工程变种恰好如此（`make_variant.py` 全量替换）；真实样本里 `XXXX` 可能还出现在压缩数据中（巧合字节），按偏移改才安全。
7. **中文乱码**：`PYTHONIOENCODING=utf-8`（PowerShell `$env:PYTHONIOENCODING='utf-8'`）。
8. **本机只有 `python` 无 `python3`**。

### 速查

```bash
# 判定（字节级依据）
readelf -h samples/so/libtarget_upx.so                 # e_type / e_entry / e_shnum 三联读
readelf -l samples/so/libtarget_upx.so                 # PT_LOAD FileSiz vs MemSiz（解压缓冲）
readelf -S samples/so/libtarget_stripped.so            # There are no sections（B13/F1）
xxd -s 0x90 -l 32 samples/so/libtarget_upx.so           # 魔数第一处（0x98）
xxd -s 0xc00 -l 16 samples/so/libtarget_upx_variant.so  # 魔数第二处（0xc03）
xxd -s 0x14a0 -l 68 samples/so/libtarget_upx_variant.so # 尾部两处（0x14b8/0x14c0）+ sz_unc 7c110100
python -c "import math,collections;d=open('samples/so/libtarget_upx.so','rb').read();c=collections.Counter(d);n=len(d);print('%.3f'%(-sum(v/n*math.log2(v/n) for v in c.values())))"  # 熵手算 => 7.309

# 脱壳
./upx.exe -t samples/so/libtarget_upx.so && ./upx.exe -d samples/so/libtarget_upx.so -o out.so
python -c "d=bytearray(open('samples/so/libtarget_upx_variant.so','rb').read());[d.__setitem__(slice(o,o+4),b'UPX!') for o in (0x98,0xc03,0x14b8,0x14c0)];open('fixed.so','wb').write(d)"
./upx.exe -t fixed.so && ./upx.exe -d fixed.so -o unpacked.so

# 验证
sha256sum samples/so/libtarget_orig.so unpacked.so
cmp -l samples/so/libtarget_orig.so unpacked.so        # => 仅 1 处：17 列 03 vs 02（e_type）

# 回归 / 复位
python tools/check_so_samples.py            # => 0 项失败
python tools/reset_lab.py restore
```
