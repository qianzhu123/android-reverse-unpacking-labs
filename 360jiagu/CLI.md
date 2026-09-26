# CLI.md — 命令行路线：用 xxd / readelf / sha256sum 逐字节复现每一步

> 本文件与 `SCRIPT.md`、`GUI.md` **结构完全平行**（同一套章节骨架一一对应），只讲「命令行怎么做」。
> 命令行工具用 **xxd / readelf / upx / sha256sum / cmp / grep**——目的是**亲手走一遍脚本做的每一步**，
> 而不是只会跑脚本。配套的一键脚本见 `SCRIPT.md`；图形工具（010 Editor / IDA / binwalk）见 `GUI.md`。
>
> 所有命令单行书写、完整可复制，每行配行内注释 + `# =>` 预期输出；输出片段全部实跑后贴入。
> **路线分工**：判定靠命令（可量化、可写进判据），看懂靠 GUI（IDA 出调用链、binwalk 出曲线）。

---

## 概述与三分钟跑一遍

**项目定位 / 建模说明**：同 `SCRIPT.md`——360 加固 native 层建模为「改版 UPX」，样本自同一份源码 NDK 编译，可逐字节对照。

### 三分钟跑一遍（命令行版 · 全部样本形态）

```bash
cd 360jiagu

# ① 判定入口：脚本给量化结论（数值依据就是下面的 xxd/readelf）
python tools/detect_360.py libtarget_orig.so libtarget_360.so libtarget_360_variant.so libtarget_stripped.so
#   => orig 0 分 / 标准 16 分 / 变种 16 分 / stripped B13（逐项解读见「判定」）

# ② xxd 直接看魔数：标准样本 4 处 UPX!，变种同位置变成 JG!!
xxd -s 0x90 -l 32 libtarget_360.so
#   => 00000090: 0000 0000 5a64 6ac0 5550 5821 300a 0e17  ....Zdj.UPX!0...
xxd -s 0x90 -l 32 libtarget_360_variant.so
#   => 00000090: 0000 0000 5a64 6ac0 4a47 2121 300a 0e17  ....Zdj.JG!!0...

# ③ readelf 看节头剥离（F1 / B13 的字节级事实）
readelf -h libtarget_orig.so          # => Number of section headers: 24（正常 NDK .so）
readelf -h libtarget_360.so           # => Number of section headers: 0（加壳剥节头）
readelf -h libtarget_stripped.so      # => Type: DYN + section headers: 0（B13 形态）

# ④ upx 直接操作：标准能解、变种不能
./upx.exe -t libtarget_360.so         # => testing libtarget_360.so [OK]
./upx.exe -d libtarget_360.so -o out.so && ./upx.exe -t libtarget_360_variant.so
#   => Unpacked 1 file.（out.so=43888）/ 变种: NotPackedException: not packed by UPX

# ⑤ 验证：与黄金样本逐字节对照
sha256sum libtarget_orig.so out.so && cmp -l libtarget_orig.so out.so
#   => 哈希不同（e_type 一处）；cmp 仅第 17 字节 1 处差异（03 vs 02）
```

五步走通就说明环境 OK：判定结论每一条都能落到 `xxd`/`readelf` 的字节读数上。`readelf` 在本机用 NDK 自带的 `llvm-readelf`（在 NDK 的 `toolchains/llvm/prebuilt/<host>/bin/` 下；`readelf` 名字同样可）。

---

## 工程结构

同 `SCRIPT.md`——本路线直接在工程根操作 `libtarget_*.so` 与 `tools/`、`analysis_output/`，无额外目录。

---

## 知识点

原理与失效边界见 `SCRIPT.md`「知识点」；本路线只给「判据 → 用哪条命令看哪个字节」的映射：

| 判据 | 量化值 | 命令行看法 |
|---|---|---|
| F1 节区头剥离 | `e_shnum=0` | `readelf -h` 看 `Number of section headers` |
| F2 整文件熵 | orig 5.011 / 壳 7.598 | detect 输出，或 python 一行手算（见「判定」） |
| F3 大解压缓冲 | `0x1000→0xD0A0` | `readelf -l` 看 PT_LOAD 的 FileSiz/MemSiz 列 |
| F4 入口在 stub | `e_entry=0x11684` | `readelf -h` 的 Entry point + `readelf -l` 对照段范围 |
| F6/F8 魔数 | `UPX!`×4 / `JG!!`×4 | `xxd` 在 4 处偏移直接读字节 |
| B13 | ET_DYN + `e_shnum=0` | `readelf -h` 两行联读 |
| 验证 | 除 e_type 外 0 差异 | `sha256sum` + `cmp -l` |

---

## 判定

### readelf 看头部与段（F1 / F3 / F4 / B13 的字节级依据）

```bash
# 原始 .so：节头完整、入口在段首、4 个 PT_LOAD 尺寸正常
readelf -h libtarget_orig.so
#   => Type: DYN / Entry point address: 0x0
#   => Number of section headers: 24    ← 正常 NDK .so 永远带完整节头
readelf -l libtarget_orig.so
#   => LOAD 0x000000 0x00000000 ... 0x09d27 0x09d27 R    ← filesz==memsz，无解压缓冲
#   => LOAD 0x009d28 0x0000ad28 ... 0x00278 0x00278 R E

# 标准 360：3 个程序头、节头 0、入口在 stub 段、第一段 memsz 是 filesz 的 13 倍
readelf -h libtarget_360.so
#   => Type: EXEC / Entry point address: 0x11684
#   => Number of section headers: 0     ← F1 命中
readelf -l libtarget_360.so
#   => LOAD 0x000000 0x00000000 ... 0x01000 0x0d0a0 RW   ← F3：filesz 0x1000 -> memsz 0xD0A0（13.0x）
#   => LOAD 0x000000 0x0000e000 ... 0x040a2 0x040a2 R E   ← stub 段；0x11684 落在它里面（F4）
#   =>（Section to Segment mapping 全空——没有节可映射）

# B13 样本：e_type 仍是 DYN，但节头表偏移与数量都被清零
readelf -h libtarget_stripped.so
#   => Type: DYN (Shared object file)
#   => Start of section headers: 0 (bytes into file)   ← 与 orig 的 42928 对比
#   => Number of section headers: 0
readelf -S libtarget_stripped.so
#   => There are no sections in this file.
readelf -S libtarget_360.so
#   => There are no sections in this file.              ← 加壳样本同样无节（F1 的另一面）
```

**逐行判读**：`readelf -h` 一次回答「是不是 DYN / 入口在哪 / 有没有节头」三件事；`readelf -l` 的 MemSiz 列远大于 FileSiz 即解压缓冲。注意 B13 与「UPX 加壳」的区分点：**B13 样本 e_type 仍是 ET_DYN**，加壳样本被 pack.sh 临时改成了 ET_EXEC——所以"无节头"要联读 e_type 才能分类。

### xxd 定位魔数（F6 / F8，4 处偏移）

```bash
# 偏移 0x98（stub 代码区）：标准 UPX! vs 变种 JG!!
xxd -s 0x90 -l 32 libtarget_360.so
#   00000090: 0000 0000 5a64 6ac0 5550 5821 300a 0e17  ....Zdj.UPX!0...
xxd -s 0x90 -l 32 libtarget_360_variant.so
#   00000090: 0000 0000 5a64 6ac0 4a47 2121 300a 0e17  ....Zdj.JG!!0...
#                                  ^^^^^^^^^^^^ 5550 5821 -> 4a47 2121（4 字节全改）

# 偏移 0x3cfb（stub 代码区第二处）
xxd -s 0x3cf8 -l 16 libtarget_360.so
#   00003cf8: 57fb dfb9 7b97 e3c7 f0b7 7e55 5058 21f0  W...{.....~UPX!.
xxd -s 0x3cf8 -l 16 libtarget_360_variant.so
#   00003cf8: 57fb dfb9 7b97 e3c7 f0b7 7e4a 4721 21f0  W...{.....~JG!!.

# 偏移 0x45cf / 0x45d8（尾部结构两处；连带看 sz_unc 字段）
xxd -s 0x45c0 -l 48 libtarget_360.so
#   000045c0: 729d 0156 0000 0000 0009 ff00 0000 0055  r..V...........U
#   000045d0: 5058 2100 0000 0000 5550 5821 0e17 0308  PX!.....UPX!....
#   000045e0: 86a0 ab0c 54b5 79be 70ab 0000 d845 0000  ....T.y.p....E..
xxd -s 0x45c0 -l 48 libtarget_360_variant.so
#   000045c0: 729d 0156 0000 0000 0009 ff00 0000 004a  r..V...........J
#   000045d0: 4721 2100 0000 0000 4a47 2121 0e17 0308  G!!.....JG!!....
#   000045e0: 86a0 ab0c 54b5 79be 70ab 0000 d845 0000  ....T.y.p....E..
```

**逐行判读**：4 处魔数 = `0x98`、`0x3cfb`（stub 区）+ `0x45cf`、`0x45d8`（尾部结构）。标准样本这 4 处都是 `55 50 58 21`（`UPX!`），变种全被改成 `4a 47 21 21`（`JG!!`）——两文件逐字节对比只有这 16 字节不同。
尾部 `70 ab`（`0xAB70` 小端）= **43888**：UPX 尾部结构记录的解压后大小，远大于文件自身 17916 字节——F7 的字节级依据。

### 熵（F2）的一行手算版

```bash
# 纯标准库手算整文件熵，结果应与 detect_360.py 输出一致（两者互为校验）
python -c "import math,collections;d=open('libtarget_360.so','rb').read();c=collections.Counter(d);n=len(d);print('entropy=%.3f'%(-sum(v/n*math.log2(v/n) for v in c.values())))"
#   => entropy=7.598
python -c "import math,collections;d=open('libtarget_orig.so','rb').read();c=collections.Counter(d);n=len(d);print('entropy=%.3f'%(-sum(v/n*math.log2(v/n) for v in c.values())))"
#   => entropy=5.011
```

### 明文 360 标记（命名用，不定性）

```bash
# 明文标记在 stub 的版本串里（0x37d5 起），不在尾部——尾部追加字节会破坏 UPX
python -c "d=open('libtarget_360.so','rb').read();print(d[0x37d5:0x37d5+40].decode('ascii','replace'))"
#   => $Id: 360 4.24 Copyright (C) 1996-2024 the UPX Team. All Righ
```

**怎么判**：这串只用于「是不是 360」的命名确认；`detect_360.py` 明确它不参与打分——否则脱壳后 payload 里的 360 标记会把原始样本误判成已加壳（误判设计见 `SCRIPT.md`「判定」的坑表）。

### upx 批量探测

```bash
# upx_probe.py = 批量 upx -t/-l/-d 的包装（一次看清四个样本谁可自动解包）
python tools/upx_probe.py libtarget_orig.so libtarget_360.so libtarget_360_variant.so libtarget_stripped.so
#   => orig:   upx -t FAIL (rc=2)   -- 需要手工/动态脱壳
#   => 360:    upx -t OK;  -l 显示 43888 -> 17916 40.82% linux/arm;  -d OK -> 43888 bytes
#   => variant: upx -t FAIL (rc=2)   -- 需要手工/动态脱壳
#   => stripped: upx -t FAIL (rc=2)  -- 需要手工/动态脱壳
```

---

## 脱壳

### 标准 360：upx -t / -d 直接操作

```bash
# -t 先验证可解（校验和过不过），-d 解出到指定文件
./upx.exe -t libtarget_360.so
#   => testing libtarget_360.so [OK]   /   Tested 1 file.
./upx.exe -d libtarget_360.so -o out.so
#   => 43889 <- 17916   40.82%   linux/arm   out.so /   Unpacked 1 file.
```

> `-d` 的体积行左侧 43889 含 1 字节对齐填充，落盘 `out.so` 实际 43888 字节——与原始 `.so` 一致。

### 变种 360：命令行手改 4 处偏移（解法 A 的手动版）

```bash
# 先实证确认真魔数（静态候选有巧合项，必须 upx -t 实证）
python tools/detect_360.py libtarget_360_variant.so --verify
#   => b'JG!!' x4 -> upx -t OK   <= 真魔数；其余 \x00\x00p\xab 等候选均 FAIL

# 命令行等价的"十六进制编辑器手改"：把 4 处偏移各 4 字节还原成 UPX!
python -c "
d=bytearray(open('libtarget_360_variant.so','rb').read())
for o in (0x98,0x3cfb,0x45cf,0x45d8): d[o:o+4]=b'UPX!'
open('fixed.so','wb').write(d)"
#   => 无输出；fixed.so = 17916 字节（体积不变，只改 16 字节）

# 验证 + 解包
./upx.exe -t fixed.so && ./upx.exe -d fixed.so -o unpacked.so
#   => testing fixed.so [OK] / Unpacked 1 file.
```

**⚠️ 必须 4 处全改**：只改 `0x98/0x3cfb/0x45cf/0x45d8` 任意单独一处，`upx -t` 实测报
`NotPackedException: not packed by UPX`——UPX/360 校验和覆盖所有内嵌魔数。
若 4 处全改后仍失败 → Stub/控制流/压缩参数也被改 → 转解法 B（`SCRIPT.md`「脱壳」）。

### 解法 B 的命令行演练

```bash
# simulate_dump 按 PT_LOAD 生成"运行态内存镜像"，dump_fix 重建可载入的 ELF
python tools/simulate_dump.py libtarget_orig.so analysis_output/sim_dump.bin
#   => [+] simulated dump -> analysis_output/sim_dump.bin  base=0x0 size=53408 (from 4 PT_LOAD, 32-bit)
python tools/dump_fix.py analysis_output/sim_dump.bin 0x0 analysis_output/dump_fixed.so --arch arm
#   => [+] wrote analysis_output/dump_fixed.so: base=0x0 size=53408 arch=arm entry=0x0
```

---

## 验证

```bash
# 判据 1：体积恢复
ls -l libtarget_orig.so unpacked.so
#   => 两边都是 43888 字节

# 判据 2：锚点找回（8 个锚点在脱壳产物里逐个 grep）
python -c "
d=open('unpacked.so','rb').read()
for a in ['360jiagu_lab_payload_marker_v1','JiaguLab-2026-SECRET-KEY','flag{jiagu_unpacking_is_fun}','com/aegis/NativeLib','getFlag','JNI_OnLoad','check_license','blob_selfcheck']:
    print(a, 'OK' if a.encode() in d else 'MISS')"
#   => 8 行全 OK

# 判据 3：字节一致（sha256 定变化、cmp 定位差异）
sha256sum libtarget_orig.so unpacked.so
#   => 47b3f17d...  libtarget_orig.so
#   => 5f5a2089...  unpacked.so        ← 哈希不同：有 e_type 一处差异
cmp -l libtarget_orig.so unpacked.so
#      17   3   2     ← 全文件唯一差异：1-based 第 17 字节 = 偏移 16 的 e_type（03=ET_DYN vs 02=ET_EXEC）
```

**逐行判读**：sha256 不同不要慌——`cmp -l` 精确指出**只有偏移 16 的 e_type 一处差异**（`upx -d` 解出的是打包时的临时 ET_EXEC 形态），代码与数据逐字节一致，脱壳成功。

---

## 决策流程

```
命令行版判定顺序（结论与 SCRIPT.md 相同，这里给出每步用的命令）：
  readelf -h <file>
 ├─ ET_DYN + 节头 24 完整 ──► 结构正常；再手算熵（≈5.0）确认 → 未见已知特征（≠未加壳）
 ├─ ET_EXEC + 节头 0 ────────► upx -t
 │     ├─ OK ───────────────► 标准 360：直接 upx -d
 │     └─ FAIL ─────────────► xxd 找 4 处魔数（UPX! 在？不在？）
 │           ├─ UPX! 在 ─────► 结构/校验被改 → 解法 B
 │           └─ 不在 ─────────► 实证候选（--verify）→ 4 处全改 → upx -t
 │                              ├─ OK → upx -d（解法 A 成）
 │                              └─ FAIL → 解法 B（内存 dump + ELF Fix）
 └─ ET_DYN + 节头 0 ─────────► B13：疑似 SO 加壳 / 自实现 Linker → 须人工 ELF 层确认
```

---

## 反复练习

复位与回归命令同 `SCRIPT.md`「反复练习」（`reset_lab.py` / `check_so_samples.py`）；命令行路线的增量只有一条：**练完自己用 `xxd` 找 4 处 `JG!!`，再用 `cmp` 验证你手改的 `fixed.so` 与脚本产物 `unpacked.so` 逐字节一致**——两个路线的产物完全可互换，互为校验。

```bash
# 练习产物判脏（out.so/fixed.so/unpacked.so 都会被 reset 识别为练习产物）
python tools/reset_lab.py status
#   => 列出练习产物；restore 一键清掉
```

---

## 踩坑与速查

### 踩坑（命令行 / 工具侧）

1. **本机没有独立 `readelf`**：用 NDK 自带的 `llvm-readelf`（`toolchains/llvm/prebuilt/<host>/bin/` 下），参数兼容 GNU readelf；四档探测见 `build/locate.sh`。
2. **`upx -d` 的体积行左侧比右侧多 1 字节**（43889 vs 17916）：那是报告里的对齐填充，落盘文件是 43888——验证时以 `ls -l` / `cmp` 为准，不要按报告行写断言。
3. **`cmp -l` 是 1-based**：输出 `17` 对应 0 偏移 16（e_type），写文档/断言时别写成"第 16 字节"。
4. **xxd 的 `-s` 是十六进制**：`-s 0x90` 从偏移 144 开始；等宽窗口（`-l 32`）对齐到 16 字节边界便于对照。
5. **Windows 下 `./upx.exe` 必须带 `.exe`**：`upx` 裸名可能撞上 PATH 里其他版本——工程根自带 `upx.exe` 优先级高于 PATH（`SCRIPT.md`「速查」的四档表），换版本要显式 `UPX=<路径>`。
6. **中文乱码**：`PYTHONIOENCODING=utf-8`（PowerShell `$env:PYTHONIOENCODING='utf-8'`）。
7. **本机只有 `python` 无 `python3`**。

### 速查

```bash
# 判定（字节级依据）
readelf -h libtarget_360.so                 # e_type / e_entry / e_shnum 三联读
readelf -l libtarget_360.so                 # PT_LOAD FileSiz vs MemSiz（解压缓冲）
readelf -S libtarget_stripped.so            # There are no sections（B13/F1）
xxd -s 0x90 -l 32 libtarget_360.so           # 魔数第一处（0x98）
xxd -s 0x3cf8 -l 16 libtarget_360_variant.so # 魔数第二处（0x3cfb）
xxd -s 0x45c0 -l 48 libtarget_360_variant.so # 尾部两处（0x45cf/0x45d8）+ sz_unc 70ab
python -c "import math,collections;d=open('libtarget_360.so','rb').read();c=collections.Counter(d);n=len(d);print('%.3f'%(-sum(v/n*math.log2(v/n) for v in c.values())))"  # 熵手算 => 7.598

# 脱壳
./upx.exe -t libtarget_360.so && ./upx.exe -d libtarget_360.so -o out.so
python -c "d=bytearray(open('libtarget_360_variant.so','rb').read());[d.__setitem__(slice(o,o+4),b'UPX!') for o in (0x98,0x3cfb,0x45cf,0x45d8)];open('fixed.so','wb').write(d)"
./upx.exe -t fixed.so && ./upx.exe -d fixed.so -o unpacked.so

# 验证
sha256sum libtarget_orig.so unpacked.so
cmp -l libtarget_orig.so unpacked.so        # => 仅 1 处：17 列 03 vs 02（e_type）

# 回归 / 复位
python tools/check_so_samples.py            # => 0 项失败
python tools/reset_lab.py restore
```
