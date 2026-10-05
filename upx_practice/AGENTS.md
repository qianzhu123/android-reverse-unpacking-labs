# AGENTS.md — upx_practice lab (ground-truth doc for agents)

> **Audience: an agent that must be productive in this lab within minutes.**
> Everything below was produced by reading the source line-by-line and by running the
> commands on this machine (Windows / Bash, python 3.13, UPX 4.2.4).
> Line numbers refer to the files as they exist now; if you edit a file, re-verify.
>
> **Repo iron rules (do not violate):** zero absolute paths; the three routes
> (SCRIPT/CLI/GUI) share one skeleton; self-built samples must be reproducible;
> third-party samples never enter the repo; the epistemic boundary is
> **"no known signature seen ≠ not hardened"**.

---

## 0. What this lab is (its relationship to 360jiagu)

`upx_practice` is the **vanilla-UPX** practice lab (as opposed to 360jiagu's "modified
UPX"), plus a **feature-rewritten variant**. It shares almost the entire code skeleton
with `360jiagu` (`detect`/`solve`/`elf_scan`/`dump_fix`/`simulate_dump`/`upx_probe`/`reset_lab`
are isomorphic on both sides); the differences concentrate in three places you must catch
when reading the code:

| Difference | 360jiagu | upx_practice |
|---|---|---|
| Detector filename/attribution | `tools/detect_360.py` (has 360 attribution markers JG!!/360 4.24) | `tools/detect_packer.py` (**pure UPX**, no 360 markers) |
| Variant token | `JG!!` (printable placeholder) | **`XXXX`** |
| What the variant rewrites | **Only** the magic `UPX!`→`JG!!` | magic `UPX!`→`XXXX` **and** attempts section names `UPX0/1/2`→`SEC0/1/2` |
| Original sample size | 43888 (bulk injected by policy_inc.h) | **70012** (`src/target.c` carries its own large string table; no gen_policy needed) |

`upx_practice` has no `gen_policy.py` (`build/` only contains `locate.sh`/`build_android.sh`/
`pack.sh`) — its compressible bulk comes from `src/target.c` itself (4214 lines, with
large constant/string blocks).

---

## 1. Directory map (open in this order)

```text
upx_practice/
├── upx.exe                    UPX 4.2.4 — GITIGNORED, must exist locally (see §5)
├── src/target.c               sample source (JNI_OnLoad / RegisterNatives / check_license /
│                              blob_selfcheck + string anchors), 4214 lines
├── build/
│   ├── locate.sh              ★ 4-tier toolchain probe (isomorphic with 360jiagu)
│   ├── build_android.sh       NDK clang → libtarget_orig.so (arm32 + arm64)
│   └── pack.sh                makes standard UPX + variant + B13 stripped
├── tools/
│   ├── detect_packer.py       ★ structural detector (F1–F8 + B13) — the core
│   ├── elf_scan.py            dependency-free ELF parser + UPX fingerprint (same name/structure as 360jiagu)
│   ├── upx_probe.py           batch upx -t / -l / -d
│   ├── solve_variant.py       ★ solution A: token repair + upx -d + anchor check
│   ├── simulate_dump.py       ELF → flat "memory image" (no-device demo of solution B)
│   ├── dump_fix.py            ★ solution B: memory dump → rebuild loadable ELF
│   ├── make_variant.py        standard → variant (UPX!→XXXX, UPX0/1/2→SEC0/1/2)
│   ├── make_stripped_so.py    clean → B13 sample (zero the section-header fields)
│   ├── check_so_samples.py    ★ two-way regression assertion (B13)
│   ├── reset_lab.py           ★ backup / status / restore
│   ├── anchors.txt            the 7 anchors expected after unpack
│   └── upx396.exe             UPX 3.96 (alternative, GITIGNORED)
├── samples/so/                ★ ALL samples live here (lab root holds no samples)
├── pristine/so/ + manifest.json   golden baseline (sha256), restore source
└── analysis_output/           script products (reset_lab restore clears it)
```

---

## 2. The sample set — verified sizes and sha256

Run from the lab root: `sha256sum samples/so/*.so`:

| file | bytes | sha256 (first 12) | e_type | `UPX!` | `XXXX` | upx -t |
|---|---|---|---|---|---|---|
| `libtarget_orig.so` | 70012 | `8905e1ab96b8` | ET_DYN(3) | 0 | 0 | FAIL rc=2 |
| `libtarget_upx.so` | 5348 | `435d54eabd2a` | **ET_EXEC(2)** | **4** | 0 | **OK rc=0** |
| `libtarget_upx_variant.so` | 5348 | `d54438e4d4c2` | **ET_EXEC(2)** | 0 | **4** | FAIL rc=2 |
| `libtarget_stripped.so` | 70012 | `3b2ef109a2c7` | ET_DYN(3) | 0 | 0 | FAIL rc=2 |
| `libtarget_orig_arm64.so` | 71848 | `e09d80de8f60` | ET_DYN(3) | 0 | 0 | (not probed) |

These also match `pristine/manifest.json`; if `reset_lab.py status` shows `[已改动]`, the
sample has drifted and you must `restore`.

> **Why ET_EXEC for the packed samples?** Official UPX 4.2.4 refuses to pack Android
> `ET_DYN` `.so` (`NotCompressibleException`). `build/pack.sh:18` uses
> `printf '\x02\x00' | dd of=_tmp_orig.so bs=1 seek=16 conv=notrunc` to change `e_type`
> (offset 16, 2 bytes, LE) to `ET_EXEC(2)` before packing. The unpacking mechanism is
> unchanged; only these 2 bytes differ — which is exactly why the §7 verification
> **ignores offset 16..17**.

---

## 3. `tools/detect_packer.py` — the detector (what it shares with / differs from detect_360)

### 3.1 CLI (`__main__`, 298–309)
```
python tools/detect_packer.py <file...> [--brief] [--verify] [--upx <path>]
```
Exactly the same shape as `detect_360.py`: `--brief` keeps only the verdict rows, `--verify`
confirms the magic empirically with `upx -t`.
**Windows console garbles Chinese**: set `PYTHONIOENCODING=utf-8` (Bash
`export PYTHONIOENCODING=utf-8`; PowerShell `$env:PYTHONIOENCODING='utf-8'`). All output in
this doc was produced with that variable set.

### 3.2 ELF parsing (`parse_elf`, 83–114)
**Byte-for-byte identical** to 360jiagu's `parse_elf` (pure `struct`, little-endian, only
collects `PT_LOAD`). Non-ELF → prints `[!] 不是 ELF 文件` and `return None` (no exception).

### 3.3 Feature extraction (`detect()`, 146–220) — thresholds identical to 360jiagu

| symbol | value | line | meaning |
|---|---|---|---|
| entropy threshold | `H > 7.0` | 170 | compressed/encrypted body |
| big decompress segment | `filesz>0 and memsz/filesz ≥ 4 and memsz ≥ 0x8000` (32KB) | 172-173 | UPX0 decompress target area |
| size ratio | `ratio_mem ≥ 3.0` | 182 | mem/file inflation |
| `sz_unc` window | `1000 < tail4 < 64MiB` and `tail4 > len(d)` | 187 | trailing uncompressed size |
| magic candidate count | `2 ≤ count ≤ 16` | 116 (`lo,hi`) | repetitiveness |
| candidate tail window | last 96 bytes | 116 (`tail=96`) | candidate must be near EOF |

- **F1** `e_shnum==0` (+2); **F2** entropy>7.0 (+2); **F3** a big decompress segment as above exists (+3);
  **F4** `e_entry` lands in a **non-first** `PT_LOAD` (`vaddr ≤ e_entry < vaddr+memsz`, 178) (+2);
  **F5** size ratio ≥3.0 (+2); **F6** `d.count(b"UPX!")>0` (+3);
  **F7** `tail4 = struct.unpack_from("<I", d, len(d)-12)` within the window and larger than the file (+2);
  **F8** `(not f6) and packed_ev≥2 and len(cands)>0` (+3), `packed_ev=sum([f1..f5])`.
- **B13** (195-196): `exec_load = any(flags & 1)`; `b13 = (e_type==3 and e_shnum==0 and exec_load)`.
  **All three conditions required**, same as 360jiagu.

`magic_candidates` (116–143) has three constraints: ① occurs `2..16` times; ② is not a 4-identical-byte
`00`/`FF` fill (133); ③ appears in the last 96 bytes (134). Sort: printable ASCII first, then ascending
by count; take the top 5.

### 3.4 Verdict logic (237–259) — decision order **identical** to 360jiagu, only the wording drops "360"

```
if   f6 and score>=6:  → 标准 UPX 壳（特征完整）
elif f8 and score>=6:  → ★ 变种 UPX 壳（UPX 特征被抹掉，但结构仍在）
elif score>=4:         → 疑似加壳（非 UPX 或深度魔改）
else:                  → 未见已知加固特征（≠未加壳）;  if b13 → 疑似 SO 加壳/自实现 Linker
```
**Same early-out**: `b13` does **not** override a scored shell verdict. Returns
`dict(b13, verdict, score, e_type, e_shnum, is_packed)`.

**The key difference from 360jiagu (only visible by reading the code)**: this detector has
**no** `JIAGU_MARKERS`/`JG_TOKEN`, and no "360 attribution" print block (360jiagu's lines
249–253). This lab's verdict is pure UPX, with no 360 naming branch mixed in.

---

## 4. Real detector runs (verbatim, use as fixtures)

### 4.1 clean `libtarget_orig.so`
```
目标: samples/so/libtarget_orig.so   (70012 bytes)
  架构: 32-bit  e_type=3  e_entry=0x0
  [  - ] F1 节区头数量         e_shnum=23
  [  - ] F2 整文件熵          4.470 bits/byte
  [  - ] F3 大解压缓冲段        无
  [  - ] F4 入口位置          e_entry=0x0 落在 PT_LOAD[1] (vaddr=0x0, size=0x1043F)
  [  - ] F5 内存/文件体积比      0.99x (memsz=0x10FFF)
  [  - ] F6 'UPX!' 魔数     出现 0 次
  [  - ] F7 尾部 sz_unc 字段  0x0 = 0
  [  - ] F8 疑似被篡改魔数       无
综合得分: 0
判定结果: 未见已知加固特征（≠未加壳）
```
**Reading**: nothing hits. Note F4's `e_entry=0x0` really is inside a `PT_LOAD`, but that is
`loads[0]`, so F4 does not hit — **do not treat "e_entry falls in a segment" as a hit**; the
code requires a "non-first segment".

### 4.2 standard UPX `libtarget_upx.so`
```
  架构: 32-bit  e_type=2  e_entry=0x1358C
  [命中] F1 e_shnum=0                          (+2)
  [命中] F2 7.309 bits/byte                    (+2)
  [命中] F3 PT_LOAD[0] filesz=0x1000 -> memsz=0x13000 (19.0x)  (+3)
  [命中] F4 e_entry=0x1358C 落在 PT_LOAD[1] (vaddr=0x13000, size=0xFAA)  (+2)
  [命中] F5 15.30x (memsz=0x13FAA)             (+2)
  [命中] F6 'UPX!' 出现 4 次                    (+3)
  [命中] F7 0x1117C = 70012                    (+2)
综合得分: 16
判定结果: 标准 UPX 壳（特征完整）
建议动作: 直接 upx -t 验证，然后 upx -d 解包，不必手脱
```
**Note F5 = 15.30x** (360jiagu is only 3.90x) — because this sample compresses extremely
well (70012→5348, 7.64%), and the decompress buffer segment `memsz=0x13000` (77824) is far
larger than the 5348-byte file.

### 4.3 variant `libtarget_upx_variant.so`
Same as 4.2 except F6 misses and F8 hits:
```
  [  - ] F6 'UPX!' 魔数     出现 0 次
  [命中] F7 尾部 sz_unc 字段  0x1117C = 70012                  (+2)
  [命中] F8 疑似被篡改魔数       候选 b'XXXX' 出现 4 次 @ ['0x98', '0xc03', '0x14b8', '0x14c0']  (+3)
综合得分: 16
判定结果: ★ 变种 UPX 壳（UPX 特征被抹掉，但结构仍在）
```

### 4.4 B13 `libtarget_stripped.so`
```
  [命中] F1 节区头数量         e_shnum=0
  [  - ] F2 整文件熵          4.469 bits/byte
  [  - ] F3 大解压缓冲段        无
[B13 · SO 加壳 / 自实现 Linker] e_type=ET_DYN 但 e_shnum=0（节头表被剥离）...
综合得分: 2
判定结果: 疑似 SO 加壳 / 自实现 Linker（ELF 节头被剥离）— 需人工进 ELF 层确认
```
**Key**: this sample has **no UPX feature at all**, and is detected purely by the B13
structural anomaly — proving B13 catches custom-linker shells that a UPX signature misses.

### 4.5 `--verify` (empirical magic)
```
[实证验证] 逐个候选打补丁后用 upx -t 检验:  (upx = upx.exe)
   b'XXXX' x4   -> upx -t OK   <= 这就是被篡改的真魔数
   b'\x00\x00|\x11' x2   -> upx -t FAIL
   b'\x00|\x11\x01' x2   -> upx -t FAIL
   b'\x00\x00\x04\x80' x2   -> upx -t FAIL
   b'\x00\x04\x80\xff' x2   -> upx -t FAIL
```
The heuristic's first candidate is the real magic; the other four are coincidences (random
data that happens to repeat and land in the trailer).

---

## 5. Toolchain resolution — `build/locate.sh` (4 tiers, isomorphic with 360jiagu)

Precedence: **CLI arg > env var > project config > auto-detect**.
- python: `$PYTHON` → `python` → `python3` → `py`.
- NDK: `$ANDROID_NDK_HOME`/`$NDK_ROOT`/`$ANDROID_NDK_ROOT` → newest `<SDK>/ndk/*`.
- UPX: `$UPX` → **`$ROOT/upx.exe`** → PATH → `tools/upx396.exe`.

**UPX ordering is deliberately project-internal-first**: this lab's measured numbers are
based on the bundled 4.2.4; to switch versions set `UPX=<path>` explicitly, do not let PATH
silently swap in another one. `locate_require` exits 1 on a missing tool and says how to
configure it.

`bash build/locate.sh --dump` on this machine should print (same SDK/NDK as 360jiagu):
`UPX=<lab root>/upx.exe`, `NDK=.../ndk/27.0.12077973`. Bare `readelf`/`objdump`/`nm` do not
exist; use the NDK's `llvm-*` if you need them.

---

## 6. `tools/make_variant.py` — what the variant actually changes (an important difference)

`make_variant` (9–23) does **two things**:
```python
data = data.replace(b"UPX!", b"XXXX")                        # ① magic
data = data.replace(b"UPX0", b"SEC0")                        # ② section names (one by one)
data = data.replace(b"UPX1", b"SEC1")
data = data.replace(b"UPX2", b"SEC2")
# optional --scramble-stub: zero bytes 0x40..0x80 (simulates a control-flow tweak; practice only)
```
**But running it shows ② is a no-op.** I counted each marker's occurrences in both samples:

| marker | libtarget_upx | libtarget_upx_variant |
|---|---|---|
| `UPX0`/`UPX1`/`UPX2` | 0/0/0 | 0/0/0 |
| `SEC0`/`SEC1`/`SEC2` | 0/0/0 | 0/0/0 |
| `UPX!` | 4 | 0 |
| `XXXX` | 0 | 4 |

That is, **UPX 4.2.4's ARM output contains no `UPX0/1/2` section names at all** (symbols are
stripped), and the `UPX0/1/2 x0/0/0` that `make_variant.py`'s ② branch prints is the proof —
it changed no bytes. So **the variant's actual difference is only: 4 × `UPX!` → `XXXX`**
(offsets `0x98`/`0xc03`/`0x14b8`/`0x14c0`). This is equivalent to 360jiagu's
`make_360_variant.py`, just with the token changed from `JG!!` to `XXXX`.
(`elf_scan.py`'s "section names containing UPX*/SEC*" is always empty for this sample —
this is why.)

---

## 7. `tools/solve_variant.py` — solution A (isomorphic with solve_360.py)

### 7.1 CLI
```
python tools/solve_variant.py <src.so> <out.so> [--orig <orig.so>] [--token XXXX]
                              [--upx PATH] [--anchor S]... [--anchors-file PATH]
```
Internals: `find_upx` (57–72, 4-tier, `_upx_from_path` skips CWD); `load_anchors` (74–92,
explicit > `tools/anchors.txt`, skip if none); `candidates` (101–111, window ≥2 occurrences,
tail-first, limit 60); `solve` (113–180): patch each candidate → `upx -t` → first OK wins →
`upx -d` → anchor check → compare against `--orig` (**ignoring offset 16..17**, 175).

### 7.2 Variant happy path (verbatim)
```
$ python tools/solve_variant.py samples/so/libtarget_upx_variant.so out.so --orig samples/so/libtarget_orig.so
[*] 样本: samples/so/libtarget_upx_variant.so (5348 bytes)
[*] 现有 'UPX!' 数量: 0
[*] 使用的 upx: upx.exe
    候选 token b'\x00\x00\x00\x00' x34 -> upx -t FAIL
    候选 token b'\x01\x00\x00\x00' x7 -> upx -t FAIL
    候选 token b'XXXX' x4 -> upx -t OK
[+] 确定被篡改的 token: b'XXXX' -> 还原为 'UPX!'（共 4 处）
[+] 解包成功: out.so (70012 bytes)

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
`solve_variant`'s first two candidates (`\x00\x00\x00\x00` x34, `\x01\x00\x00\x00` x7) both
FAIL, and the third `XXXX` is OK — **solve does not assume the printable token comes first**.

### 7.3 ⚠️ Pitfall: running solve on a **standard** sample reports a false failure (same root bug as 360jiagu)
```
$ python tools/solve_variant.py samples/so/libtarget_upx.so std.so --orig samples/so/libtarget_orig.so
[*] 现有 'UPX!' 数量: 4
[!] 未能通过特征修复使 upx -t 通过 -> 该变种改了 Stub/校验，需走内存 dump 路线
```
**Root cause (read the code, don't trust the message)**: `solve_variant.py:127`
`if data.count(MAGIC) == 0: tried += candidates(...)`. When the magic is already `UPX!`
there are **no candidates** → the loop body never runs → `found=None` → falls into the
generic "must go memory-dump" branch. For a standard sample this is **wrong**: it should
just be unpacked with `upx -d`.
**The right move**: `upx.exe --force-overwrite -d samples/so/libtarget_upx.so -o out.so`
(directly), or `solve_variant ... --token UPX!` to force the same path.

### 7.4 All 4 occurrences must be changed
The 4 are `0x98` (stub header), `0xc03` (inside the compressed payload), `0x14b8`/`0x14c0`
(near EOF; the last-96-byte window starts at `0x14c0-0x60`). Reason as in 360jiagu: **UPX's
`l_info` checksum covers every embedded magic in the whole file; changing only one always
makes `upx -t` FAIL**.

---

## 8. Solution B — `simulate_dump.py` + `dump_fix.py` (same name/structure as 360jiagu)

`simulate_dump`: maps the file into a flat image by `PT_LOAD` (`filesz` copied + `memsz`
zero-filled). `dump_fix`: rebuilds a minimal loadable ELF (single `PT_LOAD` + `.text` +
`.shstrtab`).

Actual run:
```
$ python tools/simulate_dump.py samples/so/libtarget_orig.so analysis_output/sim_dump.bin
[+] simulated dump -> analysis_output/sim_dump.bin  base=0x0 size=77824 (from 3 PT_LOAD, 32-bit)
$ python tools/dump_fix.py analysis_output/sim_dump.bin 0x0 analysis_output/dump_fixed.so --arch arm
[+] wrote analysis_output/dump_fixed.so: base=0x0 size=77824 arch=arm entry=0x0
```
**Honest boundary**: `dump_fix.py` is a **minimal rebuild** — single RWX `PT_LOAD` + `.text`,
**no `.dynamic`/`.dynsym`/relocations**; it can be opened in a disassembler to read code, but
is **not a runnable library**. The file-format details (header offsets, `sh32/sh64` layout)
are the same as 360jiagu's AGENTS.md §13 and are not repeated.

---

## 9. `tools/upx_probe.py` — batch truth check

Runs `upx -t` / `upx -l` / `upx -d` per file; the `-d` product is written to
`analysis_output/<name>.probed_unpacked.so` and deleted on success. Run on all samples:
```
SAMPLE: samples/so/libtarget_orig.so          upx -t: FAIL (rc=2)  upx -l: FAIL  upx -d: FAIL (rc=2)
SAMPLE: samples/so/libtarget_upx.so           upx -t: OK  (rc=0)  upx -l: OK    upx -d: OK -> ... (70012 bytes)
SAMPLE: samples/so/libtarget_upx_variant.so   upx -t: FAIL (rc=2)  upx -l: FAIL  upx -d: FAIL (rc=2)
SAMPLE: samples/so/libtarget_stripped.so      upx -t: FAIL (rc=2)  upx -l: FAIL  upx -d: FAIL (rc=2)
```
`-l` on the standard sample:
```
File size         Ratio      Format      Name
70012 ->      5348    7.64%    linux/arm    samples/so/libtarget_upx.so
```
**Reading**: any non-zero `rc` = "not a standard recoverable UPX package"; rc=2 is UPX's
generic "not packed / bad file" exit. This is the fastest way to separate the standard
sample from everything else before running solve.

---

## 10. Regression — `check_so_samples.py`

Same name/structure as 360jiagu (imports `detect_packer`, swallows prints, takes the
structured result):
1. **positive** `libtarget_stripped.so` → `b13 is True`;
2. **negative** `libtarget_orig.so` → `b13 is False`;
3. **anti-regression** `libtarget_upx.so` / `_variant.so` → `is_packed is True`.
Actual run (all pass, exit 0):
```
[PASS] libtarget_stripped.so   b13=True  -> 疑似 SO 加壳 / 自实现 Linker（ELF 节头被剥离）— 需人工进 ELF 层确认
[PASS] libtarget_orig.so       b13=False -> 未见已知加固特征（≠未加壳）
[PASS] libtarget_upx.so           仍为加壳判定: 标准 UPX 壳（特征完整）
[PASS] libtarget_upx_variant.so   仍为加壳判定: ★ 变种 UPX 壳（UPX 特征被抹掉，但结构仍在）

0 项失败
```
**Meaning**: "the samples are the detector's test set" is circular — a **two-way
(positive + negative) assertion is the mandatory antidote**. Any detector change must keep
this green.

### `reset_lab.py` (status/restore/backup)
- samples live in `samples/so/*`, manifest keys are relative to `samples/` (e.g.
  `so/libtarget_upx.so`), pristine mirrors to `pristine/so/`.
- Artifact globs (`DEFAULT_ARTIFACT_GLOBS`, 24-26): `*unpacked.so`/`*_repaired.so`/`*_probe.so`/
  `_tmp_*.so`/`*.fixed.so`/`fixed.so`/`out.so` — matched **only against files at the lab
  root**, not inside `analysis_output/`.
- `restore` **empties the whole `analysis_output/`** (all files, not just glob matches) —
  do not leave anything you want to keep there.
Actual status (clean state): all 5 samples `[一致]`, `练习产物: 无（环境干净）`.

---

## 11. Interface contract with `unpacker/` (who loads whose modules, by path)

`unpacker/labs.py` is a **read-only bridge**:
- `load_upx_detect()` → `upx_practice/tools/detect_packer.py`;
  `load_upx_solve()` → `upx_practice/tools/solve_variant.py`.
- `_load` (49-66) loads by **file path** via `importlib.util.spec_from_file_location`
  (the three labs have same-named files such as `reset_lab.py`, so package import is not an
  option); before exec it injects the lab's `tools/` into `sys.path`.
- **The contract this lab must honor**:
  - `detect_packer.detect(path, brief=False, verify=False, upx=None) -> dict`,
    keys `verdict, score, b13, is_packed, e_type, e_shnum`.
  - `solve_variant.solve(src, out, orig=None, token=None, upx_path=None, anchors=()) -> bool`
    and `solve_variant.load_anchors(explicit, anchor_file)`.
- `unpacker/unpack.py:100` uses `labs.load_upx_solve()`, with anchors taken from
  `upx_practice/tools/anchors.txt`; **note `unpack.py:104` passes `upx_path` explicitly** —
  because setting the `UPX` env var makes UPX 5.2.1 parse it as an option string and error out.
- The bridge **never calls** `reset_lab.py` (to avoid mutating lab state).

**Constraints on you**: changing the name/signature of `detect`/`solve`, or moving
`anchors.txt`, will break both the bridge and `unpacker/regression.py` (whose `EXPECTED`
table `regression.py:50-53` pins the expected prefixes `标准 UPX 壳` / `★ 变种 UPX` /
`疑似 SO 加壳` / `未见已知加固特征`).

---

## 12. File-format layer details

- **ELF header field offsets** (LE): `e_type`@16(2), `e_machine`@18(2), `e_entry`@24(4/8),
  `e_phoff`@28(32)/@32(64), `e_shoff`@32(32)/@40(64), `e_phnum`@44(32)/@56(64),
  `e_shnum`@48(32)/@60(64), `e_shstrndx`@50(32)/@62(64).
- **`e_type`**: 2=ET_EXEC, 3=ET_DYN. `make_stripped_so.py` zeroes ELF64 `[40:48]`+`[60:64]`,
  ELF32 `[32:36]`+`[48:52]`.
- **UPX trailer `sz_unc`**: 4-byte LE @ **EOF-12**. Packed samples read `0x1117C` = **70012**
  (the original size); clean samples read 0.
- **Packed sample PT_LOAD**s: `[0] off=0 filesz=0x1000 memsz=0x13000 flags=6` (RW decompress
  buffer), `[1] off=0 vaddr=0x13000 filesz=memsz=0xFAA flags=5` (RX stub, contains
  `e_entry=0x1358C`). Both `off` are 0 — do not assume `off` is monotonic.
- **The 4 `XXXX` offsets**: `0x98`, `0xc03`, `0x14b8`, `0x14c0`.
- **Anchor list (`tools/anchors.txt`, 7 entries)**: `AegisDroid-2026-SECRET-KEY`,
  `flag{upx_unpacking_is_fun}`, `com/aegis/NativeLib`, `getFlag`, `JNI_OnLoad`,
  `check_license`, `blob_selfcheck`.

---

## 13. Sample provenance (where the binaries come from)

`build/build_android.sh`:
1. `source build/locate.sh`, `locate_require NDK`.
2. arm32: `$CLANG --target=armv7a-linux-androideabi21 -shared -fPIC -O2
   -Wl,--hash-style=sysv -Wl,--pack-dyn-relocs=none -o samples/so/libtarget_orig.so src/target.c`
   (`--hash-style=sysv --pack-dyn-relocs=none` suppresses NDK r27's RELR/GNU-hash so an
   older UPX can identify it more easily).
3. arm64: `$CLANG --target=aarch64-linux-android21 ... -o samples/so/libtarget_orig_arm64.so`
   (reference only; UPX 4.2.4 won't pack ET_DYN anyway).

`build/pack.sh`:
1. copy orig → `_tmp_orig.so`, `dd` changes `e_type`@16 to `ET_EXEC(2)`;
2. `upx --force-overwrite -o samples/so/libtarget_upx.so _tmp_orig.so` (70012→5348, 7.64%);
3. `make_variant.py` standard → variant (`UPX!`→`XXXX`; the section-name branch is a no-op, see §6);
4. `make_stripped_so.py` orig → stripped (B13 positive).

`src/target.c` highlights: `SECRET_KEY="AegisDroid-2026-SECRET-KEY"` (27),
`FLAG_OK="flag{upx_unpacking_is_fun}"` (28), `check_license()` (41-45) does a byte-by-byte
compare, `_init()` (26) — the comment notes it "provides a DT_INIT entry for UPX; some UPX
versions require it when packing a shared library". At the OEP after unpack you should see
the call chain `JNI_OnLoad → RegisterNatives → getFlag → check_license`.

---

## 14. Pitfalls (root cause, not symptom list)

1. **Running solve on a standard sample falsely reports "must go memory-dump"**. Root:
   `solve_variant.py:127` builds candidates only when `count("UPX!")==0`; an input already
   at `UPX!` has no candidate to try → `found=None` → generic failure text. Fix: unpack
   directly with `upx -d`, or pass `--token UPX!`. (§7.3)
2. **Changing only 1 magic occurrence always fails**. Root: UPX's `l_info` checksum covers
   every embedded magic in the whole file; all 4 must be changed.
3. **`make_variant.py`'s section-name rewrite is a no-op**. Root: UPX 4.2.4's ARM output has
   no `UPX0/1/2` section names, so `replace` hits 0 times (measured count=0). Do not expect
   the variant sample to carry `SEC0/1/2` features.
4. **`upx` may pick the wrong copy on Windows**. `shutil.which()` searches CWD first and can
   let the project's own `upx.exe` shadow a system upx; `_upx_from_path` deliberately skips
   CWD; and PATH is **last** in `find_upx` because the lab numbers assume the bundled 4.2.4.
5. **F3 without a size floor misreads `.bss`**: `memsz/filesz≥4` alone flags a normal
   zero-fill segment as a decompress area; the `memsz≥0x8000` (32KB) guard excludes it.
6. **Static candidates contain coincidences**: e.g. `\x00\x00|\x11` x2 is random repeating
   data. **Do not act without `--verify`.**
7. **Trailer `sz_unc` is only a single feature**: F7 is only +2, and needs the window **and**
   `>len(d)` together; a random file could coincidentally satisfy it, so always corroborate
   with other features.
8. **`e_type` genuinely changes after unpack (DYN↔EXEC)**: any byte comparison must ignore
   offset 16..17 — `solve_variant.py:175` and `unpacker/unpack.py:75` both do.
9. **Chinese garbling**: set `PYTHONIOENCODING=utf-8`; this is a Python locale issue, not a
   script bug.
10. **`e_entry` not in any PT_LOAD → F4 silently misses**: `stub=None`, prints "not in any
    PT_LOAD", and the feature is **neither scored nor an error**.
11. **`upx.exe`/`upx396.exe` are gitignored**: a fresh clone has no UPX, but `pack.sh` and
    `--verify` need one.
12. **B13 does not override a scored verdict**: stripping the headers of the **packed**
    sample still yields "标准 UPX 壳" (its `e_type==2` fails B13's first condition). B13 only
    pre-empts the **fallback** branch.

---

## 15. Speed reference (all measured on this machine)

```bash
# --- judge (never look at the filename) ---
python tools/detect_packer.py samples/so/libtarget_orig.so          # 未见已知加固特征 (0)
python tools/detect_packer.py samples/so/libtarget_upx.so           # 标准 UPX 壳 (16)
python tools/detect_packer.py samples/so/libtarget_upx_variant.so   # ★ 变种 UPX 壳 (16)
python tools/detect_packer.py samples/so/libtarget_stripped.so      # B13 疑似 (2)
python tools/detect_packer.py samples/so/libtarget_upx_variant.so --verify   # empirical magic

# --- ELF / UPX views ---
python tools/elf_scan.py  samples/so/libtarget_orig.so samples/so/libtarget_upx.so
python tools/upx_probe.py samples/so/libtarget_orig.so samples/so/libtarget_upx.so \
                          samples/so/libtarget_upx_variant.so samples/so/libtarget_stripped.so

# --- solution A (variant) ---
python tools/solve_variant.py samples/so/libtarget_upx_variant.so unpacked.so --orig samples/so/libtarget_orig.so
# standard sample: upx -d directly (solve gives a false negative — see pitfall #1)

# --- solution B ---
python tools/simulate_dump.py samples/so/libtarget_orig.so analysis_output/sim_dump.bin
python tools/dump_fix.py analysis_output/sim_dump.bin 0x0 analysis_output/dump_fixed.so --arch arm

# --- regenerate samples ---
bash build/build_android.sh    # NDK clang → orig (arm32 + arm64)
bash build/pack.sh             # standard + variant + B13 stripped

# --- regression + reset ---
python tools/check_so_samples.py    # two-way B13 assertion — 0 failures
python tools/reset_lab.py status
python tools/reset_lab.py restore    # restores samples, clears analysis_output/

# --- repo-wide (from repo root) ---
python unpacker/regression.py        # 19/19 + cross 4/4
```

**UPX discovery order**: `--upx` > `$UPX` > `$ROOT/upx.exe` > PATH > `tools/upx396.exe`.
**NDK**: `$ANDROID_NDK_HOME`/`$NDK_ROOT` > newest `<SDK>/ndk/*`.
**python**: `$PYTHON` > `python` > `python3` > `py`.

---

## 16. Reading order for a newcomer agent

1. Read `tools/detect_packer.py` in full — every threshold in this doc comes from it.
2. Run the four "judge" lines in §15; diff against the §4 fixtures.
3. Read `tools/make_variant.py` and **verify §6's no-op yourself** (count `UPX0`/`SEC0`
   occurrences) — this is the point most easily confused with 360jiagu, and most easily missed.
4. Read `tools/solve_variant.py` and reproduce §7.3 (the false report) and §7.4 (the happy path).
5. Read `build/pack.sh` to understand why the packed samples are ET_EXEC (§2).
6. Only then read `SCRIPT.md`/`CLI.md`/`GUI.md` — they narrate the same facts for humans, but
   the **ground truth is the code**.
