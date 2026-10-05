# AGENTS.md — ajiami lab (ground-truth doc for agents)

> **Audience: agents who need to get productive inside this lab within a few minutes.**
> Every claim comes from reading the source line by line + running things on this machine (Windows / Bash, python 3.13).
> Line numbers match the file's current content; if you change a file, re-verify them yourself.
>
> **Repo iron rules**: zero absolute paths; the three routes (SCRIPT/CLI/GUI) share one skeleton; self-built samples are reproducible;
> third-party samples never enter the repo; the epistemic boundary is **"no known feature seen ≠ not hardened"**.

---

## 0. What this lab is

`ajiami` models **Aijiami's DEX-layer hardening** as **three generations**, each paired with
a **string-obfuscation variant**. DEX hardening is outside the scope of `360jiagu`/`upx_practice`
(those two only cover .so); this is the **only APK/DEX-layer lab**.

Three-generation model (`tools/packer.py` docstring + `do_v1/v2/v3`):

| Gen | Model | Technique | Key criteria |
|---|---|---|---|
| v1 | Whole-file encryption | The business dex is fully XOR-encrypted and stuffed into `assets/ijm_payload.bin`; `classes.dex` keeps only the shell | B1+B6+B7(+B4) |
| v2 | Class extraction | Class/method names are kept, the insns of **every** code_item are emptied to nop, the real instructions are stored in a side table under `assets` | B3 |
| v3 | Selective extraction + obfuscation | **Only some business classes** are extracted; the side-table filename is changed to a normal resource name `brand_res_v3.dat`, with a low-entropy decoy added | B3* (locally empty-method classes) |

**How it differs from real Aijiami**: the genuine product requires uploading the APK to the vendor's
server, so the full chain cannot be reproduced offline; this lab synthesizes an equivalent sample
offline from the same source (`packer.py` + `build/*.sh`), making detect→unpack→verify reproducible
**byte for byte**.

---

## 1. Directory map (open in this order)

```text
ajiami/
├── tools/                     ★ all Python tools (pure stdlib + a few bash subprocesses)
│   ├── detect.py              ★ three-generation verdict (criterion A naive strings + criteria B1–B13 structural)
│   ├── dexlib.py              ★ self-built dex parse/rewrite library (incl. checksum/signature recompute)
│   ├── apkutil.py             APK(zip) layer ops + Shannon entropy (entropy/extract-dex/inject-dex)
│   ├── elfinspect.py          minimal ELF parser → B13 SO structural anomalies
│   ├── crypto_lab.py          ★ byte-level identical to shell Crypto.java XOR key/container format
│   ├── packer.py              ★ the packer (v1/v2/v3) —— the real origin of the samples
│   ├── unpack_v1.py           first-gen unpack (payload decryption)
│   ├── unpack_v2.py           second/third-gen unpack (AJMT side table backfills method body)
│   ├── verify.py              quantitative verification (sha256 + anchors + byte diff)
│   ├── make_variant.py        string-obfuscation variant (equal-length reversed mapping)
│   ├── check_negatives.py     ★ bidirectional regression assertions (6 positive / 4 negative)
│   ├── mkneg.py               negative-sample construction helper
│   ├── mkpacked_so.py         build the B13 positive SO (strip section headers + XOR .text)
│   ├── mkapk.py               assemble APK (replace dex / add assets / zipalign / sign)
│   ├── envload.py             Python-side reader of build/env.sh (no source needed, works in PowerShell too)
│   ├── walkthrough.py         breaks unpacking into hex steps you can compute by hand
│   └── reset_lab.py           ★ backup / status / restore (.apk binary baseline, not via git)
├── app/                       business source (com/demo/target/*.java + AndroidManifest.xml)
├── shell/                     shell source (com/ijiami/shell/*.java —— ProxyApplication etc.)
├── vmp/                       VMP teaching source (com/ijiami/vmp/Vmp.java + com/demo/vmapp/)
├── neg/                       negative-sample source (multi-dex / high-entropy resource / normal native)
├── build/                     build and pack scripts + all intermediates (build/v1|v2|v3|variant|neg|...)
├── samples/                   ★ sample container: apks/ + dex/ + payloads/
├── pristine/                  ★ golden baseline: MANIFEST.json + apks/ + dex/ + payloads/ mirror
├── analysis_output/           unpack products (gitignored)
├── logs/                      debug logs (detect_run*.txt etc.)
└── SCRIPT.md  CLI.md  GUI.md  three-route docs (parallel to this one)
```

`git ls-files ajiami/analysis_output/` is empty——unpack products do not enter the repo (`.gitignore`).
The intermediates in `build/` **are committed** (including `.apk`/`.dex`/`.bin`), because they are the
"same-origin before/after packing" comparison artifacts.

---

## 2. Sample set

### 2.1 APKs (`samples/apks/`) —— the things being judged

`python tools/reset_lab.py status` compares against `pristine/MANIFEST.json` (34 entries, incl. .apk and .idsig).
Measured on this machine (all `OK`): `=> OK=34  DIFF=0  MISSING=0  EXTRA=0`.

| APK | Expected verdict | Trap / purpose |
|---|---|---|
| `app_orig.apk` | No known hardening feature seen | original, not hardened (negative; historical false-positive sample) |
| `app_packed_v1.apk` | Hardened: DEX whole-file encryption (gen 1) | high-entropy payload in asset |
| `app_packed_v2.apk` | Hardened: class-extraction type (gen 2 and later) | B3 all-class empty-method ratio 50% |
| `app_packed_v3.apk` | Hardened: class-extraction type (gen 2 and later) | only some classes extracted → B3* |
| `app_packed_v1_variant.apk` | Hardened: DEX whole-file encryption (gen 1) | strings fully obfuscated (criterion A fully defeated) |
| `app_packed_v2_variant.apk` | Hardened: class-extraction type (gen 2 and later) | strings fully obfuscated |
| `app_vmp.apk` | **Suspected** DEX VMP | B11 (must be judged "suspected", never "hardened") |
| `app_so_packed.apk` | **Suspected** SO packing | B13 (ELF layer) |
| `neg_multidex.apk` | No known hardening feature seen | manifest component class in classes2.dex |
| `neg_highentropy.apk` | No known hardening feature seen | legitimate high-entropy asset (keeps B1 from deciding on its own) |
| `neg_native.apk` | No known hardening feature seen | legitimate NDK .so (locks the B13/B12 clean path) |

### 2.2 Side tables/payload (`samples/payloads/`) —— measured byte headers and entropy

```
payload_v1.bin        4532 B  head=b'\xac\x11\x00\x00AJM\x01'   entropy=7.8690
codetable_v2.bin      1174 B  head=b'AJMT\x16\x00\x00\x00'      entropy=6.4900
brand_res_v3.dat       572 B  head=b'AJMT\x08\x00\x00\x00'      entropy=6.6762
```

**Key reading points**:
- `payload_v1.bin`'s first 8 bytes = `int32_le length(0x11AC=4524) + 'AJM\x01'`; entropy 7.87 > 7.5,
  **clears the B1 threshold**.
- `codetable_v2.bin` is an **AJMT side table** (`AJMT` + `u32 count=0x16=22`); entropy **6.49 < 7.5**.
- `brand_res_v3.dat` is also AJMT (count=8), entropy **6.68 < 7.5**.
- **Key trap**: the gen-2/gen-3 side-table **entropy is below the B1 threshold 7.5**, so you **cannot catch v2/v3 via a "high-entropy asset"**
  ——only via the dex empty-method ratio (B3/B3*). And v3 even disguises its filename as a normal resource, so "high-entropy file" is bound to miss.

### 2.3 dex (`samples/dex/` + `pristine/dex/`) —— golden comparison

Measured empty-method ratios (the real numbers behind B3, `dexlib.method_code_stats`):

```
pristine/dex/classes_orig.dex        total=23 with_code=22 empty= 0 ratio= 0.0%
build/v1/classes.dex（壳 dex）        total=22 with_code=22 empty= 0 ratio= 0.0%
build/v2/extracted.dex（抽取后）      total=45 with_code=44 empty=22 ratio=50.0%
pristine/dex/extracted_v3.dex         total=45 with_code=44 empty= 8 ratio=18.2%
```

- v1: the business dex is not inside the APK's classes.dex (fully encrypted into the asset); the shell dex's empty-method ratio is **0%**.
- v2: **50.0% > 40%** → hits B3 directly.
- v3: **18.2% < 40%** → B3 misses; falls through to B3* (the presence of **locally** 100% empty-method classes) to drill down.

---

## 3. Criterion system: A (naive) and B (structural)

`detect.py` outputs both criterion sets at once, **deliberately** letting you see how the naive criteria fail.

### 3.1 Criterion A —— naive strings (**never decides on its own**)
`FAMILY_STRINGS` (`detect.py:40`) = `['ijiami', 'ProxyApplication', 'ijiami_shell_version',
'ijiami_real_application', 'ijm_payload', 'ijm_codes']`. A hit records `naive`, but **does not participate in the verdict ladder**.
After variant samples fully obfuscate the strings, criterion A is always `未命中任何家族字符串`——this is the teaching aid for "never rely on strings alone".

### 3.2 Criterion B —— structural/statistical (**the sole basis for the verdict**)

| Code | Criterion | Threshold/code | Decides? |
|---|---|---|---|
| **B1** | High-entropy asset | `entropy > 7.5` and `size > 1024` (`detect.py:483`) | one of the gen-1 conditions |
| **B2** | Class count ≤ 8 means shell | **deliberately kept wrong example** (`:488-490`, must false-positive on `app_orig`) | No |
| **B3** | All-class empty-method ratio | `empty_ratio > 0.4` (`:494`) | gen-2 independent verdict |
| **B3\*** | Low overall ratio but locally empty-method classes exist | `empty_ratio > 0.02` and `hot_classes` non-empty (`:496`) | gen-3 independent verdict |
| **B4** | Proxy Application | declared class == `app_name` and method count `≤ 8` (`:505`), with dynamic-loading strings | gen-1 auxiliary |
| **B5** | Placeholder unused | `:515` | No |
| **B6** | All App business classes missing + high-entropy asset | `app_pkgs` non-empty and `biz` empty (`:521-522`) | one of the gen-1 conditions |
| **B7** | manifest-declared class missing from the union of all dex | `missing = declared - all_dex_classes` (`:531`) | strong evidence, paired with B1/B6 |
| **B8** | Known shell-vendor SO (`SUSPECT_SO` list, `:44`) | list hit (`:561`) | native signal, needs ELF confirmation |
| **B9** | SO file-level entropy > 7.5 and size>20000 | `:569` | **notes only, does not decide** |
| **B10** | Anti-analysis strings (`ANTI_ANALYSIS_STRINGS`, `:58`) | hit (`:541`) | **notes only, does not decide** |
| **B11** | Extremely short methods converging on one large method | `_tiny_call_hubs` (`:233`) | suspected DEX VMP |
| **B12** | native-method ratio | `≥ 0.30` and native≥5 (`:552`) | suspected Java2CPP |
| **B13** | SO ELF structural anomalies | `elfinspect` anomalies non-empty (`:576-581`) | suspected SO packing |

### 3.3 Verdict ladder (`detect.py:596-615`, **order is priority**)
```
if   has_b3:                 → 已加固：类抽取型（二代及以上）
elif has_b6 and has_b7:      → 已加固：DEX 整体加密型（一代）
elif has_b11:                → 疑似 DEX VMP（B3 在此形态必然失效）—— 需人工确认
elif has_b12:                → 疑似 Java2CPP / 重度 native 化 —— 需人工确认
elif has_b8:                 → 疑似 Native 侧加固（已知壳厂商 SO），需 ELF 层确认
elif has_b13:                → 疑似 SO 加壳 / 自实现 Linker，需 ELF 层确认
elif has_b7 and has_payload: → 疑似 DEX 动态加载（证据不足以下代次结论）
elif rules 且 有非 B1 规则:   → 疑似加固（证据不足以下代次结论）
else:                        → 未见已知加固特征（≠未加固）
```
**Key reading point**: `has_b3` is checked **before** `has_b6/b7`——as long as a high empty-method ratio is measured, it is judged gen 2 even if gen-1 features are also present.
B1 alone **never flips the verdict** (in real Apps, compressed resources/ML models are all high-entropy; a single rule would flag half the app store as suspicious).

### 3.4 The four specific questions you asked (code location for each)
- **Which function computes B3's empty-method ratio?** `dexlib.Dex.method_code_stats()` (`dexlib.py:340-362`).
  It walks `iter_methods()`, for each method with a `code_off` fetches the `code_item`, and treats
  `ci['insns'].count(0) == len(ci['insns']) and ci['insns_size'] > 0` (`:353`) as "empty".
  It returns `empty/with_code` as `empty_ratio` (`:361`).
- **Which line is the 40% threshold written on?** `detect.py:494` `if empty_ratio > 0.4:`. Note the numerator/denominator:
  the denominator is `with_code` (methods that have a code_item), not `total`.
- **How is B7's relative-class-name `.MainActivity` false positive exposed by the negative sample?** `aapt2_xmltree` (`detect.py:182-183`)
  fixes this: the manifest allows a relative class name `".MainActivity"`, which implicitly expands to `package + name`; if not expanded,
  `missing = declared - all_dex_classes` would always count the component as "missing". This trap is caught by the `neg_multidex.apk`
  negative sample (`forbid=['B6','B7','B11','B12']`, see `check_negatives.py:41`).
- **How the variant sample falsifies criterion A**: see `make_variant.alias()` (§9)——the strings all change, but the dex structure stays unchanged byte for byte.

---

## 4. `tools/detect.py` output, actually run (pasted verbatim)

The key lines per sample (`grep -a` to get the verdict; `--json` gets everything):

```
===== app_orig =====
  【判据 A · 朴素字符串】未命中任何家族字符串
  >> 结论：未见已知加固特征（不等于未加固，见下方认知边界）

===== app_packed_v1 =====
  【判据 A · 朴素字符串】命中家族字符串 ['ProxyApplication', 'ijiami', 'ijm_payload']
  【判据 B · 结构】B1 高熵 asset(assets/ijm_payload.bin, 7.869 bit/byte) —— 存在加密 payload
  【判据 B · 结构】B4 manifest 声明的 Application=com.ijiami.shell.ProxyApplication 在 dex 里是个"小 Application"(2 方法) 且 dex 引用了动态加载类 ['DexClassLoader', 'loadClass'] —— Application 被代理
  【判据 B · 结构】B6 所有 dex 的并集中都没有 App 自身包(com.demo.target)的业务类，且存在高熵 asset —— 真 dex 只能藏在 asset 里，判定为一代整体加密
  【判据 B · 结构】B7 AndroidManifest 声明了 2 个类，其中 1 个在所有 classes*.dex 的并集中都不存在 —— 需由运行期动态加载提供（强证据，但定性为一代还需配合 B1/B6 的载荷证据）
  >> 结论：已加固：DEX 整体加密型（一代）

===== app_packed_v2 =====
  【判据 B · 结构】B3 全类空方法率 50.0% > 40% —— 类抽取（二代）
  >> 结论：已加固：类抽取型（二代及以上）

===== app_packed_v3 =====
  【判据 B · 结构】B3* 整体空方法率仅 18.2%，但存在局部空方法类 —— 需下钻到单类
  >> 结论：已加固：类抽取型（二代及以上）

===== app_vmp =====
  【判据 B · 结构】B11 2 个极短方法体汇聚调用同一个大方法 com.ijiami.vmp.Vmp->run（目标 196 code unit） —— 业务方法已退化为解释器调用，疑似 DEX VMP（此形态下 insns 非零，B3 空方法率必然失效）
  >> 结论：疑似 DEX VMP（业务方法退化为解释器调用，B3 空方法率在此失效）—— 需人工确认

===== app_so_packed =====
  【判据 B · 结构】B13 libcalc.so 的 ELF 结构异常：no_section_headers：共享对象却完全没有节头表 —— 自定义 Linker 的典型形态（自己按 Program Header 装载）；no_dynsym：没有动态符号表，无法被标准 dlopen 解析，疑似自实现符号解析；no_dynstr：没有动态字符串表 —— 疑似 SO 加壳 / 自实现 Linker，需人工进 ELF 层确认
  >> 结论：疑似 SO 加壳 / 自实现 Linker（ELF 结构异常），需 ELF 层确认

===== neg_highentropy =====
  【判据 B · 结构】B1 高熵 asset(assets/data_blob.bin, 7.997 bit/byte) —— 存在加密 payload
  >> 结论：未见已知加固特征（不等于未加固，见下方认知边界）
```

**Key reading points**:
- v1's `app_pkgs` is inferred as `com.demo.target` (reverse-inferred from the manifest component classes); no business classes at all → B6 hits.
- v3's `B3*` is **not** B3: the overall ratio 18.2% is below 40%, and it hits by drilling into "the presence of locally 100% empty-method classes".
- `app_vmp`'s AHP convergence: `com.ijiami.vmp.Vmp->run`, target **196 code units** (far above `min_hub_units=30`).
- `neg_highentropy` **hits B1 but the verdict is still "not seen"**——live proof that B1 must not decide on its own.

---

## 5. `tools/dexlib.py` —— self-built dex parse/rewrite library

### 5.1 Header layout (`dexlib.py` top docstring, verified on this machine)
```
DexHeader 0x00-0x70
  magic[8]       0x00  "dex\n037\0"
  checksum       0x08  adler32(data[12:])
  signature[20]  0x0c  sha1(data[32:])
  file_size      0x20
  header_size    0x24  恒 0x70（HEADER_SIZE）
  endian_tag     0x28  恒 0x12345678
  map_off        0x34
  string_ids     0x38(size)/0x3c(off)
  type_ids       0x40/0x44   proto_ids 0x48/0x4c   field_ids 0x50/0x54
  method_ids     0x58/0x5c   class_defs 0x60/0x64   data 0x68/0x6c
```

### 5.2 Key functions
- `check()` (`:131-139`) returns the 4-tuple `(checksum_ok, signature_ok, size_ok, endian_ok)`.
- `finalize()` (`:141-156`)——**must be called after rewriting**; recomputes file_size→signature→checksum.
  **The order cannot be reversed** (`:147` comment is a hard-won lesson): `signature=sha1(data[32:])` is computed first,
  `checksum=adler32(data[12:])` second (the latter covers the region containing the signature). On this machine the first implementation had the order reversed,
  causing the restored dex to report `Bad checksum` under dexdump.
- `class_data(off)` (`:245-286`): the direct/virtual encoded_method groups **each independently** accumulate
  `method_idx_diff` (`:271` vs `:283`)——this is the most error-prone spot in the dex format.
- `code_item(off)` (`:289-307`): `CODE_ITEM_HEADER=16` (`registers/ins/outs/tries` each u2 +
  `debug_info_off` u4 + `insns_size` u4); `insns_bytes = insns_size * 2` (a code unit is u2).
- `write_insns(off, blob)` (`:313-322`): the length must be **exactly equal** to `insns_bytes`, otherwise it raises
  `ValueError` (this guards against misalignment when backfilling).
- `method_code_stats()` (`:340-362`): see §3.4, the source of every empty-method-ratio number.

`mutf8_decode` (`:77-97`): dex strings are **MUTF-8** (not standard UTF-8; `0xC0 0x80` means U+0000).
`read_uleb128`/`encode_uleb128` (`:50-74`): every size/index diff in dex is uleb128.

---

## 6. `tools/crypto_lab.py` —— byte-level identical to the shell's Java side

```python
KEY  = bytes([0x5A,0x3C,0x7F,0x11,0xE4,0x29,0x8D,0x63])   # crypto_lab.py:22
MAGIC= b'AJM\x01'                                          # v1 payload 容器
TABLE_MAGIC = b'AJMT'                                      # v2/v3 侧表容器
```
Stream cipher (`:37-42`): `out[i] = b ^ KEY[i & 7] ^ (i & 0xFF)`. The i-th byte additionally XORs the position counter `i&0xff`
——the same plaintext at different offsets yields different ciphertext, which blocks the dumb approach of "directly search for the dex magic" without being complex enough to prevent hand computation.

**Cross-check of consistency with Java** (read on this machine from `shell/src/com/ijiami/shell/Crypto.java`):
- `:17-18` `private static final byte[] KEY = { (byte)0x5A, (byte)0x3C, (byte)0x7F, (byte)0x11, ... }`
- `:32` `out[8 + i] = (byte)(plain[i] ^ KEY[i & 7] ^ (i & 0xff));`
- `:45` `out[i] = (byte)(packed[8 + i] ^ KEY[i & 7] ^ (i & 0xff));`
The two formulas correspond **word for word** to `crypto_lab._stream`.

**v1 payload container** (`crypto_lab.py:10-18`): `[0..4) int32_le original dex length` + `[4..8) 'AJM\x01'`
+ `[8..) the XORed dex`.
**v2/v3 AJMT side table** (`:70-97`): after `[4B magic][u32 count]`, each entry is
`[u4 class_idx][u4 method_idx][u4 code_off][u4 insns_len][insns_len bytes of XOR ciphertext]`.

`self_test()` (`:100-106`): runs a round-trip on `bytes(range(256))*3`; on this machine `python tools/crypto_lab.py`
outputs `self_test OK: len=768, packed=776` (776=768+8 header).

---

## 7. Unpacking

### 7.1 `unpack_v1.py` (gen 1: payload decryption) —— CLI run
```
$ python tools/unpack_v1.py samples/apks/app_packed_v1.apk analysis_output/unpack_v1_dex.dex \
      --pristine pristine/dex/classes_orig.dex
[1] 从 APK 取出 payload: assets/ijm_payload.bin  (4532 bytes)
[2] 头部: decl_len=4524  magic=b'AJM\x01'
[3] 解密后长度 = 4524
[4] dex 魔数校验: b'dex\n037\x00'
[5] 已写出: analysis_output/unpack_v1_dex.dex
    sha256 = e330d2998de45a680a5a3cd415d1e83290378cc15584b2c2831518028c588cc1
[6] 与黄金 classes_orig.dex 对照: 完全一致 ✓
```
**Payload location does not rely on the filename**: `read_payload_from_apk` (`:32-40`) scans files under `assets/` whose **first 4 bytes
== `b'AJM\x01'`**; only if none is found does it fall back to the conventional name `assets/ijm_payload.bin`.

### 7.2 `unpack_v2.py` (gen 2/3: AJMT side-table backfill)
```
$ python tools/unpack_v2.py samples/apks/app_packed_v2.apk analysis_output/unpack_v2_dex.dex \
      --pristine pristine/dex/classes_merged_orig.dex
[1] 在 APK 里定位侧表: assets/ijm_codes.bin  (1174 bytes)
[2] 解析侧表...
    侧表条目数 = 22
[3] 把指令回填到 dex 的 code_item.insns 区...
    成功回填 22 个方法
[4] 重算 checksum/signature 完成
[5] 已写出: analysis_output/unpack_v2_dex.dex
    sha256 = 7527307217b96ea2fa0628fc4d7170851f45302b2910166cb6847eb40656f94d
    还原后：空方法数 = 0 / 44
[6] 与黄金 classes_merged_orig.dex 对照: 完全一致 ✓
```
v3 goes through the same script (the side-table filename is disguised as `brand_res_v3.dat`, located via the **magic `AJMT`** rather than the filename):
```
$ python tools/unpack_v2.py samples/apks/app_packed_v3.apk analysis_output/unpack_v3_dex.dex \
      --pristine pristine/dex/classes_merged_orig.dex
[1] 在 APK 里定位侧表: assets/brand_res_v3.dat  (572 bytes)
    侧表条目数 = 8
    成功回填 8 个方法
    还原后：空方法数 = 0 / 44
[6] 与黄金 classes_merged_orig.dex 对照: 完全一致 ✓
```
**v3 backfills only 8 methods** (vs v2's 22), yet after restoration it is byte-for-byte identical to the **same golden**——because v3 extracted only a subset.

### 7.3 The two backfill guards (`unpack_v2.py:108-119`)
- `code_item(code_off) is None` → `[跳过]` (`code_off` is not a valid code_item);
- `ci['insns_size']*2 != len(insns)` → `[跳过]` (length mismatch, preventing writes at the wrong location);
- only after passing does it call `write_insns`.

### 7.4 ⚠️ Multi-dex silent truncation warning (`unpack_v2.py:81-93`)
Each AJMT side-table entry has only **one `code_off` (a single-dex offset)** and no "which dex it belongs to" field.
`find_table_in_apk` backfills only `classes.dex`. If the APK is multi-dex, the script **explicitly warns**:
```
[!] 检测到多 dex：classes.dex, classes2.dex
    AJMT 侧表格式只有一个 code_off，无法跨 dex 定位，本工具只能回填 classes.dex。
    以下 dex 若也含被抽取方法，将【不会被回填】，产出结果是残缺的：
      classes2.dex
```
**Root cause**: this is an **inherent limitation of the side-table format**, not a bug. This lab's samples are all single-dex, so it never triggers.

### 7.5 Variant unpacking (v2 variant)
```
$ python tools/unpack_v2.py samples/dex/extracted_v2_variant.dex \
      samples/payloads/codetable_v2_variant.bin analysis_output/unpack_v2_variant_dex.dex \
      --pristine build/variant/merged_orig_variant.dex
    还原后：空方法数 = 0 / 44
[6] 与黄金 merged_orig_variant.dex 对照: 完全一致 ✓
```

---

## 8. `tools/verify.py` —— quantitative verification (three checks)

```
$ python tools/verify.py analysis_output/unpack_v1_dex.dex pristine/dex/classes_orig.dex
[1] sha256: 一致 ✓
    还原  e330d2998de45a680a5a3cd415d1e83290378cc15584b2c2831518028c588cc1
    黄金  e330d2998de45a680a5a3cd415d1e83290378cc15584b2c2831518028c588cc1
[2] 锚点字符串: 还原 11 个 / 黄金 11 个
    全部锚点都在 ✓
[3] 无差异 ✓
=> 结论：还原成功，与黄金样本完全一致
```
- **Anchor prefix** `AJM-ANCHOR-` (`verify.py:24`); `find_anchors` (`:31-33`) reads the string pool via `dexlib`.
  On this machine `classes_orig.dex` measures **11 entries**: `AJM-ANCHOR-0000::logtag` … `AJM-ANCHOR-0009::flag{` etc.
- On mismatch it gives `[3] diff byte count + first diff offset` (`:64-75`), used to locate where the restoration went wrong.

---

## 9. `tools/make_variant.py` —— string-obfuscation variant (equal-length reversed mapping)

`alias()` (`make_variant.py:54-56`) uses `str.maketrans` to do an **equal-length** substitution:
```
_LOWER_SRC = 'abcdefghijklmnopqrstuvwxyz_'   # 27
_LOWER_DST = 'zyxwvutsrqponmlkjihgfedcba9'   # 27（下划线→9）
_UPPER 同理（去掉尾部）
```
**Why it must be equal-length** (`:19-23`): dex's `string_data_item` is
`[uleb128 utf16_size][bytes][0x00]`; equal-length substitution requires moving no data and recomputing no offsets——a minimal safe rewrite.
**Only letters and underscores are changed; `.`/`/`/`;` are kept as-is**, so `com/ijiami/shell/ProxyApplication`
becomes (measured on this machine, `str.translate`):
```
xlw/rqzrnm/hsoow/KurmbZbkovvrgmlrq
```
(The `need_rewrite` rule triggers a transform only when it hits one of `RULES` (`:44-45`) = `ijiami/ProxyApplication/ShellClassLoader/
PayloadLoader/ApplicationSwap/AJM/ijm_`.)

**patch_binary_xml** (`:93-113`): changes the feature strings inside the compiled AndroidManifest.xml in **both the UTF-8 and
UTF-16LE forms** (class names in binary XML are UTF-16LE).
**Core teaching point**: after the variant, criterion A is fully defeated, but the dex structural features (empty-method ratio/side-table presence) are **unchanged by a single byte**——
so B3/B3*/B1 still hit as before, and the variant samples in `check_negatives.py` are still judged "hardened".

---

## 10. Regression —— `check_negatives.py` (bidirectional assertions)

It imports `detect`; `run()` (`:52-55`) returns `(verdict, [rule codes])`. The assertions come in two groups:
- **Positive** (`POSITIVE`, `:30-37`): 6 samples must satisfy `concl.startswith(expected prefix)`;
- **Negative** (`NEGATIVE`, `:40-49`): 4 samples must be **neither** `已加固` **nor** hit any `forbid` code.

Run on this machine (all pass, exit 0):
```
正向样本：必须检出（防止过度修正把真壳漏掉）
  [OK  ] app_packed_v1.apk     -> 已加固：DEX 整体加密型（一代）
  [OK  ] app_packed_v2.apk     -> 已加固：类抽取型（二代及以上）
  [OK  ] app_packed_v3.apk     -> 已加固：类抽取型（二代及以上）
  [OK  ] app_packed_v2_variant.apk -> 已加固：类抽取型（二代及以上）
  [OK  ] app_vmp.apk           -> 疑似 DEX VMP（...）—— 需人工确认
  [OK  ] app_so_packed.apk     -> 疑似 SO 加壳 / 自实现 Linker（ELF 结构异常），需 ELF 层确认

负向样本：绝不允许被判成"已加固"
  [OK  ] neg_multidex.apk    -> 未见已知加固特征（...）  陷阱：多 dex：manifest 声明的组件类在 classes2.dex
  [OK  ] neg_highentropy.apk -> 未见已知加固特征（...）  陷阱：多 dex + 合法高熵 asset（守住 B1 不得单独定性）
  [OK  ] app_orig.apk        -> 未见已知加固特征（...）  陷阱：原始未加固 APK（历史负样本）
  [OK  ] neg_native.apk      -> 未见已知加固特征（...）  陷阱：正常 native 应用：含合法 NDK .so，不得因 SO/动态加载判壳

结果：全部通过（正向 6 项 / 负向 4 项）
```
**The negative `forbid` list is key**: `neg_native.apk` additionally forbids `B8` and `B13` (locking down "a legitimate NDK .so
must not trigger the SO criteria"); `neg_multidex`/`app_orig`/`neg_highentropy` forbid `B6/B7/B11/B12`.

### `tools/reset_lab.py` (backup/status/restore)
- **Scope**: all of `samples/` recursively; the manifest key is rooted at `samples/` (`apks/...`, `dex/...`,
  `payloads/...`); pristine mirrors to `pristine/<rel>`; the manifest file is `pristine/MANIFEST.json`
  (**uppercase**, unlike 360jiagu/upx_practice's `manifest.json`).
- `status` (`:75-101`) reports `OK/DIFF/MISSING/EXTRA` per entry; exits 1 on any DIFF or MISSING.
- `restore` (`:104-123`) overwrites only files whose sha256 differs (unless `--force`).
- **Why not git** (`:13-17`): the samples are signed `.apk` binaries, and practice often requires "breaking samples/" to observe
  detection behavior——an independent sha256 baseline is lighter than `git checkout` and less likely to damage unrelated changes.

Status on this machine: `=> OK=34  DIFF=0  MISSING=0  EXTRA=0`.

---

## 11. Interface contract with `unpacker/`

`unpacker/labs.py` bridges this lab read-only:
- `load_ajiami_detect()` → `ajiami/tools/detect.py`
- `load_ajiami_unpack_v1()` → `ajiami/tools/unpack_v1.py`
- `load_ajiami_unpack_v2()` → `ajiami/tools/unpack_v2.py`
- `load_ajiami_verify()` → `ajiami/tools/verify.py`

**Contract** (`labs.py` docstring and the actual calls in `analyzer.py`):
- `detect.apk_features(path) -> f` (a dict of features) and `detect.verdict(f) -> (verdict, rules, naive, hints, notes)`
  ——a **5-tuple**. `analyzer.analyze_apk_or_dex` takes `concl` as `verdict`, and `is_packed = concl.startswith('已加固')`.
- `unpack_v1.main()` / `unpack_v2.main()` are **CLI entry points** (invoked with argv), not `solve(...)`-style functions;
  `unpack.py:114+` calls them with a controlled argv.
- `verify.sha()/find_anchors()` are reused by the bridge.

**Constraints on you**: the names of `apk_features`/`verdict`, the return-tuple order, and the three prefixes
`已加固`/`疑似`/`未见已知加固特征` are all pinned by `unpacker/analyzer.py` and the `EXPECTED` table in `regression.py:54-67`. If you change them, sync everything.

---

## 12. Build chain (how the samples actually come to exist)

`build/*.sh` (bash, all of which `source build/env.sh`) + `tools/*.py`:
1. `build_target.sh`: `javac`(app/src) → `d8` → `samples/dex/classes_orig.dex` (golden);
   `aapt2 link` produces the skeleton → `apkutil inject-dex` → `zipalign -f 4` → `apksigner sign` → `app_orig.apk`.
2. `build_shell.sh`: similarly compiles `shell/src` → `build/shell/shell_classes.dex` + `shell.apk` skeleton.
3. `build_merged.sh`: compiles **business + shell** into the same `build/merged/merged_classes.dex`
   (the typical gen-2 form: classes.dex contains both business class names and the shell ProxyApplication).
4. `tools/packer.py v1|v2|v3|all`: produces `build/v{1,2,3}/`'s extracted.dex + side table + `pack_report.json`.
5. `tools/make_variant.py v1|v2|all`: produces the variants (equal-length obfuscation).
6. `tools/mkapk.py` assembles + `zipalign` + signs → `samples/apks/*.apk`.

**Toolchain resolution**: `env.sh` writes only variable references; the real values are probed by `build/locate.sh`; `envload.py` lets the Python
tools obtain `AJ_*` **without source** (because PowerShell has no `source`/`export`). `mkapk._env` (`:33-38`)
issues a `SystemExit` saying "check build/env.sh" when `AJ_*` is missing.

**The irreversibility design of packing** (`packer.py`):
- v1 `crypto_lab.encrypt(orig_dex)` → payload; classes.dex is replaced with a pure shell dex (`:68-91`).
- v2/v3 `extract()` (`:95-147`): extracts only the **non-shell** classes under `com/demo/` (`is_business_class`, `:62-64`),
  overwrites each code_item in place with `b'\x00'*len` (**dalvik opcode 0x00 = nop; the dex is still legally loadable**, `:138`),
  deduplicating by `code_off` (`seen_code_off`; a code_item referenced by multiple methods is processed only once).
- v3 additionally uses `shuffle_table=True` → `random.Random(20260922).shuffle(entries)` (`:146`, a **fixed seed**,
  ensuring reproducibility), and adds a low-entropy decoy `config_decoy.txt`.

---

## 13. File-format-layer details summary

- **dex header offsets**: see §5.1; `header_size` is always `0x70`; `endian_tag` is always `0x12345678`.
- **checksum/signature order**: first `signature=sha1(data[32:])` @0x0c, then `checksum=adler32(data[12:])` @0x08.
- **v1 payload header**: `[0..4) int32_le original dex length` + `[4..8) 'AJM\x01'`; measured `0x11AC`=4524.
- **AJMT side table**: `'AJMT'(4) + u32 count`, each entry a 16-byte header + `insns_len` bytes of XOR ciphertext.
- **ELF header offsets** (`elfinspect.py:69-71`): ELF64 `e_type@16, e_phoff@32, e_shoff@40, e_phentsize@54,
  e_phnum@56, e_shentsize@58, e_shnum@60, e_shstrndx@62`; ELF32 the corresponding @16/@28/@32/@42/@44/@46/@48/@50.
- **Phdr field order (error-prone, `elfinspect.py:91-101`)**: ELF64 is `type,flags,offset,vaddr,paddr,filesz,
  memsz,align`; ELF32 is `type,offset,vaddr,paddr,filesz,memsz,flags,align`——**you cannot unpack uniformly by order**.
- **Anchor prefix**: `AJM-ANCHOR-` (`verify.py:24`), measured 11 entries in `classes_orig.dex`.

---

## 14. Pitfalls (root causes, not a list of symptoms)

1. **`finalize()` order reversed → `Bad checksum`**. `signature` must be computed first, `checksum` second
   (checksum covers the region containing the signature). The comment at `dexlib.py:147` is this very lesson.
2. **B3's denominator is `with_code`, not `total`**. `method_code_stats` counts something as "empty" only for methods that **have a code_item**
   (native/abstract methods with `code_off==0` do not enter the denominator). Don't use the wrong denominator when hand-computing the threshold.
3. **The AJMT side table has only a single `code_off`; cross-dex is unsolvable**. A multi-dex sample would be silently truncated——the script has added an explicit warning
   (`unpack_v2.py:81-93`), but the root cause is the format itself.
4. **Criterion A being fully defeated after a variant is not "not hardened"**. String obfuscation only changes **equal-length** readable strings; the dex structure is unchanged by a single byte.
   The verdict must come from structural criteria like B3/B3*/B1. `neg_*` and `*_variant` jointly prove this.
5. **B1 alone never flips the verdict**. `neg_highentropy.apk` measurably hits B1 (7.997 bit/byte) yet is still judged "not seen"——
   in real Apps, compressed resources/ML models are all high-entropy; a single rule amounts to flagging half the app store as suspicious.
6. **b3 outranks b6/b7 in the ladder**. When a high empty-method ratio and gen-1 features coexist, it is judged gen 2 (`:596` comes first).
7. **Missing `aapt2` → B7 degrades**. If `_find_aapt2` (`:114-128`) cannot find it, it degrades to a string heuristic;
   at that point **a relative class name `.MainActivity` cannot be expanded**, and B7 false-positives on normal Apps (caught by `neg_multidex`).
8. **`reset_lab.py`'s manifest name is `MANIFEST.json` (uppercase)**, unlike the other two labs' `manifest.json`——
   don't apply one script's convention to another.
9. **Emptying a method with `b'\x00'*len` is a legal nop**, not "corruption". dalvik opcode 0x00 = nop, so an emptied
   dex can still be loaded by ART (which is what allows runtime backfilling)——this is the precondition that makes gen-2 hardening work.
10. **Windows console garbles Chinese**: set `PYTHONIOENCODING=utf-8` (PowerShell
    `$env:PYTHONIOENCODING='utf-8'`). The root cause is Python's local encoding, not a script bug.
11. **`ajiami/SCRIPT.md/CLI.md/GUI.md` show as modified in `git status`**: before I took over, the working tree already had an uncommitted
    doc change (adding a "criterion code master table" A/B1–B13). **That was not produced by this task**; I only added `AGENTS.md`.
12. **`mkpacked_so.py`'s `.text` XOR uses `os.urandom`** (`:54`)——each generated B13 sample is **nondeterministic**.
    B13's primary trigger is stripping section headers (`no_section_headers`, deterministic); `high_text_entropy` is only supplementary.

---

## 15. Quick reference (all measured on this machine)

```bash
# --- verdict ---
python tools/detect.py samples/apks/app_orig.apk
python tools/detect.py samples/apks/app_packed_v2.apk
python tools/detect.py samples/apks/app_packed_v2_variant.apk
python tools/detect.py samples/dex/extracted_v2.dex --json

# --- unpack + verify ---
python tools/unpack_v1.py samples/apks/app_packed_v1.apk analysis_output/unpack_v1_dex.dex \
       --pristine pristine/dex/classes_orig.dex
python tools/unpack_v2.py samples/apks/app_packed_v2.apk analysis_output/unpack_v2_dex.dex \
       --pristine pristine/dex/classes_merged_orig.dex
python tools/unpack_v2.py samples/apks/app_packed_v3.apk analysis_output/unpack_v3_dex.dex \
       --pristine pristine/dex/classes_merged_orig.dex
python tools/verify.py analysis_output/unpack_v1_dex.dex pristine/dex/classes_orig.dex

# --- hand-inspect dex structure ---
python tools/dexlib.py pristine/dex/extracted_v2.dex          # magic/file_size/空方法率/类表
python tools/crypto_lab.py                                    # 加解密 self-test
python tools/apkutil.py entropy samples/payloads/codetable_v2.bin

# --- pack / variant (rebuild samples) ---
python tools/packer.py v1
python tools/packer.py v2
python tools/packer.py v3 --targets SecretLogic,TokenUtil
python tools/make_variant.py all

# --- regression + reset ---
python tools/check_negatives.py     # 正向 6 / 负向 4 —— 全过才算绿
python tools/reset_lab.py status
python tools/reset_lab.py restore

# --- repo-level (run at the repo root) ---
python unpacker/regression.py        # 19/19 + 交叉 4/4
```

---

## 16. Reading order for a new agent

1. Read `tools/detect.py`'s `verdict()` (`:415-617`) end to end——all B criteria, thresholds, and the ladder live here.
2. Read `tools/dexlib.py:method_code_stats()` and `code_item()`——the source of the B3 numbers.
3. Run each item in §15 "verdict" and compare against the §4 fixtures; focus on `neg_highentropy` (hits B1 but judged "not seen") and
   `app_vmp` (B11).
4. Read `tools/packer.py`'s `extract()` and `tools/crypto_lab.py`——understand the container format and nop extraction.
5. Run `unpack_v1`/`unpack_v2` + `verify`, confirming byte-for-byte identity with the golden.
6. Read `tools/make_variant.py`'s `alias()`, and manually `str.translate` one obfuscated string.
7. Finally read `SCRIPT.md`/`CLI.md`/`GUI.md`——they restate the same facts for humans; **the ground truth is in the code**.


---
