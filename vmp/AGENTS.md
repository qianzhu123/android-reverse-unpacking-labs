# AGENTS.md — vmp lab (ground-truth document for agents)

> **Audience: an agent that needs to be productive in this lab within a few minutes.**
> Every item below comes from **reading the source line by line** and **actually running
> things on this machine** (Windows 11 / Git Bash + PowerShell, JDK at
> `D:/tools/Dev/Runtime/java`, Android SDK build-tools 37.0.0, NDK r27d
> `27.3.13750724`). Line numbers refer to the files' current contents; if you change a
> file, re-verify them yourself.
>
> **Repo iron rules that apply here**: zero absolute paths in scripts/build/docs;
> the lab root is derived from the script's own location; self-built samples ARE
> committed; the epistemic boundary is **"absence of known signatures ≠ not hardened"**.
>
> **Read this before touching the lab.** The three Chinese teaching docs
> (`SCRIPT.md`/`CLI.md`/`GUI.md`) retell the same facts for humans — **the ground truth
> is in the code, the generated sources, and the real command output pasted here.**

---

## 0. What this lab is

`vmp` teaches **virtualization-based protection (VMP) and its removal** — the topic
`PROMPT.md` explicitly puts *out of scope* for the packer/shell labs. Where `ollvm`
covers *obfuscation* and the other labs cover *packers/shells*, `vmp` covers the case
where business logic is **compiled into a custom bytecode** and executed by an
**interpreter** at runtime.

The lab is a **self-built, byte-reproducible** lab (`PROMPT.md` route):

- Every sample is generated from one **expression spec** (`tools/vmlang.py:PROGRAMS`);
- The **golden** app (`src/com/demo/calc/`) implements the same spec in plain Java;
- Each protected level's custom bytecode is `assemble`d from that same spec.

Therefore "the protected sample equals the golden logic" is a **structural guarantee**,
not an eyeball comparison — this is the lab's **semantic oracle** (`tools/verify_gen.py`).

`ajiami/vmp/` (the older, single-shape DEX VMP model in the sibling lab) is
**superseded** by this lab: `vmp` has 5 DEX levels + 3 SO levels + 4 adversarial
negatives + devirtualization tooling + a two-way regression, and is not bridged into
`unpacker/` (see §10).

---

## 1. Directory map

```text
vmp/
├── SCRIPT.md  CLI.md  GUI.md     ★ the three teaching docs (Chinese, one skeleton)
├── AGENTS.md                     ★ this file (English)
├── src/                          golden source ONLY (plaintext, no VM)
│   ├── AndroidManifest.xml
│   └── com/demo/calc/{CalcLogic.java, CalcActivity.java}
├── samples/
│   ├── apks/     13 APKs (golden + L1..L5 + S1..S3 + 4 negatives)
│   ├── dex/      golden.dex · level_L*.dex · level_S*.dex · neg_*.dex
│   ├── payloads/ golden_ops.json · level_*.bin · level_*.map.json · so_*.map.json
│   └── native/   libcalc_s{1,2,3}_{arm64,x86_64}.so
├── pristine/     sha256 baseline of samples/ (reset_lab.py restore source)
├── analysis_output/
├── tools/        vmlang vmgen build_levels build_so_levels build_negatives
│                 dexscan detect_vm devirt_dex devirt_so nop_methods
│                 verify_gen check_negatives trace_vm reset_lab
│                 + ported: apkutil dexlib elfinspect envload
├── build/        locate.sh · env.sh.example · build_{golden,vm,so,neg}.sh
├── frida/        trace_dispatch.js · so_vm_trace.js · oracle_run.js
├── neg/          (empty dir; negative sources are GENERATED into build/gen/neg_*)
└── logs/         (empty)
```

**There is no `vmp/` source tree and no `neg/` source tree on disk.** Per-level sample
sources are **generated** into `build/gen/level_*` (DEX) and `build/gen/so_*` (SO) by
`tools/build_levels.py` / `tools/build_so_levels.py`, and the negatives into
`build/gen/neg_*` by `tools/build_negatives.py`. Those generated trees are
**gitignored** (`**/build/gen/`, plus `**/build/golden|vm|so|neg/` and `**/build/neg/`);
`build/` itself keeps only the scripts (`locate.sh`, `env.sh.example`, `build_*.sh`).
**If `build/gen/` is missing, run the three generators first** — nothing else will build.

---

## 2. Sample set — measured sizes and hashes (on this machine)

`sha256` truncated to 16 hex chars; full hashes are refreshed by `reset_lab.py backup`.

| APK | bytes | sha256[:16] |
|---|---|---|
| `app_golden.apk` | 8587 | `07c03362cffa33d8` |
| `app_l1.apk` | 12683 | `5c6063f4b7db3c5c` |
| `app_l2.apk` | 12746 | `78d0402701c9304d` |
| `app_l3.apk` | 12683 | `c987bd3a1de66676` |
| `app_l4.apk` | 12683 | `9837e7860f828a99` |
| `app_l5.apk` | 12683 | `30ba9eb7c25ff6e1` |
| `app_s1.apk` | 16916 | `e4c27dfc6c853c59` |
| `app_s2.apk` | 16916 | `edfb9dec8e3b579d` |
| `app_s3.apk` | 16916 | `078b4903f45c4e3a` |
| `neg_plain.apk` | 8587 | `5a6100bafa6280f7` |
| `neg_bigswitch.apk` | 8587 | `f7687631e78b9eb7` |
| `neg_hub.apk` | 8587 | `8684c2a0ff138808` |
| `neg_extract.apk` | 8587 | `0be1a60927be8fd0` |

| native SO | bytes | sha256[:16] |
|---|---|---|
| `libcalc_s1_arm64.so` | 7216 | `2ad21875e7651eff` |
| `libcalc_s1_x86_64.so` | 6712 | `bba9dd671b9ad8f4` |
| `libcalc_s2_arm64.so` | 8144 | `dd4a8b842e76e710` |
| `libcalc_s2_x86_64.so` | 7912 | `30037a60e3766204` |
| `libcalc_s3_arm64.so` | 9064 | `0a3a6568f3f38d08` |
| `libcalc_s3_x86_64.so` | 8592 | `7c67963bc79d7d64` |

| dex | bytes |
|---|---|
| `golden.dex` | 2140 |
| `level_L1.dex` | 3108 |
| `level_L2.dex` | 3820 |
| `level_L3.dex` | 4392 |
| `level_L4.dex` | 3368 |
| `level_L5.dex` | 3260 |
| `level_S1/S2/S3.dex` | 2172 each (identical — the SO levels share one Java side) |
| `neg_plain.dex` / `neg_extract.dex` | 2136 |
| `neg_hub.dex` | 2296 |
| `neg_bigswitch.dex` | 2376 |

> **APKs are not byte-stable across rebuilds** (the zip carries timestamps and the
> signing block); the **SO and dex contents are stable**. After a rebuild, run
> `python tools/reset_lab.py backup` to refresh `pristine/manifest.json`. The table
> above is a point-in-time reading, not a golden spec.

---

## 3. The VM language — `tools/vmlang.py`

The single source of truth; read it first (194 lines).

**Instruction set** (`:29-31`):

```
BASE_OPS  = ['LOADARG','PUSH','XOR','ADD','MUL','SUB','RET']       # stack machine
SUPER_OPS = ['ADDK','MULK','XORK','ADDMUL']                        # fused (L4 only)
N_IMM = {'LOADARG':1,'PUSH':1,'XOR':0,...}                         # immediate counts
```

**Three roles** (all deterministic):

| function | line | role |
|---|---|---|
| `interpret(tokens, args, wrap32=True)` | `:39` | reference semantics — the golden answer |
| `assemble(tokens, opmap, imm_width=1)` | `:99` | canonical op stream → custom bytecode |
| `disassemble(code, opmap, imm_width=1)` | `:114` | custom bytecode → canonical op stream |
| `expand(tokens)` | — | super-ops → base ops (for readable golden Java) |
| `make_opmap(seed, shuffle, superops)` | `:138` | opcode table (dense small `0x01..` or shuffled) |

**The spec** (`PROGRAMS`, `:185`) and vectors (`VECTORS`, `:192`):

| method | program | golden outputs (vectors) |
|---|---|---|
| `mix(a,b)` | `((a^b)+0x11)*3` | `(7,3)→63`, `(0,0)→51`, `(-1,5)→33` |
| `twist(a)` | `(a*7)-5` | `(7)→44`, `(0)→-5`, `(-9)→-68` |
| `digest(a,b)` | `((a*b)^(a+b))+0x5A` | `(7,3)→121`, `(1,1)→93`, `(12,5)→135` |

`python tools/vmlang.py` self-checks: prints the three program outputs and asserts that
the super-op expansion is semantically identical. **Run it before trusting any level.**

---

## 4. Sample generation — `tools/build_levels.py`, `build_so_levels.py`, `build_negatives.py`

### 4.1 DEX levels (`build_levels.py`)

Five levels; each differs **only in the dispatch shape / bytecode carrier**:

| level | `Core.run` dispatch | bytecode carrier | `EMIT['Lx']` |
|---|---|---|---|
| L1 | regular `packed-switch`, opcodes `0x01..0xFF` | `private static final byte[] P_*` in source | `emit_L1` |
| L2 | same switch | `assets/core_a.dat`, XOR'd, `Core.init(ctx)` loads it | `emit_L2` |
| L3 | **no switch** — `int[] DISPATCH` + `Method[]` reflection (`ensureInit()` at `:`) | `byte[] P_*` in source | `emit_L3` |
| L4 | `sparse-switch`, **random non-contiguous opcodes** + fused ops | `byte[] P_*` in source | `emit_L4` |
| L5 | **inline VM** — no `Core` class; `mix/twist/digest` each embed the interpreter | `byte[] P_*` per method | `emit_L5` |

- `_expr_cases(opmap, st=…)` (`build_levels.py`) is the single switch-case code generator;
  it is **stack-variable-parameterised** (hub uses `STACK`, inline uses `st`) and
  **local-name-parameterised** (`x/y`, not `a/b`, so an inlined body can't collide with
  the method's own `a`/`b` parameters — this was a real compile failure, see §12).
- `emit_L2` writes `samples/payloads/level_L2.bin` (ciphertext, == the asset bytes) and
  `level_L2.plain.bin` (`[len_mix,len_twist,len_digest] + segments`).
- `main()` **`rmtree`s** `build/gen/level_Lx` before regenerating — without this, stale
  `.class` files from a previous shape get compiled in (this actually happened: the
  inline L5 once contained a leftover `Core.class`).

**The L2 loader must read to EOF, not `in.available()`** (`build_levels.py`, `CORE_L2`):
`AssetManager`'s decompression stream can report `available()==0` first, yielding an
empty buffer — the symptom is "the same sample returns 0 sometimes and the right value
other times". The generated loader uses a `ByteArrayOutputStream` loop.

### 4.2 SO levels (`build_so_levels.py`)

Three native levels; the Java side is identical (three `native` declarations +
`System.loadLibrary("calc")`).

| level | dispatch (in `core.c`) | built with |
|---|---|---|
| S1 | central **comparison cascade** (`subs w8,w8,#imm` / `b.eq <case>`) | **`-O0`** (keeps cascade + separate case bodies) |
| S2 | `handler_t SLOT[]` + `OPMAP[]` **assembled at runtime**, dispatched via indirect call | `-O2` |
| S3 | **threaded / computed-goto** (`goto *LBL[op]`, block net) | `-O2` |

`SO_OPMAP` (`build_so_levels.py`) is **fixed** and must match the C `case` constants:
`LOADARG=0x01 PUSH=0x02 XOR=0x03 ADD=0x04 MUL=0x05 SUB=0x06 RET=0xFF`. (The generic
`vmgen.level_opmap('L1')` returns a *different* dense map — using it here was a real bug
that made every S-level return 0; see §12.)

`build/build_so.sh` picks `OPT=-O0` for S1 and `-O2` otherwise. **This is deliberate**:
S1 is the "static-solvable" teaching case; S2/S3 are the "must go dynamic" cases.

### 4.3 Negatives (`build_negatives.py` + `nop_methods.py`)

| negative | shape | what it tests |
|---|---|---|
| `neg_plain` | plain app | baseline |
| `neg_bigswitch` | a **legitimate state machine** (`switch` + loop, 70-code-unit method) | V4/V6 false positives |
| `neg_hub` | three tiny methods calling one **big utility method** (no switch, no VM) | V1 false positive (convergence alone ≠ VM) |
| `neg_extract` | `neg_plain`'s dex with business method bodies **nop'd** (`nop_methods.py`) | "abnormal method body" ≠ VM |

---

## 5. Detection — `tools/dexscan.py` + `tools/detect_vm.py`

### 5.1 `dexscan.py` — the DEX shape scanner (read-only)

Thresholds are **constants in the file, not magic numbers**:

```python
TINY_UNITS  = 24   # dexscan.py:165  "极小方法体" bound  (business method = build array + invoke + return)
HUB_UNITS   = 30   # dexscan.py:166  "大方法" lower bound (interpreter loop)
MIN_CALLERS = 2    # dexscan.py:167  convergence criterion needs ≥2 tiny callers
LIT_ARITH   = set(range(0xb0, 0xe3))   # :179  binop/lit16 + binop/lit8 = fused-op shape
```

| function | line | what it does |
|---|---|---|
| `scan(insns)` | `:60` | one pass over a method body → `units`, `invokes` (method_idx list), `switches` (case values), `has_backbranch` |
| `find_switch(insns)` | `:173` | first `packed`/`sparse` switch → `(switch_idx, [(key, target)])` |
| `case_opcodes(insns, target, others)` | — | slice a case body up to the next case target |
| `fingerprint(opcodes)` | — | case body → `LOADARG/PUSH/XOR/ADD/MUL/SUB/RET/None` |
| `recover_opmap_from_switch(insns)` | — | `{opcode → name}` via switch-case fingerprinting |
| `find_fill_array_data(insns)` | — | raw bytes of each `fill-array-data` (static `byte[]` carrier) |

**DEX payload layouts (both once got wrong — see §12):**

- `packed-switch-payload`: `u2 ident(0x0100) | u2 size | s4 first_key | s4 targets[size]`
  → targets start at **+4 code units**, not +2.
- `sparse-switch-payload`: `u2 ident(0x0200) | u2 size | s4 keys[size] | s4 targets[size]`
  → **two separate arrays**, keys first then targets (not `(key,target)` interleaved).

### 5.2 `detect_vm.py` — the structural verdict (read-only)

Criteria (code strings are the contract with `check_negatives.py`):

| code | condition (file:line) | verdict weight |
|---|---|---|
| **V1** | ≥`MIN_CALLERS` tiny methods invoke one hub method ≥`HUB_UNITS` | **definitive** for DEX VM |
| V2 | count of tiny methods that only call (no switch, no loop) | auxiliary count only |
| **V3** | an `assets/` entry whose basename is in the dex string pool, `8 ≤ size ≤ 4096`, `entropy > 4.2` (`detect_vm.py:156`) | carrier is external |
| **V4** | a `≥HUB_UNITS` method with a switch **and** a back-branch | interpreter located |
| **V5** | ≥2 methods share an **identical switch-case set** | **definitive** for inline VM (no hub) |
| **V6** | switch case set (minus a `0xFF` sentinel) is not a dense small set | random opcodes |
| **VN1** | `Java_*` present **and** a compact `.rodata`/`.data.rel.ro` (8..4096 B) | native carrier |
| **VN2** | biggest function's dispatch shape is `indirect` or `threaded` (`:266-273`) | dispatch not a central switch |
| **B13** | `ET_DYN && e_shnum==0 && executable PT_LOAD` (from `elfinspect`) | SO packing / custom linker |

Dispatch-shape classifier (`detect_vm.py:_dispatch_shape`, `:266`):

```python
if n_br  >= 4: shape = 'threaded'    # >4 × `br xN`  = computed-goto block net
elif n_cmp >= 5: shape = 'switch'    # ≥5 × cmp with immediate = comparison cascade
elif n_blr >= 1: shape = 'indirect'  # any `blr xN`    = runtime-assembled call target
else:            shape = 'linear'
```

**Verdict rule (the load-bearing part, `detect_vm.py:_verdict_apk`):**

```
V1 hit            -> suspected DEX VM (hub)          [definitive]
elif V5 hit       -> suspected inline DEX VM          [definitive]
elif V4 or V6     -> "no VM hub/inline signature (≠ none) — interpreter-like shape
                      observed, but a normal state machine also matches"
```

**V4/V6 never classify alone.** `neg_bigswitch.apk` proves why: a legitimate state machine
has a `switch` + loop and non-contiguous cases (its cases run `4..259`), so V4/V6 both
fire on a *clean* app. Restricting the verdict to V1/V5 is what makes the regression pass.

### 5.3 Real runs (pasted verbatim)

```text
$ python tools/check_negatives.py
== 正向：DEX VMP 样本必须判为 VM，且命中代号 ==
[ PASS ] positive     app_l1.apk                 codes=V1,V4
[ PASS ] positive     app_l2.apk                 codes=V1,V3,V4
[ PASS ] positive     app_l3.apk                 codes=V1
[ PASS ] positive     app_l4.apk                 codes=V1,V4,V6
[ PASS ] positive     app_l5.apk                 codes=V4,V5
== 正向：SO/ARM64 VMP 样本 ==
[ PASS ] positive     libcalc_s1_arm64.so        codes=VN1
[ PASS ] positive     libcalc_s2_arm64.so        codes=VN1,VN2
[ PASS ] positive     libcalc_s3_arm64.so        codes=VN1,VN2
== 负向：干净/非 VM 样本必须 NOT 判为 VM ==
[ PASS ] negative     neg_plain.apk              'no known hardening signature observed (≠ none)'
[ PASS ] negative     neg_bigswitch.apk          'no VM hub/inline signature (≠ none) — V4/V6 ...'
[ PASS ] negative     neg_hub.apk                'no known hardening signature observed (≠ none)'
[ PASS ] negative     neg_extract.apk            'no known hardening signature observed (≠ none)'
== 基线：黄金样本必须「未见已知特征」 ==
[ PASS ] baseline     app_golden.apk             'no known hardening signature observed (≠ none)'
=> 13/13 ALL PASS
```

Note `app_l5.apk` shows `codes=V4,V5` and **no V1** — the inline VM deliberately has no
hub. Any tooling change that starts reporting V1 on L5 is a regression.

---

## 6. Devirtualization

### 6.1 DEX — `tools/devirt_dex.py`

Four steps (all read-only): locate the switch interpreter (V4 shape) → recover `opmap`
from case-body **fingerprints** → obtain the bytecode (`fill-array-data` bytes, or
decrypt the referenced `assets/` entry with the small static `byte[]` as XOR key) →
`disassemble` + validate against `golden_ops.json`.

```text
$ python tools/devirt_dex.py samples/apks/app_l1.apk
  note: opmap recovered from switch in Lcom/demo/calc/Core;->run
  recovered opmap (7 entries): 1=LOADARG, 2=PUSH, 3=XOR, 4=ADD, 5=MUL, 6=SUB, 7=RET
  prog0   12 bytes ->  8 ops  => semantics == golden mix
          LOADARG:0 LOADARG:1 XOR PUSH:17 ADD PUSH:3 MUL RET
  prog1    9 bytes ->  6 ops  => semantics == golden twist
  prog2   15 bytes -> 10 ops  => semantics == golden digest
```

```text
$ python tools/devirt_dex.py samples/apks/app_l2.apk
  note: opmap recovered from switch in Lcom/demo/calc/Core;->run
  note: payload assets/core_a.dat decrypted with 16-byte key from static field
  ... (identical to L1)
```

```text
$ python tools/devirt_dex.py samples/apks/app_l5.apk
  note: opmap recovered from switch in Lcom/demo/calc/CalcLogic;->digest
  prog0..prog5 -> semantics == golden mix / twist / digest
```

```text
$ python tools/devirt_dex.py samples/apks/app_l3.apk
  note: no packed-switch interpreter found -> reflection/dispatch needs dynamic tracing
  (static devirtualization insufficient — dynamic route required)
```

```text
$ python tools/devirt_dex.py samples/apks/app_l4.apk
  recovered opmap (11 entries): 34=XOR, 62=ADD, 87=RET, 101=LOADARG, 120=MUL, 154=XOR,
                                163=MUL, 202=PUSH, 203=MUL, 210=ADD, 212=SUB
  prog0   10 bytes ->  0 ops  => semantics == golden ?
          (disassembly incomplete: 未知 opcode 0x3E @0x5)
  ! fused/inline-immediate opcodes present (static fingerprint cannot split the immediate
    out) -> static devirtualization is PARTIAL; dynamic trace required
```

**Honest outcome**: L1/L2/L5 are **fully** devirtualized. **L3 is not tool-solvable**
(no switch; reflection) — though a *human* can read `ensureInit`'s `aput` constants
(opcode→slot), the `HM` `getDeclaredMethod("hN")` order (slot→handler), and the
~20-instruction `h0..h6` bodies (handler→semantics), which is why §4.1 says "no
single switch to slice" rather than "unsolvable". **L4 is only partial** — the
fingerprint cannot separate a base op from its fused variant: in the **real** dex,
`0x9A`=XOR and `0x22`=XORK both fingerprint as `XOR`; `0xD2`=ADD and `0x3E`=ADDK both
as `ADD`; `0xA3`=MUL / `0xCB`=MULK / `0x78`=ADDMUL all as `MUL`. The cause: a fused
handler uses the *same* arithmetic instruction — the only difference is reg,reg vs a
reg + an inline immediate (`aget-byte code[pc]; and #255`), which is byte-identical in
shape to `PUSH`'s immediate read. So the recovered opmap is ambiguous and disassembly
stops. This is a **documented boundary**, not a bug.

### 6.2 SO — `tools/devirt_so.py`

```text
$ python tools/devirt_so.py samples/native/libcalc_s1_arm64.so
  note: interpreter = vmr (214 insns, dispatch=switch)
  note: switch opmap: 7/7 cases fingerprinted via comparison-chain simulation
  switch opmap: 1=LOADARG, 2=PUSH, 3=XOR, 4=ADD, 5=MUL, 6=SUB, 255=RET
```

Mechanism: recognise the **comparison cascade** (`subs wR,wR,#imm` / `b.eq <case>` /
`b <next>`), then run a **symbolic walk** of that comparison tree (`_simulate_chain`, with
address snapping because `next` lands on the function body a couple of instructions
before the `subs`). For each leaf, fingerprint the case body by **data arithmetic only**:

```
`add w8, w8, w9`   (reg,reg)  -> data op   (ADD/MUL/SUB/XOR)
`add x9, x9, #0x14`(immediate)-> bookkeeping, NOT a VM op  ← the trap
`ldrb`             alone      -> PUSH
`ldrb` + scaled `ldr`         -> LOADARG   (read code[pc], then index args)
scaled `ldr` alone            -> RET       (pop from the stack array)
```

```text
$ python tools/devirt_so.py samples/native/libcalc_s2_arm64.so
  note: interpreter = Java_com_demo_calc_CalcLogic_mix (106 insns, dispatch=indirect)
  note: dispatch is indirect -> need dynamic tracing ...
  ! static devirtualization not sufficient for this dispatch shape
```

```text
$ python tools/devirt_so.py samples/native/libcalc_s3_arm64.so
  note: interpreter = vmr (123 insns, dispatch=threaded)
  ! static devirtualization not sufficient for this dispatch shape
```

S2/S3 are the honest WIP boundary (like `uncrackable/l3`): static can only classify the
dispatch shape, not recover the mapping. The documented next step is dynamic tracing
(`frida/so_vm_trace.js`).

### 6.3 Dynamic route — `tools/trace_vm.py` + `frida/*.js`

`trace_vm.py` is isomorphic with `uncrackable/tools/hook_run.py` (spawn → attach → load
script → resume → sleep → detach/kill). It finds frida via the repo-root `.venv`
(`frida 16.5.9`, pinned — 17.x drops the `Java` global the hooks need) or the current
interpreter, and **`--device usb|<ip:port>`** selects the target.

> ⚠️ `trace_vm.py` **installs and launches the target app on the connected device**.
> Only run it on a device you are authorized to use or on the local `n4tive_lab` AVD.
> Never against someone else's phone.

---

## 7. Verification — `tools/verify_gen.py`

The **semantic oracle** (no device needed). Three checks, all must pass:

1. re-run each `PROGRAMS` spec through `vmlang.interpret` → must equal the recorded results;
2. every DEX level: decrypt/extract its bytecode → `disassemble` with that level's opmap
   → `interpret` → must equal the same golden results;
3. every SO level: same, using `SO_OPMAP`.

```text
$ python tools/verify_gen.py
== 1. 黄金规范复算 ==   (9 vectors OK)
== 2. DEX 层字节码 -> 反汇编 -> 语义 ==   L1 OK  L2 OK  L3 OK  L4 OK  L5 OK
== 3. SO 层字节码 -> 反汇编 -> 语义 ==    S1 OK  S2 OK  S3 OK
=> ALL OK
```

**Run this after ANY change to `vmlang.py`, the generators, or the build scripts.**
It is the only check that proves "the sample still means what the golden means".

`tools/check_negatives.py` is the **two-way regression** (§5.3). Both must be green
before committing.

---

## 8. Toolchain

- **`build/locate.sh`** — ported from `ajiami/build/locate.sh`, four-tier resolution
  (CLI arg > env var > `build/env.sh` > auto-detect). Local deltas: `VMP_AAPT2`
  override prefix, and NDK target wrappers exported as `CLANG_AARCH64` /
  `CLANG_X86_64` / `CLANG_ARM` (`aarch64-linux-android24-clang.cmd` etc.).
- **`build/env.sh.example`** — copy to `build/env.sh`; signing config uses alias `calc`
  (so `META-INF/CALC.SF`, not a telling name) with passphrase `calclab123`.
- **Resolved on this machine**: JDK `D:/tools/Dev/Runtime/java`, SDK build-tools
  `37.0.0` (`aapt2`/`d8.jar`/`zipalign`/`apksigner.jar`/`dexdump.exe`), NDK
  `.../ndk/27.3.13750724`.
- **`tools/{apkutil,dexlib,elfinspect,envload,reset_lab}.py`** are **ported verbatim**
  from `ajiami/tools/` (lab-self-contained; no cross-directory imports). Deltas:
  `envload.ensure_env` default prefix `VMP_`; `reset_lab` manifest is `manifest.json`
  (lowercase) with a **flat** `{rel: sha256}` dict.

**Build order to make everything green from scratch:**

```bash
python tools/vmgen.py emit          # src/com/demo/calc/CalcLogic.java + payloads/golden_ops.json
python tools/build_levels.py        # build/gen/level_L1..L5/ + payloads/level_*.bin
python tools/build_so_levels.py     # build/gen/so_S1..S3/ + payloads/so_*.map.json
python tools/build_negatives.py     # build/gen/neg_*/ 
bash build/build_golden.sh          # samples/apks/app_golden.apk + samples/dex/golden.dex
bash build/build_vm.sh              # app_l1..l5.apk + level_L*.dex
bash build/build_so.sh              # app_s1..s3.apk + samples/native/libcalc_s*.so
bash build/build_neg.sh             # neg_*.apk
python tools/verify_gen.py && python tools/check_negatives.py
python tools/reset_lab.py backup
```

---

## 9. File-format-layer details

- **Package / classes**: `com.demo.calc`, classes `CalcActivity` / `CalcLogic` (+ `Core`
  in L1–L4 only). **Deliberately neutral** — no `vmp`/vendor word appears in any sample's
  package, class, resource, log tag, anchor string, or signing alias.
- **Anchor string**: `ANCHOR-0001:LOGIC-MIX` (returned by `CalcLogic.anchor1()`).
- **Log line** (all samples): `mix(7,3)=63 twist(7)=44 digest(7,3)=121
  anchor=ANCHOR-0001:LOGIC-MIX` under tag `CALC`.
- **L1 bytecode** (from `level_L1.bin`, after the 3-byte length header):
  `P_MIX = 01 00 01 01 03 02 11 04 02 03 05 07`.
- **S1 `.rodata`** (36 B @ addr/off `0x548`): `01 00 01 01 03 02 11 04 02 03 05 ff …`.
  Note **`RET` is `0xFF` here**, unlike the DEX levels' `0x07` — because SO uses
  `SO_OPMAP`, the DEX levels use `vmgen.level_opmap`.
- **APK signature**: alias `calc` → `META-INF/CALC.SF` / `CALC.RSA`.
- **`samples/payloads/golden_ops.json`**: `{methods:{<name>:{args,ops,vectors,results}}}`.
  `ops` is the canonical token list (`[["LOADARG",0],…]`); `results` is the golden answer
  for `vectors`. `devirt_dex.py` matches a recovered program against these.

---

## 10. Relationship to sibling labs / `unpacker/`

- **`unpacker/labs.py` bridges only `360jiagu`/`upx_practice`/`ajiami`** (`LABS` dict).
  `vmp` is **not** bridged — changing `vmp` does not affect `unpacker/regression.py`,
  and vice versa.
- **`ajiami/vmp/`** is the older single-shape DEX VMP model with detect criterion **B11**
  (multiple tiny methods converging). `vmp` **supersedes** it for teaching purposes;
  `ajiami` is untouched by this lab.
- **`showcase`**: `vmp` is a `PROMPT.md` (self-built) lab, so its samples **are
  committed** — unlike `uncrackable/*` (real targets, gitignored).

---

## 11. External resources (references, not vendored)

**Windows/PE-side VMP analysis (the mature field — concept reference only):**

| repo | ★ | note |
|---|---|---|
| `can1357/NoVmp` | ~2.2k | static devirtualizer for VMProtect x64 3.x (VTIL) |
| `JonathanSalwan/VMProtect-devirtualization` | ~1.5k | symbolic-execution + LLVM deobfuscation |
| `lmy375/awesome-vmp` | ~1.1k | curated VMP-analysis reading list |
| `NaC-L/Mergen` | ~0.9k | LLVM-IR based deobfuscation |
| `fjqisba/VmpHelper` | ~0.4k | IDA plugin for VMP |

**Android / ARM (open-source, legal to study — optional, gitignored if fetched):**

| repo | note |
|---|---|
| `fuqiuluo/amice` | Rust/LLVM VMP for Android (open protector — can generate your own targets) |
| `Kotoamatsukami233/xVMP` | Android ELF VM protection |
| `xopJack/XopProtector` | Android protector with a VMP component |
| `La0D3ng0/AndroidSoRecon` | Android SO VMP recon notes |

**Honest boundary**: commercial VMProtect/Themida **protected samples cannot be
self-built or redistributed**, and there is **no `star`-ranking "VMP range" for Arm**
comparable to the PE side. The self-built ladder in this lab is the main track;
`build/fetch_external.ps1` (optional) fetches the open-source Android ones into
`tools/` (gitignored). Star counts are approximate and drift — re-check before citing.

---

## 12. Pitfalls (root causes)

1. **DEX `packed-switch-payload` offset**: `u2 ident | u2 size | s4 first_key |
   s4 targets[]` — targets start at **+4** code units. Reading size/first_key at the
   wrong offsets (e.g. `+0/+1` or `+4/+2`) yields garbage cases. (`dexscan.py:find_switch`)
2. **DEX `sparse-switch-payload` layout**: `u2 ident | u2 size | s4 keys[size] |
   s4 targets[size]` — **keys array then targets array**, not interleaved pairs. Reading
   it interleaved silently misaligns every case target.
3. **A 256-entry jump table** appears for dense switch values (`packed-switch-data
   (18 units)` with a `0x0100` ident) — don't mistake its size for a case count.
4. **V6's `0xFF` sentinel**: the `RET` opcode `0xFF` made case sets look non-contiguous,
   so L1/L2 falsely reported V6. Fix: strip `0xFF` before the density test.
5. **V3 cannot key on entropy alone**: the L2 payload is 39 B and its XOR-stream entropy
   is only 5.18 — `>7.5` missed it. Fix: key on **"basename present in the dex string
   pool"** + size; entropy is only a secondary check (>4.2).
6. **`in.available()` on an assets stream** can return 0 → empty buffer → intermittent
   zeros. Fix: read to EOF (`ByteArrayOutputStream`).
7. **Stale build dirs**: regenerating a level without clearing it leaves old `.class`
   files in the dex (the inline L5 once contained a `Core.class` hub). Both
   `build_levels.main()` and `build/build_vm.sh` now `rm -rf` the per-level dir.
8. **SO opcode table mismatch**: the C `case` constants are `SO_OPMAP`
   (`RET=0xFF`), while `vmgen.level_opmap('L1')` gives a different dense map — using the
   latter assembled a bytecode the SO couldn't run (every S-level returned 0).
9. **`add x9, x9, #0x14` is bookkeeping, not a VM op.** Fingerprinting on *all* `add`
   classified every S1 case as ADD. Fix: only `add/sub` with **two w-registers**
   (reg,reg) count as data ops.
10. **`-O0` vs `-O2`**: at `-O2` clang folds S1's comparison cascade into a jump table,
    so the static devirtualizer fails. S1 is built `-O0` **on purpose** so that the
    comparison cascade survives; S2/S3 are `-O2` on purpose so that they are hard.
11. **`br` counted from the wrong column**: `llvm-objdump` lines are `addr: rawbytes
    mnemonic operands`. Matching raw address/branch text against the whole line counted
    0 branches; the fix is to extract the mnemonic field first.
12. **jadx shows `byte[]` as signed decimals** (`-1` == `0xFF`) — convert before reading
    opcodes, or the recovered map is shifted.
13. **`neg_bigswitch` is a false positive generator on purpose.** If a tool change makes
    V4/V6 alone produce a VM verdict, this negative fires. That is the intended alarm.
14. **frida must be 16.5.9** (repo `.venv`). 17.x removed the `Java` global the hooks use.
15. **Signing alias was `vmplab`** → `META-INF/VMPLAB.SF` leaked a telling name inside
    every APK. Changed to alias `calc` (`META-INF/CALC.SF`); rebuild all samples after
    changing it.

---

## 13. Quick reference (all measured on this machine)

```bash
# --- generate sources (idempotent) ---
python tools/vmgen.py emit
python tools/build_levels.py && python tools/build_so_levels.py && python tools/build_negatives.py

# --- build ---
bash build/build_golden.sh && bash build/build_vm.sh && bash build/build_so.sh && bash build/build_neg.sh

# --- detection (read-only; multiple targets OK) ---
python tools/detect_vm.py samples/apks/app_l4.apk
python tools/detect_vm.py samples/native/libcalc_s1_arm64.so
python tools/detect_vm.py samples/apks/app_l1.apk --json

# --- devirtualization ---
python tools/devirt_dex.py samples/apks/app_l1.apk        # full
python tools/devirt_dex.py samples/apks/app_l4.apk        # partial (fused ops)
python tools/devirt_so.py  samples/native/libcalc_s1_arm64.so  # full (7/7)

# --- verification (the two must-pass gates) ---
python tools/verify_gen.py          # semantic oracle  -> ALL OK
python tools/check_negatives.py     # two-way regression -> 13/13 ALL PASS

# --- reset ---
python tools/reset_lab.py status | backup | restore --force
```

---

## 14. Reading order for a new agent

1. Read `tools/vmlang.py` (`:29-31` opcodes, `:185` `PROGRAMS`, `:192` `VECTORS`) and run
   `python tools/vmlang.py` — establish the semantic baseline.
2. Read `tools/build_levels.py`'s `EMIT` dict + `_expr_cases` to see how one spec becomes
   five DEX shapes; run `python tools/build_levels.py` and read one generated
   `build/gen/level_L1/com/demo/calc/Core.java`.
3. Read `tools/dexscan.py` thresholds (`:165-167`) and `find_switch` — the two payload
   layouts in §12.1/§12.2 are the most common source of wrongness here.
4. Read `tools/detect_vm.py`'s verdict block — note that **only V1/V5 classify**.
5. Run `python tools/check_negatives.py` and `python tools/verify_gen.py`; both must be
   green before you change anything.
6. Read `tools/devirt_so.py` `_fingerprint_a64` — the reg,reg vs immediate distinction
   (§12.9) is the whole trick for S1.
7. Finally read `SCRIPT.md`/`CLI.md`/`GUI.md` — they retell the same facts for humans;
   **the ground truth is in the code, the generated sources, and §5.3's pasted output.**
