# AGENTS.md — uncrackable lab (ground-truth doc for agents)

> **Reader: an agent that needs to get productive in this lab within a few minutes.**
> Every item comes from reading the source/scripts line by line + actually running them on this machine (Windows / Bash, python 3.13, frida 16.5.9).
> Line numbers correspond to the file's current content; if you change a file, re-verify them yourself.
>
> **Repo hard rules**: zero absolute paths; the three routes (SCRIPT/CLI/GUI) share one skeleton; third-party samples are not committed;
> the epistemic boundary is **"no known signature observed ≠ not hardened"**.
>
> **The fundamental difference between this lab and a self-built lab (the `PROMPT-REAL.md` route)**: the target is **the official
> OWASP MASTG public crackmes (external / real targets)** — **no source, no golden baseline**. Verification relies on **behavior/artifact oracles**,
> **not** byte comparison. Third-party samples are **gitignored** (the repo keeps only sha256 + provenance + conclusions).

---

## 0. What this lab is / status of the three levels

`uncrackable/` is **one target family** (OWASP MASTG UnCrackable), so the three levels live under **one folder**,
sharing `tools/` ("shared runner + frida-server") — rather than three nearly duplicate top-level directories.

| Level | Form | Status | oracle type | key/result |
|---|---|---|---|---|
| **l1** | Java AES check + root detection | ✅ SOLVED | algorithm | `I want to believe` |
| **l2** | native `strncmp` check + fork/ptrace anti-debug | ✅ SOLVED | artifact + algorithm | `Thanks for all the fish` |
| **l3** | native check + **constructor-level anti-tamper watchdog** + integrity check | ⚠️ **WIP (dynamic not passed)** | — | — |

**l3 is honestly submitted as an "unsolved work item", not a solved lab** (`README.md` + `l3/SCRIPT.md:5` state this explicitly).

**Dynamic-analysis prerequisites** (see the repo-root README "Real-target lab environment setup"): you need to start an Android emulator
(`n4tive_lab`, Android 14 / SDK 34 / x86_64) + push `frida-server`; frida is pinned to **16.5.9**
(17.x's Java bridge dropped the `Java` global, and all hooks in this lab depend on it).

---

## 1. Directory map

```text
uncrackable/
├── README.md                  lab family overview + shared-runner notes
├── TUTORIAL.md                ★ guided learning path (l1→l2→l3, start here)
├── tools/                     ★ shared by l1/l2/l3
│   ├── hook_run.py            shared Frida runner (spawn + sideload + timed print + detach)
│   └── frida-server-16.5.9-android-x86_64(.xz)   gitignored
├── l1/                        Level 1 — Java AES + root detection        [SOLVED]
│   ├── SCRIPT.md  CLI.md  GUI.md
│   ├── samples/{apks,dex}/…   gitignored
│   ├── pristine/provenance.json   source + authorization + environment fingerprint + result
│   ├── frida/{enumerate,solve}.js
│   ├── analysis_output/classes.dump.txt    dexdump output (committed)
│   └── logs/solve-run.txt
├── l2/                        Level 2 — native strncmp + fork/ptrace     [SOLVED]
│   ├── samples/{apks,native,dex}/…
│   ├── frida/{enumerate,probe,solve}.js ; analysis_output/ ; logs/
└── l3/                        Level 3 — native + constructor anti-tamper watchdog   [WIP]
    ├── samples/{apks,native,dex}/…
    ├── frida/{probe,recon,solve}.js
    ├── analysis_output/{classes.dump.txt, libfoo.disasm.txt}
    └── logs/solve-run.txt     (empty — dynamic not passed)
```

**How `l*/` differs from the `PROMPT.md` layout** (`README.md`): there is **no `src/`/`shell/`** (no source);
`pristine/` is the **provenance record** (not a golden backup); `frida/` is **load-bearing structure**.
The only thing hoisted to the parent directory is the **shared runner + frida-server**.

> `samples/apks/*.apk`, `samples/native/libfoo.so`, `samples/dex/classes.dex` are all **gitignored**
> — I confirmed on this machine that they are **present** (l1 66651 B / l2 901022 B / l3 1460555 B), but they are **not committed**.
> A fresh clone must re-pull them itself from the URL in provenance.

---

## 2. `tools/hook_run.py` — the shared Frida runner (the only script)

```python
device = frida.get_usb_device(5) if args.device=="usb" else frida.get_device(args.device, 5)   # :41
pid = device.spawn([args.package]); session = device.attach(pid)
script = session.create_script(fh.read()); script.on("message", on_message); script.load()
device.resume(pid); time.sleep(args.seconds); session.detach(); device.kill(pid)               # :44-56
```
CLI: `--package` (required), `--script` (required, **resolved relative to the current working directory**, not the runner directory, see `:38-39`),
`--seconds` (default 10, the capture window), `--device` (default `usb`).
Message callbacks (`:22-28`): `type=="send"` → `[send] <payload>`; `type=="error"` → `[error] <desc>` + stack.

**Design point**: **bounded by design** (`:5`) — a real-target session **must not hang**, so after `time.sleep(seconds)`
it **force-detaches + kills**. Invocation must use the repo venv:
```
../../.venv/Scripts/python.exe ../tools/hook_run.py --package <pkg> --script frida/solve.js --seconds 8
```

---

## 3. Level 1 — Java AES check + root detection [SOLVED]

### 3.1 Target facts (**from dexdump, not guesswork** — `l1/frida/solve.js:4-14`)
The dexdump output `l1/analysis_output/classes.dump.txt` is verifiable on this machine:
- `sg.vantagepoint.uncrackable1.a.a(String) -> boolean`: `input.equals(the decrypted secret)`.
  - ciphertext (Base64) `5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=` (`string@0007`, dump:440);
  - keyHex `8d127684cbc37c17616d806cf50473cc` (`string@0008`, dump:439), converted hex→bytes by
    `uncrackable1.a.b(...)`;
  - `plain = sg.vantagepoint.a.a.a(keyBytes, encrypted)` — AES (**`AES/ECB/PKCS7Padding`**,
    dump:22; `Cipher.getInstance("AES")`, dump:25).
- root detection: `sg.vantagepoint.a.b.a(Context) -> boolean` (runs before the check, calls `System.exit`);
  `sg.vantagepoint.a.c.a()/.b()/.c()` (more root/debug checks). The dump also shows `"su"` (:105),
  `/system/xbin/daemonsu`, `/system/bin/.ext/.su`, `/dev/com.koushikdutta.superuser.daemon/` (:154-159).

### 3.2 Solve strategy (`solve.js`)
**Two steps, both in order before/after `resume()`**:
1. **Neutralize the gatekeepers** (`:19-31`): implement `a.b.a(Context)` as `return false`; make `a.c`'s `a/b/c` all `return false`.
2. **Call actively** (`:34-56`) — **do not move the constants into JS**; instead **call the app's own functions**:
   ```js
   var enc = Base64.decode(encB64, 0);       // android.util.Base64
   var key = A.b(keyHex);                    // the app's own hex->bytes
   var dec = AES.a(key, enc);                // the app's own AES
   var secret = Java.use('java.lang.String').$new(dec);
   var ok = A.a(secret);                     // oracle: the app's own check MUST return true
   var wrong = A.a('definitely-not-the-secret');  // negative control: MUST be false
   ```

### 3.3 Actual run output (verbatim, `l1/logs/solve-run.txt`)
```
[*] device: Android Emulator 5554  package: owasp.mstg.uncrackable1  script: .../uncrackable-l1/frida/solve.js
[*] spawned pid=6628
[*] resumed; capturing 8.0s of hook output ...
[+] bypass a.b.a(Context)
[+] bypass a.c.a()/.b()/.c()
[recovered] secret = "I want to believe"
[oracle] uncrackable1.a.a(secret) = true
[oracle-neg] uncrackable1.a.a("definitely-not-the-secret") = false
[*] done
```
**Reading it**: `[recovered]` is "the plaintext decrypted with the app's own AES+key"; `[oracle] ... = true` is that **the app's own
check passes** (not us asserting it ourselves); `[oracle-neg] ... = false` is the **negative control** — proving the oracle has discriminating power
(if it were always true it would be meaningless). `provenance.json` records `secret="I want to believe"`, `oracle="algorithm"`.

### 3.4 `l1/frida/enumerate.js` (27 lines)
`Java.enumerateLoadedClasses` filtered by `vantagepoint`, and for each class `getDeclaredMethods()` prints
`class.method(args)->return [static]` — **why it's needed** (script comment): the target method names are obfuscated (a/b/c), and the
dex-level prototypes are easy to misread; **ask the live JVM for the real signatures**, so later hooks are based on real names rather than guesses.

---

## 4. Level 2 — native `strncmp` + fork/ptrace anti-debug [SOLVED]

### 4.1 Target facts (`l2/frida/solve.js:4-8` + `l2/SCRIPT.md:34-66`)
`libfoo.so` exports:
- `Java_sg_vantagepoint_uncrackable2_MainActivity_init`, **returns void** — does `fork`+`ptrace` anti-debug;
- `Java_sg_vantagepoint_uncrackable2_CodeCheck_bar`, `boolean([B)` — `strncmp(input, secret, 23)`.
**The key**: `.rodata` @ file offset `0x11c0` = `"Thanks for all the fish"` (**exactly 23 bytes**).
(Consistent with `strncmp`'s `cmpl $0x17`=23 — `SCRIPT.md:57`.)

### 4.2 Two "hard-won lessons" (`solve.js:10-13`, `SCRIPT.md §8`)
- `init` returns **void** → the stub **must not `return <value>`** (otherwise the signature mismatches);
- `bar` takes a **`byte[]`** → you must construct a **Java byte array**, you cannot pass a JS string.

### 4.3 The core difficulty: the `.bss` gate flag
`bar()`'s first instruction is `cmpb $1, 0x400c` — **if the gate flag is not 1 it returns false immediately** (`SCRIPT.md:36`).
The gate flag is written by `init()` only **after the anti-debug passes**. So after stubbing out `init` you **must write `0x400c` to 1 yourself**
(`solve.js:43-48`):
```js
var base = Module.findBaseAddress('libfoo.so');
Memory.writeU8(base.add(0x400c), 1);     // gate flag = 1, the core bypass of this level
```
> Failure symptom on this machine: **without the bypass**, `onCreate` throws `Bad file descriptor` (the anti-debug breaks the instrumentation itself).

### 4.4 Actual run output (`l2/logs/solve-run.txt`)
```
[*] device: Android Emulator 5554  package: owasp.mstg.uncrackable2  script: .../uncrackable-l2/frida/solve.js
[*] spawned pid=7840
[+] stubbed MainActivity.init()
[bypass] MainActivity.init() stubbed (native anti-debug skipped)
[bypass] libfoo.so base=0x7b4db1adc000 gate[+0x400c]=1
[oracle] CodeCheck.bar("Thanks for all the fish") = true
[oracle-neg] CodeCheck.bar("nope-not-it") = false
[oracle] done
```
**Dual oracle** (`provenance.json`: `oracle="algorithm + artifact"`):
- **artifact**: statically, the key can be read from `.rodata` @0x11c0 (`Thanks for all the fish`);
- **algorithm**: at runtime `bar(key)=true` and `bar(wrong)=false` (it discriminates).
`bar` grabs an instance via `Java.choose(...)` and then calls it (`:52-60`).

---

## 5. Level 3 — constructor-level anti-tamper watchdog [WIP]

### 5.1 The difficulty (`l3/SCRIPT.md:34`)
`libfoo.so`'s **constructor** directly does `pthread_create(start=libfoo+0x37c0)` to launch a **watchdog thread**,
which on detecting Frida/tampering prints `"Tampering detected! Terminating..."` and calls `raise(SIGABRT)`/`_exit`.
**It is already running before the Java code runs** — this is the fundamental reason it's harder than L2.

`l3/analysis_output/libfoo.disasm.txt` is verifiable on this machine (x86_64):
```
38b2: leaq -0xf9(%rip),%rdx   # 0x37c0 <_Z7goodbyev+0x80>   ← watchdog routine address
38c2: callq 0xd10 <pthread_create@plt>
...
3925: callq 0xd40 <fork@plt>          ← fork/ptrace anti-debug
392c: je 0x3948                       ← child branch @0x3948
...
38d8/3a4f: addl $0x1, 0x377d(%rip)   # 0x705c   ← counter/gate flag (+1 ×2)
```
`bar` (`Java_sg_vantagepoint_uncrackable3_CodeCheck_bar` @ `0x3a70`)'s first instruction is
`cmpl $0x2, 0x705c(%rip)` → the gate flag must == **2** (not 1) for it to continue.

### 5.2 Current attack (`l3/frida/solve.js`, **unsuccessful**)
At the **libc layer, before the constructor runs** (the script is pre-loaded before resume), neutralize both lines of defense:
- `Interceptor.attach(pthread_create)`: if `a[2]` (the routine pointer) falls inside the **libfoo text range**
  (`base ≤ a[2] < base+0x8000`), swap it for `stub` (`31 c0 c3` = `xor eax,eax; ret`, a clean
  pthread entry) (`:14-24`);
- `Interceptor.replace(fork)` → return `-1` (take the parent branch); `Interceptor.replace(ptrace)` → return `0` (`:25-28`);
- Java-level stub of `System.exit`/`Runtime.exit`/`killProcess`/`MainActivity.init([B)`/`verifyLibs()`/
  `showDialog`, and force `IntegrityCheck.isDebuggable`=`false`, `RootDetection.checkRoot1/2/3`=`false` (`:30-39`);
- write the gate flag `Memory.writeU32(m.base.add(0x705c), 2)` (`:48`);
- hook **near `bar` at `0x3aaa` to grab the plaintext off the stack** (read 24 bytes at `rsp`, `:45-47`), then run the oracle
  `bar(plaintext)==true` with it.

### 5.3 Status and next steps (**honest record**)
`l3/SCRIPT.md:5` states explicitly: **static work is complete and empirically confirmed; the dynamic oracle is not achieved**; `logs/solve-run.txt` is **empty**.
Suggested next steps (`l3/SCRIPT.md:98`): ① `frida -f` + `--enable-jit` or spawngating for earlier injection;
② **rename/patch** frida-server to evade string and thread detection; ③ switch to a real device / a lower Android version so the integrity check is self-consistent;
④ first fully decompile the constructor in Ghidra and enumerate **all** anti-tamper paths, then kill them one by one.

### 5.4 Helper scripts
- `l3/frida/probe.js` (11 lines): periodic liveness probe — at `[500,1500,3000,5000,8000]ms` it prints
  `libfoo=<base> CodeCheck=<yes/no> MainActivity=<yes/no>`, used to determine "when" the module/class appears.
- `l3/frida/recon.js` (38 lines): reconnaissance.
- `l3/analysis_output/libfoo.disasm.txt` + `classes.dump.txt`: static artifacts (**committed**).

---

## 6. provenance — how external samples come in (`PROMPT-REAL.md` discipline)

Each `l*/pristine/provenance.json` records: `lab` / `prompt` / `target` (name+package+kind) /
`provenance` (source URL + upstream_repo + pulled date + **sha256** + bytes) / `authorization`
(basis + redistribution) / `environment_fingerprint` / `result`.

Key fields read on this machine:

| | l1 | l2 |
|---|---|---|
| source | `raw.githubusercontent.com/OWASP/owasp-mastg/master/Crackmes/Android/Level_01/UnCrackable-Level1.apk` | `.../Level_02/UnCrackable-Level2.apk` |
| sha256 | `1da8bf57d266109f9a07c01bf7111a1975ce01f190b9d914bcd3ae3dbef96f21` | `4c7980ef1f6cc29508f38417c2a5b5b7721eeb4a3d7f00a0c1a08f5192fa6ddd` |
| bytes | 66651 | 901022 |
| pulled | 2026-10-04 | 2026-10-04 |
| authorization | public teaching crackme; sample not committed (gitignored) | same |
| env | Android 14(SDK34) x86_64; frida-server 16.5.9; host frida 16.5.9 / tools 13.7.0 / py 3.13.9 | same |

**Authorization basis**: crackmes publicly released by OWASP for reverse-engineering training; the **samples are NOT committed** —
the repo carries only sha256 + provenance + conclusions. **Do not commit `.apk`/`.so` into the repo.**

---

## 7. File-format/protocol-layer details

- **l1 AES**: `Cipher.getInstance("AES")`, algorithm string `AES/ECB/PKCS7Padding` (`classes.dump.txt:22/25`).
- **l1 gatekeeper classes**: `sg.vantagepoint.a.b` / `sg.vantagepoint.a.c` (obfuscated names `a/b/c`).
- **l2 native symbols**: `Java_sg_vantagepoint_uncrackable2_MainActivity_init` (void),
  `..._CodeCheck_bar` (boolean([B)); `.rodata` key @ file offset `0x11c0`; gate flag `.bss 0x400c`;
  `strncmp` length `0x17`=23.
- **l3 key addresses** (x86_64): watchdog routine `libfoo+0x37c0`; fork child branch `0x3948`;
  gate flag `0x705c` (must == 2); `bar` @ `0x3a70` (first instruction `cmpl $0x2,0x705c`).
- **l2 gate-flag determination**: `bar` is always false if `[0x400c]!=1` (`cmpb $1, 0x400c`).

---

## 8. Environment / prerequisites (actual state on this machine)

- `tools/frida-server-16.5.9-android-x86_64` (113 MB) and its `.xz` are **present** (gitignored).
- On this machine **`adb devices` currently shows no device** (`List of devices attached` is empty) — **before running any hook you must first
  start the emulator + push frida-server** (see the repo-root README "Per-session bring-up").
- Sample APKs present: l1 66651 B / l2 901022 B / l3 1460555 B (gitignored).
- Interpreter: the **repo venv** `../../.venv/Scripts/python.exe` (frida pinned to 16.5.9, **never install globally**).

---

## 9. Relationship to `unpacker/` (no interface)

`unpacker/labs.py`'s `LABS` contains **only** `360jiagu`/`upx_practice`/`ajiami`; `unpacker/regression.py`'s
`EXPECTED` does not include uncrackable either. Reason: this lab is on the **real-target / dynamic** route and has no bridgeable
`detect(path)->dict` / `solve(...)->bool`-style static tool (its "tool" is `hook_run.py` + frida scripts, which
need a device). **Changing this lab does not affect `unpacker/regression.py`.**

---

## 10. Pitfalls (root causes)

1. **l3 is WIP, not solved**. `logs/solve-run.txt` is empty; `SCRIPT.md:5` states the dynamic oracle is not achieved.
   **Do not describe l3 as solved** — this is consistent with the repo's "honest WIP" discipline.
2. **Anti-debug breaks the instrumentation itself**. Without the bypass in l2, `onCreate` throws `Bad file descriptor` — it's not that your script
   is wrong, it's `init`'s fork/ptrace at work. The fix is to stub `init`.
3. **`bar` always false after stubbing `init` ≠ bar is broken**. It's because the gate flag `.bss 0x400c` was never written to 1 by `init`.
   **You must write the gate flag yourself** — this is the core of l2, not an optional step.
4. **Two signature pitfalls in l2**: `init` returns void (don't `return` a value in the stub); `bar` takes `byte[]` (passing a JS string
   causes a type mismatch). `solve.js:10-13` explicitly records this as a "hard-won lesson".
5. **The l3 gate flag is 2, not 1** (`cmpl $0x2, 0x705c`); and l3 has two `+1`s (`0x38d8`/`0x3a4f`) — writing it correctly
   once is not enough.
6. **frida must be 16.5.9**. All hooks use the Java bridge (`Java.perform`/`Java.use`/`Java.choose`);
   frida 17.x dropped the `Java` global. The host and device-side **versions must match**, otherwise attach fails.
7. **`hook_run.py`'s `--script` is resolved relative to the current working directory** (`:38-39`), not relative to the runner directory —
   when running from `l*/`, the point is `--script frida/solve.js` (from the lab directory).
8. **The timed window**: the runner force-detaches + kills after capturing `--seconds` (default 10) (bounded by design).
   The `setTimeout` delays inside hooks (l1 2000ms / l2 2500ms / l3 1500ms) must be **less than** `--seconds`,
   otherwise the output won't be captured.
9. **Samples are gitignored**: a fresh clone has no `.apk`/`.so` and must re-pull them from the URLs in provenance (see §6).
10. **The `oracle-neg` negative control cannot be skipped**. Running only `oracle=true` is meaningless (if the oracle were always true there'd be no way to discriminate);
    both l1/l2 include `oracle-neg ... = false` as proof of discriminating power.
11. **Chinese mojibake**: set `PYTHONIOENCODING=utf-8` (this lab's script output is mostly English, but dumps/logs may contain Chinese).

---

## 11. Quick reference (all facts verified on this machine)

```bash
# Bring up the environment first (see repo-root README): emulator + frida-server; then:
cd uncrackable/l1
../../.venv/Scripts/python.exe ../tools/hook_run.py \
    --package owasp.mstg.uncrackable1 --script frida/solve.js --seconds 8
#   => [recovered] secret = "I want to believe"
#   => [oracle] uncrackable1.a.a(secret) = true

cd ../l2
../../.venv/Scripts/python.exe ../tools/hook_run.py \
    --package owasp.mstg.uncrackable2 --script frida/solve.js --seconds 7
#   => [bypass] libfoo.so base=... gate[+0x400c]=1
#   => [oracle] CodeCheck.bar("Thanks for all the fish") = true

cd ../l3   # WIP: dynamic not passed
../../.venv/Scripts/python.exe ../tools/hook_run.py \
    --package owasp.mstg.uncrackable3 --script frida/solve.js --seconds 8

# Static recon (using the NDK), l2:
#   llvm-nm libfoo.so        # get the JNI entries
#   llvm-objdump -d libfoo.so  # bar: strncmp(input,secret,23) + cmpb $1,0x400c
#   llvm-objdump -s -j .rodata libfoo.so | grep -A2 11c0   # → "Thanks for all the fish"
```

**Known results**: l1 `I want to believe` (algorithm oracle); l2 `Thanks for all the fish`
(artifact+algorithm oracle, key @ .rodata 0x11c0, gate flag .bss 0x400c); l3 unsolved.

---

## 12. Reading order for a new agent

1. Read `TUTORIAL.md` (guided path) and `README.md` (layout + shared-runner) — establish the real-target route premise first.
2. Read `tools/hook_run.py` (only 61 lines) — understand the bounded design of spawn/attach/time-limited/detach.
3. Read `l1/frida/solve.js` + `l1/analysis_output/classes.dump.txt` — the AES chain and the oracle paradigm.
4. Read the "hard-won lessons" in `l2/SCRIPT.md §8` + `l2/frida/solve.js` — gate flag 0x400c is the core.
5. Read `l3/SCRIPT.md` — focus on **why it's hard** (the constructor watchdog runs before the Java code) and on the **next-step directions**,
   and remember it is WIP.
6. `provenance.json` tells you the external samples' source and authorization boundary — **do not commit samples**.
