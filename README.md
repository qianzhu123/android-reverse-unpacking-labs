# Android Unpacking & Packer-Hardening Labs

> Self-built, evidence-based, **deterministic-first** labs for studying Android packers
> and hardening protectors. Each lab models a real-world protector with **locally
> compiled samples** so every detection and unpacking step is reproducible byte-for-byte.

---

## What this repository is

A collection of hands-on study labs that treat **Android packers / shell protectors**
(UPX and its variants, 360-style native hardening, Aijiami-style DEX hardening) as the
subject of reverse-engineering practice.

Three hard constraints shape every lab:

1. **Deterministic rules before any LLM.** All detection and unpacking is hand-written
   structural analysis (section tables, entropy, `PT_LOAD` `filesz` vs `memsz`, entry
   points, missing classes, byte offsets). No large language model is involved in the
   logic.
2. **Evidence-based findings.** Every conclusion is anchored to a structural feature
   with a concrete threshold, never to a file name or a single magic string. The fallback
   verdict is always *"no known hardening signature observed (≠ none)"*, never
   *"clean / not protected"*.
3. **Externalized configuration.** Toolchains (NDK / SDK / `aapt2` / Java / Python) are
   never hard-coded. They are resolved through four tiers: CLI argument → environment
   variable → optional `build/env.sh` → auto-detection.

> **Why self-built samples?** Real commercial protectors (e.g. the genuine Aijiami
> service) require uploading an APK to a vendor server, so the full chain cannot be
> reproduced offline or compared byte-for-byte. Each lab therefore builds an *equivalent*
> sample from the same source tree, then drives the entire detect → unpack → verify loop
> locally and repeatably.

---

## ⚠️ Disclaimer

This repository is for **authorized security education, training, and self-study only**.

- All binaries in this repo are **compiled by the author from first-party source**
  (`ndk-build` / `clang` / `javac` / `d8`). No third-party, copyrighted, or commercial
  protector binaries are included or redistributed.
- The protectors are **modeled**, not the genuine commercial products. Naming is used
  only to reference the publicly known hardening *technique* being studied.
- Do not apply these techniques to software you do not own or are not authorized to
  analyze. The author is not responsible for any misuse.

---

## Repository layout

```text
android-reverse/
├── README.md            # this file
├── AGENTS.md            # agent quick-start (paste to an agent instead of re-explaining)
├── LICENSE              # MIT
├── .gitignore
├── PROMPT.md            # prompt template: self-built, byte-reproducible lab
├── PROMPT-REAL.md       # prompt template: external real-target analysis lab
├── 360jiagu/            # 360-style native hardening (modeled as a modified UPX)
│   ├── SCRIPT.md  CLI.md  GUI.md
│   ├── src/             # libtarget source (target.c, policy_inc.h)
│   ├── tools/           # detectors, solvers, variant/negative generators, reset_lab.py
│   ├── build/           # build_android.sh, pack.sh, locate.sh, gen_policy.py
│   ├── samples/so/      # analyzed .so samples (no samples at lab root)
│   ├── pristine/        # baseline copy + sha256 manifest
│   └── analysis_output/ # detection / dump / solve reports
├── upx_practice/        # vanilla UPX + a feature-rewritten variant
│   ├── SCRIPT.md  CLI.md  GUI.md
│   ├── src/ tools/ build/ samples/so/ pristine/ analysis_output/
├── ajiami/              # Aijiami-style DEX hardening: 3 generations + string-obf variant
    ├── SCRIPT.md  CLI.md  GUI.md
    ├── app/  shell/  neg/  vmp/  samples/{apks,dex,payloads}/
    ├── tools/           # detect.py, unpack_v1/v2/v3.py, check_negatives.py, ...
    ├── build/           # build_*.sh, pack.sh, env.sh, lab.keystore
    ├── pristine/  logs/  analysis_output/
└── ollvm/               # OLLVM / string-protection lab (code obfuscation)
    ├── SCRIPT.md  CLI.md  GUI.md
    ├── samples/apks/    # archived debug/release APKs (hashes in the docs)
    ├── pristine/        # sha256 baseline of samples/ (reset_lab.py restore source)
    ├── app/             # self-contained gradle project (gradle root lives here):
    │                    #   Java plaintext / Java XOR / JNI XOR / nativeOpaque
    ├── build/           # build.ps1, bootstrap.ps1 (PowerShell toolchain)
    ├── tools/           # analyze-apk.ps1, inspect-native.ps1, logcat.ps1, reset_lab.py
    ├── frida/           # frida-hook.js (Java/native boundary hook)
    └── analysis_output/ # apktool / jadx unpack output (gitignored)
├── uncrackable/         # REAL-TARGET labs (external: OWASP MASTG UnCrackable, PROMPT-REAL.md)
│   ├── README.md        # lab-family overview + shared-runner notes
│   ├── TUTORIAL.md      # guided learning path l1 -> l2 -> l3 (start here)
│   ├── tools/           # hook_run.py (shared Frida runner) + frida-server (gitignored)
│   ├── l1/              # Level 1 — Java AES check + root detection            [SOLVED]
│   ├── l2/              # Level 2 — native strncmp + fork/ptrace anti-debug    [SOLVED]
│   └── l3/              # Level 3 — native check + constructor anti-tamper     [WIP]
│       # each l*/ : SCRIPT.md CLI.md GUI.md + samples/(gitignored) +
│       #            pristine/provenance.json + frida/ + analysis_output/ + logs/
```
> `ollvm/` covers *code obfuscation / string protection*, which is outside the
> packers / shell-protector scope of the other labs, so it does not use the unpacking
> prompt template — but it follows the same three-doc + fixed-directory-layout
> conventions. It used to be an independent git repo; its history was folded into this
> repository.

---

## Labs at a glance

| Lab | Models | Sample form | Highlights |
|-----|--------|-------------|-----------|
| `360jiagu` | 360 native hardening, modeled as a **modified UPX** (magic `UPX!` → `JG!!`, marker `360 4.24`) | self-built NDK `.so` | structural detection, runtime-unpack → OEP → ELF Fix, variant handling, B13 |
| `upx_practice` | vanilla UPX + a **feature-rewritten variant** | self-built NDK `.so` | scoring detector, dump-and-fix, negative / section-stripped samples |
| `ajiami` | Aijiami DEX hardening — gen-1 (whole-DEX encryption) → gen-2 (class extraction) → gen-3 + string-obfuscation variant | self-built Android app + shell | 3-generation detection, script + manual unpack, negative-sample regression |
| `ollvm` | Java plaintext / Java XOR / JNI XOR string protection + native control-flow baseline (`nativeOpaque`); OLLVM pass comparison via external fork | self-built Android app (archived debug/release APKs) | three-way SCRIPT/CLI/GUI analysis, verified native address chain (`0x24f10 → 0x24fd4 → 0x14db9`), PowerShell toolchain |
| `uncrackable/l1` | **real-target** (external): OWASP MASTG UnCrackable Level 1 — AES check + root detection | third-party APK (gitignored) | `PROMPT-REAL.md` route: static recon → Frida spawn-gated bypass → active-invocation oracle (`bar`-style check returns true); frida/venv pinned 16.5.9 |
| `uncrackable/l2` | **real-target** (external): OWASP MASTG UnCrackable Level 2 — native `strncmp` check + fork/ptrace anti-debug | third-party APK + `libfoo.so` (gitignored) | native reversing (llvm-nm/objdump → `.rodata` secret + `.bss` gate @0x400c), anti-debug bypass, artifact + algorithm oracle |
| `uncrackable/l3` | **real-target** (external) · **WIP**: OWASP MASTG UnCrackable Level 3 — native check + constructor-level anti-tamper watchdog + integrity check | third-party APK + `libfoo.so` (gitignored) | static done (bar = `keyTable ^ plaintext`, runtime decrypt); **dynamic route not yet passed** — anti-Frida watchdog; blocker + next directions documented |

The first four labs are **self-built, byte-reproducible** (`PROMPT.md` route).
The `uncrackable/` labs are **external real targets** (`PROMPT-REAL.md` route) — one
family under one folder (`uncrackable/l1|l2|l3`) sharing `uncrackable/tools/`, since they
share a target family and environment: no source, no golden baseline — verification is a
behavior/artifact **oracle**, and the third-party samples are gitignored (repo carries
sha256 + provenance + conclusions only).
`uncrackable/l3` is committed as an **unsolved work item** (honest WIP), not a solved lab.

Each lab's docs are `SCRIPT.md` (script route) + `CLI.md` (command-line route) +
`GUI.md` (GUI-tool route) — three parallel documents sharing one section skeleton.

---

## Methodology & conventions

These rules are enforced across all labs (originally captured in `PROMPT.md`):

- **Two parallel docs per lab, fixed `§0`–`§8` skeleton.** `SCRIPT.md` (script route:
  detect / unpack / verify tools, run end-to-end) + `MANUAL.md` (manual route:
  `unzip` / `aapt2` / `xxd` / entropy, byte-for-byte reproduction). §0 intro → §1 project
  layout → §2 knowledge points → §3 detection → §4 unpack → §5 verification → §6 decision
  tree → §7 repeatable practice (`pristine/` + `reset_lab.py`) → §8 pitfalls & speed-ref.
- **Zero absolute paths.** No `D:\…`, `C:\Users\…`, `/d/…`, or `/c/Users/…` anywhere in
  scripts, build config, source, docs (except `cd` examples), or generated reports.
  The project root is always derived from the script's own location.
- **Negative samples + bidirectional regression assertions (anti circular-reasoning).**
  A detector trained and tested only on its own hand-made samples is trivially correct.
  Every detection tool ships with adversarial **negative samples** and a
  two-way assertion script (e.g. `check_negatives.py`, `check_so_samples.py`):
  - *Positive:* a real sample **must** be classified as its generation (guards against
    "over-correcting false positives until real shells slip through").
  - *Negative:* a clean sample **must never** be classified as "hardened", and must not
    trip the specified false-positive rules.
- **B13 for SO/ELF projects (hard requirement).** Detect
  `e_type == ET_DYN(3) && e_shnum == 0 && executable PT_LOAD present` — the
  section-header-stripped shape used by custom linkers. This is signature- and
  score-independent and catches custom-linker packers that UPX-style signatures miss.
  B13 hits are reported as *"suspected SO packing / self-implemented linker (ELF section
  headers stripped) — confirm manually at the ELF layer"*, never as a definitive verdict.
- **Enumerated cognitive boundary.** The fallback always lists what the tool **cannot**
  decide statically and that requires dynamic tracing — at minimum: SO VMP,
  non-hub-converging VMP, and sophisticated string encryption. "Zero features triggered"
  is **not** equivalent to "not protected".
- **Repeatable practice.** `pristine/` holds the golden baseline (with a sha256
  manifest); `tools/reset_lab.py` supports `status` / `restore` / `backup` so a lab can
  be wiped and re-run from scratch.

---

## Prerequisites

- **Android NDK** (`ndk-build` / `clang`) — to compile the `.so` / app samples.
- **Android SDK build-tools** with `aapt2` — for the DEX/APK labs.
- **Java** (for APK building / signing in the DEX lab) and **Python 3** (for all
  detection, solving, and regression scripts).
- No toolchain path is hard-coded; each lab's `build/locate.sh` (or `build/env.sh`)
  auto-detects them, and every script accepts `--ndk` / `--aapt2` / `--root` overrides.
- *Note:* the UPX-family labs assume a UPX-compatible packer binary present on your
  machine; that binary is **not included** in this repository (see `.gitignore`).

---

## How to run a lab

Pick a lab and follow its `SCRIPT.md` / `MANUAL.md` §0.1 ("three-minute run"). The pattern is
identical for all of them:

```bash
# from the repository root
cd 360jiagu            # or: cd upx_practice  /  cd ajiami

# ① detect (structural features only, never the file name)
python tools/detect_360.py libtarget_orig.so     # => score 0 · no known signature (≠none)
python tools/detect_360.py libtarget_360.so      # => standard 360 (UPX! retained)
python tools/detect_360.py libtarget_360_variant.so  # => variant 360 (UPX! rewritten, structure intact)

# ② unpack / solve, then verify against the pristine baseline
python tools/solve_360.py libtarget_360.so analysis_output/out.so --pristine pristine/libtarget_orig.so
#   => byte-for-byte identical to golden baseline ✓

# ③ run the negative-sample regression (both directions must pass)
python tools/check_so_samples.py
```

Replace the detector/solver names with those of the lab you are in
(`detect_packer.py` / `solve_variant.py` for `upx_practice`;
`detect.py` / `unpack_v1.py` … for `ajiami`). Each lab's `SCRIPT.md` / `MANUAL.md` document its exact
commands and real, pasted output.

**Real-target labs (`uncrackable/l1` / `uncrackable/l2`) run differently** — dynamic is the
primary route and there is no golden baseline. They need an emulator + frida-server, use the
repo-local venv, and verify by oracle. Example:

```bash
# from the repository root (emulator up, frida-server running — see the lab's CLI.md §4)
cd uncrackable/l1

# ① static recon (locate the check) — llvm-* from the NDK
../.venv/Scripts/python.exe tools/hook_run.py --package owasp.mstg.uncrackable1 --script frida/enumerate.js

# ② solve + verify by oracle (no byte-diff: the app's own check must return true)
../.venv/Scripts/python.exe tools/hook_run.py --package owasp.mstg.uncrackable1 --script frida/solve.js
#   => [recovered] secret = "I want to believe"
#   => [oracle] uncrackable1.a.a(secret) = true
```

---

## Real-target lab environment setup

The `uncrackable-*` labs need an emulator + a version-matched frida-server. Everything is
**project-local and reproducible** — this section is the single source of truth for that
environment, so the labs can be resumed after any break.

**Pinned versions (the environment fingerprint — do not drift):**

| Component | Version | Why pinned |
|-----------|---------|------------|
| frida (host, in `.venv`) | **16.5.9** | 17.x's Java bridge drops the `Java` global; the labs' hooks require it |
| frida-tools | 13.7.0 | matches frida 16.5.9 |
| frida-server (on device) | **16.5.9** `android-x86_64` | **must equal the host frida** or attach fails |
| AVD / system image | `n4tive_lab` · Android 14 (SDK 34) · `google_apis;x86_64` | x86_64 matches the emulator ABI |
| Python (`.venv`) | 3.13 | repo-local interpreter |
| NDK binutils | `llvm-*` on PATH (android-ndk-r27d) | bare GNU names do not exist on this machine |

**One-time setup (already done — reproduce on a fresh machine):**

```bash
# 1. project-local venv + pinned frida  (NEVER global: a global frida install breaks
#    the machine's websockets/langsmith pins; keep everything in .venv/)
python -m venv .venv
./.venv/Scripts/python.exe -m pip install "frida==16.5.9" "frida-tools==13.7.0"

# 2. system image + AVD  (sdkmanager needs SKIP_JDK_VERSION_CHECK on JDK 26)
SDK="${ANDROID_HOME:-$ANDROID_SDK_ROOT}"
export SKIP_JDK_VERSION_CHECK=1
yes | "$SDK/cmdline-tools/latest/bin/sdkmanager" "system-images;android-34;google_apis;x86_64"
"$SDK/cmdline-tools/latest/bin/avdmanager" create avd -n n4tive_lab \
    -k "system-images;android-34;google_apis;x86_64" -d pixel_5 --force

# 3. frida-server for the device (matches host frida), kept out of git in .tools/
curl -L -o .tools/frida-server-16.5.9-android-x86_64.xz \
    https://github.com/frida/frida/releases/download/16.5.9/frida-server-16.5.9-android-x86_64.xz
python -c "import lzma,shutil;shutil.copyfileobj(lzma.open('.tools/frida-server-16.5.9-android-x86_64.xz','rb'),open('.tools/frida-server-16.5.9-android-x86_64','wb'))"
```

**Per-session bring-up (do this before running any lab):**

```bash
SDK="${ANDROID_HOME:-$ANDROID_SDK_ROOT}"; ADB="$SDK/platform-tools/adb"

# boot the emulator headless (background)
"$SDK/emulator/emulator" -avd n4tive_lab -no-window -no-audio -no-boot-anim \
    -no-snapshot -gpu swiftshader_indirect -port 5554 &
"$ADB" wait-for-device
until [ "$("$ADB" shell getprop sys.boot_completed | tr -d '\r')" = 1 ]; do sleep 5; done

# push + start frida-server as root (emulator supports `adb root`)
"$ADB" root; "$ADB" wait-for-device
MSYS_NO_PATHCONV=1 "$ADB" push .tools/frida-server-16.5.9-android-x86_64 /data/local/tmp/frida-server
"$ADB" shell "chmod 755 /data/local/tmp/frida-server; nohup /data/local/tmp/frida-server >/dev/null 2>&1 &"

# verify connectivity, then install a target
./.venv/Scripts/frida-ps.exe -U | head
"$ADB" install -r uncrackable/l1/samples/apks/UnCrackable-Level1.apk

# stop the emulator when done
"$ADB" emu kill
```

**Likely-required env vars** (this machine uses non-standard SDK/NDK locations):
`ANDROID_HOME` / `ANDROID_SDK_ROOT` (SDK), and the NDK `llvm-*` binutils must be on
`PATH`. `JAVA_HOME` handling, `MSYS_NO_PATHCONV=1` for adb pushes, and the
`SKIP_JDK_VERSION_CHECK=1` sdkmanager workaround are all environment facts recorded in
each lab's `SCRIPT.md` §8.

**Lab status:** `uncrackable/l1` ✅ and `uncrackable/l2` ✅ are solved (oracle verified,
committed). `uncrackable/l3` is a **WIP whose dynamic route is not yet passed** — its
`SCRIPT.md` documents the blocker (constructor-level anti-tamper watchdog) and the next
attack directions; it is committed as a work item, not as a solved lab.

---

## Adding a new lab

Pick the prompt by lab type — **the two prompts are siblings, not versions of each other**:

| Lab type | Prompt | Situation |
|----------|--------|-----------|
| Self-built, byte-reproducible | `PROMPT.md` | You compile the sample from `src/`; packed/unpacked share one source and compare **byte-for-byte** against `pristine/`. |
| External real target | `PROMPT-REAL.md` | You do **not** have the source or a golden baseline; dynamic (Frida / memory dump / active invocation) is the primary route and verification is a **behavior oracle**, not a byte diff. |

1. Create a new folder under the repository root.
2. Copy the structure appropriate to the type above (`src/`, `tools/`, `build/`, `pristine/`,
   `analysis_output/`, `SCRIPT.md` + `MANUAL.md`); a real-target lab drops `src/`/`shell/`,
   repurposes `pristine/` as a provenance record, and adds `frida/` + `logs/` (see
   `PROMPT-REAL.md`'s layout deltas).
3. Follow the matching prompt — it fills in the topic, the `§0`–`§8` skeleton, the
   negative-sample discipline (self-built) or the authorization/oracle discipline
   (real target), and the four-tier toolchain resolution.
4. **Self-built labs** (`PROMPT.md`): keep the protector within the *packer / shell*
   scope (UPX & variants, compression shells, memory dump, OEP, ELF Fix, whole-DEX
   encryption, class extraction). Code obfuscation / string protection / VMP teaching is
   out of scope for that prompt — for those, use a separate prompt.
   **Real-target labs** (`PROMPT-REAL.md`): the packer/shell-scope restriction does not
   apply — dynamic analysis, anti-analysis bypass, native algorithm reconstruction, and
   VMP/protector identification against external samples are all in scope, bounded only
   by the authorization gate.

---

## License

Released under the **MIT License** — see [LICENSE](./LICENSE).

---

## GitHub repository metadata (use for the "About" section)

When creating the repository, set:

- **Description (About):**
  > `Educational Android unpacking & packer-hardening labs — self-built, evidence-based, deterministic-first reverse-engineering study materials.`

- **Topics:**
  > `android` `reverse-engineering` `unpacking` `packers` `dex` `elf` `ndk`
  > `anti-tamper` `static-analysis` `educational`

- **Visibility:** public.
