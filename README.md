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
├── LICENSE              # MIT
├── .gitignore
├── PROMPT.md            # reusable prompt template for spinning up a new lab
├── 360jiagu/            # 360-style native hardening (modeled as a modified UPX)
│   ├── README.md
│   ├── src/             # libtarget source (target.c, policy_inc.h)
│   ├── tools/           # detectors, solvers, variant/negative generators, reset_lab.py
│   ├── build/           # build_android.sh, pack.sh, locate.sh, gen_policy.py
│   ├── pristine/        # baseline .so + sha256 manifest
│   └── analysis_output/ # detection / dump / solve reports
├── upx_practice/        # vanilla UPX + a feature-rewritten variant
│   ├── README.md
│   ├── src/ tools/ build/ pristine/ analysis_output/
└── ajiami/              # Aijiami-style DEX hardening: 3 generations + string-obf variant
    ├── README.md
    ├── app/  shell/  neg/  vmp/  samples/
    ├── tools/           # detect.py, unpack_v1/v2/v3.py, check_negatives.py, ...
    ├── build/           # build_*.sh, pack.sh, env.sh, lab.keystore
    ├── pristine/  logs/  analysis_output/
```

> `ollvm/` (LLVM obfuscation experiments) lives in this directory but is an
> **independent git repository** and is intentionally excluded from this project via
> `.gitignore`. It is out of scope — this repo covers *packers / shell protectors*, not
> code-obfuscation.

---

## Labs at a glance

| Lab | Models | Sample form | Highlights |
|-----|--------|-------------|-----------|
| `360jiagu` | 360 native hardening, modeled as a **modified UPX** (magic `UPX!` → `JG!!`, marker `360 4.24`) | self-built NDK `.so` | structural detection, runtime-unpack → OEP → ELF Fix, variant handling, B13 |
| `upx_practice` | vanilla UPX + a **feature-rewritten variant** | self-built NDK `.so` | scoring detector, dump-and-fix, negative / section-stripped samples |
| `ajiami` | Aijiami DEX hardening — gen-1 (whole-DEX encryption) → gen-2 (class extraction) → gen-3 + string-obfuscation variant | self-built Android app + shell | 3-generation detection, script + manual unpack, negative-sample regression |

Each lab's `README.md` is the **single source of truth** for that lab and follows the
fixed `§0`–`§12` skeleton described below.

---

## Methodology & conventions

These rules are enforced across all labs (originally captured in `PROMPT.md`):

- **One README per lab, fixed skeleton.** `§0` intro → `§1` knowledge points → `§2`
  detection → `§3` script solution → `§4` manual solution → `§5` fallback/dynamic →
  `§6` decision tree → `§7` verification criteria → `§8` pitfalls → `§9` repeatable
  practice (`pristine/` + `reset_lab.py`) → `§10` command cheatsheet → `§11` file index →
  `§12` one-liner to remember.
- **Zero absolute paths.** No `D:\…`, `C:\Users\…`, `/d/…`, or `/c/Users/…` anywhere in
  scripts, build config, source, READMEs (except `cd` examples), or generated reports.
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

Pick a lab and follow its `README.md §0.1` ("three-minute run"). The pattern is
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
`detect.py` / `unpack_v1.py` … for `ajiami`). Each lab README documents its exact
commands and real, pasted output.

---

## Adding a new lab

1. Create a new folder under the repository root.
2. Copy the structure (`src/`, `tools/`, `build/`, `pristine/`, `analysis_output/`,
   `README.md`).
3. Follow `PROMPT.md` — it is a reusable prompt that fills in the topic, the `§0`–`§12`
   skeleton, the negative-sample discipline, and the four-tier toolchain resolution.
4. Keep the protector within the *packer / shell* scope (UPX & variants, compression
   shells, memory dump, OEP, ELF Fix, whole-DEX encryption, class extraction). Code
   obfuscation / string protection / VMP teaching is out of scope for this repo — keep it
   separate.

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
