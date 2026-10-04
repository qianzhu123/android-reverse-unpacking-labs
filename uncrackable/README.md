# uncrackable — OWASP MASTG UnCrackable real-target labs

> `PROMPT-REAL.md` route: external real targets, no source, no golden baseline —
> verification is a **behavior/artifact oracle**, not a byte diff.
> Third-party samples are **gitignored** (repo carries sha256 + provenance + conclusions only).

These three labs share one target family (OWASP MASTG UnCrackable), so they live under
**one folder** with a shared runner and tooling, not as three near-identical top-level
directories. The environment (emulator + frida-server + venv) is documented once, at the
repo root: **README → "Real-target lab environment setup"**.

## Layout

```text
uncrackable/
├── README.md            # this file
├── tools/               # shared across l1/l2/l3
│   ├── hook_run.py      #   spawn+sideload Frida runner
│   └── frida-server-16.5.9-android-x86_64(.xz)   # gitignored
├── l1/                  # Level 1 — Java AES check + root detection            [SOLVED]
│   ├── SCRIPT.md  CLI.md  GUI.md
│   ├── samples/{apks,dex}/…        # gitignored
│   ├── pristine/provenance.json    # source + authorization + env fingerprint + result
│   ├── frida/{enumerate,solve}.js
│   └── analysis_output/  logs/
├── l2/                  # Level 2 — native strncmp check + fork/ptrace anti-debug [SOLVED]
│   ├── SCRIPT.md  CLI.md  GUI.md
│   ├── samples/{apks,native,dex}/…
│   ├── pristine/provenance.json
│   ├── frida/{enumerate,probe,solve}.js
│   └── analysis_output/  logs/
└── l3/                  # Level 3 — native check + constructor anti-tamper watchdog [WIP]
    ├── SCRIPT.md  CLI.md  GUI.md
    ├── samples/{apks,native,dex}/…
    ├── frida/{probe,recon,solve}.js
    └── analysis_output/  logs/
```

Each `l*/` follows the `PROMPT-REAL.md` layout deltas vs. `PROMPT.md`: **no `src/`/`shell/`**
(no source), `pristine/` is a **provenance record** (not a golden backup), and `frida/` is
load-bearing. The only thing hoisted to this parent is the **shared runner + frida-server**.

## Run one lab (from the repo root)

```bash
# environment up first — see root README "Real-target lab environment setup"
cd uncrackable/l1
../../.venv/Scripts/python.exe ../tools/hook_run.py \
    --package owasp.mstg.uncrackable1 --script frida/solve.js --seconds 8
#   => [recovered] secret = "I want to believe"
#   => [oracle] uncrackable1.a.a(secret) = true
```

## Status

| Lab | Difficulty added | Secret / result | Verified by |
|---|---|---|---|
| `l1` | Java + AES + root detect | `I want to believe` | algorithm oracle: `a.a(secret)==true`, wrong `==false` |
| `l2` | native `strncmp` + fork/ptrace anti-debug + `.bss` gate | `Thanks for all the fish` | artifact (`.rodata`) + algorithm (`bar(secret)==true`) |
| `l3` | + constructor-level anti-tamper **watchdog thread** + integrity check | **not recovered** | **not passed** — see `l3/SCRIPT.md` §4/§8 for the blocker and next directions |

`l3` is committed as an **unsolved work item** (honest WIP). Its static analysis is done
(`bar = keyTable ^ plaintext`, runtime-decrypted); the dynamic route is blocked by an
anti-Frida watchdog started from a library constructor, i.e. before any Java code runs.

## Conventions

- Docs `SCRIPT.md` / `CLI.md` / `GUI.md` are **Chinese**, §0–§8 skeleton (same as every lab).
- Zero absolute paths; the NDK binutils are `llvm-*`; adb resolves via `$ANDROID_HOME`.
- Any tool output pasted into docs comes from a real run (doc-code sync).
