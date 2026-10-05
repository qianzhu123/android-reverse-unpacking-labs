# Android Reverse-Engineering · Real-Target Analysis Prompt

> Lives at the repository root as `PROMPT-REAL.md`, sibling to `PROMPT.md`.
> `PROMPT.md` governs **self-built, byte-reproducible labs** (sample = spec = test set).
> This file governs **analysis of external targets you do not control** (real apps,
> third-party protectors, CTF/practice APKs) where the source is absent and no golden
> baseline exists. Use this one when the honest answer to "can we compare byte-for-byte?"
> is **no**.
> Usage: copy the **Prompt Body** below, replace `<target-name>` and `<objective>`.

> ⚠️ **Language convention (mandatory)**
> - **This file and all repository-level files are in English** (root `README.md`,
>   `PROMPT.md`, `PROMPT-REAL.md`, commit messages, GitHub About/Topics).
> - **Each lab's three documents (`SCRIPT.md` / `CLI.md` / `GUI.md`) are written in
>   Chinese** — they are teaching material for the author's own study loop; technical
>   terms, tool names, file paths, and pasted tool output stay in their original language.
> - **Each lab root also carries `AGENTS.md` — written in English.** It is the
>   agent-facing ground-truth doc: what an agent reads before touching that lab. It holds
>   real paths, line numbers, thresholds, byte offsets, addresses, and command output that
>   was **actually read and actually run** — never a restatement of the Chinese teaching
>   docs. Every lab ships one.
> - Commit messages follow the English convention even when they describe
>   Chinese-language lab docs (e.g. `docs(frida-labs): ...`).

> ⚠️ **Local command convention**: this machine **has `python`, no `python3`**.
> All scripts and doc examples use `python xxx.py`. Shebangs use `#!/usr/bin/env python`.
> **`adb` / `frida` / `frida-ps` / `objection` are assumed on `PATH`**; the frida-server
> binary on the device is version-matched to the host and named in the environment
> fingerprint (see below), never assumed.

> ⚠️ **Authorization & redistribution boundaries (hard — this is the ethics gate)**
> This prompt produces **analysis of software you did not write**. Non-negotiable:
> 1. **Authorized scope only**: own apps, apps you have written permission to test,
>    public CTF/practice targets, or public samples analyzed for education. **Never** a
>    third party's production app you are not authorized to analyze.
> 2. **No redistribution of third-party samples**: a real target's APK / `.so` / dumped
>    payload is **not committed** to this repo. Commit only: its **sha256**, provenance
>    (public URL / release tag / date pulled), and the **analysis conclusions**. The
>    sample itself is fetched by the reader through the same public source, or held
>    out-of-tree (see `.gitignore`).
> 3. **No cracking / piracy / bypass-for-profit framing**: the deliverable is
>    *understanding and documentation*, never a working exploit aimed at someone else's
>    paid product. Methods learned here stay in authorized / educational use.
> 4. If a target's own license or terms forbid reverse engineering, **record that and
>    stop** — pick a practice target instead.

> ⚠️ **Dynamic-route environment pinning (the real-target analogue of `pristine/`)**
> Self-built labs reproduce byte-for-byte; real-target analysis reproduces by **environment
> fingerprint**. A result with no environment record is not reproducible and must not be
> documented as a result. Every real-target lab pins, in the docs and in `build/env.sh`:
> device model + Android version + ABI, ROM/root status, **frida-server version**,
> host frida / objection / Python versions. When behavior changes across any of these,
> that is a finding, not noise.

> ⚠️ **Verify-before-write (hard rule)**: every command that goes into a document —
> CLI route especially — must be **run once by the agent while writing the doc**, so its
> existence and its real output are both confirmed. Do not write a command from memory or
> from how it is usually named on Linux. On this machine the NDK binutils are
> `llvm-`-prefixed (`llvm-readelf` / `llvm-objdump` / `llvm-nm` / `llvm-strings` /
> `llvm-strip` / `llvm-size` / `llvm-objcopy` / `llvm-addr2line`); bare GNU names do not
> exist. Toolchain paths resolve through four tiers (CLI arg > env var > `build/env.sh` >
> auto-detect); never hard-code one.

> ⚠️ **Documentation-writing conventions** (inherited from `PROMPT.md` — keep identical)
> 1. **Script → CLI → GUI** order: automation run first, then generic-command
>    reproduction, then graphical-tool understanding.
> 2. Commands are **complete and copy-pasteable** (no `...apk` / `xxx.sh` placeholders).
> 3. Commands live in **code blocks**, never inside table cells.
> 4. Command explanations are **never one-liners**: purpose + per-parameter note + real
>    output excerpt + line-by-line reading + failure criteria. Excerpts come from actual
>    runs, never memory.
> 5. **No absolute paths in pasted output**: trim above the lab root; relative paths only.
> 6. **Route purity (hard)**: `SCRIPT.md` runs this repo's tooling only; `CLI.md` uses
>    generic commands only (never `python tools/*.py`); `GUI.md` uses graphical tools
>    only. Cross-reference between docs, never cross-execute.

> ⚠️ **Verification without a golden baseline (hard — the central difference)**
> `PROMPT.md` verifies by byte-for-byte comparison against `pristine/`. **That is
> impossible here** — there is no source and no golden output. Verification instead rests
> on a **behavior oracle**: an externally observable fact that is true **iff** the analysis
> succeeded. Acceptable oracles (pick the strongest the target allows):
> - the app proceeds past a check it previously failed (screen/state transition observed);
> - a recorded network request carries correct decrypted/unsigned fields;
> - a hooked function's args/return match the algorithm you reconstructed;
> - a dumped artifact loads/parses (dex `magic` + `map_list`, ELF `llvm-readelf` clean).
> **A claim with no oracle is a hypothesis, not a finding** — label it as such. "It looked
> right in the decompiler" is never a verification.

> ⚠️ **Cognitive boundary (hard — stricter than `PROMPT.md`)**
> On a real target the cost of a wrong "I understood it" is higher, because nobody hands
> you the spec to check against. Every conclusion must carry an explicit boundary list:
> **what was not determined, and what evidence would determine it**. The fallback always
> reads "**no known signature observed (≠ none)**" plus named uncovered schemes
> (at minimum: SO VMP, non-hub-converging VMP, runtime-decrypted strings, packer behavior
> only reachable on a specific device/version). Never "clean / not protected".

> ⚠️ **Zero absolute paths** (hard, same as `PROMPT.md`): no `D:\...` / `C:\Users\...` /
> `/d/...` in scripts, build config, docs, or generated artifacts. Lab root derives from
> the script's own location. Sole exception: `cd` examples in docs.

> ⚠️ **GitHub publishing conventions** (same as `PROMPT.md`): monorepo; the new lab is a
> folder under the repo root committed as `feat(<target>): ...`; **third-party sample
> binaries are never committed** — add them to `.gitignore` and commit only sha256 +
> provenance + conclusions; English About/Topics; MIT.

---

## Prompt Body

```
Create a folder <target-name> under the repository root: a real-target analysis lab for
「<objective>」 — analyzing an EXTERNAL Android target whose source we do NOT have.

Relationship to PROMPT.md: PROMPT.md builds self-made, byte-reproducible samples
(sample = spec = test set). This lab is the opposite situation — external sample, no
source, no golden baseline. Do NOT use PROMPT.md's byte-for-byte verification here; use
the behavior-oracle rules below.

Topic scope: dynamic analysis and real-target reversing — Frida attach/spawn hooks,
memory dumping (dex/so), active invocation, anti-analysis bypass, native algorithm
reconstruction, and protector identification against real samples. Self-built sample
labs remain governed by PROMPT.md.

Requirements:

1. Authorization & provenance (do this FIRST, before touching the target)
   - Record: target name, public source URL / release tag, date pulled, sha256 of the
     exact artifact analyzed, and the authorization basis (own app / public practice
     target / CTF / educational public sample).
   - If the target's terms forbid RE, stop and record why. Do not proceed.
   - The third-party artifact is NOT committed: it is fetched by the reader from the
     same public source, or added to .gitignore. The repo carries sha256 + provenance +
     conclusions only.

2. Documents (top priority)
   - Three parallel documents, one shared skeleton, section-for-section:
       SCRIPT.md — this repo's tooling route: Python + Frida hook scripts in `tools/`
                   and `frida/` (attach / spawn / dump / trace / verify).
       CLI.md    — generic-command route: adb / frida / frida-ps / frida-trace /
                   objection / llvm-readelf / llvm-objdump / unzip / aapt2.
       GUI.md    — graphical-tool route: jadx / IDA / Ghidra / 010 Editor / GDA / JEB.
     The three lab documents are written in Chinese; tool output and paths stay as-is.
   - Fixed directory layout — REUSE the slots `PROMPT.md` already defines; the deltas for
     a real-target lab are called out explicitly:
       <target-name>/
       ├── SCRIPT.md / CLI.md / GUI.md   # the only three docs at lab root
       ├── samples/        # external target artifacts, by content:
       │                    #   apks/  = the target APK(s)              (gitignored, sha256 only)
       │                    #   native/= .so extracted/dumped from it   (gitignored, sha256 only)
       │                    #   dex/   = dumped/unpacked dex             (gitignored, sha256 only)
       ├── pristine/       # DELTA: no golden source exists. Holds the provenance record:
       │                    #   provenance.json (url/tag/date/sha256/authorization) +
       │                    #   a sha256 manifest of the ORIGINAL untouched artifact, so
       │                    #   "did my analysis mutate the input?" is answerable.
       ├── analysis_output/ # dumps, decompiled trees, hook logs, reports (reset-cleared)
       ├── tools/          # this repo's Python tooling + anchor lists (anchors.txt)
       ├── build/          # env.sh / device-profile scripts (device+android+frida pins)
       ├── frida/          # dynamic hooks — FIRST-CLASS here; one .js per objective
       ├── neg/            # OPTIONAL: a self-built clean control app, used ONLY to show a
       │                    #   criterion/hook does not fire on a normal app (differential
       │                    #   contrast against the real target)
       └── logs/           # device-side evidence: logcat, frida console transcripts
       Layout deltas vs PROMPT.md, stated once so they are not mistaken for sloppiness:
         · `src/` and `shell/` are ABSENT (no source; the target is external).
         · `pristine/` is redefined from "golden sample backup" to "provenance + input
           integrity record" — there is no golden output to restore to.
         · No byte-for-byte comparison anywhere; verification is the behavior oracle (§4).
         · `frida/` and `logs/` are load-bearing (dynamic is the primary route), not
           optional extras.
   - Fixed chapter skeleton (same §0–§8 shape as PROMPT.md, methods re-pointed):
       Overview: one-line positioning / why this target / provenance + authorization /
                 target list table
       Lab layout / target list (samples/apks · samples/native · samples/dex)
       Knowledge points: five-part set — what it is / how to see it (static feature OR
                 runtime observable) / verification means / real output / failure boundary
       Static reconnaissance: packer/protector identification (reuse PROMPT.md's
                 structural criteria and B13 — they still apply as a starting map)
       Dynamic analysis: attach/spawn, hook map, memory dump, active invocation,
                 anti-analysis bypass — each with before/after observable
       Verification: the behavior oracle chosen, and why it is sufficient (§4 below)
       Decision flow (when static ends and dynamic is mandatory)
       Repeatable practice: environment fingerprint + reset (restore input integrity)
       Pitfalls (toolchain / device / version drift / false positives / failure boundary)

3. Method: static reconnaissance FIRST as a map, dynamic SECOND as the truth
   - Static (jadx/IDA/Ghidra + B13 + entropy + section tables) yields a HYPOTHESIS about
     what protector/algorithm is present. It almost never yields the verdict on a real
     target — runtime-decrypted strings, VMP handlers, and device-gated checks are
     invisible statically. State this explicitly; do not let a static guess read as a
     finding.
   - Dynamic is the primary route: Frida spawn/attach to observe the check, dump the
     decrypted artifact from memory, and drive behavior the UI does not naturally reach.
   - When the target resists instrumentation (Frida detected, ptrace blocked, root
     checks), record the detection mechanism, the bypass, and the environment it was
     verified in — a bypass claimed but not observed on-device is a hypothesis.

4. Verification by behavior oracle (replaces byte-for-byte)
   - Choose exactly one primary oracle per claim and name it in the Verification chapter:
       state oracle     — the app advances past a check it failed before;
       protocol oracle  — a recorded request carries the correct decrypted/unsigned field;
       algorithm oracle — a hooked call's args/return match the reconstructed algorithm
                          on N observed inputs (N stated);
       artifact oracle  — a dumped dex/so parses cleanly (dex magic + map_list; ELF
                          section/program headers via llvm-readelf) and its extracted code
                          matches a known anchor.
   - Record the oracle's exact observation (log line, screenshot path, request hash),
     not a summary. "Worked as expected" is not evidence.
   - Every claim not backed by an oracle is labeled **hypothesis**.

5. Environment fingerprint (the reproducibility backbone)
   - Pin in docs and `build/env.sh`: device model, Android version + ABI, ROM/root
     status, frida-server version, host frida/objection/python versions, and the sha256
     of the analyzed artifact.
   - Any behavior that differs across these is a documented finding (version-gated
     protector behavior is itself a result), never silently averaged away.

6. Cognitive boundary (mandatory, stricter than PROMPT.md)
   - Every conclusion lists what was NOT determined and the evidence that would determine
     it. Name the uncovered schemes explicitly: SO VMP, non-hub-converging VMP,
     runtime-decrypted strings, version/device-gated checks.
   - Fallback phrase: "no known signature observed (≠ none)". "Clean / not protected" is
     forbidden.

7. Ethical & redistribution self-check (before commit)
   - Confirm: authorized target only; no third-party artifact committed (sha256 +
     provenance only); no exploit/pirate framing in the deliverable; terms-of-service
     obstacle recorded if any.
   - Any third-party binary accidentally in the tree → .gitignore it and purge before
     commit.

8. Paths & tools externalized (same four-tier rule as PROMPT.md)
   - CLI arg > env var > build/env.sh > auto-detect. On total miss, tell the user what is
     missing and which flag overrides it. No hard-coded absolute tool paths.
   - NDK binutils are llvm-prefixed (llvm-readelf / llvm-objdump / llvm-nm / llvm-strings
     / llvm-size / llvm-addr2line); bare GNU names do not exist on this machine.

9. Zero absolute paths (hard) — same as PROMPT.md: no drive/user paths in scripts, build
   config, or generated artifacts; lab root from the script's own location.

10. Reset & integrity — tools/reset_lab.py supports status / restore / backup, where
    "restore" means: restore the ORIGINAL artifact hash from `pristine/` (detect if the
    analysis mutated the input) and clear `analysis_output/`. It no longer restores to a
    golden output — no such thing exists for a real target.
```

---

## Conventions quick reference

| Item | Convention |
|---|---|
| Scope | Analysis of **external real targets** (no source, no golden baseline) — the complement to `PROMPT.md`'s self-built labs |
| When to use | Source is absent, byte-for-byte comparison is impossible, dynamic is the primary route |
| Do NOT use for | Self-made reproducible sample labs — that is `PROMPT.md` |
| Authorization gate | Own / permitted / public-practice / CTF only; record provenance + basis; stop if terms forbid RE |
| Redistribution | Third-party artifacts **never committed** — sha256 + provenance + conclusions only; binaries gitignored |
| Documents | Three parallel docs `SCRIPT.md` + `CLI.md` + `GUI.md`, one shared skeleton; Chinese lab docs, English repo-level files |
| Directory layout | Reuse `PROMPT.md` slots; deltas: no `src/`/`shell/`; `pristine/` → provenance+integrity record; `frida/`+`logs/` load-bearing |
| Method | Static = map/hypothesis; dynamic (Frida/memory dump/active invocation) = truth; bypass must be observed on-device |
| Verification | Behavior oracle (state / protocol / algorithm / artifact) with the exact observation recorded; unbacked claims = **hypothesis** |
| Reproducibility | Environment fingerprint (device + Android + ABI + frida-server + host versions + artifact sha256) — the real-target analogue of `pristine/` |
| Cognitive boundary | "no known signature observed (≠ none)" + named uncovered schemes (SO VMP / non-hub VMP / runtime strings / version-gated); "clean/not protected" forbidden |
| Paths & tools | Four tiers: CLI arg > env var > build/env.sh > auto-detect; NDK binutils are `llvm-`-prefixed |
| Zero absolute paths | Repo-wide ban on drive/user paths; sole exception: `cd` examples in docs |
| Reset | `pristine/` input-hash restore + clear `analysis_output/`; no golden-output restore (none exists) |
| Ethics self-check | Authorized target · no third-party binary committed · no crack/pirate framing · ToS obstacle recorded |
| Publishing | Monorepo; `feat(<target>): ...`; MIT; English About/Topics; sample binaries gitignored |
