# Android Reverse-Engineering Labs · Reusable Prompt

> Lives at the repository root as `PROMPT.md`. Shared across all labs.
> Usage: copy the **Prompt Body** below, replace `<project-name>` and `<topic>`.

> ⚠️ **Language convention (mandatory)**
> - **This prompt and all repository-level files are in English** (root `README.md`,
>   `PROMPT.md`, commit messages, GitHub About/Topics).
> - **Each lab's three documents (`SCRIPT.md` / `CLI.md` / `GUI.md`) are written in Chinese** —
>   they are teaching material for the author's own study loop; technical terms,
>   tool names, file paths, and pasted tool output stay in their original language.
> - Commit messages follow the English convention even when they describe
>   Chinese-language lab docs (e.g. `docs(ajiami): ...`).

> ⚠️ **Local command convention**: this machine **has `python`, no `python3`**.
> All scripts and doc examples use `python xxx.py`. Shebangs use `#!/usr/bin/env python`.

> ⚠️ **Documentation-writing conventions**
> 1. **Script → CLI → GUI**: chapter order = theory → script run → CLI reproduction →
>    GUI understanding. Give the correct answer via automation first, then explain why;
>    do not open with byte-level steps.
> 2. **Commands must be complete**: no `...apk` / `xxx.sh` placeholders — every command
>    must be copy-paste executable as written.
> 3. **Commands live in code blocks**, never inside table cells; tables carry only
>    explanatory content (purpose / parameter meaning / interpretation / dependency).
> 4. **Command explanations are never one-liners**: each command gets
>    purpose + per-parameter explanation + real output excerpt + line-by-line reading
>    + failure criteria. Output excerpts must come from actual runs, never memory.
> 5. **No absolute paths in pasted output**: trim anything above the lab root;
>    keep relative paths only.
> 6. **Every command carries its own explanation**: inline comments in the block
>    (what it does / key parameters) + `# =>` expected output, followed by a
>    "what these commands do" paragraph after the block.
>    Example (follow this style):
>    ```bash
>    # ① Detection: which generation is this packer? (read-only structural check)
>    python tools/detect.py samples/apks/app_packed_v1.apk
>    #   => verdict: hardened — whole-DEX encryption (generation 1)
>
>    # ② Unpack: --pristine supplies the golden sample for immediate comparison
>    python tools/unpack_v1.py samples/apks/app_packed_v1.apk analysis_output/out.dex --pristine samples/dex/classes_orig.dex
>    #                    └ input             └ output   └ golden => byte-identical to golden ✓
>    ```

> ⚠️ **Verification & cognitive-boundary conventions** (mandatory — distilled from a
> real false-positive incident in the ajiami lab)
> Self-built-sample projects carry an inherent circular-reasoning risk:
> **sample = spec = test set**; a detector is trivially correct on samples designed for it.
> Before delivering any detection/verdict tool, complete all four:
> 1. **Negative samples are mandatory and must not all be self-built**. Besides "detects X",
>    verify "does not misfire on non-X inputs". Without external negatives, at least
>    hand-construct counter-examples shaped like real apps: multi-dex / AndroidX
>    components / large SO / high-entropy assets / tens of thousands of methods.
> 2. **Falsification question per criterion**: what *normal* input would also trigger it?
>    If a normal input can trigger it, the verdict is "suspected", never definitive.
> 3. **No universal negation in conclusions**. The fallback must read
>    "**no known hardening signature observed (≠ none)**" plus an explicit list of
>    schemes the tool does **not** cover (cognitive boundary). Over-claiming (normal
>    sample flagged as packed) and over-trusting (unknown scheme flagged as safe) are
>    symmetric failures; guarding only one side is not enough.
> 4. **Every "only-first / only-main-file" logic must be explicit**: either generalize to
>    all items, or emit a loud warning on extras (listing what was ignored and the
>    consequence). Silent partial results are forbidden.
> Known traps: ① `classesN.dex` multi-dex (main-dex-only logic flags normal apps as
> packed, and partially restores multi-dex samples while still reporting success);
> ② hard-coding the practice lab's package name as "the business package"
> (never true for real apps → the criterion degenerates to always-true/always-false).

> ⚠️ **Zero absolute paths** (hard constraint)
> No file in the repo (scripts / build config / source / docs / generated artifacts)
> may contain machine paths like `D:\...`, `C:\Users\...`, `/d/...`.
> All external dependencies resolve through four tiers, in order:
> **CLI argument > environment variable > project config (`build/env.sh`, optional) >
> auto-detection**. If all four fail, **error out and tell the user**: what is missing,
> where it is normally installed, whether to add PATH or set an env var, and which
> CLI flag overrides it for one run.
> Project roots are always derived from the script's own location
> (bash: `$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)`;
> python: `os.path.dirname(os.path.abspath(__file__))`) — never from the working directory.
>
> **Sole exception**: `cd` examples in docs may use the real local path
> (so they can be copy-pasted); scripts / build config / generated artifacts never may.

> ⚠️ **GitHub publishing conventions** (mandatory — this repo is public, as a portfolio)
> 1. **Repo topology**: this repository is a monorepo of "hardening labs + this prompt".
>    If a sub-project carries its own `.git` (e.g. the obfuscation-topic `ollvm/`),
>    exclude it in the root `.gitignore` with `/<subdir>/`; never mix histories.
> 2. **Commit discipline**: root `git init`; commit in "infrastructure → per-lab" batches:
>    `README.md` (repo overview) / `LICENSE` / `.gitignore` / `PROMPT.md` first, then one
>    commit per lab (each containing `SCRIPT.md` + `CLI.md` + `GUI.md`).
>    Message style: `type(scope): one line` (e.g. `feat(360jiagu): ...`).
> 3. **Path scrubbing**: before publishing, re-scan the whole repo for real drive/user
>    paths and rewrite to relative or generic forms.
> 4. **Never committed**: third-party/local binaries (e.g. UPX `*.exe`) and signing
>    `*.keystore` — not in the repo, not explained in docs. Keep only `build/*.sh` /
>    `build/*.py` / `build/env.sh` as tooling; ignore generated dirs with
>    `**/build/<name>/` (trap: `build/v1/` matches only the root-level dir and misses
>    `ajiami/build/v1/` — the `**/` form is required).
> 5. **LICENSE**: MIT for public repos; copyright line = the local git identity.
> 6. **GitHub metadata (required when publishing)**:
>    - **About**: one English sentence (modeling + method), e.g.
>      `Educational Android unpacking & packer-hardening labs — self-built, evidence-based, deterministic-first reverse-engineering study materials.`
>    - **Topics**: lowercase English, at least `android` `reverse-engineering` `unpacking`
>      `packers` `dex` `elf` `ndk` `anti-tamper` `static-analysis` `educational`.
> 7. **Pushing**: the local `gh` does not support `gh repo create --topic/--branch`.
>    Create+push with `gh repo create <name> --public --description "..." --source . --push`;
>    topics go through REST: write `{"names":[...]}` into a JSON file, then
>    `gh api repos/<owner>/<repo>/topics -X PUT -H "Accept: application/vnd.github.mercy-preview+json" --input <file>`
>    (`-F names='[...]'` is parsed as a string and 422s — real JSON via `--input` is required).

---

## Prompt Body

```
Create a folder <project-name> under the repository root: a practice lab for
「<topic>」.
Topic scope: Android packers and unpacking (UPX and variants, compression shells,
memory dump, OEP, ELF Fix, whole-DEX encryption, class extraction, hardening detection).
Out of scope: code obfuscation / string protection / VMP teaching — do not use this
prompt for those; write a separate one.
Requirements:

1. Documents (top priority)
   - All knowledge goes into three parallel documents (one shared chapter skeleton,
     section-for-section): do not create docs/ or any other markdown file;
     no per-lab README.md.
       `SCRIPT.md` — script route: live runs of this repo's Python tools in `tools/`
                     (detect / unpack / verify, etc.).
       `CLI.md`   — command-line route: byte-level reproduction of every step with
                    generic commands (unzip / aapt2 / xxd / readelf / sha256sum / cmp /
                    apkutil (entropy), etc.).
       `GUI.md`   — graphical-tool route: jadx / IDA / Ghidra / 010 Editor / GDA / JEB /
                    binwalk (entropy curve) / apkid — operations and interpretation
                    at the corresponding steps.
     **The three lab documents are written in Chinese** (see the language convention
     at the top of this file); tool output and paths stay as-is.
   - **Fixed directory layout (mandatory — copy verbatim, do not invent)**. The lab
     root contains **only** the entries below. Before creating any new directory or
     flat file, check it fits one slot; if it does not fit, it must not be created:
       ```
       <project-name>/
       ├── SCRIPT.md / CLI.md / GUI.md   # the only three docs; no other md at lab root
       ├── samples/        # analysis targets (four bins by content: apks/dex/payloads/
       │                    # native; SO labs use so/ instead of apks/)
       │                    # all "analyzed files" live here — never flat at lab root
       ├── pristine/       # sha256 baseline backup of samples/ (reset restore source)
       ├── analysis_output/ # practice artifacts only (unpack results, reports, jadx
       │                    # output, memory dumps) — wiped by reset
       ├── src/            # business-sample source (.c/.cpp/.java/.xml, with anchors)
       ├── shell/          # packer-shell source (modeled-shell labs only)
       ├── neg/            # negative-sample source (only if adversarial negatives exist)
       ├── vmp/            # VMP teaching-sample source (only if a VMP sample exists)
       ├── tools/          # this repo's Python tools + anchor list (anchors.txt) +
       │                    # tool binaries (gitignored)
       ├── build/          # build scripts (*.sh / *.py / env.sh / env.sh.example) —
       │                    # no generated artifacts
       ├── app/            # runnable app project (only when dynamic verification of
       │                    # "unpacked output still runs" is in scope; full gradle layout)
       ├── frida/          # dynamic-route hook scripts (dynamic-route labs only;
       │                    # one .js per sample)
       └── logs/           # practice logs (may stay empty; never a documentation source)
       ```
       Layout rules:
       ① **Samples must live in `samples/`**: .so/.apk/dex/payload all inside bins;
         the lab root must never contain flat samples like `libtarget_*.so`, `*.apk`.
         Bins by content: `apks/` = APK analysis targets, `dex/` = golden/shell/
         extracted-state/unpacked dex, `payloads/` = encrypted payloads / side tables /
         decoys / policy tables, `native/` = the packer's auxiliary SOs (shell native
         components, multi-SO-chain intermediates — the third kind of SO that is
         neither protected target nor payload). Pure-SO labs replace the `apks/` bin
         with `so/`; the rest is the same. Do not create empty bins for absent content.
       ② **Source must live in `src/` (or shell/ / neg/ / vmp/)**: no loose
         `.c/.java/.xml` at the lab root.
       ③ **Artifacts go only to `analysis_output/`**: unpack output, dumps, reports,
         jadx trees, adb-pulled memory images (`analysis_output/dumps/`) — all here,
         all clearable by reset.
       ④ **Optional dirs on demand**: shell/ / neg/ / vmp/ / app/ / frida/ exist only
         when the corresponding sample/route exists; no empty placeholders.
       ⑤ **Tool binaries (upx.exe etc.) go to `tools/` and are gitignored**; multiple
         versions coexist version-named (`tools/upx396.exe`, `tools/upx521.exe`), and
         each doc references whichever it actually ran. Binaries under `samples/` and
         `pristine/` *are* committed (they are the practice data, size-bounded).
   - **Fixed chapter skeleton (copy verbatim, do not invent numbering)**: the three
     documents share one skeleton and differ only in method —
       SCRIPT.md: this repo's tools/ Python code,
       CLI.md: generic commands,
       GUI.md: graphical tools.
       Overview: one-line positioning / why self-built samples (modeling note) /
                 sample-list table / three-minute run
       The three-minute run is an **environment smoke test**: 4–8 commands that
       prove the toolchain works end-to-end on the reader's machine and show the
       minimal loop of this lab. It is NOT a summary of later chapters — each
       command must be runnable as-is, and its expected output must be the
       "it works" signal (green check / correct verdict), not teaching content.
       Every command in it must belong to THIS document's route (see the
       route-purity rule below); a CLI smoke test uses generic commands only.
       Lab layout / sample list (four bins: apks / dex / payloads / native; SO: so/)
       Knowledge points: fixed five-part set per section — what it is / how to see it
                 (structural feature + threshold) / verification means / real output /
                 failure boundary; [verifiable] when a sample exists,
                 [knowledge framework] for pure theory
       Detection: feature comparison table + live run output + threshold-design pitfalls
       Unpacking: each document reproduces with its own method; byte-for-byte comparison
       Verification criteria (size / anchors / sha256 / diff bytes + first-diff offset)
       Decision flow (decision tree)
       Repeatable practice: pristine/ + reset_lab.py (status / restore / backup)
       Pitfalls (toolchain / environment / thresholds / false positives / failure boundaries)
   - Route division: **verdicts come from SCRIPT/CLI (quantifiable, criterion-grade);
     understanding comes from GUI** (jadx yields Java, IDA yields call graphs,
     binwalk yields entropy curves). The same step shows its own method's version in
     each document — no cross-copying conclusions. GUI outputs (decompiled code,
     entropy curves, hex views) are described via key reading points + necessary real
     excerpts; never leave the reader with a tool and no idea what to look at.
   - **Route purity (hard)**: each document runs ONLY its own method's tools.
     CLI.md uses generic commands (unzip / aapt2 / xxd / readelf / sha256sum / cmp /
     apktool...) — invoking `python tools/*.py` inside CLI.md is forbidden (that is
     SCRIPT.md's route; where a number CLI commands cannot produce, CLI.md says so
     and points to SCRIPT.md instead of borrowing its scripts). GUI.md uses
     graphical tools (jadx / IDA / 010 Editor / binwalk / apkid...); its smoke test
     and steps likewise never invoke `tools/*.py`. SCRIPT.md is the only document
     that runs this repo's Python tools. Cross-references between documents are
     fine; cross-execution is not.
   - Every chapter states "what to do / what you should see / why" — conclusions alone
     are not acceptable.
   - Command style: complete and copy-pasteable (no `...` placeholders), in code blocks
     (not tables), each with purpose + per-parameter notes + real output excerpt +
     line-by-line reading + failure criteria. Excerpts must come from actual runs.
   - Self-explaining commands: inline comments per command (what / key parameters) +
     `# =>` expected output, plus a "what these commands do" paragraph after each block.

2. Samples (must be reproducible)
   - Four fixed bins under `samples/`: `samples/apks/` (APK analysis targets),
     `samples/dex/` (golden / shell / extracted-state / unpacked dex),
     `samples/payloads/` (encrypted payloads / side tables / decoys / policy tables),
     `samples/native/` (packer auxiliary SOs: shell native components,
     multi-SO-chain intermediates). Scripts and docs always use these bin-relative
     paths; never mix file kinds at the `samples/` root. SO labs (no APK) replace the
     `apks/` bin with `samples/so/` (.so analysis targets); absent bins are not created.
     **Flat .so/.apk samples at the lab root are forbidden.**
   - Compile real Android .so from source with the local NDK clang, so packed and
     unpacked outputs derive from the same source (identical code and strings) and
     compare byte-for-byte.
   - Produce at least three: original .so, standard packed sample, variant sample
     (variants may be generated by rewriting features).
   - Place explicit analysis anchors in the source (signature strings / JNI_OnLoad /
     RegisterNatives / business functions) to verify unpacking success.

3. Detection (no shortcuts)
   - Verdicts ("packed? which packer? variant?") must rest on structural features:
     section-table count, entropy, PT_LOAD decompression buffer (filesz vs memsz),
     entry position, memory/file size ratio, trailer fields.
   - Concluding from file names or a single string feature is forbidden.
   - Provide a quantified feature comparison table (unpacked vs packed, measured
     values) and record wrong criterion/threshold designs (why wrong, how fixed).

4. Script / CLI / GUI (script first, then CLI, then GUI)
   - Manual reproduction must exist: exact byte offsets, editable with a hex editor
     (010 Editor / HxD); every command and every GUI step explained.
   - Scripts only automate those steps — never the sole answer. GUI tools (jadx / IDA)
     serve understanding of structure and call relations; they do not replace
     quantified verdicts.
   - State each method's preconditions and failure conditions: when the dynamic /
     memory route becomes mandatory.

5. Reset (repeatable practice)
   - Provide a reset tool: samples backed up to pristine/ (with sha256 manifest),
     supporting status / restore.
   - restore must restore sample files + remove practice artifacts + clear the
     analysis output directory.

6. Verification & pitfalls
   - Quantified verification criteria (size / anchors / byte diff), actually run
     once, with the real output pasted into the docs.
   - Record pitfalls hit in this environment (tool limitations, errors, false
     positives) — never the ideal path only.

7. Paths and tools fully externalized (important)
   - No external tool (UPX / NDK / SDK / aapt2 / java / python) may be hard-coded
     to an absolute path. Four-tier resolution, in priority order:
       ① CLI arguments (--upx / --ndk / --aapt2 / --root / --python)
       ② Environment variables (UPX / NDK_ROOT / ANDROID_NDK_HOME / ANDROID_HOME /
          JAVA_HOME / PYTHON)
       ③ Project config build/env.sh (optional, sourced only if present; ship
          build/env.sh.example as the template — placeholders and notes only,
          no real paths)
       ④ Auto-detection (PATH, standard SDK/NDK layouts, newest version wins)
   - If all four tiers fail, **tell the user**: what is missing, where it usually
     installs, whether to fix PATH or an env var, which flag overrides it for one
     run. Never silently assume a tool exists.
   - The lab root is derived from the script's own location, never hard-coded;
     build artifacts print relative paths only.

8. Zero absolute paths (hard)
   - No drive paths (`D:\`, `C:\`) or user dirs (`/c/Users/`, `/d/`) in source,
     build scripts, Python tools, docs, or generated artifacts (*.json / *.txt).
   - Docs refer to the lab location as "the lab root (the directory holding this
     lab's documents)"; example commands use relative paths.
   - **Sole exception**: `cd` examples in docs may carry the real local path;
     scripts / build config / generated artifacts never may.
   - Pre-delivery self-check: repo-wide search for `:\` and `/Users/` must be
     clean except documented `cd` examples and historical artifacts; any hit is
     either externalized or added to the reset cleanup and regenerated.

9. Verification discipline for detection tools (hard — cures circular reasoning)
   - "Validating your own detector only on your own samples" is forbidden: negative
     samples / counter-examples are mandatory, with each criterion checked against
     normal inputs for false triggering.
   - The conclusion ladder requires **mutually corroborating evidence**; a single
     criterion may never classify alone (e.g. one missing-class signal does not
     establish a generation).
   - The fallback must read "no known signature observed (≠ none)" plus an explicit
     list of uncovered schemes (cognitive boundary). SO labs must name at least
     SO VMP / non-hub-converging VMP / string encryption (see rule 11) — all
     dynamic-trace-only.
   - Any "first dex only / main file only / first entry only" logic: generalize to
     all, or warn loudly on extras (listing ignored items and consequences).
   - The pitfalls chapter of all three documents must record: which criterion
     false-fired in which real scenario, root cause, and the fix.

10. Adversarial negative samples + regression assertions — not just samples (hard)
   - Build one or more **adversarial negatives**: clean, yet nearly triggering the
     criteria. A negative is valuable only if it nearly trips a rule; another clean
     single-dex sample is worth nothing. Embed real-world-shaped traps: multi-dex
     (component classes in secondary dex), legitimate high-entropy assets, relative
     class shorthand (`.MainActivity`), legitimate DexClassLoader use, normal .so.
   - Negatives must be **reproducible from source** (built in this repo, not mystery
     binaries), tracked in the pristine/ baseline, and reset-managed.
   - A **two-way assertion script** is mandatory (e.g. check_negatives.py):
       positive: true samples must classify as their generation (guards against
       over-correcting false positives until real shells slip through)
       negative: clean samples must never classify as "hardened" and must not hit
       the designated false-positive criteria
     Both directions required; one-sided always fails. Failures print red and
     exit non-zero.
   - Remember: **a negative sample without assertions is decoration** — its value
     is being runnable, not existing.

11. SO/ELF labs: structural anomaly detection (B13) + enumerated cognitive boundary
    (hard)
   - Any lab with SO/ELF verdicts must implement B13 alongside UPX-class features:
     detect `e_type==ET_DYN(3) && e_shnum==0 && an executable PT_LOAD exists` —
     the section-header-stripped shape. Rationale: normal NDK .so always carries a
     full section table; custom linkers load via Program Headers and write no
     standard section headers. This signal is deterministic and independent of any
     UPX magic/score, catching custom linkers UPX-class detectors miss
     (already landed in three labs: ajiami / 360jiagu / upx_practice).
   - On a B13 hit, the verdict reads "suspected SO packing / self-implemented
     linker (ELF section headers stripped) — confirm manually at the ELF layer";
     never definitive, never conflated with "not packed".
   - The cognitive boundary must explicitly name these **statically undecidable,
     dynamic-trace-required** scenarios (zero features triggered still ≠ unpacked):
       ① SO VMP — the interpreter is just a large ordinary function; normal ELF
       structure means static analysis cannot confirm;
       ② custom VMP without the hub-convergence shape (hub heuristics miss it);
       ③ sophisticated string encryption (strings never touch the constant pool —
       no structural anomaly).
   - A **B13 two-way regression assertion** must ship (e.g. check_so_samples.py):
       positive — the stripped sample must trigger B13;
       negative — the original NDK .so (full section table) must not;
       anti-regression — existing UPX/360 verdicts must survive the B13 changes.
```

---

## Conventions quick reference

| Item | Convention |
|---|---|
| Project location | A `<project-name>` folder under the repo root (new folder each time); docs say "the lab root" only |
| Documents | Three parallel docs `SCRIPT.md` (script) + `CLI.md` (CLI) + `GUI.md` (GUI), one shared skeleton |
| **Language** | **Repo-level files & commits in English; each lab's three docs in Chinese** (teaching material; tool output/paths stay original) |
| Method layering | SCRIPT = this repo's tools/ Python code; CLI = unzip/aapt2/xxd/readelf generic commands; GUI = jadx/IDA/Ghidra/010 Editor/GDA/JEB/binwalk(-E)/apkid |
| Topic | Android **packers & unpacking** (UPX/variants/compression shells/memory dump/OEP/ELF Fix/whole-DEX encryption/class extraction) |
| Out of scope | Code obfuscation / string protection / VMP teaching → separate prompt |
| Samples | NDK clang from source; packed/unpacked same-source, byte-comparable |
| Sample bins | `samples/apks/` (APK) · `samples/dex/` (golden/shell/extracted/unpacked) · `samples/payloads/` (payloads/side tables/decoys/policy) · `samples/native/` (packer auxiliary SO); SO labs use `samples/so/` instead of apks; never flat at lab root |
| Directory layout (hard) | Lab root allows only: three md + samples/ + pristine/ + analysis_output/ + src/ + optional(shell/ neg/ vmp/ app/ frida/) + tools/ + build/ + logs/; samples→samples/, sources→src/, artifacts→analysis_output/, build scripts→build/; tool binaries→tools/ (gitignored, version-named) |
| Detection | Structural features + quantified thresholds; never file names / single strings |
| Knowledge-point style | Five-part set: what / how to see / verification means / real output / failure boundary |
| Reset | `pristine/` backup + `tools/reset_lab.py` (status / restore / backup) |
| Doc order | Theory → script run → CLI reproduction → GUI understanding; GUI steps reference script output |
| GUI tool selection (agents pick per step) | Java/resource decompile: jadx; SO reversing/call graphs/xrefs: IDA or Ghidra; hex editing: 010 Editor (or HxD/ImHex); APK structure browsing: GDA or JEB; entropy curve: binwalk -E (`-p` saves PNG); external packer cross-check: apkid; unpack/repack: apktool. GUI commands stay copy-paste complete (jadx -d / binwalk -E -p / apktool d); in-tool steps spell out where to click / what to look at / how to judge |
| Command style | Complete, no ellipsis, in code blocks, with purpose/params/real output/line-by-line reading |
| Self-explaining commands | Inline comment per command (what / key params) + `# =>` expected output; "what these commands do" paragraph after each block |
| Paths & tools | Four tiers: CLI arg > env var > build/env.sh (optional) > auto-detect; on total miss, error with guidance |
| Zero absolute paths | Repo-wide ban on drive/user paths; lab root from script location; artifacts print relative paths; sole exception: `cd` examples in docs |
| Env template | `build/env.sh.example` carries placeholders and notes only |
| Verification discipline (anti-circular) | Negative samples/counter-examples mandatory; single criterion never classifies; corroborating evidence before generation verdicts |
| Cognitive boundary (hard) | Fallback reads "no known signature observed (≠ none)" + explicit uncovered-scheme list (SO labs name at least: SO VMP / non-hub VMP / string encryption — dynamic-trace-only); "not hardened / all clear" is forbidden |
| Silent partiality (forbidden) | "Main dex only / first entry only": generalize, or warn loudly on extras |
| Doc-code sync (hard) | Any tool output pasted into docs must come from a fresh run; when criteria/thresholds/assertions change, update docs before committing — stale outputs are forbidden (once occurred in ajiami: docs still showed the pre-B11 "missed detection" output after B11 landed) |
| Legacy lab migration | Early single-README labs (360jiagu / upx_practice) may ship as-is while content-complete, but must be split into SCRIPT.md + CLI.md + GUI.md on next major revision; new labs are three-doc from the start — no more single-README deliveries |
| Legacy directory cleanup | 360jiagu / upx_practice currently keep .so samples flat at the lab root; on the next touch of those labs, migrate to the fixed layout in one pass (.so → samples/so/, pristine manifest recomputed, doc command paths updated) with regressions green — no piecemeal moves |
