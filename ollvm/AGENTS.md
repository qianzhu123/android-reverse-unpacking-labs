# AGENTS.md — ollvm lab (ground-truth document for agents)

> **Audience: an agent that needs to be productive in this lab within a few minutes.**
> Every item comes from reading the source line by line + actually running things on this machine (Windows / PowerShell + Bash, JDK 21, NDK r27d).
> Line numbers refer to the files' current contents; if you change a file, re-verify them yourself.
>
> **Repo iron rules**: zero absolute paths; **this lab is a PowerShell toolchain** (not bash); self-built samples are reproducible;
> third-party samples are not committed; the epistemic boundary is **"absence of known signatures ≠ not hardened"**.
>
> **The fundamental difference between this lab and the others**: `360jiagu`/`upx_practice`/`ajiami` are about **packers/shells**
> (packing, unpacking); `ollvm` is about **code obfuscation / string protection**, which is **outside packer/shell scope**, so
> **it does not use PROMPT.md's packer template** — but it follows the same "three docs + fixed directories" convention
> (see the notes in the root `README.md`). **This lab has no `detect`/`solve`/`unpack` tooling, and no
> packer-style automated verdict**; what it outputs is a "before/after obfuscation comparison + analysis techniques".

---

## 0. What this lab is (and one honest boundary that has to be stated plainly)

`ollvm` uses a **self-built Android app** to present four forms of code/string protection side by side, for comparative study:

| Form | Where | When the plaintext appears |
|---|---|---|
| **Java plaintext** | `MainActivity.onCreate` | At compile time it is in the dex string pool (`PLAIN_SECRET=ollvm-lab:static-string`) |
| **Java-level XOR** | `MainActivity.XOR_BLOB` | Decoded at runtime (`JAVA_XOR_SECRET`) |
| **JNI-level XOR** | `native-lib.cpp:decode_secret` | Decoded at runtime (`JNI_SECRET=ollvm-native`) |
| **native control-flow baseline** | `native-lib.cpp:nativeOpaque` | No string; used to compare the CFG before and after OLLVM passes |

> **⚠️ The most important honest boundary (admitted outright in `SCRIPT.md:7`)**: the current APK is a baseline of **ordinary NDK
> compilation + source-level XOR runtime decoding**. `app/build.gradle` does **not** enable `-mllvm -fla/-sub/-bcf`,
> so **the existing APK cannot be described as "obfuscated with OLLVM"**. `ollvm/toolchains/` is only
> **instructions for integrating an external OLLVM fork** (see §7). Any conclusion that calls the current sample an
> "OLLVM-obfuscated sample" is wrong.

**Why it is worth a lab of its own**: it separates "obfuscation" and "string protection" from "packing" — this is the other side
of the epistemic boundary ("absence of known characters/signatures ≠ not hardened"): **being able to read plaintext ≠ unprotected;
being unable to read plaintext does not mean OLLVM was used either**.

---

## 1. Directory map

```text
ollvm/
├── app/                       ★ self-contained gradle project (the gradle root is right here, not the repo root)
│   ├── settings.gradle        rootProject.name='ollvm-lab'; single module
│   ├── build.gradle           AGP 8.13.0; compileSdk 35; ndkVersion 27.3.13750724
│   ├── gradlew.bat            Gradle wrapper
│   └── src/main/
│       ├── java/com/example/ollvmlab/MainActivity.java   UI for the four forms
│       ├── cpp/native-lib.cpp + CMakeLists.txt           JNI XOR + nativeOpaque
│       ├── res/layout/activity_main.xml                  4 buttons
│       └── AndroidManifest.xml                           .MainActivity (launcher)
├── build/
│   ├── bootstrap.ps1          ★ pins JDK 21 + provisions project-local Gradle 8.13
│   └── build.ps1              calls gradlew assembleDebug|Release
├── tools/
│   ├── analyze-apk.ps1        apktool + jadx + aapt2 badging
│   ├── inspect-native.ps1     llvm-readelf/objdump/strings on the SO
│   ├── logcat.ps1             adb logcat filtered by OLLVM_LAB
│   └── reset_lab.py           ★ backup/status/restore (Python, isomorphic with the other labs)
├── frida/frida-hook.js        ★ hooks the two JNI exports (Java bridge)
├── samples/apks/              ★ archived APKs (app-debug / app-release-unsigned)
├── pristine/                  sha256 baseline + apks/ mirror
├── analysis_output/           apktool/jadx artifacts (gitignored)
└── SCRIPT.md  CLI.md  GUI.md  the three-track docs (parallel to this one)
```

**Note `app/.cxx/` and `app/build/intermediates/`**: these are CMake/Ninja build intermediates
(there are traces of them committed in `ollvm-history-backup.bundle` too); **do not** mistake them for source — the
genuinely handy entry point is `app/src/main/`.

---

## 2. Sample set — measured hashes

`sha256sum samples/apks/*.apk` (consistent with `pristine/manifest.json`):

| APK | bytes | sha256 |
|---|---|---|
| `app-debug.apk` | 1371508 | `06935b0b8f0eef249e2d202e2059141b389f7f5760788024ef1175fc1def045e` |
| `app-release-unsigned.apk` | 1204141 | `b02aef06944b280b84d4e32edaf5c19bd6edc353d8fa3c60c89ff66d93e794cd` |

`pristine/manifest.json` uses the **`{"files":..., "config":...}` format**, with keys relative to `samples/`
(`apks/app-debug.apk`), and `config.clean_dir = "analysis_output"`.

On this machine, `python tools/reset_lab.py status`:
```
  [一致]   apks/app-debug.apk                        1371508 bytes
  [一致]   apks/app-release-unsigned.apk             1204141 bytes
输出目录 analysis_output/: 空
当前环境: 干净，可直接开始练习
```

> **APK hashes change after a rebuild** (`SCRIPT.md:107`): the packaging timestamp goes into the zip, so after rebuilding you must
> run `python tools/reset_lab.py backup` to refresh the `pristine/` baseline. But the **arm64 SO content is stable**
> (`SCRIPT.md:107` records that after an actual rebuild the SO sha256 is still `555B4EE7...`) — because the SO has no timestamp.
> The hashes recorded in the docs take the archived copies in `samples/apks/` as authoritative.

### APK internal structure (measured on this machine for `app-debug.apk`, 10 entries)
```
classes.dex                     1924 B
lib/arm64-v8a/libollvmlab.so   383632 B
lib/armeabi-v7a/libollvmlab.so 229196 B
lib/x86/libollvmlab.so         359432 B
lib/x86_64/libollvmlab.so      364320 B
AndroidManifest.xml            2124 B
```
**All four ABIs are packaged** — because under the default `ndkVersion 27.3.13750724` configuration, AGP emits SOs for every ABI.
`classes.dex` is only 1924 B — all the logic lives in a single Activity, so the dex is tiny.

---

## 3. `app/src/main/cpp/native-lib.cpp` — the native side of the four forms

### 3.1 `decode_secret` (`:4-9`) — JNI-level XOR
```cpp
static std::string decode_secret() {
    const unsigned char blob[] = {0x10,0x14,0x13,0x05,0x09,0x1f,0x19,0x08,0x1f,0x0e,0x67,0x35,0x36,0x36,0x2c,0x37,0x77,0x34,0x3b,0x2e,0x33,0x2c,0x3f,0x00};
    const unsigned char key = 0x5a; std::string out;
    for (size_t i = 0; blob[i] != 0; ++i) out.push_back(static_cast<char>(blob[i] ^ key));
    return out;
}
```
**Computed on this machine** (byte-by-byte `^ 0x5a`):
```
JNI_SECRET=ollvm-native
```
That is, a NUL-terminated array of ciphertext bytes + a single-byte key `0x5a`. `blob` has 24 elements; the final `0x00` is the
terminator (the loop condition is `blob[i]!=0`, so after the last `0x2c`, `0x3f^0x5a='e'` is still decoded, and what is hit next is
the array's 24th element, `0x00`).

### 3.2 `nativeSecret` (`:11-13`) — JNI export
```cpp
extern "C" JNIEXPORT jstring JNICALL Java_com_example_ollvmlab_MainActivity_nativeSecret(JNIEnv* env, jobject) {
    std::string s = decode_secret(); return env->NewStringUTF(s.c_str());
}
```
A name-mangled export (not `RegisterNatives`). **`decode_secret` is `static`, so it gets inlined into the JNI function body** —
this is why no standalone symbol shows up in the disassembly (see §4).

### 3.3 `nativeOpaque` (`:15-20`) — control-flow baseline
```cpp
int x = input * 3 + 1;
if (((x ^ 0x55) + 7) % 2 == 0) x += 0x10; else x -= 0x0b;
for (int i = 0; i < 3; ++i) x = (x ^ (i * 13 + 3)) + 1;
return x;
```
**Computed on this machine, `nativeOpaque(7)`**:
```
nativeOpaque(7) = 43
```
(`x=22` → `(22^0x55)+7=78`, even → `+0x10=38`; loop i=0,1,2 → 43, with no 32-bit wraparound.)

> **The comment says it outright** (`:16`): `// Deliberately simple baseline for comparing with OLLVM passes.`
> So this is **a naive baseline for single-variable experiments with OLLVM**, and it is **not** obfuscated itself.

---

## 4. `tools/inspect-native.ps1` — how it reads the SO (actually run on this machine)

The script uses **NDK r27d's llvm-* binutils** (not a bare `readelf` — that does not exist on this machine):
```
$llvm = D:\...\android-ndk-r27d\toolchains\llvm\prebuilt\windows-x86_64\bin
$readelf/$objdump/$strings = llvm-readelf.exe / llvm-objdump.exe / llvm-strings.exe
```
It runs four sections: `== SYMBOLS ==` (`llvm-readelf -Ws` grep `Java_|decode_secret|nativeOpaque`),
`== SECTIONS ==` (`llvm-readelf -S` grep `.text|.rodata|.debug`),
`== STRINGS ==` (`llvm-strings` grep `ollvm|secret|JNI`),
`== DISASSEMBLY ==` (`llvm-objdump -d --demangle` grep `nativeSecret|nativeOpaque|decode_secret`).

> ⚠️ **The script has hard-coded absolute paths** (the llvm directory at `:4`, the apktool path at `analyze-apk.ps1:8`,
> the JDK path at `bootstrap.ps1:5`). This **conflicts** with the "zero absolute paths" iron rule — it is a historical
> leftover of `ollvm` (it used to be a standalone repo). On this machine those paths **all exist** (verified: NDK r27d's
> `llvm-readelf.exe` and apktool.bat are both in place). Porting to another machine requires editing these constants.

**Actually run on this machine (after extracting the arm64 SO)**:
```
    79: 0000000000024f10   196 FUNC    GLOBAL DEFAULT    14 Java_com_example_ollvmlab_MainActivity_nativeSecret
   216: 000000000002515c   196 FUNC    GLOBAL DEFAULT    14 Java_com_example_ollvmlab_MainActivity_nativeOpaque
```
`llvm-objdump -d` disassembling `nativeSecret`:
```
0000000000024f10 <Java_com_example_ollvmlab_MainActivity_nativeSecret>:
   24f10: sub  sp, sp, #0x70
   ...
   24f38: bl   0x24fd4 <...nativeSecret+0xc4>       ← decode loop (decode_secret was inlined)
   24f48: bl   0x25138 <_ZN7_JNIEnv12NewStringUTFEPKc+0x34>
   24f54: bl   0x58800 <_ZN7_JNIEnv12NewStringUTFEPKc@plt>
```
**Reading**: the `bl 0x24fd4` at `0x24f38` is the proof that "the source-level `decode_secret` was inlined into local
code inside the JNI function" — `decode_secret` has no standalone symbol. This is consistent with what `SCRIPT.md:223/235`
records. **This is the teaching aid for "you can't see the function name ≠ the function isn't there".**

### 4.1 Evidence for string protection (verified on this machine)
Searching for plaintext in the arm64 SO:
```
ollvm-native     no      ← decode_secret's target string is not in .rodata
JNI_SECRET       no      ← the prefix isn't there either (the UI layer concatenates it)
nativeOpaque     YES     ← the symbol name survives (exported function name)
nativeSecret     YES
decode_secret    no      ← static, and after inlining there is no symbol
```
**Reading**: `ollvm-native` / `JNI_SECRET` **cannot be found** in the SO → string protection (runtime XOR decoding) works;
but `nativeOpaque`/`nativeSecret` still exist as **exported symbol names** in `.dynsym` — **"can't read a plaintext string" ≠
"no information"**, and **"has symbols" ≠ "not protected"**. This is the discriminative-power boundary this lab repeatedly stresses.

### 4.2 arm64 SO section sizes (measured on this machine)
```
.dynsym  size=0x3648 (13896)
.dynstr  size=0x477D (18301)
.rodata  size=0x3EC4 (16068)
.text    size=0x338F8 (211192)
.data    size=0x60 (96)
```
`e_type=3 (ET_DYN)`, 64-bit. `.rodata` (0x3EC4) holds the ciphertext bytes, and `llvm-strings` cannot find the full plaintext
— a **byte-for-byte match** with what `SCRIPT.md:234` records (`.rodata` 0x3ec4 bytes).

---

## 5. `app/src/main/java/.../MainActivity.java` — the Java side

```java
static { System.loadLibrary("ollvmlab"); }                       // :10
private static final byte[] XOR_BLOB = {0x10,0x1b,0x0c,0x1b,0x05,0x02,0x15,0x08,0x05,0x09,0x1f,0x19,0x08,0x1f,0x0e};  // :11
private static final int XOR_KEY = 0x5a;                          // :12
private native String nativeSecret();                            // :13
private native int nativeOpaque(int input);                      // :14
```
**Java-level XOR computed on this machine** (every byte of `XOR_BLOB` `^ 0x5a`):
```
JAVA_XOR = JAVA_XOR_SECRET
```
The four buttons (`:20-23`):
- `plain` → `PLAIN_SECRET=ollvm-lab:static-string` (**plaintext, in the dex string pool at compile time**);
- `xor` → `JAVA_XOR=<decoded>` (decoded at runtime);
- `nativeBtn` → `JNI_SECRET=<nativeSecret()>` → the UI then **concatenates** the prefix a second time, so what is finally shown is
  **`JNI_SECRET=JNI_SECRET=ollvm-native`** (`SCRIPT.md:259` explains that **the duplicated prefix is the sample code's expected
  behavior, not a decoding error**);
- `opaque` → `OPAQUE_RESULT=<nativeOpaque(7)>` = `OPAQUE_RESULT=43`.

`show()` (`:25`) both `setText`s to the TextView **and** `Log.i("OLLVM_LAB", value)` — so you can capture it with
logcat (`tools/logcat.ps1`: `adb logcat -s OLLVM_LAB:D '*:S'`).

**Build-config point** (`app/build.gradle`): `applicationVariants.all {... outputFileName = "app-${variant.name}.apk"}`
— the output names are fixed as `app-debug.apk` / `app-release.apk`, **matching the archive names in `samples/apks`**.

---

## 6. `frida/frida-hook.js` — hooking the two JNI exports

```javascript
// Run: frida -U -f com.example.ollvmlab -l frida/frida-hook.js --no-pause
Java.perform(function () {
  const MainActivity = Java.use('com.example.ollvmlab.MainActivity');
  MainActivity.nativeSecret.implementation = function () { const v=this.nativeSecret(); console.log('[nativeSecret] '+v); return v; };
  MainActivity.nativeOpaque.implementation = function (input) { const r=this.nativeOpaque(input); console.log('[nativeOpaque] input='+input+' result='+r); return r; };
});
```
It replaces the two native method implementations using **frida's Java bridge** (`Java.perform`/`Java.use`). Run it and tap the buttons;
the expected output (`SCRIPT.md:322-323`):
```
[nativeSecret] JNI_SECRET=ollvm-native
[nativeOpaque] input=7 result=43
```
**Key point**: `nativeOpaque(7)`'s output **does not depend on whether you can read the internal CFG** — which makes it a natural probe
for comparing "behavioral consistency before and after obfuscation" (obfuscation should not change the input/output). **See the repo
root README for the frida version constraint**: frida is pinned to **16.5.9** (17.x's Java bridge dropped the `Java` global, which
this hook depends on).

---

## 7. `tools/analyze-apk.ps1` + the OLLVM fork integration notes

`analyze-apk.ps1` (12 lines): `apktool d -f` (hard-coded `D:\...\static\apktool\apktool.bat`) + `jadx -d`
(found on PATH; `Write-Warning` if not found) + `aapt2 dump badging` (hard-coded `$env:ANDROID_HOME\build-tools\35.0.0\aapt2.exe`)
→ output goes to `analysis_output/`.

**OLLVM fork integration (`SCRIPT.md:390-401`, this lab's "advanced" part, not yet wired in)**:
- Before integrating, confirm at least: the LLVM/OLLVM commit, the clang path, NDK/ABI/API compatibility, the optimization level,
  and **the pass arguments the fork actually supports (defer to its own `clang --help`)**.
- Do **not** overwrite the SDK/NDK bundled clang; do **not** commit third-party binaries into the repo.
- It is recommended to do **a single-variable experiment on `nativeOpaque` only** (turn on one variable at a time: one pass, or string
  protection, or R8), otherwise you cannot tell where a change came from.
- Keep a record for every build: the clang command, the fork commit, the pass arguments, ABI/API, optimization level, and
  **the SO hash + APK hash**.
- Comparison dimensions: `.text`/`.rodata`/`.dynsym` sizes, whether the JNI exports are still present, whether function symbols remain,
  whether the full string is still in `.rodata`, and whether the XOR/key/`NewStringUTF` path still exists.

**Behavioral verification** (must still hold after obfuscation): tapping the OLLVM button still prints `43` for `nativeOpaque(7)`;
tapping the JNI button still shows `JNI_SECRET=JNI_SECRET=ollvm-native`.

---

## 8. Toolchain — `build/bootstrap.ps1` + `build/build.ps1` (PowerShell, not bash)

`bootstrap.ps1`:
- **Pins JDK 21** (`$javaHome = 'D:\tools\Dev\Runtime\jdk21'`, `throw`s if it does not exist), sets `$env:JAVA_HOME`
  and prepends its `bin` to `$env:Path`.
- Project-local Gradle 8.13: if `tools\gradle-8.13\bin\gradle.bat` is missing, it downloads and unpacks
  `https://services.gradle.org/distributions/gradle-8.13-bin.zip` (`-SkipGradle` skips this).
- Prints `JAVA_HOME` / `SDK` (`$env:ANDROID_HOME`) / `NDK`.

`build.ps1`: `param([ValidateSet('debug','release')]$Variant, [switch]$Install)`;
it runs `bootstrap.ps1` first, and the **gradle project root is in `app\`** (`Push-Location app`), then runs
`gradlew.bat assembleDebug|assembleRelease`; with `-Install` it does `adb install -r` + `am start`.

**How it differs from the other labs**: this one is **PowerShell** (the others are bash + a four-tier `locate.sh` probe).
`build/build.ps1` has **no `locate.sh`-style auto-detection** — the JDK/Gradle paths are hard-coded.
`reset_lab.py` is the only Python tool; everything else is `.ps1`.

---

## 9. `tools/reset_lab.py` — isomorphic with the other labs (but the manifest file is named `manifest.json`)

- **Scope**: all of `samples/` recursively (this lab only has `apks/`), mirrored into pristine as `pristine/<rel>`,
  with the manifest at `pristine/manifest.json` (**lowercase**, unlike `ajiami`'s `MANIFEST.json`).
- Manifest format `{"files": {...}, "config": {"clean_dir": "analysis_output"}}` (the same as
  `360jiagu`/`upx_practice`; `ajiami` uses a flat dict).
- `backup` snapshots `samples/` into `pristine/` and writes sha256; `status` compares file by file;
  `restore` restores from `pristine/` and empties `analysis_output/`.
- **Why not use git**: APKs are binary and can get mangled during exercises, so a standalone sha256 baseline is lighter (same as `ajiami`).

`SCRIPT.md:456` on this machine records: `backup→status (two files consistent)→restore (debug APK hash still 0693...)`
— the whole chain has been verified by an actual run, and it matches the `06935b0b...` I see on this machine.

---

## 10. Relationship to `unpacker/` (no interface)

**`unpacker/labs.py` bridges only the three labs `360jiagu`/`upx_practice`/`ajiami`** — `ollvm` is **not among them**
(the `LABS` dict at `labs.py:38-42` has only three entries). `unpacker/regression.py`'s `EXPECTED` table **does not include**
the ollvm samples either. The reason: `ollvm` is a **code-obfuscation** topic with no packer-style detect/unpack tooling to bridge.

**Conclusion**: changing `ollvm` does not affect `unpacker/regression.py`; and vice versa.

---

## 11. File-format-layer details

- **JNI export names**: `Java_com_example_ollvmlab_MainActivity_nativeSecret` is `FUNC GLOBAL` in `.dynsym`
  (measured on this machine: addr `0x24f10`, size 196); `nativeOpaque` @ `0x2515c`, size 196.
- **arm64 SO key section sizes**: see §4.2 (`.text` 211192 / `.rodata` 16068 / `.dynsym` 13896).
- **XOR ciphertext**: Java `XOR_BLOB` is 15 bytes, native `blob[]` is 24 bytes (NUL terminator included); both keys are `0x5a`.
- **APK entries**: see §2 (10 entries; 4 ABI SOs + classes.dex 1924 B).
- **gradle project root**: `ollvm/app/` (both `settings.gradle` + `build.gradle` are inside `app/`,
  `rootProject.name='ollvm-lab'`).

---

## 12. Pitfalls (root causes)

1. **Treating the existing APK as an "OLLVM-obfuscated sample" is wrong**. `app/build.gradle` does not enable `-fla/-sub/-bcf`;
   the current sample is just **ordinary NDK compilation + source-level XOR**. This is the boundary the lab itself admits at `SCRIPT.md:7`.
2. **`decode_secret` "disappearing" from the disassembly is inlining, not deletion**. It is `static` and gets inlined into
   `nativeSecret` (on this machine the disassembly has `bl 0x24fd4` at `0x24f38`, which is the decode loop).
   **Not seeing the function name ≠ the function does not exist.**
3. **Not finding `ollvm-native` ≠ no information**. The plaintext is protected by XOR (`.rodata` holds only ciphertext), but the **exported
   symbol names `nativeSecret`/`nativeOpaque` are still there**. "Can't read the plaintext" and "has symbols" are two independent
   dimensions; do not conflate them.
4. **The duplicated prefix in `JNI_SECRET=JNI_SECRET=ollvm-native` is expected behavior**. native returns
   `JNI_SECRET=ollvm-native`, and the UI concatenates `JNI_SECRET=` again. **It is not a decoding bug.**
5. **After a rebuild the APK hash changes but the SO hash does not**. The zip packaging timestamp is included; the SO has no timestamp.
   After a rebuild you must run `reset_lab.py backup` to refresh the baseline; **the documented hashes take the archived copies in
   `samples/apks/` as authoritative**.
6. **This lab's .ps1 files contain hard-coded absolute paths** (JDK/NDK/apktool/aapt2), which conflicts with the "zero absolute paths"
   iron rule and is a historical leftover. Moving to another machine means editing these constants.
7. **`pristine/manifest.json` is lowercase, while `ajiami` uses `MANIFEST.json`**. Do not apply one script's assumptions to the other —
   `ollvm`'s manifest has the `{"files":...,"config":...}` structure, `ajiami`'s is a flat dict.
8. **frida must be 16.5.9**. `frida-hook.js` uses the Java bridge (`Java.perform`), and frida 17.x dropped the
   `Java` global. See the repo root README for the version constraint (the "Pinned versions" table).
9. **There is no locate.sh-style auto-detection in `build.ps1`**. The JDK/Gradle paths are hard-coded — **completely different**
   from the bash `locate.sh` four-tier probe in the other three labs. Don't look for `source` in PowerShell.

---

## 13. Quick reference (all measured on this machine)

```powershell
# --- build (PowerShell) ---
.\build\bootstrap.ps1                      # pin JDK21 + provision Gradle 8.13
.\build\build.ps1 -Variant debug           # → app\build\outputs\apk\debug\app-debug.apk
.\build\build.ps1 -Variant release
.\build\build.ps1 -Variant debug -Install  # install to device and launch

# --- analysis ---
.\tools\analyze-apk.ps1                    # apktool + jadx + aapt2 badging → analysis_output\
.\tools\inspect-native.ps1                 # llvm-readelf/objdump/strings on the SO
.\tools\logcat.ps1                         # adb logcat -s OLLVM_LAB:D '*:S'

# --- reset (Python) ---
python tools/reset_lab.py status
python tools/reset_lab.py backup
python tools/reset_lab.py restore

# --- decryption cross-check (computed on this machine, not a script) ---
#   Java  XOR_BLOB ^ 0x5a  -> JAVA_XOR_SECRET
#   native blob[] ^ 0x5a   -> JNI_SECRET=ollvm-native
#   nativeOpaque(7)        -> 43
```

**Expected behavior** (tapping the four buttons):
`PLAIN_SECRET=ollvm-lab:static-string` / `JAVA_XOR=JAVA_XOR_SECRET` /
`JNI_SECRET=JNI_SECRET=ollvm-native` / `OPAQUE_RESULT=43`.

---

## 14. Reading order for a new agent

1. Read `app/build.gradle` + `SCRIPT.md:7` — first establish the premise that "this is an ordinary NDK baseline, not an OLLVM sample".
2. Read `app/src/main/cpp/native-lib.cpp` (only 20 lines) and `MainActivity.java` — all four forms are right there.
3. Run the three decryption cross-checks from §13 by hand (Java XOR / native XOR / nativeOpaque(7)) and verify them against §3/§5.
4. Extract the arm64 SO, and use `llvm-readelf -Ws` + `llvm-objdump -d` to reproduce §4 (symbols present, decode inlined,
   plaintext string absent).
5. Read `tools/inspect-native.ps1` / `analyze-apk.ps1` to understand the PowerShell analysis techniques, and **note the
   hard-coded paths in them**.
6. Finally read `SCRIPT.md`/`CLI.md`/`GUI.md` — they retell the same facts for humans; **the ground truth is in the code and the SO**.
