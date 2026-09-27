# CLI.md：命令行路线——用 PowerShell 与 NDK llvm-* 工具逐字节复现

## 概述

一句话定位：不跑脚本，用 `Get-FileHash`、`jar`/`apktool`、`llvm-readelf`/`llvm-objdump`/`llvm-strings`、`adb`/`logcat`、`Select-String` 逐条命令复现 SCRIPT.md 的每一步，把「明文在哪、密文在哪、key 是什么、解码循环长什么样」落到具体字节和地址。

为什么自造样本（建模说明）：同一个 APK 故意装下四种情况——Java 明文、Java 层 XOR、JNI 层 XOR、native 控制流基线 `nativeOpaque`。命令行路线的价值是**可量化**：哈希、段大小、符号地址、密文字节都能抄进判据；GUI 工具（见 GUI.md）负责「看懂结构与调用链」，不替代这里的量化判定。

样本事实（默认分析已有 APK，不重新构建；哈希与 SCRIPT.md 一致）：

| 项目 | 值 |
| --- | --- |
| 包名 | `com.example.ollvmlab` |
| 启动 Activity | `com.example.ollvmlab.MainActivity` |
| ABI | `arm64-v8a`、`armeabi-v7a`、`x86`、`x86_64` |
| Java 明文 | `PLAIN_SECRET=ollvm-lab:static-string` |
| Java XOR 结果 | `JAVA_XOR=JAVA_XOR_SECRET`（key `0x5a`） |
| JNI XOR 结果 | `JNI_SECRET=JNI_SECRET=ollvm-native`（key `0x5a`） |
| `nativeOpaque(7)` 结果 | `43` |
| debug APK SHA-256 | `06935B0B8F0EEF249E2D202E2059141B389F7F5760788024EF1175FC1DEF045E` |
| release APK SHA-256 | `B02AEF06944B280B84D4E32EDAF5C19BD6EDC353D8FA3C60C89FF66D93E794CD` |
| arm64 debug SO SHA-256 | `555B4EE785E5040FA1F7CC503FAFDA16B88411C79C242E769BADDCA22BA318C2` |

JNI 绑定为命名导出 `Java_com_example_ollvmlab_MainActivity_nativeSecret` / `...nativeOpaque`。已有 APK 的 badging `compileSdkVersion=36`，当前 Gradle 写 `compileSdk=35`——以实际 APK 为准并记录差异。

### 三分钟跑一遍（最小闭环）

```powershell
cd D:\code\android\reverse\ollvm
$apk = (Resolve-Path .\samples\apks\app-debug.apk).Path
Get-FileHash $apk -Algorithm SHA256          # ① 固定样本哈希
#   => 06935B0B8F0EEF249E2D202E2059141B389F7F5760788024EF1175FC1DEF045E

jar tf $apk | Select-String '^classes.*\.dex|^lib/.+\.so'
#   ② 不解包先盘点：多 dex + 四个 ABI 的 SO
#   => classes.dex / classes2.dex / lib/<abi>/libollvmlab.so × 4

$llvm = 'D:\tools\Security\Reverse\Android\dev\android-ndk-r27d\toolchains\llvm\prebuilt\windows-x86_64\bin'
$so = '.\analysis\out\apktool\lib\arm64-v8a\libollvmlab.so'   # 先跑过 analyze-apk.ps1 或 apktool d
& "$llvm\llvm-readelf.exe" -Ws $so | Select-String 'Java_com'
#   ③ 确认 JNI 命名导出 => 两条 Java_..._nativeSecret / nativeOpaque

& "$llvm\llvm-strings.exe" $so | Select-String 'JNI_SECRET|ollvm-native'
#   ④ 证明 SO 中没有完整明文 => 零命中，字符串保护生效
```

### 工程结构（命令行路线会用到的路径）

```text
samples\apks\app-debug.apk        分析主样本
samples\apks\app-release-unsigned.apk  release 对照
analysis\out\apktool\...                          apktool 解包产物（smali/SO/Manifest）
analysis\out\apktool\lib\<abi>\libollvmlab.so     按 ABI 的 native 库
analysis\out\aapt2-badging.txt                    aapt2 dump badging 输出
app\src\main\cpp\native-lib.cpp                   JNI XOR 与 native 控制流源码
app\src\main\java\...\MainActivity.java           Java 入口与三个字符串样例
```

## 环境与工具

命令行路线的全部外部工具（均为 PowerShell 可直接调用）：

| 工具 | 用途 | 本机位置/判定方式 |
| --- | --- | --- |
| `Get-FileHash` | PowerShell 内置，SHA-256 固定样本 | 内置 cmdlet，无需安装 |
| `jar` | JDK 自带，列 APK 内部条目 | 本机 `D:\tools\Dev\Runtime\java\bin\jar.exe`（无 `7z` 时的替代） |
| `7z` | 列 APK 内部条目（若装了 7-Zip） | 本机未装/不在 PATH；有则 `7z l $apk` 同效 |
| `apktool` | 解包出 Manifest/smali/SO | `D:\tools\Security\Reverse\Android\static\apktool\apktool.bat`（`analyze-apk.ps1` 内写死） |
| `aapt2` | `dump badging` 看包名/ABI/debug 标记 | `%ANDROID_HOME%\build-tools\35.0.0\aapt2.exe` |
| `llvm-readelf` / `llvm-objdump` / `llvm-strings` | ELF 段/符号/反汇编/字符串 | NDK r27d：`D:\tools\Security\Reverse\Android\dev\android-ndk-r27d\toolchains\llvm\prebuilt\windows-x86_64\bin` |
| `adb` | 设备安装、`am start`、logcat | 已在 PATH |
| `Select-String` | PowerShell 内置 grep，搜 jadx/smali 输出 | 内置 cmdlet（本机无 `rg`，文档一律用 `Select-String`） |
| `frida` | Java native 返回边界 hook | 需与设备端 Frida Server 版本匹配 |

依赖检查（含 Java/jadx/apktool/adb 状态表）：

```powershell
& "$env:USERPROFILE\.agents\skills\android-reverse-engineering\scripts\check-deps.ps1"
```

NDK/SDK/JDK 路径换机时参照 `local.properties.example`；脚本内写死的 apktool 与 NDK llvm 路径变更须同步修改 `scripts\analyze-apk.ps1` 与 `scripts\inspect-native.ps1`。

## 知识点

命令行判定的核心是「**搜不到明文 ≠ 搜不到证据**」。字符串保护把明文换成三样可静态定位的东西——密文字节、key、解码循环：

```text
DEX 层（Java XOR）：byte[] 数组 + const/16 0x5a + xor-int/lit8 + int-to-char + StringBuilder.append(C)
SO 层（JNI XOR）： .rodata 密文 + mov w8, #0x5a + ldrb/eor + std::string::push_back + NewStringUTF
```

OLLVM 的证据则完全在另一侧——native `.text` 的 CFG 形态（dispatcher/state、等价长指令序列、诱饵块），且必须与同 ABI/同优化级别的未混淆基线做差分才能归因；`strings` 结果对判断 OLLVM 没有直接意义。三个概念的完整对照表见 SCRIPT.md「知识点」章，此处只保留命令行可验证的锚点：

| 观察 | 命令 | 结果解读 |
| --- | --- | --- |
| DEX 有无完整明文 | 搜 smali `const-string` | 有 → 普通明文；无 → 找 byte[]+循环 |
| SO 有无完整明文 | `llvm-strings` 搜目标文本 | 零命中 → 字符串保护，但不证明 OLLVM |
| JNI 绑定方式 | `llvm-readelf -Ws` 搜 `Java_` | 有命名导出 → 静态绑定；无 → 疑似 `RegisterNatives`，去搜 `JNI_OnLoad` |
| 解码 key | 反汇编搜 `0x5a` 立即数 | 命中 + 附近 `eor`/`push_back` → XOR 循环 |

## 静态分析（逐条命令）

### ① 固定样本哈希

```powershell
cd D:\code\android\reverse\ollvm
$apk = (Resolve-Path .\samples\apks\app-debug.apk).Path   # Resolve-Path 转绝对路径
Get-FileHash $apk -Algorithm SHA256                                      # 固定 debug 样本身份
#   => 06935B0B8F0EEF249E2D202E2059141B389F7F5760788024EF1175FC1DEF045E

$release = (Resolve-Path .\samples\apks\app-release-unsigned.apk).Path
Get-FileHash $release -Algorithm SHA256                                  # release 对照
#   => B02AEF06944B280B84D4E32EDAF5C19BD6EDC353D8FA3C60C89FF66D93E794CD
```

这几条命令分别干什么：`Resolve-Path` 把相对路径解析成绝对路径存进变量，后续命令复用；`Get-FileHash -Algorithm SHA256` 算哈希，分析前后各算一次确认对象没变。重新构建后哈希必变，应重新记录。

### ② 不解包先盘点 APK 内部

```powershell
jar tf $apk | Select-String '^classes.*\.dex|^lib/.+\.so'
#   => classes.dex
#   => classes2.dex
#   => lib/arm64-v8a/libollvmlab.so
#   => lib/armeabi-v7a/libollvmlab.so
#   => lib/x86/libollvmlab.so
#   => lib/x86_64/libollvmlab.so
```

这条命令做什么：`jar tf` 把 APK 当 zip 列出全部条目（JDK 自带，免 7z/解包）；`Select-String` 按正则只留 dex 和 native 库。判读：**两个 dex**（正常 App 多 dex 很常见，别把 classes2 当异常）；四个 ABI 各一份同名 SO——每份都是独立二进制，地址/CFG/哈希必须分 ABI 记录，后续统一用 arm64。有 `7z` 时等价写法：`7z l $apk | Select-String 'classes.*\.dex|lib/.+\.so'`；若是 XAPK/APKS bundle 则先定位 `base.apk` 再如法炮制。

### ③ 解包（apktool）并确认 Manifest 与 ABI

```powershell
$apktool = 'D:\tools\Security\Reverse\Android\static\apktool\apktool.bat'
& $apktool d -f $apk -o analysis\out\apktool          # -f 覆盖旧输出，-o 指定输出目录
#   => I: Using Apktool ... on app-debug.apk ...  （解包完成）

Select-String -Path .\analysis\out\apktool\AndroidManifest.xml -Pattern 'package=|debuggable|uses-permission|<activity'
#   => <manifest ... package="com.example.ollvmlab" ...>
#   => <application android:debuggable="true" android:extractNativeLibs="false" ...>
#   => <activity android:exported="true" android:name="com.example.ollvmlab.MainActivity">
```

这几条命令分别干什么：apktool 解出 Manifest/资源/smali/按 ABI 的 SO（等价于脚本路线的 `analyze-apk.ps1`，但手动可控）；`Select-String` 提取 Manifest 关键行。判读：包名 `com.example.ollvmlab`、入口 `MainActivity`、`debuggable="true"`（release unsigned 无此标记）、**没有 `uses-permission` 命中** → 样例不发起网络请求；Activity 在 `smali_classes2`（次级 dex）而不是 `smali`，搜 smali 时两条目录都要看。

aapt2 badging（脚本已生成则直接读）：

```powershell
Select-String -Path .\analysis\out\aapt2-badging.txt -Pattern 'package:|sdkVersion|native-code|application-label'
#   => package: name='com.example.ollvmlab' versionCode='1' ... compileSdkVersion='36'
#   => minSdkVersion:'26'
#   => targetSdkVersion:'35'
#   => application-label:'OLLVM Lab'
#   => native-code: 'arm64-v8a' 'armeabi-v7a' 'x86' 'x86_64'
```

### ④ 在 smali/jadx 输出中定位三类 Java 路径

先确认 jadx 输出存在（没有则用 GUI.md 章节的 jadx 命令生成），然后搜关键锚点：

```powershell
Select-String -Path .\analysis\out\jadx\sources\com\example\ollvmlab\MainActivity.java `
  -Pattern 'PLAIN_SECRET|XOR_BLOB|XOR_KEY|nativeSecret|nativeOpaque|loadLibrary|JAVA_XOR'
#   => 12: private static final byte[] XOR_BLOB;
#   => 13: private static final int XOR_KEY = 90;
#   => 15: private native int nativeOpaque(int i);
#   => 17: private native String nativeSecret();
#   => 20: System.loadLibrary("ollvmlab");
#   => 21: XOR_BLOB = new byte[]{16, 27, 12, 27, 5, 2, 21, 8, 5, 9, 31, 25, 8, 31, 14};
#   => 61: show(output, "PLAIN_SECRET=ollvm-lab:static-string");
#   => 67: for (byte x : XOR_BLOB) {
#   => 70: show(output, "JAVA_XOR=" + ((Object) b));
#   => 75: show(output, "JNI_SECRET=" + nativeSecret());
#   => 80: show(output, "OPAQUE_RESULT=" + nativeOpaque(7));
```

一条命令拿到全部线索。smali 侧（DEX 层原始字节码）再印证：

```powershell
$smali = '.\analysis\out\apktool\smali_classes2\com\example\ollvmlab\MainActivity.smali'
Select-String -Path $smali -Pattern 'XOR_BLOB|XOR_KEY|nativeSecret|const-string|fill-array-data| xor-int'
#   => 7: .field private static final XOR_BLOB:[B
#   => 9: .field private static final XOR_KEY:I = 0x5a
#   => 26: fill-array-data v0, :array_0
#   => 63: .method private native nativeOpaque(I)I
#   => 66: .method private native nativeSecret()Ljava/lang/String;
#   => 92: const-string v0, "PLAIN_SECRET=ollvm-lab:static-string"
#   => 110: sget-object v1, Lcom/example/ollvmlab/MainActivity;->XOR_BLOB:[B
#   => 138: const-string v2, "JAVA_XOR="
#   => xor-int/lit8 v5, v4, 0x5a
```

逐行判读：

- `const-string "PLAIN_SECRET=..."` → Java 明文以 DEX 字符串常量保存，静态定位成本最低；
- `XOR_BLOB:[B` + `XOR_KEY:I = 0x5a` + `fill-array-data` + `xor-int/lit8 v5, v4, 0x5a` → Java XOR 的完整证据链：密文数组、key、按字节循环（配合 `int-to-char` + `StringBuilder->append(C)`，见下方解码循环行）；
- `native nativeSecret()Ljava/lang/String;` 且方法体只有声明 → 实现不在 DEX，在 `libollvmlab.so`，必须转 ELF 层。

smali 解码循环的另外几行（实跑）：

```text
112: array-length v2, v1
124: int-to-char v5, v5
126: invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;
```

### ⑤ 手工还原 Java XOR

key 是 `0x5a`（十进制 90）。第一个字节 `0x10 ^ 0x5a = 0x4a`，即 `J`；对 `XOR_BLOB` 全部 15 字节做同样运算：

```text
10 14 13 05 09 1f 19 08 1f 0e  →  J A V A _ X O R _ S E
```

完整结果：

```text
JAVA_XOR_SECRET
```

key、数组和解码循环全在 DEX 中——沿数据流即可还原，这就是「XOR 不是加密」的直观演示。

### ⑥ ELF 层：`llvm-readelf` 看段与符号

```powershell
$llvm = 'D:\tools\Security\Reverse\Android\dev\android-ndk-r27d\toolchains\llvm\prebuilt\windows-x86_64\bin'
$so = (Resolve-Path .\analysis\out\apktool\lib\arm64-v8a\libollvmlab.so).Path

& "$llvm\llvm-readelf.exe" -S $so | Select-String '\.text|\.rodata|\.dynsym|\.dynstr'
#   =>  [ 3] .dynsym   DYNSYM   00000000000002f8 0002f8 003648 18  A  7  1  8
#   =>  [ 7] .dynstr   STRTAB   0000000000004c10 004c10 00477d 00  A  0   0  1
#   =>  [11] .rodata   PROGBITS 00000000000147a0 0147a0 003ec4 00 AMS  0   0 16
#   =>  [14] .text     PROGBITS 0000000000024eb0 024eb0 0338f8 00  AX  0   0 16

& "$llvm\llvm-readelf.exe" -Ws $so | Select-String 'Java_com'
#   => 79: 0000000000024f10  196 FUNC GLOBAL DEFAULT 14 Java_com_example_ollvmlab_MainActivity_nativeSecret
#   => 216: 000000000002515c  196 FUNC GLOBAL DEFAULT 14 Java_com_example_ollvmlab_MainActivity_nativeOpaque
```

这几条命令分别干什么：`-S` 列节区表（`.rodata` 起始 `0x147a0` 大小 `0x3ec4`，`.text` 起始 `0x24eb0`——后面 objdump 的地址都落在这个区间）；`-Ws` 列宽符号表并过滤 JNI 导出。判读：两个 `Java_` 命名导出存在 → 静态 JNI 绑定，不需要找 `RegisterNatives`；`nativeSecret` 入口地址 `0x24f10`、`nativeOpaque` 入口 `0x251c`（对照 SCRIPT.md 反汇编）。**不要**把 `decode_secret` 是否出现在符号表当判据——它是 `static` 函数，可能被内联或没有独立符号。

### ⑦ `llvm-strings` 证明 SO 无完整明文

```powershell
& "$llvm\llvm-strings.exe" $so | Select-String 'JNI_SECRET|ollvm-native'
#   => （零命中）
```

判读：完整 `JNI_SECRET=ollvm-native` 不以普通字符串存在于 SO——这是字符串保护的效果，**不是** OLLVM 的证据。对照实验：搜 `Java_com` 或 `libollvmlab` 都能命中，说明不是工具失灵，而是明文真的不在。

### ⑧ `llvm-objdump` 定位密文与解码循环

先看 JNI 入口的调用链：

```powershell
& "$llvm\llvm-objdump.exe" -d --start-address=0x24f10 --stop-address=0x24f60 --demangle $so
#   （节选）
#   24f30: d10083a8   sub  x8, x29, #0x20      ; x8 = std::string 临时对象地址（隐藏结果指针）
#   24f38: 94000027   bl   0x24fd4              ; 进入解码函数（被内联的 decode_secret）
#   24f48: 9400007c   bl   0x25138             ; 取字符串数据指针（c_str 包装）
#   24f54: 9400ce2b   bl   0x58800 <_ZN7_JNIEnv12NewStringUTFEPKc@plt>  ; JNI 明文输出边界
```

再进解码循环（`0x25030`–`0x25080`，实跑输出）：

```text
25030: f94017e9   ldr  x9, [sp, #0x28]        ; 循环索引 i
25034: d10083a8   sub  x8, x29, #0x20         ; 密文缓冲区基址
25038: 38696908   ldrb w8, [x8, x9]           ; 读第 i 个密文字节
2503c: 340002c8   cbz  w8, 0x25094            ; 字节为 NUL → 退出循环
25050: 38696908   ldrb w8, [x8, x9]           ; （循环体）重读字节
25054: 52800b49   mov  w9, #0x5a              ; XOR key = 0x5a
25058: 4a090101   eor  w1, w8, w9             ; 明文字节 = 密文 ^ 0x5a
2505c: 9400cdf5   bl   0x58830 <std::string::push_back(char)@plt>  ; 追加到字符串
2506c: 91000508   add  x8, x8, #0x1           ; i++
25074: 17ffffef   b    0x25030                ; 回循环头
```

逐行判读：`mov w9, #0x5a` + `eor` + `push_back` + `cbz` 退出条件（NUL 结尾）→ 一个教科书式的逐字节 XOR 解码循环，且结构上是**普通循环**，与 OLLVM 的 dispatcher/状态机完全不同。

密文本身在 `.rodata` 的 `0x14db9`（`adr` 指令引用的 literal pool）：

```powershell
& "$llvm\llvm-objdump.exe" -s --start-address=0x14db9 --stop-address=0x14dd0 -j .rodata $so
#   （节选，字节与 ASCII 对照）
#   14db0 00783131 00643330 00101413 05091f19  .x11.d30........
#   14dc0 081f0e67 3536362c 3777343b 2e332c3f  ...g566,7w4;.3,?
#   14dd0 00517561 6c4e6f6e 65...               .QualNone...
```

`0x14db9` 开始的 24 字节密文（最后一个字节 `0x00` 为 NUL 终止）：

```text
10 14 13 05 09 1f 19 08 1f 0e 67 35 36 36 2c 37 77 34 3b 2e 33 2c 3f 00
```

用 `0x5a` 逐字节 XOR：

```text
JNI_SECRET=ollvm-native
```

判读：`-s` dump 段内容、`-j .rodata` 限定节、`--start/stop-address` 限定窗口——这三个参数让你不写脚本也能把密文精确到字节。UI 会在 native 返回值前再拼 `JNI_SECRET=`，所以按钮最终显示 `JNI_SECRET=JNI_SECRET=ollvm-native`（预期行为，不是解码错误）。

### ⑨ `nativeOpaque` 基线（命令行视角）

```text
x = 7 * 3 + 1 = 22 → ((22 ^ 0x55) + 7) % 2 == 0 → x += 0x10 得 38
i=0: (38 ^ 3) + 1 = 38 → i=1: (38 ^ 16) + 1 = 55 → i=2: (55 ^ 29) + 1 = 43
```

`OPAQUE_RESULT=43`。`llvm-objdump -d` 中该函数（入口 `0x251c`）就是 `mul`/`eor`/`subs`/`b.ge` 组成的乘法 + 一个条件分支 + 三次循环——普通控制流基线，后续每个 OLLVM 变体都必须保持输出 43。

### ⑩ grep 定位 XOR_BLOB 的完整命令合集（速查）

```powershell
# jadx 输出里搜三样东西（明文/密文声明/native 声明）
Select-String -Path .\analysis\out\jadx\sources\com\example\ollvmlab\*.java `
  -Pattern 'PLAIN_SECRET|XOR_BLOB|XOR_KEY|nativeSecret|nativeOpaque|loadLibrary'
# smali 里搜解码循环
Select-String -Path .\analysis\out\apktool\smali_classes2\com\example\ollvmlab\MainActivity.smali `
  -Pattern 'XOR_BLOB|XOR_KEY|fill-array-data| xor-int|const-string'
# SO 里搜 JNI 导出与解码指令
& "$llvm\llvm-readelf.exe" -Ws $so | Select-String 'Java_com|decode_secret'
& "$llvm\llvm-objdump.exe" -d $so | Select-String '0x5a|push_back|NewStringUTF'
```

第三条会命中 `mov w9, #0x5a`、`bl ...push_backEc@plt`、`bl ...NewStringUTF...@plt` 三类行——密文、key、sink 一次搜全。找不到 `Java_` 导出时不要断言没有 JNI：改为搜 `JNI_OnLoad` 与 `RegisterNatives`（动态注册路线，见 GUI.md「JNI 绑定的两种查找方式」）。

## 动态分析（逐条命令）

### ① 设备检查与安装

```powershell
adb devices                              # 确认设备已连接且状态为 device（不是 unauthorized）
#   => List of devices attached
#   => <serial>  device

adb install -r $apk                      # -r 覆盖安装并保留应用数据
adb shell am start -n com.example.ollvmlab/.MainActivity
#   => Starting: Intent { cmp=com.example.ollvmlab/.MainActivity }
```

签名不匹配时先在自己授权的测试设备上卸载旧包再装；不要把 debug 样本装到生产设备。

### ② logcat 只看 OLLVM_LAB

```powershell
adb logcat -c                            # 清空缓冲，避免旧日志干扰
adb logcat -s OLLVM_LAB:D '*:S'          # -s = 只保留指定 tag；'*:S' = 其余全部静默
```

依次点击四个按钮，预期输出：

```text
PLAIN_SECRET=ollvm-lab:static-string
JAVA_XOR=JAVA_XOR_SECRET
JNI_SECRET=JNI_SECRET=ollvm-native
OPAQUE_RESULT=43
```

判读：四条日志 = 三种字符串路径 + 一个控制流基线的运行时答案；`JNI_SECRET=JNI_SECRET=...` 的重复前缀来自按钮代码拼接，属预期。`scripts\logcat.ps1` 就是这两条命令的封装。

### ③ Frida 在 Java native 返回边界取值

```powershell
frida -U -f com.example.ollvmlab -l .\scripts\frida-hook.js --no-pause
```

`-U` 走 USB 设备、`-f` spawn 启动、`-l` 加载 hook 脚本。点击 JNI 和 OLLVM 按钮：

```text
[nativeSecret] JNI_SECRET=ollvm-native
[nativeOpaque] input=7 result=43
```

意义：`nativeSecret()` 返回值已是完整 `String` → 明文至少在 JNI 返回点可见；Frida 观察到的是**结果**，不等于还原了 native 内部每条指令。也可以在 `show(TextView, String)` 处 hook，同时捕获三个字符串按钮。

## 对照验证（OLLVM 变体差分的命令行部分）

前提与实验矩阵见 SCRIPT.md「对照验证」章；本节只列命令行侧的差分动作。

```powershell
# 每个变体固定身份
Get-FileHash $variant_so -Algorithm SHA256

# 段大小差分：.text / .rodata / .dynsym 三行数值抄进对照表
& "$llvm\llvm-readelf.exe" -S $variant_so | Select-String '\.text|\.rodata|\.dynsym'

# 符号差分：JNI 导出还在吗？源码函数名还留吗？
& "$llvm\llvm-readelf.exe" -Ws $variant_so | Select-String 'Java_com|decode_secret|nativeOpaque'

# 明文/密文差分：完整字符串回来了吗？密文和 XOR 循环还在吗？
& "$llvm\llvm-strings.exe" $variant_so | Select-String 'JNI_SECRET|ollvm-native'
& "$llvm\llvm-objdump.exe" -d --demangle $variant_so |
  Select-String 'Java_...nativeSecret|0x5a|push_back|NewStringUTF'
```

判读纪律（防把正常现象当 OLLVM）：

- `.text` 变大 ≠ `fla`/`bcf`；普通 `-O2/-O3`、C++ 异常、栈保护、标准库都会变大；
- `strings` 看不到明文 ≠ OLLVM；可能只是 XOR/分片；
- OLLVM 只影响 LLVM/native 路径，Java `const-string` 不会自动消失；
- 行为验证兜底：变体必须仍输出 `nativeOpaque(7)=43` 与 `JNI_SECRET=JNI_SECRET=ollvm-native`，输入输出不变是「同输入同输出」差分实验的前提。

## 踩坑 / 速查

| 现象 | 根因与处理 |
| --- | --- |
| `Select-String` 搜 smali 搜不到 | Activity 在 `smali_classes2` 不在 `smali`；多 dex 目录都要搜 |
| 本机没有 `rg` / `7z` | 用 `Select-String` / `jar tf` 等价替代；文档命令已按本机实况写 |
| `llvm-objdump -s --start-address` 输出超长 | 必须 `-j .rodata` 限定节，否则 dump 全部节 |
| `decode_secret` 在 `-Ws` 里找不到 | `static` 函数被内联是常态；从 `Java_..._nativeSecret` 入口跟 `bl` 链 |
| 找不到 SO | 先跑 apktool 解包；`Get-ChildItem .\analysis\out\apktool\lib -Recurse -Filter libollvmlab.so` |
| 不同 ABI 地址对不上 | 每个 SO 是独立二进制，地址/CFG/哈希分 ABI 记录，不跨 ABI 套用 |
| release 和 debug 差异大 | 记录变体/哈希/ABI；当前 release 未启用 R8/ProGuard，也不是 OLLVM |
| `adb install` 签名失败 | 测试设备上卸载旧包再装；`-r` 只解决覆盖不解决签名不一致 |
| `frida` 找不到进程 | 查 `adb devices`、包名、Frida Server 与主机版本匹配、`-f` 启动参数 |

每次实验至少记录（模板）：

```text
设备/API/ABI：
APK SHA-256：
按钮或函数：
hook/断点位置：
输入：
明文或输出首次出现的位置：
UI/日志/网络等 sink：
是否启用 OLLVM pass：
静态复杂度与动态成本变化：
```

安全结论：XOR、分片、JNI 和 OLLVM 都是逆向阻碍措施；只要客户端必须获得明文，命令行动态工具（logcat/Frida/LLDB）就能拿到它。长期密钥应移出 APK，改用服务端校验、短期令牌、轮换和最小权限。
