# SCRIPT.md：脚本路线——用本仓 tools/ + build/ 脚本一次跑通分析

## 概述

一句话定位：`tools/`（分析）+ `build/`（构建）+ `frida/`（hook）下几个现成脚本把「APK 解包 → ELF 检查 → 构建 → logcat → Frida 取证」整条链路自动化；本路线先用脚本拿到正确答案，CLI.md 和 GUI.md 再拆解每一步为什么。

为什么自造样本（建模说明）：同一个 APK 故意装下四种情况——Java 明文、Java 层 XOR、JNI 层 XOR、native 控制流基线 `nativeOpaque`——「代码放在哪里」和「明文何时出现」可以并排比较。当前 APK 是普通 NDK 编译 + 源码级 XOR 运行时解码的基线；`ollvm/toolchains/` 只是外部 OLLVM fork 的接入说明，`app/build.gradle` 没有启用 `-mllvm -fla/-sub/-bcf`，所以现有 APK 不能被描述为「已经用 OLLVM 混淆完成」。

样本事实（默认分析已有 APK，不重新构建）：

| 项目 | 值 |
| --- | --- |
| 包名 | `com.example.ollvmlab` |
| 启动 Activity | `com.example.ollvmlab.MainActivity` |
| ABI | `arm64-v8a`、`armeabi-v7a`、`x86`、`x86_64`（每个 ABI 一份 `libollvmlab.so`） |
| Java 明文 | `PLAIN_SECRET=ollvm-lab:static-string` |
| Java XOR 结果 | `JAVA_XOR=JAVA_XOR_SECRET` |
| JNI XOR 结果 | `JNI_SECRET=JNI_SECRET=ollvm-native` |
| `nativeOpaque(7)` 结果 | `43`，用于控制流对照 |
| debug APK SHA-256 | `06935B0B8F0EEF249E2D202E2059141B389F7F5760788024EF1175FC1DEF045E` |
| release APK SHA-256 | `B02AEF06944B280B84D4E32EDAF5C19BD6EDC353D8FA3C60C89FF66D93E794CD` |
| arm64 debug SO SHA-256 | `555B4EE785E5040FA1F7CC503FAFDA16B88411C79C242E769BADDCA22BA318C2`（383632 字节） |

JNI 绑定使用命名导出 `Java_com_example_ollvmlab_MainActivity_nativeSecret` 和 `Java_com_example_ollvmlab_MainActivity_nativeOpaque`。已有 APK 的 badging 显示 `compileSdkVersion=36`，当前 Gradle 配置写的是 `compileSdk=35`；分析报告以实际 APK 为准，把这视为构建产物与当前配置的差异。

### 三分钟跑一遍（最小闭环）

```powershell
cd D:\code\android\reverse\ollvm
$apk = (Resolve-Path .\samples\apks\app-debug.apk).Path
.\tools\analyze-apk.ps1 -Apk $apk -Out analysis_output          # ① apktool+jadx+aapt2 解包
#   => analysis_output\ 下生成 apktool\ / jadx\ / aapt2-badging.txt

$so = (Resolve-Path .\analysis_output\apktool\lib\arm64-v8a\libollvmlab.so).Path
.\tools\inspect-native.ps1 -So $so                         # ② ELF 符号/段/反汇编
#   => SYMBOLS 里看到 Java_..._nativeSecret / ..._nativeOpaque

adb install -r $apk                                            # ③ 装进已授权设备
adb shell am start -n com.example.ollvmlab/.MainActivity       #   => 启动后点四个按钮
.\tools\logcat.ps1                                           # ④ 抓 OLLVM_LAB 日志
#   => PLAIN_SECRET=... / JAVA_XOR=... / JNI_SECRET=JNI_SECRET=ollvm-native / OPAQUE_RESULT=43

frida -U -f com.example.ollvmlab -l .\frida\frida-hook.js --no-pause
#   ⑤ 点击 JNI / OLLVM 按钮
#   => [nativeSecret] JNI_SECRET=ollvm-native
#   => [nativeOpaque] input=7 result=43
```

### 工程结构

```text
tools\analyze-apk.ps1    APK 解包：apktool d + jadx + aapt2 dump badging
tools\inspect-native.ps1 ELF 检查：llvm-readelf/-objdump/-strings，筛 JNI 符号与解码循环
build\bootstrap.ps1      环境初始化：JDK 21 + Gradle 8.13 + SDK/NDK 路径打印
build\build.ps1          构建 assembleDebug/Release，可选 -Install 直装
tools\logcat.ps1         清空并只看 OLLVM_LAB tag 的 logcat
frida\frida-hook.js      Frida hook：Java native 方法返回边界取值
analysis_output\              脚本输出目录（生成物，已 .gitignore）
ollvm\toolchains\             外部 OLLVM fork 接入说明（占位，未启用）
```

## 环境与工具

### 依赖检查

```powershell
& "$env:USERPROFILE\.agents\skills\android-reverse-engineering\scripts\check-deps.ps1"
```

本机已验证的工具状态：

| 工具 | 状态/用途 |
| --- | --- |
| Java | 已检测到 Java 26；逆向工具要求 JDK 17+ |
| jadx | 已安装，路径 `%USERPROFILE%\.local\share\jadx\bin\jadx.bat`；入 PATH 后脚本自动调用 |
| apktool | 已安装，`analyze-apk.ps1` 内写死本机路径 `D:\tools\Security\Reverse\Android\static\apktool\apktool.bat` |
| adb | 已安装，用于设备安装和 logcat |
| Fernflower/Vineflower、dex2jar | 未安装，可选 |

### 构建环境（仅在需要重新构建时）

```text
JDK 21：D:\tools\Dev\Runtime\jdk21
Gradle：项目内 tools\gradle-8.13 或用户缓存
Android Gradle Plugin：8.13.0
compileSdk（当前配置）：35
NDK：D:\tools\Security\Reverse\Android\dev\android-ndk-r27d
```

`local.properties.example` 是换机器时的路径模板；真实 `local.properties` 已被 `.gitignore` 忽略。脚本内写死的 JDK/apktool/NDK 路径如果换机要同步改（`bootstrap.ps1`、`analyze-apk.ps1`、`inspect-native.ps1` 各一处）。

## 知识点

### 字符串保护五要素 [可验证]

```text
原始明文
  -> 变换算法（XOR/加法/分片/密码算法）
  -> 密文字节或分散片段
  -> key/参数
  -> 运行时解码点
  -> 明文消费者（UI、日志、JNI、网络请求）
```

普通版本特征：DEX `const-string` / SO `.rodata` 直接可搜到完整文本；控制流贴近源码。
字符串保护的静态特征：`byte[]`/整数数组长度接近目标字符串、固定 key、按字节 `xor` 循环、`StringBuilder`/`push_back`/`NewStringUTF` 组装调用、明文只在临时变量或 JNI 参数中出现。
动态特征：字符串保护不能消除明文，只能缩短或延后生命周期；观察边界是解码函数返回前后、`TextView.setText()` 入口、`NewStringUTF` 参数、日志/网络等明文 sink。

固定 `0x5a` 的 XOR 是可逆变换，不是密码学加密：密文、key 和解码逻辑都在客户端。「编码、混淆、加密」不是一回事——编码（Base64）不依赖秘密 key；字符串混淆 key 与程序一起发布；加密依赖独立密钥，本项目没有实现。

### OLLVM 三个 pass [知识框架 + 外部对照]

OLLVM 类 fork 在 LLVM IR 到机器码之间插入 pass，只影响经过该 clang/LLVM 流程编译的代码；Java/Kotlin 的 DEX 字符串不会自动受保护：

```text
C/C++ 源码 -> LLVM IR -> OLLVM pass -> AArch64/ARM/x86 指令 -> ELF/SO -> APK
```

| Pass | 主要改变 | 典型反汇编/CFG 特征 |
| --- | --- | --- |
| `-fla` | 控制流平坦化 | dispatcher、状态变量、中心循环、基本块跳转关系被重排 |
| `-sub` | 指令替换 | 简单算术/逻辑变成长的等价指令序列，数据依赖增加 |
| `-bcf` | 虚假控制流 | 诱饵块、额外谓词、恒真/恒假或与结果无关的分支 |

这些特征必须和**未混淆、同编译器/同优化级别/同 ABI** 的版本比较；C++ 异常、栈保护、标准库和普通 `-O2/-O3` 也会造成复杂 CFG，不能凭一个长函数或几个跳转断言是 OLLVM。

### 普通版本 / 字符串保护 / OLLVM 三方对照

| 维度 | 普通版本 | 字符串保护（本项目 Java/JNI XOR） | OLLVM 混淆（外部对照） |
| --- | --- | --- | --- |
| 主要目标 | 可运行、便于维护调试 | 降低明文字符串静态可见性 | 提高 native 控制流/指令静态阅读成本 |
| 典型位置 | DEX `const-string`、SO `.rodata` | 密文字节 + 解码循环 | native `.text` 的 dispatcher、替换序列、虚假块 |
| 是否改变业务结果 | 否 | 否，运行时仍返回原字符串 | 理论上否，输入输出应一致 |
| 静态搜索 | 直接搜到完整明文 | 可能只搜到密文、key 或零散片段 | 函数结构变复杂，调用关系更难读 |
| 运行时明文 | 直接存在 | 使用前必须出现 | 如果仍用字符串保护，明文生命周期不变 |
| Java 字符串自动受保护 | 否 | 只保护显式改写的字符串 | 否，OLLVM 主要处理 LLVM/native 路径 |
| 性能/体积影响 | 最小 | 通常较小 | 可能增加代码体积、执行时间和调试难度 |

## 静态分析（脚本实跑）

### `analyze-apk.ps1`：解包、Manifest、ABI

```powershell
cd D:\code\android\reverse\ollvm
$apk = (Resolve-Path .\samples\apks\app-debug.apk).Path
.\tools\analyze-apk.ps1 -Apk $apk -Out analysis_output
```

这条命令做什么：apktool 解包（Manifest/资源/smali/按 ABI 的 SO）→ jadx 反编译（在 PATH 时）→ aapt2 dump badging（包名/ABI/debug 标记）。输出目录结构：

```text
analysis_output\apktool\AndroidManifest.xml
analysis_output\apktool\smali\ ... smali_classes2\        # MainActivity 在 smali_classes2（多 dex）
analysis_output\apktool\lib\<abi>\libollvmlab.so
analysis_output\aapt2-badging.txt
analysis_output\jadx\sources\                             # jadx 在 PATH 时生成
```

实跑 `aapt2-badging.txt` 关键行：

```text
package: name='com.example.ollvmlab' versionCode='1' versionName='1.0' ... compileSdkVersion='36'
minSdkVersion:'26'
targetSdkVersion:'35'
application-label:'OLLVM Lab'
native-code: 'arm64-v8a' 'armeabi-v7a' 'x86' 'x86_64'
```

实跑 Manifest 关键行：

```text
<manifest ... android:compileSdkVersion="36" ... package="com.example.ollvmlab" ...>
<application android:debuggable="true" android:extractNativeLibs="false" ...>
<activity android:exported="true" android:name="com.example.ollvmlab.MainActivity">
```

判读：包名 `com.example.ollvmlab`、入口 `MainActivity`、Manifest 未声明网络权限（样例不发起外部请求）、debug 标记 `true`（release unsigned 没有该标记）、四个 ABI 各一份 SO。后续选择与设备匹配的 ABI，优先 arm64。

### `inspect-native.ps1`：ELF 段、符号、密文与解码循环

```powershell
$so = (Resolve-Path .\analysis_output\apktool\lib\arm64-v8a\libollvmlab.so).Path
.\tools\inspect-native.ps1 -So $so
```

这条命令做什么：用 NDK r27d 的 `llvm-readelf -Ws`（符号）、`llvm-readelf -S`（段）、`llvm-strings`（字符串）、`llvm-objdump -d --demangle`（反汇编）逐项过滤 JNI 相关内容。实跑输出（节选）：

```text
== SYMBOLS ==
   79: 0000000000024f10   196 FUNC    GLOBAL DEFAULT    14  Java_com_example_ollvmlab_MainActivity_nativeSecret
  216: 000000000002515c   196 FUNC    GLOBAL DEFAULT    14  Java_com_example_ollvmlab_MainActivity_nativeOpaque
== SECTIONS ==
  [11] .rodata           PROGBITS        00000000000147a0 0147a0 003ec4 00 AMS  0   0 16
  [14] .text             PROGBITS        0000000000024eb0 024eb0 0338f8 00  AX  0   0 16
== STRINGS ==
Java_com_example_ollvmlab_MainActivity_nativeSecret
_ZN7_JNIEnv12NewStringUTFEPKc
Java_com_example_ollvmlab_MainActivity_nativeOpaque
libollvmlab.so
== DISASSEMBLY ==
0000000000024f10 <Java_com_example_ollvmlab_MainActivity_nativeSecret>:
     24f38: 94000027      bl 0x24fd4
     24f48: 9400007c      bl 0x25138 <_JNIEnv::NewStringUTF(char const*)+0x34>
     24f54: 9400ce2b      bl 0x58800 <_ZN7_JNIEnv12NewStringUTFEPKc@plt>
     25054: 52800b49      mov w9, #0x5a               // =90
     25058: 4a090101      eor w1, w8, w9
     2505c: 9400cdf5      bl 0x58830 <std::string::push_back(char)@plt>
```

逐行判读：

- `== SYMBOLS ==` 两条 `Java_` 命名导出存在 → JNI 绑定方式是静态命名导出，不是 `RegisterNatives`；
- `.rodata`（0x3ec4 字节）存密文字节，`== STRINGS ==` 里**没有**完整 `JNI_SECRET=ollvm-native` → 字符串保护生效；
- `0x24fd4` 是解码函数（源码 `decode_secret`，`static` 被内联成 JNI 函数内部）；
- `mov w9, #0x5a` + `eor w1, w8, w9` + `push_back` → 逐字节 XOR 解码循环，key `0x5a`；
- `NewStringUTF` 调用链 → JNI 明文输出边界。

不要要求 `llvm-readelf -Ws` 一定能找到源码函数名 `decode_secret`：它是 `static` 函数，可能被内联、拆分或没有独立符号；以调用链和指令特征为准。

脚本默认（不带 `-So`）会在 `app\build\intermediates\...` 下自动找 arm64 SO；找不到 SO 时先确认：

```powershell
Get-ChildItem .\analysis_output\apktool\lib -Recurse -Filter libollvmlab.so
```

实跑（四个 ABI 全部在场，arm64 最大）：

```text
lib\arm64-v8a\libollvmlab.so  383632
lib\armeabi-v7a\libollvmlab.so  229196
lib\x86\libollvmlab.so  359432
lib\x86_64\libollvmlab.so  364320
```

### 脚本路线下的手工还原（答案速记）

Java XOR：key `0x5a`，第一个字节 `0x10 ^ 0x5a = 0x4a` 即 `J`，完整结果 `JAVA_XOR_SECRET`。
JNI XOR：同样 key `0x5a`，完整返回值 `JNI_SECRET=ollvm-native`；UI 又在返回值前拼接 `JNI_SECRET=`，所以按钮最终显示 `JNI_SECRET=JNI_SECRET=ollvm-native`——重复前缀是样例代码的预期行为，不是解码错误。

### `nativeOpaque` 基线推算

输入固定 `7`：

```text
x = 7 * 3 + 1 = 22
((22 ^ 0x55) + 7) % 2 == 0，因此 x += 0x10，得到 38
i=0: (38 ^ 3) + 1  = 38
i=1: (38 ^ 16) + 1 = 55
i=2: (55 ^ 29) + 1 = 43
```

所以 `OPAQUE_RESULT=43`。OLLVM 变体必须保持这个输入输出关系；变化只应体现在 CFG、指令形态、体积、性能和调试成本。

### 从特征判断是哪类保护

| 观察到的特征 | 更可能的结论 |
| --- | --- |
| DEX `const-string` 直接包含完整文本 | 普通 Java 明文 |
| DEX 有 byte array、key 和 XOR/移位循环 | Java 字符串保护 |
| SO `.rodata` 有密数字节，`.text` 有循环、key 和 `NewStringUTF` | JNI 字符串保护 |
| `.text` 出现 dispatcher/state、诱饵块、等价长算术序列，且相对基线 CFG 显著变复杂 | 可能启用了 OLLVM pass |
| 只有字符串变成字节数组，但 CFG 与基线基本相同 | 字符串保护，不足以证明 OLLVM |

## 动态分析（脚本实跑）

### `build.ps1 -Install` / `logcat.ps1`：安装并取证

```powershell
.\build\build.ps1 -Variant debug -Install
#   => 构建（必要时）+ adb install -r + am start；APK 已存在时可直接 adb install -r 手动装
.\tools\logcat.ps1
```

`logcat.ps1` 就是两条命令的封装：`adb logcat -c` 清空缓冲 + `adb logcat -s OLLVM_LAB:D '*:S'` 只看 `OLLVM_LAB` tag。依次点击四个按钮，预期输出：

```text
PLAIN_SECRET=ollvm-lab:static-string
JAVA_XOR=JAVA_XOR_SECRET
JNI_SECRET=JNI_SECRET=ollvm-native
OPAQUE_RESULT=43
```

四种路径的动态观察点不同：

| 按钮 | 明文/结果最早出现的位置 | 说明 |
| --- | --- | --- |
| Java 明文 | `plain` 回调创建字符串时 | 明文从 DEX 常量直接进入 `show()` |
| Java XOR | XOR 循环的 `StringBuilder` 中 | 每个字符逐步还原，完整结果在 `show()` 前形成 |
| JNI XOR | native 解码循环结束后、`NewStringUTF` 参数中 | SO 静态 `.rodata` 没有完整明文，但 JNI 返回值有 |
| nativeOpaque | `nativeOpaque(7)` 返回点 | 观察控制流混淆前后的输入输出一致性 |

### `frida-hook.js`：在 Java native 返回边界取值

```powershell
frida -U -f com.example.ollvmlab -l .\frida\frida-hook.js --no-pause
```

脚本内容就是两个 `implementation` 替换：`nativeSecret` 打印返回值、`nativeOpaque` 打印输入输出。点击 JNI 和 OLLVM 按钮，输出：

```text
[nativeSecret] JNI_SECRET=ollvm-native
[nativeOpaque] input=7 result=43
```

这个 hook 的意义是观察 Java/native 边界：

- `nativeSecret()` 的返回值已经是完整 `String`，说明明文至少在 JNI 返回点可见；
- `nativeOpaque(7)` 的输出不依赖你能否读懂内部 CFG，适合比较混淆前后的行为；
- Frida 观察到的是结果，不等于已经还原了 native 内部每条指令。

前提：主机端 Frida 与设备端 Frida Server 版本匹配。只想观察 UI/log sink 时也可以在 `show(TextView, String)` 处 hook——那会同时捕获三个字符串按钮。

常见故障：

| 现象 | 处理 |
| --- | --- |
| `unable to find process` | 确认包名、`adb devices`、`-f` 参数 |
| `ClassNotFoundException` | 类名必须是 `com.example.ollvmlab.MainActivity` |
| hook 没输出 | 确认点击的是当前启动的 Activity，且装的是 debug APK |
| native 方法没命中 | 先在 Java 层确认调用发生，再检查 ABI 与 Frida Server 版本 |

### LLDB/Android Studio：观察 JNI 内部

Android Studio 打开项目、选 `debug` 变体 attach。断点顺序：

```text
Java 回调              -> nativeSecret()
JNI 导出函数           -> Java_com_example_ollvmlab_MainActivity_nativeSecret
解码循环               -> 读取密文字节并执行 XOR 的位置
JNI 输出               -> _JNIEnv::NewStringUTF
Java 返回/日志         -> show() 或 Log.i("OLLVM_LAB", ...)
```

`decode_secret()` 没符号不算失败：在 `Java_..._nativeSecret` 内搜 `0x5a`、循环读字节、`push_back` 或 `NewStringUTF`。arm64 JNI 调用可从 `x0`（`JNIEnv*`）、`x1`（`jobject`）和返回前的 `jstring` 结果开始观察；Android Studio 自动生成的 LLDB attach 配置优先于手写命令。

### 动态观察 OLLVM 特征（针对外部 fork 变体）

- 断点单步经过更多基本块和跳转；
- 平坦化时状态变量在 dispatcher 中频繁变化；
- 虚假控制流带来不影响最终结果的分支；
- 指令替换增加算术指令数量，但函数输入输出不变；
- 符号、源码行和反编译变量可能变得不可靠。

先在 JNI 入口/返回点记录输入输出，再决定是否跟踪内部状态。动态 trace 的价值是恢复真实执行路径，而不是证明所有静态分支都可达。

## 对照验证（OLLVM 单变量实验）

前提：当前 APK 不是 OLLVM 变体（`app/build.gradle` 无 OLLVM clang、无 `-mllvm`；`CMakeLists.txt` 只做普通 C++17 编译；`ollvm/toolchains/README.md` 只是接入说明）。实验分两步：先用已有 APK 建立普通基线，再用兼容的 OLLVM fork 生成对照 APK；没有 fork 时前半部分仍可完成。

### 基线固定

```powershell
$baseline = (Resolve-Path .\analysis_output\apktool\lib\arm64-v8a\libollvmlab.so).Path
.\tools\inspect-native.ps1 -So $baseline
Get-FileHash $baseline -Algorithm SHA256
#   => 555B4EE785E5040FA1F7CC503FAFDA16B88411C79C242E769BADDCA22BA318C2
```

基线要点：两个 JNI 导出在符号表可查；`nativeSecret` 内有密数字节、`0x5a` XOR 循环和 `NewStringUTF` 路径；`nativeOpaque` 是简单乘法、条件分支和三次循环；`strings` 看不到完整明文——这是字符串保护的效果，不是 OLLVM 的证据。

### 单变量实验矩阵

| 变体 | 只改变的因素 | 需要比较的现象 |
| --- | --- | --- |
| baseline | 普通 NDK Clang | 原始 CFG、函数大小、输出 |
| `sub` | 仅 `-sub` | 指令数量、等价算术序列、输出 |
| `fla` | 仅 `-fla` | dispatcher/state、跳转数量、CFG 形状 |
| `bcf` | 仅 `-bcf` | 诱饵块、谓词、可达路径和体积 |
| 组合 | 按 fork 支持组合 | 综合静态成本、性能和调试体验 |

外部 fork 接入前至少确认：LLVM/OLLVM commit、clang 路径、NDK/ABI/API 兼容性、优化级别、实际支持的 pass 参数（以该 fork 的 `clang --help` 为准）。不要直接覆盖 SDK/NDK 自带 clang，不要把第三方二进制提交进仓库；建议只对 `nativeOpaque` 做单变量实验，不要一开始同时打开字符串保护、R8、多个 pass 和不同优化级别，否则无法判断变化来源。每次构建保留：clang 命令、fork commit、pass 参数、ABI/API、优化级别、SO 哈希和 APK 哈希。

### 变体比较（脚本部分）

```powershell
$variant = (Resolve-Path .\path\to\variant\libollvmlab.so).Path
.\tools\inspect-native.ps1 -So $variant
```

比较 `.text`/`.rodata`/`.dynsym` 大小、JNI 导出是否仍在、函数符号存留、完整字符串是否仍在 `.rodata`、XOR/key/`NewStringUTF` 路径是否仍存在。行为验证：点 OLLVM 按钮确认 `nativeOpaque(7)` 仍输出 `43`，点 JNI 按钮确认仍显示 `JNI_SECRET=JNI_SECRET=ollvm-native`；同设备同 ABI 记录延迟与体积；Frida/LLDB 比较入口、返回点和单步体验。

### 结论模板

```text
样本/APK SHA-256：
SO/ABI：
编译器与 OLLVM commit：
优化级别/API：
pass：
字符串保护方式：
静态变化：
CFG 特征：
动态变化：
体积/性能变化：
对字符串保护的实际帮助：
仍可观察到的明文边界：
```

动态取证记录模板（每次实验至少记录）：

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

## 踩坑 / 速查

### 最容易写错的结论

- `strings` 看不到明文，不代表启用了 OLLVM；可能只是 XOR/分片；
- 函数变大不一定是 `fla`/`bcf`；普通优化和 C++ 运行库也会变大；
- OLLVM 不自动保护 Java/Dex 字符串；`const-string` 仍需单独处理；
- OLLVM 不让运行时明文消失；`NewStringUTF`、UI、日志和网络参数仍可泄露；
- release 构建 ≠ OLLVM 构建；当前 release unsigned 也没启用 R8/ProGuard，不能当作「经过完整发布加固」的样本。

### 脚本与环境坑

| 现象 | 处理 |
| --- | --- |
| `APK not found` | 分析用归档副本 `samples\apks\*.apk`；构建产物在 `app\build\outputs\apk\...`，只有缺失时才 `.\build\build.ps1 -Variant debug` |
| jadx 不在 PATH | `analyze-apk.ps1` 用 `Get-Command jadx` 检测，不会扫用户目录；把 jadx 的 `bin` 加入 PATH，或手动用 `%USERPROFILE%\.local\share\jadx\bin\jadx.bat` |
| 找不到 SO | 先跑 `analyze-apk.ps1`，再 `Get-ChildItem analysis_output\apktool\lib -Recurse -Filter libollvmlab.so` |
| LLDB 断点未命中 | 确认装的是 debug APK、ABI 匹配、模块已加载；`decode_secret` 可能已内联 |
| `frida` 找不到进程 | 检查 `adb devices`、包名、Frida Server 版本和 `-f` 启动参数 |
| 构建失败 | 先 `java -version`；`bootstrap.ps1` 要求 JDK 21 在写死路径，命令行 Java 版本 ≠ Gradle 实际用的 JDK |

### 安全结论

XOR、分片、JNI 和 OLLVM 都是逆向阻碍措施，不是长期秘密的安全存储方案。只要客户端必须获得明文，调试器和运行时 hook 就有机会读取它。长期有效密钥应移出 APK，改用服务端校验、短期令牌、轮换和最小权限。正确的总结通常是：「pass 增加了静态理解成本，但没有替代字符串保护、密钥管理或服务端安全设计。」
