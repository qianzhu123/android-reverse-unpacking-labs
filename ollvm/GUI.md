# GUI.md：图形工具路线——jadx-gui 看 Java 层，IDA 分析 SO

> **本路线的工具必须是图形应用**：Java/Dex 反编译用 **jadx-gui**（打开 APK 的图形界面，读包树与反编译视图）；native SO 用 **IDA**（反汇编 / Hex-Rays / 图视图）；十六进制查看可用 **010 Editor**。
> **命令行工具不属于本路线**：`jadx -d ...`（无界面转储）、`apktool.bat`（解包提取制品）、`llvm-objdump` / `Get-FileHash`（核对）都是命令——它们属命令行/脚本路线（`CLI.md`、`tools/*.ps1`）；`GUI.md` 只**在图形应用里读取/分析**，命令行只用于「准备制品」（如提取 SO）与「核对哈希」，不作为分析方法。

## 概述

一句话定位：jadx-gui 打开 APK 看 Java 层的明文/密文/`native` 声明，IDA 打开 `libollvmlab.so` 看 JNI 入口、Hex-Rays 伪代码、已验证的地址链和控制流——本路线负责「看懂结构与调用关系」，量化判定（哈希、段大小、密文字节）以 SCRIPT.md / CLI.md 为准。

为什么自造样本（建模说明）：同一个 APK 装下 Java 明文、Java XOR、JNI XOR、`nativeOpaque` 四种情况，GUI 路线可以并排展示「同一份逻辑在 jadx-gui 里长什么样、在 IDA 里长什么样」；当前 APK 是普通 NDK 编译 + 源码级 XOR 的基线（未启用 OLLVM pass），IDA 里看到的就是未混淆的对照组。

样本事实（与 SCRIPT.md / CLI.md 一致）：

| 项目 | 值 |
| --- | --- |
| 包名 / 入口 | `com.example.ollvmlab` / `com.example.ollvmlab.MainActivity` |
| ABI | `arm64-v8a`、`armeabi-v7a`、`x86`、`x86_64`（GUI 分析统一用 arm64） |
| debug APK SHA-256 | `06935B0B8F0EEF249E2D202E2059141B389F7F5760788024EF1175FC1DEF045E` |
| arm64 debug SO SHA-256 | `555B4EE785E5040FA1F7CC503FAFDA16B88411C79C242E769BADDCA22BA318C2`（383632 字节） |
| 关键明文/结果 | `PLAIN_SECRET=ollvm-lab:static-string` / `JAVA_XOR_SECRET` / `JNI_SECRET=ollvm-native` / `nativeOpaque(7)=43` |
| JNI 绑定 | 命名导出 `Java_com_example_ollvmlab_MainActivity_nativeSecret` / `...nativeOpaque` |

### 三分钟跑一遍（最小闭环）

```text
① jadx-gui 打开 .\samples\apks\app-debug.apk
   -> 左侧包树展开 com.example.ollvmlab -> 双击 MainActivity
   => 右侧反编译视图直接看到 PLAIN_SECRET 明文、XOR_BLOB / XOR_KEY=90、native 两个声明
```

```text
② IDA 打开 .\analysis_output\apktool\lib\arm64-v8a\libollvmlab.so
   （该 SO 由命令行 apktool 先行提取，见「环境与工具」）
   -> 等 Auto-analysis -> Exports 里找 Java_..._nativeSecret
   -> 双击进入 -> F5 看伪代码 -> 跟进 sub_24FD4
   => 看到 mov w8, #0x5a / eor / push_back 解码循环，0x14db9 处 24 字节密文
```

### 工程结构（GUI 路线会用到的路径）

```text
analysis_output\apktool\lib\arm64-v8a\libollvmlab.so                  IDA 分析对象（arm64 debug；由命令行 apktool 提取）
analysis_output\apktool\smali_classes2\com\example\ollvmlab\...       smali 原始字节码（jadx-gui 看不懂时兜底）
app\src\main\cpp\native-lib.cpp                                   JNI 源码（对照用）
```

> jadx-gui 直接打开 `samples\apks\app-debug.apk` 即可，不需要预先转储 `analysis_output\jadx\sources\`；上表保留 apktool 目录仅因 IDA 需要它的 SO 制品。

## 环境与工具

| 工具 | 状态/位置 |
| --- | --- |
| jadx-gui | 已安装：`%USERPROFILE%\.local\share\jadx\bin\jadx-gui.bat`（图形界面；同目录另有命令行 `jadx.bat`，属 CLI 路线） |
| IDA | 本机已装，按 05 篇现状使用（安装位置不做新约定） |
| apktool | `D:\tools\Security\Reverse\Android\static\apktool\apktool.bat`（**命令行**，仅用于提取 SO 等制品，不作分析方法） |
| Fernflower/Vineflower、dex2jar | 未安装，可选；复杂 Java 代码对比时用（APK/DEX 转 JAR 需先装 dex2jar） |
| Android Studio + LLDB | 动态补充时使用，需 debug APK；release unsigned 不适合作为可调试样本 |

**命令行与图形应用的分工**：jadx-gui 直接打开 APK 即可（无需先转储目录）；apktool.bat、`Get-FileHash`、`llvm-objdump` 这些命令行只用于**准备制品**（提取 SO）与**核对哈希**——分析方法本身在 jadx-gui / IDA。图形工具打开的 SO 必须和 CLI 哈希记录的是同一份——分析前用 `Get-FileHash` 对一遍（见 CLI.md 静态分析①）。

## 知识点：字符串保护和 OLLVM 的特征边界

jadx-gui 里找到的 `XOR_BLOB`/`XOR_KEY`/循环/`StringBuilder` 是**字符串保护**的特征，不是 OLLVM 特征。两类特征的位置完全不同：

| 观察位置 | 字符串保护常见特征 | OLLVM 常见特征 |
| --- | --- | --- |
| Java/Dex | byte 数组、key、XOR/移位循环、`StringBuilder`、`Cipher`、`Base64` | OLLVM 不处理 Java 字节码 |
| ELF `.rodata` | 密文字节、分片、长度/终止符、没有完整明文 | 不以 `.rodata` 字段名为特征 |
| ELF `.text` | 解码循环、读字节、XOR、写缓冲区、`NewStringUTF` | `fla` 的 dispatcher/state、`sub` 的等价长指令序列、`bcf` 的诱饵块/opaque predicate |
| CFG | 普通循环和少量分支 | 相对 baseline 明显膨胀、中心调度循环、路径被重排或加入无效块 |
| 运行时 | 明文在字符串消费者前出现 | 输入输出通常不变，但单步和 trace 更复杂 |

没有一个通用的「OLLVM 字符串字段」。OLLVM 是 native 编译阶段的代码变换；只有当 Java/JNI 字符串解码函数也经过 OLLVM 编译时，才可能在同一个解码函数里同时看到两类特征。判断 OLLVM 必须与同 ABI、同优化级别的未混淆 baseline 做差分（矩阵见 SCRIPT.md「对照验证」）。

jadx-gui 侧逐字段判读（`XOR_BLOB` 代码到底是不是保护特征）：

| 字段/语句 | 实际含义 | 是否是保护特征 |
| --- | --- | --- |
| `private` | Java 访问修饰符，只限制源码层访问 | 不是。DEX 仍可被反编译和读取 |
| `static` | 类级别字段，通常只有一份数组引用 | 不是。只是存储位置特征 |
| `final` | 引用不能重新指向其他数组；数组元素本身并不因此加密 | 不是 |
| `byte[]` | 适合存放密文字节或二进制数据 | 是候选线索，但单独不足以证明加密 |
| `XOR_KEY = 90` | 十进制 90，即十六进制 `0x5a` | 是解码参数线索 |
| `new byte[]{...}` | 密文/编码数据进入 DEX 的数组初始化 | 是字符串保护的强线索 |
| `x ^ 90` | 对每个字节执行 XOR；XOR 可逆，`P = C ^ K` | 是核心解码特征 |
| `StringBuilder.append`、`char` | 把解码结果组装成 Java 字符串 | 是明文生成点 |
| `System.loadLibrary("ollvmlab")` | 加载 `libollvmlab.so` | 是 Java 到 JNI 的桥接线索，不是加密算法 |

这里的 `90` 不是秘密密钥：密文、key 和解码逻辑都在 APK 中。更准确的名称是**字符串混淆**或**运行时解码**，而不是安全的密码学加密。

这段代码在 DEX/smali 中对应（IDA 看不到它，它属于 `classes*.dex`）：

```text
new-array -> fill-array-data -> 读取数组元素
const/16 0x5a -> xor-int/lit8
int-to-char -> StringBuilder.append(C)
```

IDA 应该分析的是 JNI native 实现和 native 控制流，不替代 jadx-gui 的 Java/Dex 分析。

## 静态分析（jadx-gui 部分）

### 用 jadx-gui 打开 APK 读 Java

点哪里/看什么：jadx-gui `File → Open` 打开 `samples\apks\app-debug.apk`，左侧包树展开 `com.example.ollvmlab` → 双击 `MainActivity`，右侧反编译视图应看到三段并列的代码（实跑摘录）：

```java
private static final byte[] XOR_BLOB;
private static final int XOR_KEY = 90;
...
static { System.loadLibrary("ollvmlab"); }
XOR_BLOB = new byte[]{16, 27, 12, 27, 5, 2, 21, 8, 5, 9, 31, 25, 8, 31, 14};
...
show(output, "PLAIN_SECRET=ollvm-lab:static-string");   // 61 行：Java 明文
for (byte x : XOR_BLOB) { b.append((char) (x ^ XOR_KEY)); }  // 67 行：Java XOR
show(output, "JAVA_XOR=" + ((Object) b));               // 70 行
show(output, "JNI_SECRET=" + nativeSecret());           // 75 行：JNI 路径
show(output, "OPAQUE_RESULT=" + nativeOpaque(7));       // 80 行：控制流基线
private native String nativeSecret();
private native int nativeOpaque(int i);
```

怎么判：

- 明文按钮：`const-string` 直接可读——普通版本的基线；
- Java XOR：字节数组 + 固定 key + 循环 + `StringBuilder`，沿数据流手工还原出 `JAVA_XOR_SECRET`；
- JNI 路径：Java 层只有 `native` 声明 + `loadLibrary`，实现必须去 SO 找——这就是切到 IDA 的信号。

大型 APK 的 jadx-gui 搜索策略：字段名可能被 R8/ProGuard 改名，按行为特征搜而不是按名字搜——`System.loadLibrary`、`native `、`RegisterNatives`、`JNI_OnLoad`、`XOR`、`Cipher.getInstance`、`SecretKeySpec`、`Base64`、`StringBuilder`、`byte[]`（jadx-gui 用 `Ctrl+Shift+F` 全局搜索）。混淆工具可以改名，但不能把这些运行时 API 的语义完全消除。找不到 `XOR_BLOB` 时继续搜 `byte[]` 初始化和 `new String(...)`。

### jadx-gui → SO 的映射表（找「桥」，不只找明文）

```text
Java 类/方法
  -> System.loadLibrary("ollvmlab")
  -> libollvmlab.so
  -> native 方法名/签名
  -> JNI 静态导出或 RegisterNatives 表
  -> 解码函数/业务函数
  -> UI、日志、网络或文件 sink
```

## 静态分析（IDA 部分）

### 提取正确的 SO（命令行准备制品）

IDA 需要的是 SO 制品，这一步用**命令行 apktool** 提取（属制品准备，不是分析）：

```powershell
# 用命令行 apktool 解包 APK，得到的 lib 目录即 IDA 的分析对象
& 'D:\tools\Security\Reverse\Android\static\apktool\apktool.bat' d -f `
  .\samples\apks\app-debug.apk -o .\analysis_output\apktool

# 核对哈希：IDA 打开的必须与文档记录的是同一份（Get-FileHash 属核对命令）
Get-FileHash .\analysis_output\apktool\lib\arm64-v8a\libollvmlab.so -Algorithm SHA256
#   => 555B4EE785E5040FA1F7CC503FAFDA16B88411C79C242E769BADDCA22BA318C2
```

IDA 应打开与设备 ABI 匹配的 ELF（arm64 → AArch64；armeabi-v7a → ARM/Thumb；x86_64 → x86-64；x86 → x86）。直接打开 apktool 输出目录里的 SO，不必把整个 APK 导入 IDA。

大型 APK 先按 ABI 和库名排序再决定分析谁（自有命名库 > 业务 JNI/加密/授权库 > 游戏引擎/广告统计 > 纯资源适配库）：

```powershell
Get-ChildItem .\analysis_output\apktool\lib -Recurse -Filter '*.so' |
    Select-Object FullName, Length | Sort-Object Length -Descending
#   => arm64-v8a 383632 / x86_64 364320 / x86 359432 / armeabi-v7a 229196
```

### 首次加载的基本检查（点哪里/看什么/怎么判）

在 IDA 中打开 `libollvmlab.so` 后：

1. 等待 Auto-analysis 完成；
2. 看 ELF Header：确认 `AArch64`、`DYN`/PIE shared object 和目标 ABI；
3. 看 Segments：确认 `.text`、`.rodata`、`.dynstr`、`.dynsym`；
4. 看 Exports/Names：应看到（当前 debug arm64 SO 实测）：

```text
Java_com_example_ollvmlab_MainActivity_nativeSecret
Java_com_example_ollvmlab_MainActivity_nativeOpaque
```

5. 看 Imports：找 `NewStringUTF`、`GetStringUTFChars`、`RegisterNatives`、`FindClass`、`memcpy`、`malloc`；
6. 立即保存一个 IDB/数据库副本，按 APK、ABI、debug/release 命名。

`decode_secret()` 在源码中是 `static`，可能被内联或没有独立符号；找不到这个函数名是正常情况，应从 `Java_..._nativeSecret` 进入内部解码路径。

### Strings 和 Xrefs 建立入口

点哪里：View → Open subviews → Strings（Shift+F12）。看什么（优先检查）：

```text
JNI
Java_
NewStringUTF
RegisterNatives
ollvmlab
nativeSecret
nativeOpaque
```

怎么判：对字符串或导出函数按 `x` 查交叉引用，把调用者/被调用者重命名建立语义：

```text
Java_..._nativeSecret       JNI 入口
sub_decode_secret           推断出的解码逻辑
make_jstring                JNI 输出包装
```

名字是给当前 IDB 建立语义的备注，不代表原始符号真实存在。遇到没有可读字符串的密文时切到 `.rodata`，根据数据引用、数组长度、终止 `0` 和函数加载地址定位。

### 在 `nativeSecret` 中找解码循环

预期逻辑（源码抽象）：

```cpp
std::string out;
for (size_t i = 0; blob[i] != 0; ++i) {
    out.push_back(static_cast<char>(blob[i] ^ 0x5a));
}
return env->NewStringUTF(out.c_str());
```

AArch64 反汇编中重点找：循环索引递增和数组读取；`0x5a` 作为立即数或从 literal pool/寄存器加载；`eor`/XOR 字节变换；`std::string::push_back` 或缓冲区追加；循环结束后调用 `NewStringUTF`。如果 `0x5a` 没直接显示为立即数，应从密文数组的数据引用向上追踪，而不是只搜文本 `5a`。

图视图判读：普通 XOR 解码是一个简单循环（初始化 → 读字节 → 变换 → 追加 → 索引加一 → 回循环头 → 遇 NUL 退出），这个结构和 OLLVM 的 dispatcher/状态机明显不同。

### 如何解读 Hex-Rays 伪代码（F5 输出逐行判读）

对 `Java_..._nativeSecret` 按 F5，你看到的函数按下面语义理解：

```cpp
// Hex-Rays 为了表示 ABI 和局部对象，可能把类型和隐藏参数显示得不完整。
std::string tmp;                         // 对应 v5[24]
decode_secret(/* hidden result = */ &tmp); // 对应 sub_24FD4()
const char *p = tmp.c_str();             // 对应 sub_25138(v5)
jstring result = env->NewStringUTF(p);   // 对应 NewStringUTF(a1, v1)
tmp.~basic_string();                     // 对应 std::string::~string(v5)
return result;
```

| Hex-Rays 代码 | 应如何理解 |
| --- | --- |
| `__int64 ...` | IDA 尚未把返回值识别成 `jstring`；`jstring` 本质是对象句柄，伪代码显示整数宽度是常见现象 |
| `__fastcall` | Hex-Rays 对当前架构/调用约定的标注，不代表业务用了某种「快速加密调用」 |
| `_JNIEnv *a1` | `x0` 中的 `JNIEnv*`；真实 JNI 函数通常还有 `jobject thiz` 在 `x1`，本函数未使用它，Hex-Rays 可能省略 |
| `v6 = *(_QWORD *)(_ReadStatusReg(TPIDR_EL0) + 40)` | AArch64 线程本地存储中的栈保护值（stack canary），不是 XOR key，也不是密文 |
| `_BYTE v5[24]` | 很可能是编译器为 `std::string` 临时对象分配的 24 字节存储；后面调用 `~string(v5)` 是强证据。不要把它当 `char[24]` |
| `sub_24FD4()` | 很可能是源码 `decode_secret()` 的优化后函数/构造函数。非平凡 `std::string` 返回值通过 AArch64 ABI 的隐藏返回地址（`x8`）写入 `v5`，所以 Hex-Rays 看不到显式参数 |
| `sub_25138(v5)` | 很可能是 `std::string::c_str()`/`data()` 或其内联包装，返回传给 JNI 的 `const char *`；应通过反汇编和 Xrefs 确认后再重命名 |
| `_JNIEnv::NewStringUTF(a1, v1)` | 把 native 的 NUL 结尾字符串转换成 Java `String`；JNI 明文输出边界 |
| `std::string::~string(v5)` | JNI 返回对象创建完成后销毁临时 native 字符串，说明明文曾经在 native 内存中存在 |

这段伪代码已经能证明「native 先生成字符串，再通过 JNI 返回 Java」，但还没展示 XOR 循环本身——下一步应双击 `sub_24FD4` 或按 `x` 查 Xrefs。

不要仅凭 `sub_24FD4` 这个地址名断言它一定是 `decode_secret`。更稳妥的记录方式：

```text
sub_24FD4：疑似 decode_secret，依据是其返回/构造的 std::string 被送入 sub_25138 与 NewStringUTF
sub_25138：疑似 std::string::c_str()/data()，需结合反汇编确认
```

在 IDA 中完成数据流确认后再把函数重命名为 `decode_secret`、`string_c_str` 等——学习笔记既保留推理过程，也不会把 Hex-Rays 的临时命名误当作原始符号。

### 本项目 debug arm64 SO 的已验证链路

对仓库当前的 `analysis_output\apktool\lib\arm64-v8a\libollvmlab.so`（SHA-256 `555B4EE7...`），用汇编验证伪代码，而不是只信 F5：

```text
0x24f10  Java_..._nativeSecret
  -> 0x24fd4  构造/解码 std::string（隐藏结果地址来自 x8）
       -> 0x14db9  读取 24 字节密文（最后一个字节为 NUL）
       -> 0x25054  加载 0x5a
       -> 0x25058  eor 每个字节
       -> 0x58830  std::string::push_back(char)
  -> 0x25138  读取临时 std::string 的字符数据（疑似 c_str/data 包装）
  -> 0x25104  _JNIEnv::NewStringUTF 包装函数
  -> 0x58800  JNI 函数表中的 NewStringUTF 实际调用
```

对应的 AArch64 关键指令（`llvm-objdump` 实跑，与 IDA 显示一致）：

```asm
24f30: sub x8, x29, #0x20       ; x8 = v5，std::string 临时对象地址
24f38: bl  0x24fd4              ; x8 作为隐藏结果地址传入
24ffc: adr x8, 0x14db9          ; 密文 literal pool
25010: mov w8, #0x5a            ; XOR key
25050: ldrb w8, [x8, x9]
25058: eor  w1, w8, w9           ; 每字节解码
2505c: bl   ...push_backEc      ; 追加明文字符
24f48: bl  0x25138              ; 得到 const char *
24f54: bl   ...NewStringUTF...   ; 转成 jstring
```

解码循环内的完整位置（IDA 图视图中按 `G` 跳转逐个确认）：

```text
0x24ffc  adr x8, 0x14db9       ; 密文地址
0x25010  mov w8, #0x5a         ; key
0x25030  循环入口
0x25038  ldrb 读取密文字节
0x2503c  cbz  遇到 NUL 退出
0x25058  eor  执行 XOR
0x2505c  push_back 追加解码字符
0x25074  回到循环
```

所以对本样本可以把 `sub_24FD4` 从「疑似 decode_secret」升级为「已由数据流和指令确认的 native 解码函数」。`sub_25138` 应先命名为 `string_data_helper` 或 `string_c_str_wrapper`，除非继续跟进 `0x25374` 等内部函数确认其返回字符缓冲区。`0x24f10`、`0x24fd4`、`0x14db9` 等地址只对当前 debug/arm64 构建有效，换 ABI、release、编译器或重新构建后必须重新定位。

### 跳到 `0x14db9` 查看密文

点哪里：按 `G` 输入 `0x14db9` 跳转。看什么：如果这里还没被识别为数据，先取消错误的代码定义，再按 `D` 定义字节。本样本按 24 字节观察，最后一个字节 `0x00`：

```text
10 14 13 05 09 1f 19 08 1f 0e 67 35
36 36 2c 37 77 34 3b 2e 33 2c 3f 00
```

用 `0x5a` 逐字节 XOR 后是：

```text
JNI_SECRET=ollvm-native
```

把这块数据命名为 `secret_blob_xor5a`——把「密文在哪里」和「哪个函数使用它」通过 Xrefs 连起来。不要把 `0x14db9` 当通用地址；换构建后应从 `adr`/数据引用重新定位。

### 识别 `NewStringUTF` 包装层

`0x25104` 的汇编大致是：

```asm
ldr x8, [x0]              ; JNIEnv 函数表
ldr x8, [x8, #0x538]      ; 当前 ABI 的 NewStringUTF 槽位
blr x8                    ; 调入 Android Runtime
```

这里不需要继续追 Android Runtime 的实现——它只是 JNI 函数表间接调用，证明 native `char*` 已经跨越到 Java `String`。`0x538` 是当前架构/构建的函数表偏移，不是跨 ABI 固定特征。

### 回到 Java 调用者闭环

jadx-gui 里 `MainActivity` 的调用：

```java
show(output, "JNI_SECRET=" + nativeSecret());
```

native 返回 `JNI_SECRET=ollvm-native`，UI/logcat 最终显示：

```text
JNI_SECRET=JNI_SECRET=ollvm-native
```

这一步把 IDA 的 native 数据流和 Java 的调用语义闭环。需要动态确认时再用 Frida/LLDB（见动态分析章）；不是每次静态分析都必须跑脚本。

### 这时应该记录的结论

```text
Java 入口：MainActivity.nativeSecret()
SO 入口：Java_com_example_ollvmlab_MainActivity_nativeSecret
解码函数：sub_24FD4（已确认）
密文位置：0x14db9（当前 debug/arm64）
算法：逐字节 XOR
key：0x5a
明文生成：std::string::push_back
Java 边界：_JNIEnv::NewStringUTF
最终消费者：MainActivity.show() / Log.i
OLLVM 结论：当前链路没有 OLLVM 特征，属于普通 JNI + XOR 运行时解码
```

### 建议在 IDA 中修正的类型和命名

Hex-Rays 当前显示：

```c
__int64 __fastcall Java_..._nativeSecret(_JNIEnv *a1)
```

这通常是类型恢复不完整，不是 JNI 真的只有一个参数。JNI 原型应按 Java 声明理解为：

```c
jstring Java_..._nativeSecret(JNIEnv *env, jobject thiz);
```

本函数的 `jobject thiz`（`x1`）没有参与业务计算，IDA 可能因未使用而省略；汇编仍显示它曾被保存到栈上。可以在 IDA 用 `Y` 修改函数类型、补回第二个参数、返回类型标为 `jstring`/对象句柄；本地类型库没有 JNI typedef 时暂时用 `__int64` 也不影响数据流分析。

建议命名：

```text
Java_..._nativeSecret  -> jni_nativeSecret
sub_24FD4              -> decode_secret
sub_25138              -> string_data_helper（确认后再改成 c_str/data）
0x14db9 数据           -> secret_blob_xor5a
```

不要把 `_ReadStatusReg(TPIDR_EL0) + 40` 重命名为 key：它读取的是线程本地的 stack canary，用于栈破坏检测；真正的 XOR key 在本样本中是 `mov w8, #0x5a`。

### 检查 `nativeOpaque` 是否是 OLLVM

点哪里：Exports 双击 `Java_..._nativeOpaque`（入口 `0x251c`），F5 + 图视图同看。看什么：乘法、一个条件分支和三次循环；输入 7 结果 43。当前仓库没启用 OLLVM pass，因此**不应**期待中心 dispatcher/state 变量、大量诱饵基本块、等价指令替换长算术链、相对 baseline 显著膨胀的 CFG。

真正的 OLLVM 变体需要和未混淆 SO 做函数级差分：`fla` 找状态变量、中心循环、多路分发；`sub` 找被展开的等价算术/逻辑序列；`bcf` 找无业务影响的额外谓词、复制块和诱饵路径。这些是启发式特征，不是唯一签名——优化器、C++ 异常、栈保护和标准库也会产生复杂 CFG。

### 脚本和 IDA 的分工

| 工具 | 适合做什么 | 不应替代什么 |
| --- | --- | --- |
| `analyze-apk.ps1` | 解包 APK、列出 ABI、导出 smali/库文件 | 不替代 IDA 的 CFG、Xrefs 和类型恢复 |
| `inspect-native.ps1` | 快速查看 ELF 段、符号、字符串和反汇编片段 | 不替代对 `sub_24fd4`、数据引用和调用约定的人工确认 |
| jadx-gui | 找 Java 字符串、`native` 声明、`loadLibrary` 和调用者 | 不显示 native `.text` 的真实控制流 |
| IDA | 定位函数、跟踪 Xrefs、查看 CFG、重命名和恢复类型 | 不负责 APK 解包和 Java 业务调用链全貌 |
| Frida/LLDB | 确认运行时参数、返回值和明文边界 | 不替代静态证据和样本哈希记录 |

正确流程：「脚本准备样本 → jadx-gui 找桥 → IDA 证明 native 数据流 → 必要时动态验证」，而不是只看脚本输出或只看 F5 伪代码。

### JNI 绑定的两种查找方式

静态命名导出（本项目）：Java 方法 `private native String nativeSecret();` 对应导出 `Java_com_example_ollvmlab_MainActivity_nativeSecret`——最直接的 IDA 入口。方法名有重载时 JNI 名称可能带参数签名编码，应同时参考 Java 方法描述符。

`RegisterNatives` 动态注册（大型 APK 常见）：导出表没有 `Java_` 不等于没有 JNI。定位顺序：

1. 找 `JNI_OnLoad`；
2. 找 `RegisterNatives` 的调用或 JNI 函数表调用；
3. 找附近的类名、方法名和签名字符串（`{"nativeSecret", "()Ljava/lang/String;", (void *) fn_secret}` 这类三元组）；
4. 把 `JNINativeMethod` 三元组中的函数指针作为真实 native 入口；
5. 再沿函数指针进入解码/业务逻辑。

## 动态分析（GUI 侧的动态补充）

静态分析卡住时（IDA 无法稳定恢复解码逻辑），先用动态边界确认目标：

```text
Java nativeSecret() 调用
  -> JNI 导出/动态注册入口
  -> 解码循环
  -> NewStringUTF 参数
  -> Java 返回值
```

Android Studio + LLDB：打开项目、连接测试设备、选 `debug` 变体 attach，按以下顺序设断点：

```text
Java 回调 -> nativeSecret() -> Java_..._nativeSecret -> 解码循环 -> NewStringUTF -> show()/Log.i
```

Frida hook（脚本见 SCRIPT.md「动态分析」）在 Java native 返回边界直接看到 `[nativeSecret] JNI_SECRET=ollvm-native` / `[nativeOpaque] input=7 result=43`。动态结果用于确认静态推断，不替代对 APK/ABI/函数来源的记录；LLDB 断点未命中时先确认装的是 debug APK、ABI 匹配、模块已加载（`decode_secret` 可能已内联）。

对真正启用 OLLVM 的变体，动态调试通常看到：单步经过更多基本块和跳转；平坦化时状态变量在 dispatcher 中频繁变化；虚假控制流带来不影响结果的分支；指令替换增加算术指令但输入输出不变；符号/源码行/反编译变量可能不可靠。推荐先在 JNI 入口/返回点记录输入输出，再决定是否跟踪内部状态。

## 对照验证（通用方法与样本证据分开记）

这套流程哪些通用、哪些只属于本项目——学习笔记必须分开记录：

| 内容 | 是否通用 | 说明 |
| --- | --- | --- |
| `Get-FileHash` 固定 APK/SO 哈希 | 通用 | 确认分析对象没有变化 |
| apktool 解包、jadx-gui 打开 APK 读 Java、搜 `loadLibrary/native/RegisterNatives` | 通用 | 适用大多数 APK；split/bundle 先定位 base APK |
| 按 ABI 选择 `arm64-v8a`/`armeabi-v7a`/`x86_64`/`x86` | 通用 | 必须与设备和目标 SO 匹配 |
| IDA 的 ELF Header、Segments、Exports、Imports、Strings、Xrefs、Graph View | 通用 | IDA 版本不同，窗口名称可能略有变化 |
| 从 JNI 入口追到密文、解码循环、字符串 sink | 通用 | 适用静态命名导出和动态注册（后者入口改为 `JNI_OnLoad/RegisterNatives`） |
| `.\tools\analyze-apk.ps1`、`.\tools\inspect-native.ps1` | 本项目脚本 | 换其他 APK 要替换为自己的 apktool/ELF 工具命令 |
| `com.example.ollvmlab`、`libollvmlab.so`、`Java_com_...` | 当前样本 | 其他应用的包名、库名和 JNI 名不同 |
| `0x5a`、`XOR_BLOB`、`sub_24FD4`、`sub_25138`、`0x24f10` | 当前构建/ABI | 重编译、换 release、换 ABI 或换编译器后都可能变化，不能当通用地址 |

建议在笔记中同时写「方法」和「样本证据」：例如「通用方法：从 JNI 入口找字符串构造；本样本证据：`Java_...nativeSecret -> sub_24FD4 -> sub_25138 -> NewStringUTF`」。变体差分的实验矩阵与判读纪律见 SCRIPT.md「对照验证」；IDA 侧只做函数级 CFG 差分（baseline 与变体同时导入，`fla` 看中心 dispatcher、`sub` 看展开的算术序列、`bcf` 看无关块和谓词），并把「字符串路径」（`.rodata`/解码循环）和「控制流路径」（`.text`/CFG）分开标注——一个函数可能同时用两者，但证据位置不同。

## 踩坑 / 速查

### IDA 常见误区

| 现象 | 正确解释 |
| --- | --- |
| IDA 的 Strings 中没有完整明文 | 可能是字符串保护；继续找密文数组和解码循环 |
| 找不到 `decode_secret` | `static` 函数可能被内联、拆分或被优化掉 |
| `NewStringUTF` 不在 Imports | 可能通过 C++ wrapper、JNIEnv 函数表或间接调用 |
| F5 伪代码很乱 | 先修正函数边界、调用约定和类型，再结合汇编/图视图 |
| 只有少量 `Java_` 导出 | 可能使用 `RegisterNatives` 动态注册 |
| 不同 ABI 地址不同 | 每个 SO 是独立二进制，地址、CFG 和哈希必须分 ABI 记录 |
| release 看起来更简单/更乱 | 优化、strip、LTO、编译选项不同，不等于 OLLVM |
| 看到 `xor/eor` 就认定是字符串加密 | XOR 也常用于校验、哈希、位运算和业务逻辑，必须结合数据流和字符串 sink |
| 把 `_ReadStatusReg(TPIDR_EL0)+40` 当 key | 那是 stack canary；真正的 key 是 `mov w8, #0x5a` |

### 工具坑

| 现象 | 处理 |
| --- | --- |
| jadx（命令行）不在 PATH，脚本跳过转储 | 本路线用图形界面 `%USERPROFILE%\.local\share\jadx\bin\jadx-gui.bat`（双击或运行即可，不依赖 PATH）；命令行 `jadx.bat` 属 CLI 路线 |
| Fernflower 报缺少 dex2jar | APK/DEX 转 JAR 需要 dex2jar；简单 Java 观察直接用 jadx-gui |
| IDA 打开的 SO 和文档地址对不上 | 先 `Get-FileHash` 对哈希；换 APK/release/ABI 后地址必须重新定位，不能套用 `sub_24FD4`/`0x14db9` |
| 只打开 SO 看不到 `XOR_BLOB` | 它在 `classes*.dex` 里，不在 SO；Java 层归 jadx-gui 管 |
| LLDB 断点未命中 | 确认 debug APK、ABI 匹配、模块已加载 |

### 大型 APK 的最小报告模板

```text
APK 名称/版本：
APK SHA-256：
是否 split/bundle：
目标 ABI：
SO 路径和 SHA-256：
加载库的 Java 类：
JNI 绑定方式：命名导出 / RegisterNatives：
字符串存储：DEX / .rodata / assets / 其他：
解码算法和 key：
明文首次出现的函数/调用边界：
明文 sink：UI / 日志 / 网络 / 文件：
是否观察到 OLLVM：
OLLVM 证据：dispatcher / substitution / bogus CFG / 无：
```

结论：当前项目分两条线分析——jadx-gui 找到 Java XOR 字段和 JNI 调用关系，IDA 分析 `libollvmlab.so` 中的 JNI 入口、native XOR 解码和 `nativeOpaque` 控制流。`XOR_BLOB`、`XOR_KEY`、循环和 `StringBuilder` 是字符串保护的特征；OLLVM 的特征应在 native `.text` 的 CFG 和指令结构中寻找，而不是在这些 Java 字段名中寻找。
