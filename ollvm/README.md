# OLLVM Lab：Android 字符串保护与混淆分析靶场

这是一个只包含自有示例代码的 Android 逆向练习项目。项目用同一个应用展示四种情况：Java 明文、Java 层 XOR 字符串、JNI 层 XOR 字符串，以及一个用于 OLLVM 对照的简单 native 控制流函数。

## 先看结论

仓库已经包含可直接分析的 APK，默认不需要重新编译：

| 产物 | 路径 | 用途 | 当前事实 |
| --- | --- | --- | --- |
| Debug APK | `samples/apks/app-debug.apk`（归档副本；构建产物在 `app/build/outputs/apk/debug/`） | 静态分析、安装、Frida/LLDB 调试 | `debuggable=true`，适合动态取证 |
| Release APK | `samples/apks/app-release-unsigned.apk`（归档副本；构建产物在 `app/build/outputs/apk/release/`） | 对比 release 打包结果 | 未签名，`minifyEnabled=false`，不是 OLLVM 产物 |
| Native 库 | APK 内的 `lib/<abi>/libollvmlab.so` | 分析 JNI 和 native 控制流 | 当前由普通 NDK Clang 编译 |

当前版本的“保护”是源码级 XOR 和运行时解码，不是密码学意义上的加密。`ollvm/toolchains/` 只提供外部 OLLVM fork 的接入说明，`app/build.gradle` 没有启用 `-mllvm -fla/-sub/-bcf`；因此不能把现有 APK 称为“已经完成 OLLVM 混淆的 APK”。

## 已有样本中的四个按钮

| 样例 | 代码位置 | 静态分析结果 | 运行时结果 |
| --- | --- | --- | --- |
| Java 明文 | `MainActivity.java` 的 `plain` 回调 | 完整字符串直接进入 DEX 的 `const-string` | 点击后直接显示/写入 logcat |
| Java XOR | `XOR_BLOB`、`XOR_KEY` 和 `xor` 回调 | DEX 中看到字节数组、key 和 XOR 循环，可手工还原 | `StringBuilder` 中生成明文 |
| JNI XOR | `native-lib.cpp` 的 `decode_secret` | APK 的 SO 中通常只有密数字节；JNI 导出函数和 XOR 指令仍可定位 | `NewStringUTF` 前生成完整明文 |
| Native 控制流基线 | `nativeOpaque` | 可观察分支、循环和算术指令 | 输入固定为 `7`，输出用于对照 OLLVM |

这四个样例故意放在同一个 APK 中，便于比较“代码放在哪里”和“明文何时出现”。完整的区别、优缺点和逆向观察点见 [`SCRIPT.md`](SCRIPT.md)「知识点」章。

## 快速开始：直接分析已有 APK

在 PowerShell 中执行：

```powershell
cd D:\code\android\reverse\ollvm
$apk = (Resolve-Path .\samples\apks\app-debug.apk).Path
Get-FileHash $apk -Algorithm SHA256
.\tools\analyze-apk.ps1 -Apk $apk -Out analysis_output
```

重点产物：

- `analysis_output\apktool\AndroidManifest.xml`：Manifest、资源、smali 和按 ABI 解出的 SO；
- `analysis_output\jadx\sources`：jadx 反编译的 Java（若 jadx 已加入 PATH）；
- `analysis_output\aapt2-badging.txt`：包名、启动 Activity、ABI 和 debug 标记。

检查 arm64 native 库：

```powershell
.\tools\inspect-native.ps1 `
  -So .\analysis_output\apktool\lib\arm64-v8a\libollvmlab.so
```

如果只想快速阅读 Java，也可以直接调用本机已安装的 jadx：

```powershell
& "$env:USERPROFILE\.local\share\jadx\bin\jadx.bat" `
  -d .\analysis_output\jadx .\samples\apks\app-debug.apk
```

`analysis_output` 是生成目录，已加入 `.gitignore`，不会成为源码的一部分。

## 什么时候才需要重新构建

只有在修改了 Java/C++、需要新的 ABI，或要接入自己的 OLLVM fork 时才构建：

```powershell
.\build\build.ps1 -Variant debug
.\build\build.ps1 -Variant release
```

安装 debug APK 到已授权的测试设备是可选步骤：

```powershell
.\build\build.ps1 -Variant debug -Install
.\tools\logcat.ps1
```

构建脚本会优先使用项目内的 Gradle 8.13 和 `bootstrap.ps1` 中配置的 JDK 21。换机器时先检查 `local.properties.example` 中的 SDK/NDK 路径。当前仓库中的 APK 是已有构建产物，APK 的实际 Manifest 和哈希应优先于“重新构建后可能变化的结果”。

## 学习路线

1. 阅读 [`SCRIPT.md`](SCRIPT.md)，先用脚本跑通全链路并建立“明文、字符串保护、控制流混淆”三个概念的边界。
2. 阅读 [`CLI.md`](CLI.md)，用 PowerShell 与 NDK `llvm-*` 命令逐字节复现每一步。
3. 阅读 [`GUI.md`](GUI.md)，用 JADX 看 Java 层、用 IDA 分析 SO（伪代码、地址链、JNI 桥接、CFG 差分）。
4. 三份文档共用同一套章节骨架（概述 → 环境与工具 → 知识点 → 静态分析 → 动态分析 → 对照验证 → 踩坑/速查），按手头工具就近取用；OLLVM 单变量对照实验的矩阵与结论模板在 SCRIPT.md「对照验证」章。

## 工具与路径

- Android SDK：由 `ANDROID_HOME` / `ANDROID_SDK_ROOT` 指向；本机示例路径是 `D:\tools\Security\Reverse\Android\dev\AndroidSDK`；
- Android NDK：`D:\tools\Security\Reverse\Android\dev\android-ndk-r27d`；
- apktool：`tools/analyze-apk.ps1` 使用本机配置的 apktool 路径；
- jadx：本机常见位置为 `%USERPROFILE%\.local\share\jadx\bin\jadx.bat`，也可以加入 PATH；
- ELF 检查：使用 NDK 自带的 `llvm-readelf`、`llvm-objdump` 和 `llvm-strings`；
- 动态分析：只使用自有 APK、授权设备、`adb`、匹配版本的 Frida Server 和 Android Studio LLDB。

## 安全边界

只在自己编写的 APK、自己拥有的设备和明确授权的测试环境中使用这些方法。XOR 字符串保护和 OLLVM 都不能把客户端秘密变成不可提取的秘密：只要客户端必须得到明文，调试器、Frida、日志或内存取证就可能在运行时拿到它。真实项目应避免把长期有效的密钥放进 APK，改用服务端校验、短期令牌、轮换和最小权限。

## 项目结构

```text
SCRIPT.md / CLI.md / GUI.md            三份平行文档（同一章节骨架，工程根）
samples/apks/                          分析对象 APK（归档副本，哈希见文档）
pristine/                              samples/ 的 sha256 基线备份（reset 的还原源）
app/src/main/java/.../MainActivity.java  Java 入口、明文和 Java XOR 样例
app/src/main/cpp/native-lib.cpp          JNI XOR 与 native 控制流基线
build/                                  构建脚本：build.ps1 / bootstrap.ps1
tools/                                  分析工具：analyze-apk.ps1 / inspect-native.ps1 / logcat.ps1 / reset_lab.py + gradle-8.13（gitignore）
frida/frida-hook.js                     动态 hook 脚本
analysis_output/                        练习产物（解包/反汇编输出，gitignore）
ollvm/toolchains/                       外部 OLLVM fork 接入说明
```

## 反复练习

```powershell
python tools\reset_lab.py backup    # 首次：把 samples/ 备份进 pristine/（含 sha256 清单）
python tools\reset_lab.py status    # 查看样本是否被改动、产物目录是否干净
python tools\reset_lab.py restore   # 还原样本 + 清空 analysis_output/
```
