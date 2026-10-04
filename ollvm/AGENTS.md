# ollvm · 项目文档（给智能体）

> 用途：新会话要动这个子项目时，把本文件整份贴给智能体即可开工。
> 教学版（知识点五要素、三方对照、地址链）见 `SCRIPT.md` / `CLI.md` / `GUI.md`。

## 这是什么

**代码混淆 / 字符串保护**的对照练习工程（主题上**不属于**仓库其余"壳/脱壳"范围，故不吃 `PROMPT.md` 模板，但同守三文档+固定布局约定）。
一个 APK 里故意并排装**四种情况**，比较「代码放在哪里」与「明文何时出现」：

| 项 | 值 | 说明 |
|---|---|---|
| Java 明文 | `PLAIN_SECRET=ollvm-lab:static-string` | DEX 常量池直接可见 |
| Java 层 XOR | `JAVA_XOR=JAVA_XOR_SECRET` | Java 运行期解码 |
| JNI 层 XOR | `JNI_SECRET=ollvm-native` | native 运行期解码 |
| `nativeOpaque(7)` | `43` | 控制流对照（非真 OLLVM） |

⚠️ **诚实边界**：当前 APK 是**普通 NDK 编译 + 源码级 XOR 运行时解码**的基线；
`ollvm/toolchains/` 只是外部 OLLVM fork 的**接入说明（占位，未启用）**，
`app/build.gradle` **没有**启用 `-mllvm -fla/-sub/-bcf`。**所以不得称现有 APK「已 OLLVM 混淆完成」**。

## 事实（分析以实际 APK 为准，不重新构建）

- 包名 `com.example.ollvmlab`；启动 Activity `com.example.ollvmlab.MainActivity`
- ABI：`arm64-v8a` / `armeabi-v7a` / `x86` / `x86_64`（每 ABI 一份 `libollvmlab.so`）
- JNI 命名导出：`Java_com_example_ollvmlab_MainActivity_nativeSecret`、`..._nativeOpaque`
- debug APK SHA-256 `06935B0B…DEF045E`；release APK SHA-256 `B02AEF06…3E794CD`
- arm64 debug SO SHA-256 `555B4EE7…A318C2`（383632 字节）
- 已存 APK badging 显示 `compileSdkVersion=36`，而当前 Gradle 配置写 `compileSdk=35`——**视为产物与配置的差异，报告以实际 APK 为准**

## 目录

```
ollvm/
├── samples/apks/app-debug.apk / app-release.apk   默认分析对象（哈希见上）
├── app/         自含 gradle 工程（gradle 根在此）：Java 明文/Java XOR/JNI XOR/nativeOpaque
├── frida/frida-hook.js   Java/native 边界 hook
├── tools/analyze-apk.ps1   apktool+jadx+aapt2 解包
├── tools/inspect-native.ps1 ELF 符号/段/反汇编
├── tools/logcat.ps1        只看 OLLVM_LAB tag
├── tools/reset_lab.py      status/restore/backup
├── build/build.ps1 / bootstrap.ps1  PowerShell 工具链
├── ollvm/toolchains/       外部 OLLVM fork 接入说明（占位）
└── analysis_output/  pristine/
```

## 最小闭环（PowerShell，默认不重建）

```powershell
cd <lab root>
$apk = (Resolve-Path .\samples\apks\app-debug.apk).Path
.\tools\analyze-apk.ps1 -Apk $apk -Out analysis_output        # ① 解包 → apktool/ jadx/ aapt2-badging.txt
$so = (Resolve-Path .\analysis_output\apktool\lib\arm64-v8a\libollvmlab.so).Path
.\tools\inspect-native.ps1 -So $so                            # ② ELF 符号/段/反汇编（见 Java_..._native*）
adb install -r $apk; adb shell am start -n com.example.ollvmlab/.MainActivity
.\tools\logcat.ps1                                            # ④ OLLVM_LAB 日志
#   => PLAIN_SECRET=… / JAVA_XOR=… / JNI_SECRET=ollvm-native / OPAQUE_RESULT=43
frida -U -f com.example.ollvmlab -l .\frida\frida-hook.js --no-pause   # ⑤ 点 JNI/OLLVM 按钮
#   => [nativeSecret] JNI_SECRET=ollvm-native / [nativeOpaque] input=7 result=43
```

## 关键知识点

- **字符串保护五要素** [可验证]：明文在哪（常量池 vs 运行期）、何时出现、用什么解（XOR 密钥/算法）、解的入口（Java `String` 构造 vs JNI 回调）、能否静态抓到。
- **OLLVM 三 pass** [知识框架 + 外部对照]：`-fla` 控制流平坦化（dispatcher/状态变量/中心循环）、`-sub` 指令替换、`-bcf` 虚假控制流。
  **只影响经该 clang/LLVM 流程编译的代码**（C/C++ → LLVM IR → OLLVM pass → 指令 → ELF）；**DEX 字符串不受其保护**。
- **三方对照**：普通版本 / 字符串保护 / OLLVM —— 必须与**未混淆、同编译器、同优化级别、同 ABI** 的版本比较；
  C++ 异常 / 栈保护 / 普通 `-O2/-O3` 也会造成复杂 CFG，**不能凭"一个长函数或几个跳转"断言是 OLLVM**。

## 安全边界（本项目文档明确要求）

只在自己编写的 APK、自己拥有的设备和**明确授权**的测试环境里使用。
**XOR 字符串保护与 OLLVM 都不能把客户端秘密变成不可提取的秘密**——只要客户端必须得到明文，
调试器/Frida/日志/内存取证就能在运行时拿到。真实项目应避免把长期有效密钥放进 APK，改用服务端校验、短期令牌、轮换与最小权限。

## 铁律与坑

- **零绝对路径**；`build/*.ps1` 四档探测工具链；`cd` 示例可用真实路径（唯一例外）。
- 默认**不重新构建**：改 Java/C++、需新 ABI、或接入自有 OLLVM fork 时才 `build/build.ps1`。
- 工具是 **PowerShell**（`analyze-apk.ps1` 等），不是 Python——别按 `python tools/*.py` 去调。

## 上下文入口

- 教学版：`SCRIPT.md` / `CLI.md` / `GUI.md`
- 仓库级：`../README.md`、`../METHODS.md`
