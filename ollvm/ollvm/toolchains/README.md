# OLLVM 工具链放置位置与识别指南

本目录预留给实验用的 LLVM/OLLVM fork，不把第三方二进制提交到仓库。Android NDK 自带 Clang 负责普通编译；只有支持相应 pass 的 OLLVM fork 才能处理 `-mllvm -fla/-sub/-bcf`。

## 1. OLLVM 在编译链中的位置

```text
C/C++ 源码
  -> Clang 前端
  -> LLVM IR
  -> OLLVM pass（fla/sub/bcf）
  -> 目标指令（AArch64/ARM/x86）
  -> ELF/SO
  -> APK
```

OLLVM 主要改变 native `.text` 的控制流和指令形态。它不会自动处理 Java/Kotlin 的 DEX 字符串，也不会替应用管理密钥。

## 2. 三个常见 pass 的基础和特征

| Pass | 基础概念 | 反汇编/CFG 常见特征 | 不应误判为 |
| --- | --- | --- | --- |
| `-fla` | 控制流平坦化，用 dispatcher/state 变量统一调度基本块 | 中心循环、多路跳转、状态变量、源码分支层级消失 | 普通循环、异常处理或编译器生成的 switch |
| `-sub` | 指令替换，用等价算术/逻辑序列替换简单指令 | `and/or/xor`、移位、加减组合变长，数据依赖增加 | 单纯的 `-O2/-O3` 优化或编译器 peephole 变换 |
| `-bcf` | 虚假控制流，插入诱饵块和无效路径 | 额外谓词、恒真/恒假分支、与结果无关的块，CFG 膨胀 | C++ 异常路径、栈保护和正常错误处理 |

这些只是识别线索，必须与同编译器、同 ABI/API、同优化级别的 baseline 做差分。单凭函数变大、跳转变多或反编译质量下降，不能严谨证明使用了某个 pass。

## 3. 和字符串保护的关系

字符串保护与 OLLVM 可以叠加，但证据位置不同：

- 字符串保护：`.rodata` 中的密文字节、解码循环、key/参数、`std::string`/`NewStringUTF` 或 Java `StringBuilder`；
- OLLVM：`.text` 中的 dispatcher、等价指令序列、诱饵块和复杂 CFG；
- 动态分析：两者最终都要在 UI、日志、JNI 返回值或网络参数中产生/传递明文。

因此，`strings` 看不到完整文本只能说明静态字符串可见性降低，不能单独证明 OLLVM；OLLVM 也不会阻止运行时 hook 读取已经生成的明文。

## 4. 推荐实验顺序

1. 先分析仓库已有 APK，确认 Java 明文、Java XOR、JNI XOR 和 `nativeOpaque` 基线。
2. 准备与 NDK r27d、API level 和目标 ABI 兼容的 fork，并记录 LLVM/OLLVM commit。
3. 先只对 `nativeOpaque` 启用一个 pass，再分别比较 `baseline`、`sub`、`fla`、`bcf`。
4. 保存 clang 命令、pass 参数、ABI、优化级别、SO/APK 哈希和行为输出。
5. 最后再尝试组合 pass，并单独记录体积、性能、崩溃和调试体验。

不要直接覆盖 Android SDK/NDK 自带 clang，也不要把第三方二进制提交到仓库。具体参数名、阈值和函数选择规则以所用 fork 的文档和 `clang --help` 为准。

## 5. 接入方式

可以使用独立 CMake toolchain、`OLLVM_CLANG` 环境变量或 fork 文档要求的 Gradle/CMake 参数。当前项目没有假设某个 fork 的目录结构，也没有在 `app/build.gradle` 中伪造一个“已启用 OLLVM”的配置；接入后应把实际命令和 commit 写入实验记录，而不是把占位说明当作构建事实。

## 6. 最终判断标准

一个可信的 OLLVM 对照结论应同时满足：

- 变体使用了可追溯的 OLLVM/LLVM fork 和明确 pass；
- 与 baseline 的 CFG/反汇编差异符合 pass 的预期特征；
- 相同输入输出保持一致（本项目 `nativeOpaque(7)` 应为 `43`）；
- 已记录体积、性能、调试和反编译成本；
- 没有把字符串保护、OLLVM 或密钥管理混写成同一件事。
