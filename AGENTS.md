# android-reverse · Agent 上手文档

> 用法：新会话前把本文件内容贴给 agent，或直接说「读 `D:\code\android\reverse\AGENTS.md`」，
> 即可免去解释与探索。本项目的历史决策详见 `~/.claude/.../memory/android-reverse-*.md`。

## 定位

Android **逆向 / 脱壳实验室合集**。两类 lab：**自建、可 byte-for-byte 复现**的拆壳 lab，
以及**外部真实目标**的动态逆向 lab。是学习+教学仓库，**不是**生产应用。

## 技术栈 / 运行时

- 无单一语言栈：Python 3（检测/脱壳脚本）、C/JNI（自建样本）、Gradle+NDK（构建），
  以及 Frida / adb / Android SDK 模拟器（动态分析）。
- **本机必需运行时**（非标准路径，靠 env 解析）：
  - `ANDROID_HOME` / `ANDROID_SDK_ROOT` → SDK（含 build-tools 的 `dexdump`）
  - NDK 的 `llvm-*` binutils 在 PATH（**裸 `readelf`/`objdump`/`strings`/`nm` 不存在**，必须用 `llvm-` 前缀）
  - 项目级 `reverse/.venv`（**frida 装这里，不装全局**；版本锁 **16.5.9**）

## 目录地图

```
reverse/
├── README.md          ← 总览 +「Real-target lab environment setup」环境复原节
├── PROMPT.md          ← 模板A：自建可复现 lab 的生成器
├── PROMPT-REAL.md     ← 模板B：外部真实目标 lab 的生成器
├── METHODS.md         ← 可复用方法集（静态判据篇 + 动态分析篇）
├── 360jiagu/ upx_practice/ ajiami/ ollvm/   # 自建 lab 群（静态、拆壳/混淆）
├── uncrackable/       ← 真实目标 lab 群（动态、oracle 验证）
│   ├── TUTORIAL.md    ← 学习入口（l1→l2→l3 课程线）
│   ├── l1/ l2/ l3/    （l3 为 WIP，动态未通过）
│   └── tools/         共享 hook_run.py + frida-server
└── unpacker/          ← 统一脱壳工具（含 exe 构建）
```

**别乱动**：各 lab 的 `pristine/`（基线/来源记录）、`samples/`（样本，多为 gitignored）。

## 怎么跑

- **自建 lab**：`cd <lab>` 后照其 `SCRIPT.md`。示例：`python tools/detect_360.py samples/so/libtarget_360.so`
- **真实目标 lab**：先按 `README.md`「Real-target lab environment setup」起模拟器+frida-server，
  再 `cd uncrackable/l1 && ../../.venv/Scripts/python.exe ../tools/hook_run.py --package owasp.mstg.uncrackable1 --script frida/solve.js`

## 关键约定（铁律）

1. **零绝对路径**：脚本/配置/文档里禁止 `D:\` `C:\Users\` `/d/`；工具链四级解析（CLI>env>build/env.sh>自动探测）。唯一例外：文档里的 `cd` 示例。
2. **三路线纯度**：每个 lab 的 `SCRIPT.md`（本仓库工具）/`CLI.md`（通用命令，禁 `python tools/*.py`）/`GUI.md`（图形化，禁脚本）各自只用自己的手法。
3. **第三方样本零入库**：真实目标的 apk/so/dex **不提交**，只留 sha256 + 来源 + 结论（`PROMPT-REAL.md` 授权红线）。
4. **自建 lab 必须可复现**：样本自建、`pristine/` 基线、正负样本双向回归。
5. **认知边界**：结论必须写"未见已知特征（≠ 无）"+ 未覆盖方案清单；禁止"clean/未加固"。

## 常见坑

- **frida 版本必须一致**：host（`.venv`）与 device（frida-server）都锁 **16.5.9**，否则 `Java is not defined`。
- **Git Bash 路径改写**：`adb push /data/...` 会被改成 `C:/Program Files/Git/...` → 用 `MSYS_NO_PATHCONV=1`。
- **sdkmanager 在 JDK26 下报版本错** → `SKIP_JDK_VERSION_CHECK=1`。
- **别新建近平行目录**：同一目标家族（如 UnCrackable）放**一个文件夹**下的子级（`uncrackable/l1|l2|l3`），不并列成 `foo-l1 foo-l2`。
- **`dexdump` 随 build-tools 下发**，不在 NDK；反汇编优先 `llvm-objdump`。

## 上下文入口

- 总览/环境：`README.md`
- 真实目标学习入口：`uncrackable/TUTORIAL.md`
- 方法沉淀：`METHODS.md`
- 生成新 lab 的模板：`PROMPT.md`（自建）/ `PROMPT-REAL.md`（真实目标）

## 当前状态

- 主线：自建 lab（360jiagu/upx_practice/ajiami/ollvm）已完成；`uncrackable/l1`、`l2` 已解（oracle 通过）；**`l3` 为 WIP**（卡在构造函数级反篡改看门狗，攻关方向见 `uncrackable/l3/SCRIPT.md` §8）。
- 易变的进度细节见 memory：`android-reverse-*`。
