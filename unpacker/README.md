# unpacker — 统一解固工具（判定 / 路由解固 / 跨工程回归）

> 独立工具，聚合三个练习工程（`360jiagu` / `upx_practice` / `ajiami`）的检测器与解壳器。
> **只读复用**：`labs.py` 通过按文件路径加载各 lab 的模块，不复制、不修改任何练习工程的代码；
> 本工具的失败会反过来暴露 lab 接口变更（跨工程回归即为此兜底）。

## 两种使用形态

**① 源码**（开发 / 随仓库使用）：

```bash
python unpacker/main.py analyze 360jiagu/libtarget_360_variant.so
python unpacker/main.py unpack  360jiagu/libtarget_360_variant.so --pristine 360jiagu/libtarget_orig.so
python unpacker/main.py regression
# 各子模块也可直接跑（与之前完全兼容）：
python unpacker/analyzer.py ...   python unpacker/unpack.py ...   python unpacker/regression.py
```

**② 单文件 exe（GUI + CLI 双形态，一次构建出两个）**：

```bash
python unpacker/build_exe.py        # PyInstaller -> unpacker/dist/ 下两个 exe
```

- **`unpacker.exe`（GUI 版，无黑色控制台窗口）**——分发主形态，双击/无参数启动直接开图形界面：
  - 顶部拖放区（全窗口接受拖放）：把 APK / dex / so 拖进去
  - 按钮：**① 判定（只读体检）**、**② 解固（判定→路由→验证）**、
    **选黄金样本（可选）**、**选产物位置**（选中/清除都即时反映在旁边标签上）、
    **③ 回归矩阵**、**清空输出**
  - **产物默认与拖入文件同路径**：`D:\samples\xxx.so` → `D:\samples\xxx_unpacked.so`
    （APK 出 `_unpacked.dex`）；产物已存在时自动加 `_1/_2` 编号，**不静默覆盖**
  - 输出区实时显示 `[!]/[*]/[+]`（失败红 / 步骤灰 / 成功绿），与 CLI 输出一致；「清空输出」只清历史文本，不打断正在运行的任务
  - 长任务后台线程跑，界面不冻结；无控制台场景下 CLI 型错误改走弹窗
- **`unpacker-cli.exe`（CLI 版，带控制台）**：`analyze|unpack|regression ...` 子命令用这个（把文件拖到 exe 图标上则直接判定并回车退出）
- **CLI 子命令不变**：`unpacker.exe analyze|unpack|regression ...`（把文件拖到 exe 图标上则直接判定并回车退出）

exe 的仓库定位（解固路由依赖三个 lab 的模块）：**exe 所在目录向上找** >
`ANDROID_REVERSE_LABS` 环境变量 > `--repo <仓库根>` > exe 内置兜底副本（打包时把三个
lab 的 `tools/*.py` 收进 exe；找不到仓库时判定/解固照常可用，但不保证与 lab 最新代码同步）。
exe 单独分发时产物默认写在**被解固文件同目录**（`<样本名>_unpacked.so/.dex`），不写系统临时目录。
**exe 归属 unpacker/ 内部**：构建产物在 `unpacker/dist/unpacker.exe`，仓库根目录零残留。

## 定位（诚实声明）

「针对本仓库已建模壳种的统一判定 + 解固器」，**不是**万能脱壳器：
对已知壳种给出准确分类与自动解固（有黄金样本时可逐字节验证）；
对未知输入按仓库纪律降级——`疑似`（须动态 trace）或 `未见已知加固特征（≠未加固）`，
绝不假装能脱、绝不输出"未加固"的全称否定结论。

## 快速上手（源码形态，在仓库根执行）

```bash
# ① 判定：拖入任意 APK / dex / so，只读体检，不修改文件
python unpacker/analyzer.py 360jiagu/libtarget_360_variant.so
#   => 类型 elf | [360 检测器] 得分=16 | [UPX 检测器] 得分=16 | 统一结论: ★ 变种 360 加固…

# ② 解固：判定 → 按壳种路由 → 两级验证（byte-exact / anchor-only）
python unpacker/unpack.py 360jiagu/libtarget_360_variant.so --pristine 360jiagu/libtarget_orig.so
#   => 魔数还原(JG!!→UPX! ×4) → upx -d → 8 锚点找回 → 除 e_type 外 0 字节差异 => 解固成功

# ③ 回归：全仓库混淆矩阵（正向防漏报 / 负向防误报 / 检测器交叉防分歧）
python unpacker/regression.py
#   => 19/19 通过, 交叉 4/4 通过
```

## 路由表（判定结论 → 解法 → 验证）

| 判定结论 | 解法 | 来源 lab | 验证 |
|---|---|---|---|
| 标准 UPX / 360 壳（SO） | `upx -d` 直接解 | 通用 | e_type 外逐字节 |
| ★ 变种 360 壳 | 候选 token `upx -t` 实证 → 全部还原 → `-d` | `solve_360.py` | 同上 + 锚点 |
| ★ 变种 UPX 壳 | 同上 | `solve_variant.py` | 同上 + 锚点 |
| 已加固：DEX 整体加密（一代） | payload 解密还原 dex | `unpack_v1.py` | sha256 / 锚点 |
| 已加固：类抽取（二/三代） | AJMT 侧表回填 `insns` | `unpack_v2.py` | sha256 / 空方法率 |
| 疑似 VMP / B13 / Java2CPP | **拒绝解固**（认知边界：须动态 trace） | — | — |
| 未见已知加固特征 | **拒绝解固**（≠未加固） | — | — |

## upx 版本说明（本机实测教训）

本工具**优先用 PATH 里的 upx**（本机 5.2.1 实测能解开仓库全部标准/变种样本），
PATH 没有才回退各 lab 自带的 `upx.exe`（4.2.4，lab 实测基线）。
注意 upx 的环境变量坑：**upx 自身会把名为 `UPX` 的环境变量当选项串解析**，
设成 exe 路径会让 upx 5.2.1 直接报 `invalid string ... in environment variable 'UPX'`。
因此 `unpack.py` 调用 lab solve 前会摘掉进程 env 的 `UPX`，改走 `--upx` 显式参数。

## 文件清单

| 文件 | 作用 |
|---|---|
| `labs.py` | 只读桥接层：按文件路径加载各 lab 模块（无包式 import，互不污染） |
| `main.py` | exe 入口：无参数=开 GUI；CLI 子命令 `analyze` / `unpack` / `regression`；仓库定位、UTF-8、无控制台兜底 |
| `gui.py` | 图形界面：tkinter + tkinterdnd2 真拖放；判定/解固/回归/清空按钮 + 实时输出区 |
| `analyzer.py` | 统一判定入口；SO 管线跑 360+UPX 双检测器互为交叉验证，APK/dex 走 ajiami |
| `unpack.py` | 解固入口：判定 → 路由 → 两级验证（`--pristine` 给黄金样本则 byte-exact） |
| `regression.py` | 全仓库混淆矩阵：19 样本 × 双向断言 + SO 检测器交叉验证；exit 0 = 全绿 |
| `build_exe.py` | PyInstaller 打包脚本：单 exe + GUI + 三个 lab tools/ 内置兜底副本，产物收在 `unpacker/dist/` |

产物默认与输入文件**同目录同名前缀**：`<样本名>_unpacked.so`（ELF）/ `<样本名>_unpacked.dex`（APK）；
`-o <目录>` 或 GUI「选产物位置」可改到指定目录；产物已存在自动加 `_1/_2` 编号，不静默覆盖。
输出约定：`[!]=失败/告警`、`[*]=步骤`、`[+]=成功`；每个结论都附认知边界提示。
