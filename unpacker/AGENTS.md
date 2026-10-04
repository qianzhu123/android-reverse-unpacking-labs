# unpacker · 项目文档（给智能体）

> 用途：新会话要动这个子项目时，把本文件整份贴给智能体即可开工。
> 完整说明见本目录 `README.md`。

## 这是什么

**统一解固工具**：聚合 `360jiagu` / `upx_practice` / `ajiami` 三个练习工程的检测器与解壳器，
提供「**判定 → 路由解固 → 两级验证**」一条链。**只读复用**——`labs.py` 按文件路径加载各 lab 模块，
**不复制、不修改**任何 lab 代码；本工具的失败会反过来暴露 lab 接口变更（跨工程回归即为此兜底）。

**诚实定位**：针对**本仓库已建模壳种**的统一判定+解固器，**不是**万能脱壳器。
未知输入按仓库纪律降级为 `疑似`（须动态 trace）或 `未见已知加固特征（≠未加固）`——
**绝不假装能脱、绝不输出"未加固"的全称否定**。

## 目录

```
unpacker/
├── labs.py         ★ 只读桥接层：按文件路径加载各 lab 模块（无包式 import，互不污染）
├── main.py         ★ exe 入口：无参数=开 GUI；CLI 子命令 analyze / unpack / regression
├── gui.py          tkinter + tkinterdnd2 真拖放界面
├── analyzer.py     统一判定入口（SO 走 360+UPX 双检测器交叉验证；APK/dex 走 ajiami）
├── unpack.py       解固入口：判定 → 路由 → 两级验证（--pristine → byte-exact）
├── regression.py   全仓库混淆矩阵：19 样本 × 双向断言 + SO 检测器交叉验证
├── build_exe.py    PyInstaller 打包（单 exe + GUI + 图标 + 三 lab tools 内置兜底）
├── make_icon.py    生成 app_icon.ico
└── dist/unpacker.exe   构建产物（exe 归属 unpacker/ 内部，仓库根零残留）
```

## 两种用法

```bash
# ① 源码形态（在仓库根执行）
python unpacker/analyzer.py 360jiagu/samples/so/libtarget_360_variant.so      # 判定（只读体检）
python unpacker/unpack.py   360jiagu/samples/so/libtarget_360_variant.so \
       --pristine 360jiagu/samples/so/libtarget_orig.so                        # 解固（给黄金样本→逐字节验证）
python unpacker/regression.py                                                  # 全仓回归 => 19/19 通过, 交叉 4/4
# 子模块也可直接跑：analyzer.py / unpack.py / regression.py

# ② 单文件 exe（GUI 主形态，无黑框）
python unpacker/build_exe.py    # PyInstaller -> unpacker/dist/unpacker.exe（--noconsole）
# 双击 = 开 GUI；同一 exe 也能当 CLI：unpacker.exe analyze|unpack|regression …
```

**exe 的仓库定位**（解固路由依赖三个 lab 模块）：`exe 所在目录向上找` > `ANDROID_REVERSE_LABS` 环境变量 >
`--repo <仓库根>` > exe 内置兜底副本。单独分发时产物默认写在**被解固文件同目录**。

## 路由表（判定结论 → 解法 → 验证）

| 判定结论 | 解法 | 来源 lab | 验证 |
|---|---|---|---|
| 标准 UPX / 360 壳（SO） | `upx -d` 直接解 | 通用 | e_type 外逐字节 |
| ★ 变种 360 壳 | 候选 token `upx -t` 实证 → 全部还原 → `-d` | `solve_360.py` | + 锚点 |
| ★ 变种 UPX 壳 | 同上 | `solve_variant.py` | + 锚点 |
| 已加固：DEX 整体加密（一代） | payload 解密还原 dex | `unpack_v1.py` | sha256 / 锚点 |
| 已加固：类抽取（二/三代） | `AJMT` 侧表回填 `insns` | `unpack_v2.py` | sha256 / 空方法率 |
| 疑似 VMP / B13 / Java2CPP | **拒绝解固**（认知边界：须动态 trace） | — | — |
| 未见已知加固特征 | **拒绝解固**（≠未加固） | — | — |

## 关键事实与坑

- **upx 版本**：优先用 **PATH 里的 upx**（本机 5.2.1 能解开仓库全部标准/变种样本），没有才回退 lab 自带 `upx.exe`（4.2.4 基线）。
- **`UPX` 环境变量坑**：upx 自身会把名为 `UPX` 的环境变量当选项串解析——设成 exe 路径会让 upx 报
  `invalid string ... in environment variable 'UPX'`。故 `unpack.py` 调 lab solve 前会**摘掉进程 env 的 `UPX`**，改走 `--upx` 显式参数。
- **产物命名**：`<样本名>_unpacked.so`（ELF）/ `_unpacked.dex`（APK）；`-o <目录>` 或 GUI 可改；已存在自动加 `_1/_2`，
  **不静默覆盖**。输出约定：`[!]=失败/告警`、`[*]=步骤`、`[+]=成功`，每个结论附认知边界提示。
- **无控制台场景**：lab 脚本的 subprocess 调用被 GUI 统一加 `CREATE_NO_WINDOW`（不改 lab 代码），CLI 型错误改走弹窗。

## 回归（改任何 lab 后必跑）

```bash
python unpacker/regression.py     # 19 样本双向断言 + SO 检测器交叉 4/4；exit 0 = 全绿
```
失败即说明某 lab 的检测器/解壳接口被改动，回到对应 lab 排查。

## 上下文入口

本目录 `README.md`（完整）；被聚合的 lab：`../360jiagu/`、`../upx_practice/`、`../ajiami/`；仓库级：`../README.md`、`../METHODS.md`
