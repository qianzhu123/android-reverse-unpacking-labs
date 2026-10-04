# ajiami · 项目文档（给智能体）

> 用途：新会话要动这个子项目时，把本文件整份贴给智能体即可开工。自包含——判据、脚本、命令、预期输出、坑都在。
> 教学版（三代演化 + 字节偏移指南 + 负样本工程）见 `SCRIPT.md` / `CLI.md` / `GUI.md`。

## 这是什么

把 Android **DEX 加固（类爱加密）的三代演化**全链路搬到本地：**原理 → 结构特征 → 判定 → 脚本脱壳 → 验证**，
做到可编译、可量化、可复现。壳（`shell/`）与业务 App（`app/`）**都本地自造**，脱壳结果与黄金 dex **逐字节对照**。

**三代模型**：一代＝整体 DEX 加密；二代＝全量类抽取（方法体 `insns` 清零，存侧表）；
三代＝**选择性**抽取（整体空率低、但存在局部 100% 空方法类）。另有字符串混淆变种 + DEX VMP 教学模型。

**三条硬约束**：① 先确定性规则、不依赖 LLM；② 结论全部落在**结构特征**（偏移/空方法率/熵/缺失类）；
③ 工具链外置（`build/locate.sh` 四档探测）。

## 目录

```
ajiami/
├── shell/         壳源码（代理 Application / 解密 / 类加载 / 反射换回）
├── app/           业务 App 源码（含锚点串 AJM-ANCHOR-0000..0010）
├── neg/           负样本源码（多 dex / 高熵资源 / 合法 native）
├── vmp/           DEX VMP 教学模型源码
├── build/         locate.sh / env.sh / pack.sh / build_vmp.sh / build_negatives.sh
├── tools/detect.py          ★ 结构判定 B1–B13
├── tools/unpack_v1.py       一代整体加密脱壳（取 payload → 解密 → 写 dex）
├── tools/unpack_v2.py       二/三代类抽取脱壳（按 AJMT 侧表回填 insns）
├── tools/verify.py          ★ 三项自检（sha256 / 锚点 / 字节差 + 首偏移）
├── tools/check_negatives.py ★ 双向回归断言
├── tools/walkthrough.py     字节偏移指南（脚本→手动的桥）
├── tools/reset_lab.py       status/restore/backup
├── samples/apks/ samples/dex/ samples/payloads/  ★ 分析对象
├── pristine/  logs/  analysis_output/
```

## 样本清单

| 样本 | 代次/类型 | 黄金样本（`--pristine`） |
|---|---|---|
| `samples/apks/app_orig.apk` | 未加固基线 | — |
| `app_packed_v1.apk` | 一代·整体加密 | `samples/dex/classes_orig.dex` |
| `app_packed_v2.apk` | 二代·全量抽取 | `samples/dex/classes_merged_orig.dex` |
| `app_packed_v3.apk` | 三代·选择性抽取 | `samples/dex/classes_merged_orig.dex` |
| `app_packed_v2_variant.apk` | 二代·字符串混淆变种 | `build/variant/merged_orig_variant.dex` |
| `app_vmp.apk` | DEX VMP 教学模型（认知边界） | — |
| `app_so_packed.apk` | SO 加壳 / 自实现 Linker（B13） | — |
| `neg_multidex / neg_highentropy / neg_native .apk` | 负样本 | — |

## 判据总表（A / B1–B13，三处共用同一 ID：`detect.py` 输出 / `check_negatives.py` 断言 / 文档）

**分野**：**A＝朴素字符串**（`ijiami`/`ProxyApplication` 等）——易被混淆绕过，**仅作对照、永不单独定性**（变种样本已实证 A 全灭）；
**B＝结构/统计**——**定性唯一依据**。

| 代号 | 判据 | 阈值 | 参与定性 | 说明 |
|---|---|---|---|---|
| B1 | 高熵 asset | 熵 > 7.5 | 一代条件之一 | — |
| B3 | 全类空方法率 | > 40% | 二代独立定性 | 有 code_item 但 insns 全 0 |
| B3\* | 整体空率低但存在局部 100% 空方法类 | 单类下钻 | 三代独立定性 | — |
| B4 | 代理 Application（小 Application + 动态加载类） | 方法数 ≤ 8 | 一代辅助 | — |
| B6 | App 自身包业务类全缺失 + 高熵 asset | 缺失=全部 | 一代条件之一 | — |
| B7 | Manifest 声明类在所有 dex 并集中缺失 | 缺失 ≥ 1 | 强证据（须配 B1/B6） | 对多 dex 真实 App 会误报，须补全相对类名 |
| B8 | 已知壳厂商 SO 名单 | 名单命中 | Native 侧信号 | 须进 ELF 确认 |
| B9 | SO 熵异常 | > 7.5 | **不参与定性** | 仅提示人工 |
| B10 | 反分析痕迹串 | 串命中 | **不参与定性** | 仅提示人工 |
| B11 | 多极短方法体汇聚调用同一大方法 | 汇聚形态 | 疑似 DEX VMP | B3 对 VMP 恒失效时的补偿 |
| B12 | native 方法占比 | ≥ 30% | 疑似 Java2CPP | — |
| B13 | SO 的 ELF 结构异常（节头剥离） | e_shnum=0 | 疑似 SO 加壳/自实现 Linker | — |

**组合规则**：一代 = B1+B6+B7(+B4)；二代 = B3；三代 = B3\*；VMP 靠 B11。
⚠️ **B2 故意保留为错误示范**（"类数 ≤ 8 判壳"，在 `app_orig` 上必误报）、**B5 占位未用**——
两个"洞"是教学点：**绝对值阈值必然翻车，只有「Manifest 声明 vs dex 实有」的交叉验证是硬的**。

## 判定 → 脱壳 → 验证（典型闭环）

```bash
# ① 判定：这是哪一代？（只读结构体检）
python tools/detect.py samples/apks/app_packed_v1.apk
#   => hardened — whole-DEX encryption (generation 1)

# ② 脱壳（按代次选脚本），--pristine 给黄金样本
python tools/unpack_v1.py samples/apks/app_packed_v1.apk analysis_output/out.dex \
    --pristine samples/dex/classes_orig.dex
#   => byte-identical to golden ✓

# ③ 验证：sha256 / 锚点 / 字节差 + 首偏移
python tools/verify.py analysis_output/out.dex samples/dex/classes_orig.dex
#   => "no differences" 或列出差异块

# ④ 双向回归（负样本必须不被误判）
python tools/check_negatives.py
```

**定位代理组件（不靠类名）**：`dexdump -d` 圈 `extends Application` 候选 → `llvm-strings` 快筛谁含
`DexClassLoader/reflect/getAssets` → 看 `attachBaseContext` 的 invoke 链形状（壳会「读载荷→解密→落地→类加载→反射换回」）。
完整方法见仓库根 `METHODS.md`。

## 验证标准

- **逐字节**：还原 dex 与黄金样本一致（sha256 + `cmp`）。
- **锚点**：业务源码预埋 `AJM-ANCHOR-0000..0010`（11 个）计满 11 才算数。
- **双向回归**：`check_negatives.py` —— 正向（真壳样本必判为对应代次）+ 负向（`neg_*` 必不判为加固、不触发指定误报规则），失败红字退出非零。

## 认知边界

「未见已知特征」**≠「未加固」**。不覆盖：SO VMP / 不走汇聚形态的 VMP / 精巧字符串加密——静态不可判、须动态 trace。
兜底话术：「**未见已知加固特征（≠未加固）**」+ 不覆盖清单；**禁止**"未加固"。

## 反复练习 / 重置

```bash
python tools/reset_lab.py status|restore|backup   # restore 恢复样本+清 analysis_output
python tools/walkthrough.py                        # 字节偏移指南（手动复现入口）
```

## 铁律与坑

- **零绝对路径**；工具链四档解析；工程根由脚本位置推导；唯一例外：文档 `cd` 示例。
- **采样值/字节大小这类绝对值阈值必然翻车**（B2 教训）——判据要用**交叉验证**（Manifest vs dex 实有）。
- **负样本是用来证伪判据的**：至少一条真实误报（B7 的 `.MainActivity` 相对类名）是负样本当场挖出来的，不是推理想到的。
- **多 dex 必用并集**：只看主 dex 会把多 dex 真实 App 误判、且只还原部分 dex 还报成功。

## 上下文入口

- 教学版：`SCRIPT.md`（脚本）/ `CLI.md`（命令）/ `GUI.md`（jadx/binwalk/010 Editor）
- 仓库级：`../README.md`、`../PROMPT.md`、`../METHODS.md`；统一工具：`../unpacker/`
