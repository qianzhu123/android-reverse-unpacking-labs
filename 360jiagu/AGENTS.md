# 360jiagu · 项目文档（给智能体）

> 用途：新会话要动这个子项目时，把本文件整份贴给智能体即可开工，无需再探索仓库。
> 它自包含——命令、阈值、预期输出、判读、坑都在这；需要更细的教学版再看 `SCRIPT.md`。

## 这是什么

把「**360 加固 native 层 = 改版 UPX**」的**判定 + 脱壳**做成可复核的练习工程。
样本是本机 NDK **自建**、加壳前后同源，脱壳结果可与黄金 `.so` **逐字节对照**。
仅覆盖 **native（.so）层**，不含 dex 层加固。

**建模口径**：360 早期 native 保护基于 UPX 改写（史实）。本工程用「改特征」来建模——
魔数 `UPX!` → `JG!!`、明文标记 `360 4.24`。**脱壳机制（Stub→运行期解压→跳 OEP→ELF Fix）
与真实 360 一致**，差异只在被改写的特征。

## 目录

```
360jiagu/
├── upx.exe                 UPX 4.2.4（默认；UPX=<路径> 可覆盖）
├── src/target.c            样本源码（JNI_OnLoad/RegisterNatives/check_license/blob_selfcheck + 锚点）
├── src/policy_inc.h        AUTO-GENERATED 策略表（体积锚点，勿手改）
├── build/locate.sh         ★ 工具链四档探测（NDK/UPX/python）
├── build/build_android.sh  NDK 编译原始 .so（先跑 gen_policy.py）
├── build/pack.sh           生成标准 + 变种样本
├── tools/detect_360.py     ★ 结构判定（未加壳/标准360/变种360，--verify）
├── tools/solve_360.py      解法 A 自动化（特征修复 + upx -d + 锚点校验）
├── tools/dump_fix.py       解法 B：内存 dump → 重建 ELF
├── tools/make_stripped_so.py / make_360_variant.py  生成对照样本
├── tools/check_so_samples.py  ★ B13 双向回归断言
├── tools/reset_lab.py      ★ status/restore/backup
├── tools/anchors.txt       脱壳后应找回的锚点
├── samples/so/             ★ 分析对象一律住这里（不平铺根）
├── pristine/so/            samples 的镜像 + manifest.json（勿手改）
└── analysis_output/        脚本产出（可删）
```

## 样本一览（判定的基准）

| 文件 | e_type | `UPX!` | `JG!!` | `upx -t` | 用途 |
|---|---|---|---|---|---|
| `samples/so/libtarget_orig.so` | ET_DYN(3) | 0 | 0 | FAIL | 原始 SO，**黄金对照** |
| `samples/so/libtarget_360.so` | ET_EXEC(2) | 4 | 0 | OK | **标准 360**，可自动解包 |
| `samples/so/libtarget_360_variant.so` | ET_EXEC(2) | 0 | 4 | FAIL | **变种 360**，需手工/动态脱壳 |
| `samples/so/libtarget_stripped.so` | ET_DYN(3) | 0 | 0 | — | **B13 正样本**（节头剥离） |
| `samples/so/libtarget_orig_arm64.so` | ET_DYN(3) | 0 | 0 | — | ARM64 对照 |

⚠️ 官方 UPX 4.2.4 不能直接打包 Android `ET_DYN` `.so`；故标准/变种样本以 `linux/arm ET_EXEC`
打包——**脱壳机制相同**，仅 `e_type` 不同。原始 `.so` 仍是真 ARM32 `ET_DYN`。

## 判定：结构特征（判据 + 阈值 + 实测值）

判据**只认结构**，绝不靠文件名/单个字符串。本工程实跑对照：

| 特征 | orig | 标准360 | 变种360 | B13 | 原理/阈值 |
|---|---|---|---|---|---|
| `e_shnum` | 24 | **0** | **0** | **0** | 加壳/剥节头 → IDA 看不到 `.text/.rodata` |
| 整文件熵 | 5.011 | **7.598** | **7.598** | 5.010 | 正常代码 4~6.5；**>7.0 = 压缩/加密** |
| 大解压缓冲段 | 无 | **0x1000→0xD0A0 (13.0×)** | 同左 | 无 | UPX0：文件近空、内存很大；**memsz≥32KB** 排除 `.bss` |
| `e_entry` | 0x0(段首) | **0x11684(stub 段内)** | 同左 | 0x0 | 入口先跑解压代码 |
| 总 memsz/文件 | 1.03× | **3.90×** | 3.90× | 1.03× | 运行期解压出远多于文件的内容 |
| `UPX!` 魔数 | 0 | **4** | 0 | 0 | 变种改写掉魔数 |
| 尾部 `sz_unc` | 0 | **43888** | 43888 | 0 | UPX 尾部记录解压后大小 |
| 明文 `360` | 脱壳后 | **文件内 `360 4.24`** | 同左 | 无 | 360 标记（lab 注入，仅命名用） |

```bash
# 判定（标准/变种/未加壳三态；--verify 附实证）
python tools/detect_360.py samples/so/libtarget_360.so
#   => 标准 360：综合得分 16，UPX! 保留，upx -t 通过
python tools/detect_360.py samples/so/libtarget_360_variant.so
#   => 变种 360：同分但魔数 JG!!，upx -t 失败
python tools/detect_360.py samples/so/libtarget_stripped.so
#   => [B13] 疑似 SO 加壳 / 自实现 Linker（节头被剥离）— 需人工进 ELF 层确认
```

**B13 判据（强信号、与"未加壳"严格区分）**：`e_type==ET_DYN(3) && e_shnum==0 && 存在可执行 PT_LOAD`。
正常 NDK `.so` 永远带完整节头；自定义 Linker 按 Program Header 装载、不写标准节头。
B13 只输出"**疑似**"，不下确定结论。

## 脱壳

- **解法 A（`solve_360.py`）**：特征修复 → `upx -d` → 锚点校验。适用「只抹特征、Stub/控制流未动」的变种。
- **解法 B（`dump_fix.py`）**：运行期内存 dump → 重建 ELF。通用主力路线，Stub/压缩参数被改也走这条。

```bash
# 解法 A：脱壳并立即与黄金样本逐字节对照
python tools/solve_360.py samples/so/libtarget_360_variant.so analysis_output/out.so \
    --pristine pristine/so/libtarget_orig.so
#   => byte-for-byte identical to golden baseline ✓
```

## 验证标准

- **逐字节对照**：脱壳产物 vs `pristine/so/libtarget_orig.so`（`cmp`/sha256 一致）。
- **锚点找回**：`tools/anchors.txt` 里的签名串在产物中全部命中。
- **B13 双向回归**：`python tools/check_so_samples.py` —— `stripped` **必触发**、`orig`（节头完整）**必不触发**，且原有 UPX/360 判定不被破坏。失败打印红字、退出非零。

## 认知边界（写结论时必须带）

「未见已知特征」**≠「未加固」**。静态不可定性、须动态 trace 的三类：
① SO VMP（解释器只是普通大函数，ELF 正常）；② 不走汇聚形态的自定义 VMP；③ 精巧字符串加密（不在常量池）。
兜底话术永远是「**未见已知加固特征（≠未加壳）**」+ 上面的不覆盖清单，**禁止**写"未加固/没问题"。

## 反复练习 / 重置

```bash
python tools/reset_lab.py status     # 看样本与 pristine 是否一致
python tools/reset_lab.py restore    # 恢复样本 + 清 analysis_output
python tools/reset_lab.py backup     # 重新生成 pristine 基线
python tools/check_so_samples.py     # B13 双向回归
```

## 铁律与坑

- **零绝对路径**：脚本/配置/文档禁 `D:\`/`C:\Users\`；工具链四档解析（CLI>env>build 配置>自动探测），工程根由脚本位置推导。唯一例外：文档里的 `cd` 示例。
- **`UPX` 环境变量会被 upx 当成选项串解析**：用 `UPX=<路径>` 走本工程的探测，别直接 `export UPX=...` 丢给 upx 二进制。
- **B2 是故意保留的错误示范**（"类数 ≤ 8 判壳"，在 `app_orig` 上必误报）——绝对值阈值必然翻车，只有交叉校验是硬的。
- **样本=需求=测试集**（自建样本固有循环论证）→ 强制配 B13 双向断言。

## 上下文入口

- 教学版（含五件套知识点、真实输出）：`SCRIPT.md`（脚本）/ `CLI.md`（命令）/ `GUI.md`（IDA/Ghidra/binwalk）
- 仓库级：`../README.md`、`../PROMPT.md`（生成新 lab 的模板）、`../METHODS.md`（通用方法集）
