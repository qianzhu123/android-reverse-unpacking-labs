# upx_practice · 项目文档（给智能体）

> 用途：新会话要动这个子项目时，把本文件整份贴给智能体即可开工。自包含——命令、阈值、预期输出、判读、坑都在。
> 教学版（五件套知识点）见 `SCRIPT.md`。

## 这是什么

把「**UPX 壳 + 其特征重写变种**」的**判定 + 脱壳**做成可复核练习工程。
样本本机 NDK **自建**、加壳前后同源，脱壳结果与黄金 `.so` **逐字节对照**。

**建模**：官方 UPX 4.2.4 壳开源；真实对抗里常见**变种**（改 Stub / 抹特征 / 改控制流）。
本工程用 `make_variant.py` 把 `UPX!` 魔数整体换成 `XXXX` 得到变种——**脱壳机制相同**，差异在特征是否被改写。

## 目录

```
upx_practice/
├── upx.exe                 UPX 4.2.4（默认；UPX=<路径> 覆盖）
├── src/target.c            样本源码（JNI_OnLoad/RegisterNatives/check_license/blob_selfcheck + 锚点）
├── build/locate.sh         ★ 工具链四档探测（NDK/UPX/python）
├── build/build_android.sh  NDK 编译原始 .so
├── build/pack.sh           生成标准 + 变种样本
├── tools/detect_packer.py  ★ 结构判定（未加壳/标准UPX/变种，--verify）
├── tools/solve_variant.py  解法 A（特征修复 + upx -d + 锚点校验）
├── tools/dump_fix.py       解法 B：内存 dump → 重建 ELF
├── tools/check_so_samples.py  ★ B13 双向回归断言
├── tools/reset_lab.py      ★ status/restore/backup
├── tools/anchors.txt       脱壳后应找回的锚点
├── samples/so/             ★ 分析对象一律住这里
├── pristine/so/            samples 镜像 + manifest.json（勿手改）
└── analysis_output/        脚本产出（可删）
```

## 样本一览

| 文件 | 大小 | e_type | `UPX!` | `XXXX` | `upx -t` | 用途 |
|---|---|---|---|---|---|---|
| `samples/so/libtarget_orig.so` | 70012 | ET_DYN(3) | 0 | 0 | FAIL | 原始 SO，**黄金对照** |
| `samples/so/libtarget_upx.so` | 5348 | ET_EXEC(2) | **4** | 0 | **OK** | **标准 UPX**，可自动解包 |
| `samples/so/libtarget_upx_variant.so` | 5348 | ET_EXEC(2) | 0 | **4** | **FAIL** | **变种 UPX**，需手工/动态脱壳 |
| `samples/so/libtarget_stripped.so` | 70012 | ET_DYN(3) | 0 | 0 | — | **B13 正样本**（节头剥离） |
| `samples/so/libtarget_orig_arm64.so` | 71848 | ET_DYN(3) | 0 | 0 | — | ARM64 对照 |

⚠️ 官方 UPX 4.2.4 不能直接打包 Android `ET_DYN` `.so`；标准/变种以 `linux/arm ET_EXEC` 打包
——**脱壳机制相同**（同样的 Stub、UPX0 段、OEP），仅 `e_type` 不同。原始 `.so` 仍是真 ARM32 `ET_DYN`。

## 判定

**只认结构特征**（节头数、熵、PT_LOAD 的 filesz vs memsz、entry 位置、memsz/文件比、尾部 `sz_unc`、魔数），
绝不靠文件名/单字符串。与 `360jiagu` 判据同族（同一套检测框架），区别只是壳种特征值不同。

```bash
python tools/detect_packer.py samples/so/libtarget_upx.so          # => 标准 UPX
python tools/detect_packer.py samples/so/libtarget_upx_variant.so  # => 变种 UPX（UPX! 被改成 XXXX）
```

**B13 判据**：`e_type==ET_DYN(3) && e_shnum==0 && 存在可执行 PT_LOAD` → 「疑似 SO 加壳 / 自实现 Linker」。
正常 NDK `.so` 永远带完整节头，此信号不会误伤；B13 **只输出"疑似"**，不下确定结论。

## 脱壳

- **解法 A（`solve_variant.py`）**：特征修复 → `upx -d` → 锚点校验（适用于"只抹特征、Stub 未动"的变种）。
- **解法 B（`dump_fix.py`）**：内存 dump → 重建 ELF，通用主力。

```bash
python tools/solve_variant.py samples/so/libtarget_upx_variant.so analysis_output/out.so \
    --pristine pristine/so/libtarget_orig.so
#   => byte-for-byte identical to golden baseline ✓
```

## 验证标准

- 逐字节：产物 vs `pristine/so/libtarget_orig.so`（sha256/`cmp`）。
- 锚点：`tools/anchors.txt` 全命中。
- **B13 双向回归**：`python tools/check_so_samples.py` → `stripped` 必触发、`orig` 必不触发，且原 UPX 判定不破。

## 认知边界（写结论必须带）

「未见已知特征」**≠「未加固」**。静态不可定性的三类：SO VMP / 不走汇聚形态的 VMP / 精巧字符串加密。
兜底话术：「**未见已知加固特征（≠未加壳）**」+ 不覆盖清单；**禁止**"未加固/没问题"。

## 反复练习 / 重置

```bash
python tools/reset_lab.py status|restore|backup
python tools/check_so_samples.py
```

## 铁律与坑

- **零绝对路径**；工具链四档解析（CLI>env>build 配置>自动探测），工程根由脚本位置推导；唯一例外：文档 `cd` 示例。
- **`UPX` 环境变量会被 upx 当选项串解析**：用 `UPX=<路径>`，别把路径直接 `export` 给 upx。
- 与 `360jiagu` 共用检测框架，但**样本/特征值不同**——别把两工程的期望输出互相套用。

## 上下文入口

- 教学版：`SCRIPT.md` / `CLI.md` / `GUI.md`
- 姊妹工程（同框架、不同壳种）：`../360jiagu/`；仓库级：`../README.md`、`../PROMPT.md`、`../METHODS.md`
