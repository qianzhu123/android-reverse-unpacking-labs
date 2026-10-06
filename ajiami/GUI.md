# GUI.md — 图形工具路线：用 jadx-gui / IDA·Ghidra / 010 Editor 看懂每一步

> 本文件与 `SCRIPT.md`、`CLI.md` **结构完全平行**（同一套章节骨架一一对应），只讲「图形工具怎么做」。
> **本路线的工具必须是图形应用**：反编译读 Java 用 **jadx-gui**（打开 APK/dex 的图形界面）；
> 十六进制读/改字节用 **010 Editor**（或 HxD / ImHex）；SO 结构（节视图 / 段视图）用 **IDA / Ghidra**。
> **命令行工具不属于本路线**：`binwalk -E`（熵曲线）、`apkid`（壳特征扫描）、`jadx -d ...`（无界面转储）
> 都是命令——它们属于命令行路线（`CLI.md`）；`GUI.md` 只**读取**这些命令导出的产物（如用图片查看器打开
> `binwalk -E` 导出的曲线 PNG），或做等价图形操作。凡本节需借用某命令产物，只说明其来源是命令行工具并以**产物**形式读取，不在本文件里重跑命令。
> **路线分工**：判定靠 SCRIPT/CLI（可量化、可写进判据），看懂靠 GUI（jadx-gui 出可浏览的 Java、IDA/Ghidra 出调用图、010 Editor 出可编辑的十六进制视图）。
> 图形工具给出的是「可读形态」，不替代量化判据；每节都写清「点哪里 / 看什么 / 怎么判」。
> 本文的实测截图/源码摘录来自同版本工具实际打开样本后所见（jadx-gui 1.5.5 / 010 Editor，Windows 11 实测）。

---

## 概述

**项目定位**：同 `SCRIPT.md` ——用自造「类爱加密」样本，把 DEX 加固三代演化的判定与脱壳全链路搬到本地。
**建模说明与循环论证风险**：同 `SCRIPT.md`「为什么自造样本」。

### 文件与样本索引

| 图形工具 | 用在哪一步 | 本文档对应章节 |
|---|---|---|
| jadx-gui | 打开样本看壳类结构 / VMP 形态 / 黄金对照（可浏览的包树 + 反编译源码） | 「判定 · 一代」「判定 · VMP 样本」「脱壳后验证」 |
| 010 Editor | 打开文件、十六进制读/改字节，复现解壳（对照 CLI 的 xxd 步骤） | 「脱壳 · 一代」 |
| IDA / Ghidra | 打开 `libcalc.so`，看段视图/节视图（B13 可读形态） | 「判定 · SO 样本」 |
| （CLI 命令，非本路线）`binwalk -E` / `apkid` | 熵曲线 / 外部壳特征——**命令行工具**，本文只读其产物 | 「判定 · 一代」「负样本回归」 |

`samples/` 清单与 `SCRIPT.md`「文件与样本索引」完全相同。

---

## 工程结构与样本

```
ajiami/
├── samples/         # 干净基线样本（分析对象）
├── pristine/        # samples/ 的 sha256 清单备份（「复位」节用）
├── analysis_output/  # 产物目录（jadx/binwalk 输出也建议放这里或系统临时目录，不污染 samples/）
└── app/ shell/ build/ tools/ logs/
```

---

## 知识点总览（图形工具能看到什么）

> 图形工具是「原理的可视化出口」：每条判据在 GUI 里都有一个肉眼可读的对应形态。
> 原理与失效边界见 `SCRIPT.md`「知识点」；本表只给「判据 → 可读形态」的映射。

### 判据代号总表（先看这张，再看「判定」）

`detect.py` 的结论全部落在带编号的判据上，代号与脚本输出、`check_negatives.py` 回归断言三处共用同一套 ID。量化阈值与定性规则见 `SCRIPT.md`「框架类判据」/`CLI.md`「判定据代号总表」，GUI 只补充「可读形态」一列：

**两套判据的分野**：**A = 朴素字符串**（找 `ijiami`/`ProxyApplication` 等家族串）——易被混淆/加密绕过，仅作对照，**永不单独定性**；**B = 结构/统计**——定性唯一依据。

| 代号 | 判据（量化阈值详见 SCRIPT/CLI） | 在 GUI 里长什么样 |
|---|---|---|
| B1 | 高熵 asset（熵 > 7.5），一代定性条件之一 | binwalk 曲线全程贴着高位走 |
| B3 | 全类空方法率 > 40%，二代定性 | jadx 打开抽取态样本会**装载失败**（见「判定 · 二代」实测坑）；回填后的 dex 打开则每个方法有完整实现 |
| B3\* | 整体空率低但局部 100% 空类，三代定性 | jadx 左侧树业务包还在，逐类点开敏感类（SecretLogic/TokenUtil）方法体为空 |
| B4 | 代理 Application（小 Application + 动态加载类），一代辅助 | jadx 里 ProxyApplication 的 attachBaseContext 只有解密→落地→DexClassLoader→反射四步 |
| B6 | App 自身包业务类全缺失 + 高熵 asset，一代定性条件之一 | jadx 左侧树里没有 com.demo.target 包 |
| B7 | Manifest 声明类在所有 dex 并集中缺失，强证据（须配 B1/B6） | jadx 树里找不到 Manifest 声明的 MainActivity，但反编译壳里能看到它的引用 |
| B8 | 已知壳厂商 SO 名单，Native 侧提示 | — |
| B9 | SO 熵异常（> 7.5），仅提示不参与定性 | binwalk 对 SO 的曲线贴高位 |
| B10 | 反分析痕迹串，仅提示不参与定性 | jadx 里搜 `TracerPid`/`frida` 等串的命中点 |
| B11 | 多极短方法体汇聚调用同一大方法，疑似 DEX VMP | jadx 里业务方法只剩 `Vmp.run(PROG_*, args)` 一行 |
| B12 | native 方法占比 ≥ 30%，疑似 Java2CPP | jadx 里大量方法只剩 `native` 声明、无方法体 |
| B13 | SO 的 ELF 结构异常（e_shnum=0 等），疑似 SO 加壳/自实现 Linker | （IDA/Ghidra 视角）SO 没有节名，只有段——见「SO 样本」 |

> 编号不连续说明：**B2 是故意保留的错误示范**（「类数 ≤ 8 判壳」，在 `app_orig` 上必误报）；**B5 占位未用**——这两个"洞"是教学点：绝对值阈值必然翻车，只有「Manifest 声明 vs dex 实有」的交叉验证是硬的。
> 代号组合规则：**一代 = B1 + B6 + B7（+B4）叠加**；二代 = B3；三代 = B3\*；VMP 样本靠 B11（B3 对 VMP 恒失效）。

---

## 判定：这是哪一代（图形工具）

### 一代 · 整体加密

**jadx-gui 操作**：`File → Open` 选择 `samples/apks/app_packed_v1.apk`（jadx-gui 自身解压 APK，无需先 unzip）。

打开后**左侧包树**里只有以下 Java 源（jadx-gui 实跑所见）：

```
com/ijiami/shell/ApplicationSwap.java
com/ijiami/shell/Crypto.java
com/ijiami/shell/PayloadLoader.java
com/ijiami/shell/ProxyApplication.java
com/ijiami/shell/Reflection.java
com/ijiami/shell/ShellClassLoader.java
defpackage/R.java
```

**看什么**：jadx-gui 左侧包树里**只有 `com.ijiami.shell` 一个业务相关包**，`com.demo.target` 一个类都没有——这正是判据 B6（dex 里没有业务类）的可读形态。
**顺藤摸瓜（GUI 的强项）**：壳类是明文的，双击 `com.ijiami.shell.Crypto` 打开右侧反编译视图，直接读它就能还原加固机制——

实测（`Crypto.java` 节选）：

```java
public final class Crypto {
    private static final byte[] KEY = {90, 60, 127, 17, -28, 41, -115, 99};   // = 0x5a 3c 7f 11 e4 29 8d 63
    public static final byte[] MAGIC = {65, 74, 77, 1};                        // = 'A''J''M'\x01

    public static byte[] encrypt(byte[] bArr) {
        byte[] bArr2 = new byte[bArr.length + 8];
        putInt(bArr2, 0, bArr.length);            // 头 4 字节：明文长度
        System.arraycopy(MAGIC, 0, bArr2, 4, 4);  // 接 4 字节：magic AJM\x01
        for (int i = 0; i < bArr.length; i++) {
            bArr2[i + 8] = (byte) ((bArr[i] ^ KEY[i & 7]) ^ (i & 255));   // XOR 流
        }
        ...
```

**怎么判**：壳的加密实现（KEY / MAGIC / `[长度][magic][密文]` 布局）在 jadx-gui 右侧视图里**全文可读**——CLI「字节偏移指南」里手算的 XOR 公式，源头就是这几行 Java。这就是 GUI 路线的价值：**判定靠结构，但"壳怎么工作的"答案直接写在壳源码里**。
**失效边界**：真实商业壳会混淆/加密壳类（本工程的壳为教学目的保持明文）；混淆后 jadx-gui 读不出这些实现，只能退回结构判定。

熵分布曲线（对照命令行「判定 · 一代」的数值 7.869）——**曲线本身是命令行工具 `binwalk -E` 的产物，本路线只读取它**：

- **取产物**：熵曲线由命令行工具 `binwalk -E` 生成（导出的曲线 PNG 即其产物）。
- **看图**：用任意图片查看器打开导出的熵曲线 PNG。

**怎么判**：曲线**全程贴着高位（≈7.9）**波动 = 整体加密数据；若曲线**前段低、后段高**，则是"明文头 + 密文体"（真实壳常见：头部是解密 stub 的伪 dex 头）。单点数值（apkutil entropy）回答"多少"，曲线回答"哪里高哪里低"——两者互补。
**本机坑**：`binwalk -E` 的命令行用法与踩坑（`-p` 存 PNG 依赖 Kaleido、缺 `mf.dll` 时生成 0 字节 PNG）属命令行工具，见 `CLI.md`「踩坑」；本路线只负责用图片查看器读那张曲线图。

### 二代 · 类抽取

**先说一个反直觉的实测结果**：用 jadx-gui `File → Open` 打开 `samples/apks/app_packed_v2.apk`：

```
#   => ERROR - Load failed! No classes for decompile!
```

（同样地，把 APK 内 classes.dex 解出来直接喂 jadx-gui 也一样。）
**为什么**：二代的 `insns` 被抽成全 0 的 nop，jadx-gui 的装载/校验路径直接拒绝这种"有 code_item 但指令全空"的形态。
**这个失败的判读价值**：jadx-gui 装载失败 + 用归档工具目录看到 classes.dex 体积正常（10284 字节，类都在）——两者合起来就是**"类抽取"的可感知形态**：文件结构完好（类名、方法名都在），但代码体被掏空到连反编译器都不认。
**正确的 GUI 姿势**：抽取态样本先走 SCRIPT 路线回填（`unpack_v2.py`），或直接用 jadx-gui 打开黄金样本（回填后的完整 dex，一切正常）：

打开 `samples/dex/classes_merged_orig.dex`（jadx-gui `File → Open`），左侧包树里点开 `com.demo.target.SecretLogic`，右侧即"被抽取前"的完整实现：

```java
public class SecretLogic {
    private final String seed = "AJM-ANCHOR-0008::secret-seed";     // ← 锚点字符串肉眼可见

    public static String mix(String str, String str2) {
        String str3 = str + "|" + str2;
        int iCharAt = -2128831035;
        for (int i = 0; i < str3.length(); i++) {
            iCharAt = ((iCharAt ^ str3.charAt(i)) * 16777619) & Integer.MAX_VALUE;   // FNV 变体哈希
        }
        return Integer.toString(iCharAt, 16);
    }
    ...
```

**怎么用**：脱壳后的验证锚点（`AJM-ANCHOR-0008` 等字符串）在 jadx-gui 里**肉眼可搜**（Ctrl+Shift+F 全局搜索）——SCRIPT「验证」的 11/11 锚点命中，在 GUI 里就是"每个锚点都能搜到出处"。

### VMP 样本 · 认知边界（图形工具反而最能"看见"）

**jadx-gui 操作**：`File → Open` 打开 `samples/apks/app_vmp.apk`，点开 `com.demo.vmapp.VmBusiness`（节选）：

```java
public class VmBusiness {
    private static final byte[] PROG_MIX = {1, 0, 1, 1, 3, 2, 17, 4, 2, 3, 5, -1};   // ← 自定义字节码载荷

    public static int mix(int i, int i2) {
        return Vmp.run(PROG_MIX, new int[]{i, i2});    // ← 方法体只剩解释器调用 = B11 的可读形态
    }

    public static int plainAdd(int i, int i2) {
        return i + i2;    // ← 未保护的方法保持正常（对照）
    }
}
```

**怎么读**：jadx-gui 把 `detect.py` 的 B11（汇聚调用大方法）翻译成了肉眼可读的 Java——每个被虚拟化的方法都退化成 `Vmp.run(byte[], int[])` 一行，真实的算术逻辑进了 `PROG_*` 字节数组、由 `com.ijiami.vmp.Vmp.run` 的 `switch` 解释执行。**这就是 VMP**：类名/方法名/签名都在（jadx-gui 里"看起来很正常"），但方法体已经不是原逻辑。反过来这解释了为什么 B3 空方法率对 VMP 恒为 0——`insns` 非零，只是"零业务语义"。
**jadx-gui 的盲区**：① `PROG_*` 字节码是自定义指令集，jadx-gui 只能显示为 `byte[]` 字面量，**还原不了原逻辑**——这是 VMP 的设计目标，不是 jadx 的缺陷；② 对二代抽取样本，jadx-gui 直接装载失败（见「判定 · 二代」），不是显示空方法体。所以判定要配合结构判据，GUI 工具解决的是"看懂"而不是"判别"。
> 这是最有价值的反例：**A 与 B 各有盲区、正好互补**——变种上 A 漏报 B 命中；VMP 上 B 漏报 A 命中。判定须多层证据叠加，单一指标不可押注。

### SO 样本 · B13（在 IDA/Ghidra 里的形态）

B13 的量化判定（`e_shnum=0`）见 SCRIPT「判定 · SO 样本」；GUI 侧的可读形态：
- **IDA / Ghidra 打开 `libcalc.so`**：段视图（Segments）正常、节视图（Sections）**为空或缺失**——正常 NDK .so 打开后 IDA 的 Sections 窗口有一长串 `.text/.rodata/.dynsym`，本样本一个都没有。
- **判读**：加载器仍可按 Program Header 装载运行，但静态分析工具失去了节级导航——这就是"自实现 Linker / 剥节头"要达到的效果（反分析，不是功能需要）。
- 010 Editor 打开同一个文件，用其 **ELF 模板**（Templates 菜单 → ELF/EXE）解析头部：`e_shoff=0 / e_shnum=0` 两个字段直接高亮为异常值。

---

## 脱壳：图形工具参与方式

### 一代 · 010 Editor 手改字节（对照 CLI 的 xxd 步骤）

CLI「脱壳 · 一代」用 `xxd` 读 payload、手算 XOR；同样的字节操作在 010 Editor 里更直观：

1. **打开**：010 Editor 拖入 `samples/payloads/payload_v1.bin`（或先解出的 assets 成员）。
2. **看头**：`Tools → Templates... → Run Template` 选 ELF/EXE 不适用（这是自造容器），直接肉眼读前 16 字节——`4C 11 00 00`（长度 4524）+ `41 4A 4D 01`（`AJM\x01`），与 CLI 读出的偏移 0/4 完全一致。
3. **模拟解密**：实际解密属脚本路线（XOR 流逐字节），010 Editor 的价值在**读**与**改单点**（如验证"改一个字节 checksum 就变"的完整性实验——见 CLI「完整性」节），不在批量流运算。
4. **怎么判**：解出的 dex 头 4 字节应为 `64 65 78 0A`（`dex\n`）——在 010 Editor 里看到这 4 字节就是"解对了"最快判据（对应 SCRIPT `unpack_v1.py` 的 `[4]` 步）。

**失效边界**：010 Editor 是"十六进制编辑器的 GUI 化"，不产生新的判据；所有读出的偏移/字节值必须与 CLI 的 xxd 读数一致，两路线互为校验。

### 二代 / 三代

抽取态样本的回填是结构级批量操作（22 个方法、重算 checksum/signature），GUI 工具不适合也不应该承担——走 SCRIPT 的 `unpack_v2.py`。GUI 的参与点在**回填之后**：用 jadx 打开还原 dex、全局搜索锚点字符串（见「判定 · 二代」的黄金样本演示）。

---

## 验证判据（图形工具视角）

SCRIPT「验证」的三项判据（sha256 / 锚点 / 字节差）都是 CLI/脚本域的事；GUI 视角只有一个对应动作：**用 jadx-gui 同时打开两个文件、肉眼对照**。

- **打开两个**：分别 `File → Open` 打开 `analysis_output/unpack_v3_dex.dex`（还原产物，先经 SCRIPT `unpack_v2.py` 生成）与 `samples/dex/classes_merged_orig.dex`（黄金样本）。
- **对照**：两边各按 `Ctrl+Shift+F` 搜 `AJM-ANCHOR-0000..0010`，都能命中同样出处；点开 `SecretLogic.mix` 两边的实现应逐行一致。

**怎么判**：GUI 对照是**直观复核**，不是判据本身——最终结论仍以 `verify.py` 的 sha256 一致 + 0 字节差异为准（SCRIPT「验证」）。

---

## 决策流程

```
图形工具在流程里的位置（判定结论永远来自 SCRIPT/CLI 的量化判据）：
  SCRIPT/CLI 判定 ──► 是哪一代？
       │
       ├─ 一代 ──► jadx-gui 读壳类源码（看 KEY/MAGIC/布局，理解机制）
       ├─ 二代 ──► jadx-gui 直接打开必装载失败（这本身就是佐证）；回填后再用 jadx-gui 复核锚点
       ├─ VMP ──► jadx-gui 看 Vmp.run 退化形态（B11 可读化）；解释器逻辑须动态分析
       └─ B13 ──► IDA/Ghidra 节视图为空；010 Editor ELF 模板高亮 e_shnum=0
```

---

## 负样本回归（外部交叉验证）

> **apkid 是 CLI 命令，不属于本路线**——它的实跑与输出在 `CLI.md`「负样本回归」节。这里只记录**读它输出的结论**（GUI 路线不重跑该命令）：

按 `CLI.md` 跑 `apkid samples/apks/app_packed_v2.apk`，其输出为：

```json
{"apkid_version": "3.1.0", "files": [{"filename": ".../app_packed_v2.apk!classes.dex", "matches": {"compiler": ["r8"]}}], "rules_sha256": "e3b0..."}
```

**怎么判（这条比看起来重要）**：apkid 对本工程的加壳样本**只报 compiler=r8，识别不到任何壳**。
这不是 bug——apkid 的特征库来自真实商业壳（爱加密/360/腾讯乐固等的真实签名特征），而本工程是**自造的类爱加密教学样本**，不携带任何真实厂商特征。
**这正是「自造样本循环论证边界」的实证**：本工程的检测器（detect.py）在自己造的样本上 6/6 全对，但拿真实世界的检测器（apkid）来交叉，立刻暴露"它认识的是我们自造的特征，不是真实壳的特征"。所以：
- apkid 在**真实样本**上是第一道筛（免费拿到"可能是哪家壳"的线索）；
- 在**本工程**上，它的价值是标记认知边界——见 PROMPT.md 的验证纪律。
**失效边界**：apkid 特征库覆盖已知厂商，对未知/定制壳同样会漏报；输出只做"线索"，不做定性。

---

## 复位

图形工具的产物（jadx-gui 项目文件、010 Editor 工作副本等）写在系统临时目录或 `analysis_output/`，不污染 `samples/`；实验台复位仍用 SCRIPT「复位」的 `reset_lab.py`（status / restore / backup），与 GUI 无关。

---

## 踩坑

1. **jadx-gui 对抽取态 dex 装载失败**：`app_packed_v2.apk` 及其解出的 classes.dex 用 jadx-gui 1.5.5 打开报 `Load failed! No classes for decompile!`——不是文件损坏（detect.py 能正常解析、归档体积正常），是 jadx 拒绝"insns 全 0"的形态。**判读**：装载失败 + 体积正常 = 抽取型加固的旁证；要看反编译结果，先回填（SCRIPT 路线）或看黄金样本。
2. **jadx-gui 反编译视图含绝对路径来源注释**：`JADX INFO: loaded from:` 一类信息带本机绝对路径，公开分享反编译产物/截图时注意裁剪（对齐「零绝对路径」约定）。
3. **CLI-only 工具的坑（归 `CLI.md`）**：`binwalk -E` 存 PNG 依赖 Kaleido（缺 `mf.dll` 时生成 0 字节 PNG）、`binwalk` 不直接读 APK 内条目须先 unzip、`apkid` 对自造样本必然识别不到壳、以及这些命令输出的中文乱码（`PYTHONIOENCODING=utf-8`）——**它们的实跑与踩坑记录在 `CLI.md`「踩坑」**，不在本路线重复。
