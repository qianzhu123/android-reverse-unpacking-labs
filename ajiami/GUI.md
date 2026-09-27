# GUI.md — 图形工具路线：用 jadx / binwalk / 010 Editor / apkid 看懂每一步

> 本文件与 `SCRIPT.md`、`CLI.md` **结构完全平行**（同一套章节骨架一一对应），只讲「图形工具怎么做」。
> 工具按步骤就近取用：反编译读 Java 用 **jadx**；熵分布曲线用 **binwalk -E**；十六进制编辑改字节用
> **010 Editor**（或 HxD / ImHex）；外部壳特征交叉验证用 **apkid**。
> **路线分工**：判定靠 SCRIPT/CLI（可量化、可写进判据），看懂靠 GUI（jadx 出 Java、binwalk 出曲线）。
> 图形工具给出的是「可读形态」，不替代量化判据；每节都写清「点哪里 / 看什么 / 怎么判」。
> 所有命令先实跑再贴入（jadx 1.5.5 / binwalk 3.1.1 / apkid 3.1.0，Windows 11 实测）。

---

## 概述

**项目定位**：同 `SCRIPT.md` ——用自造「类爱加密」样本，把 DEX 加固三代演化的判定与脱壳全链路搬到本地。
**建模说明与循环论证风险**：同 `SCRIPT.md`「为什么自造样本」。

### 文件与样本索引

| 图形工具 | 用在哪一步 | 本文档对应章节 |
|---|---|---|
| jadx | 反编译看壳类结构 / VMP 形态 / 黄金对照 | 「判定 · 一代」「判定 · VMP 样本」「脱壳后验证」 |
| binwalk -E | payload 熵分布曲线 | 「判定 · 一代」 |
| 010 Editor | 手动改字节复现解壳（对照 CLI 的 xxd 步骤） | 「脱壳 · 一代」 |
| apkid | 外部壳特征库交叉验证（认知边界的实证） | 「负样本回归」 |

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

| 判据 | 量化值（SCRIPT/CLI 的事） | 在 GUI 里长什么样 |
|---|---|---|
| B6 无业务类 | class_defs=6 全是壳类 | jadx 左侧树里没有 com.demo.target 包 |
| B3 空方法率 50% | 22/44 方法 insns 全 0 | jadx 打开抽取态样本会**装载失败**（见「判定 · 二代」实测坑）；回填后的 dex 打开则每个方法有完整实现 |
| B11 VMP 汇聚 | 2 个极短方法调用同一 196-unit 大方法 | jadx 里业务方法只剩 `Vmp.run(PROG_*, args)` 一行 |
| B1 高熵 asset | 熵 7.869 | binwalk 曲线全程贴着高位走 |
| B13 SO 节头剥离 | e_shnum=0 | （IDA/Ghidra 视角）SO 没有节名，只有段——见「SO 样本」 |

---

## 判定：这是哪一代（图形工具）

### 一代 · 整体加密

```bash
# 反编译一代样本：看"业务类整体消失"
jadx -d /tmp/jadx_v1 --no-res samples/apks/app_packed_v1.apk
```

实测（`/tmp/jadx_v1/sources/` 的文件清单）：

```
com/ijiami/shell/ApplicationSwap.java
com/ijiami/shell/Crypto.java
com/ijiami/shell/PayloadLoader.java
com/ijiami/shell/ProxyApplication.java
com/ijiami/shell/Reflection.java
com/ijiami/shell/ShellClassLoader.java
defpackage/R.java
```

**看什么**：jadx 左侧包树里**只有 `com.ijiami.shell` 一个业务相关包**，`com.demo.target` 一个类都没有——这正是判据 B6（dex 里没有业务类）的可读形态。
**顺藤摸瓜（GUI 的强项）**：壳类是明文的，直接读它就能还原加固机制——

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

**怎么判**：壳的加密实现（KEY / MAGIC / `[长度][magic][密文]` 布局）在 jadx 里**全文可读**——CLI「字节偏移指南」里手算的 XOR 公式，源头就是这几行 Java。这就是 GUI 路线的价值：**判定靠结构，但"壳怎么工作的"答案直接写在壳源码里**。
**失效边界**：真实商业壳会混淆/加密壳类（本工程的壳为教学目的保持明文）；混淆后 jadx 读不出这些实现，只能退回结构判定。

熵分布曲线（对照 CLI「判定 · 一代」的数值 7.869）：

```bash
# binwalk 熵曲线：先解出 APK 内成员（binwalk 不直接读 APK 内条目）
unzip -o -q samples/apks/app_packed_v1.apk assets/ijm_payload.bin -d /tmp/bw
binwalk -E -p /tmp/bw/payload_entropy.png /tmp/bw/assets/ijm_payload.bin
```

**怎么判**：曲线**全程贴着高位（≈7.9）**波动 = 整体加密数据；若曲线**前段低、后段高**，则是"明文头 + 密文体"（真实壳常见：头部是解密 stub 的伪 dex 头）。单点数值（apkutil entropy）回答"多少"，曲线回答"哪里高哪里低"——两者互补。
**本机坑**：binwalk 3.1.1 的 `-E` 出 Plotly 图，`-p` 存 PNG 依赖 Kaleido；本机 Kaleido 缺 `mf.dll` 时存图失败、生成 0 字节 PNG——图仍会在浏览器打开，存图不行就截图，或修 Kaleido 环境（详见「踩坑」）。

### 二代 · 类抽取

**先说一个反直觉的实测结果**：对 `app_packed_v2.apk` 直接跑 jadx：

```bash
jadx -d /tmp/jadx_p2 --no-res samples/apks/app_packed_v2.apk
#   => ERROR - Load failed! No classes for decompile!
```

实测：jadx 1.5.5 **装载失败**，一个类都不出（把 APK 内 classes.dex 用 python zipfile 解出来直接喂 jadx 也一样）。
**为什么**：二代的 `insns` 被抽成全 0 的 nop，jadx 的装载/校验路径直接拒绝这种"有 code_item 但指令全空"的形态。
**这个失败的判读价值**：jadx 装载失败 + `unzip -l` 显示 classes.dex 体积正常（10284 字节，类都在）——两者合起来就是**"类抽取"的可感知形态**：文件结构完好（类名、方法名都在），但代码体被掏空到连反编译器都不认。
**正确的 GUI 姿势**：抽取态样本先走 SCRIPT 路线回填（`unpack_v2.py`），或直接看黄金样本：

```bash
# 黄金样本（回填后的完整 dex）在 jadx 里一切正常
jadx -d /tmp/jadx_golden --no-res samples/dex/classes_merged_orig.dex
```

实测（`SecretLogic.java` 节选——这就是"被抽取前"的完整实现）：

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

**怎么用**：脱壳后的验证锚点（`AJM-ANCHOR-0008` 等字符串）在 jadx 里**肉眼可搜**（Ctrl+Shift+F 全局搜索）——SCRIPT「验证」的 11/11 锚点命中，在 GUI 里就是"每个锚点都能搜到出处"。

### VMP 样本 · 认知边界（图形工具反而最能"看见"）

```bash
jadx -d /tmp/jadx_vmp --no-res samples/apks/app_vmp.apk
```

实测（`/tmp/jadx_vmp/sources/com/demo/vmapp/VmBusiness.java`，节选）：

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

**怎么读**：jadx 把 `detect.py` 的 B11（汇聚调用大方法）翻译成了肉眼可读的 Java——每个被虚拟化的方法都退化成 `Vmp.run(byte[], int[])` 一行，真实的算术逻辑进了 `PROG_*` 字节数组、由 `com.ijiami.vmp.Vmp.run` 的 `switch` 解释执行。**这就是 VMP**：类名/方法名/签名都在（JADX 里"看起来很正常"），但方法体已经不是原逻辑。反过来这解释了为什么 B3 空方法率对 VMP 恒为 0——`insns` 非零，只是"零业务语义"。
**JADX 的盲区**：① `PROG_*` 字节码是自定义指令集，jadx 只能显示为 `byte[]` 字面量，**还原不了原逻辑**——这是 VMP 的设计目标，不是 jadx 的缺陷；② 对二代抽取样本，jadx 直接装载失败（见「判定 · 二代」），不是显示空方法体。所以判定要配合结构判据，GUI 工具解决的是"看懂"而不是"判别"。
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

SCRIPT「验证」的三项判据（sha256 / 锚点 / 字节差）都是 CLI/脚本域的事；GUI 视角只有一个对应动作：

```bash
# 还原 dex 与黄金样本是否一致？jadx 同时打开两个，肉眼对照锚点出处
jadx -d /tmp/jadx_restored --no-res analysis_output/unpack_v3_dex.dex
jadx -d /tmp/jadx_golden --no-res samples/dex/classes_merged_orig.dex
#   => 两边搜 AJM-ANCHOR-0000..0010 都能命中同样出处；SecretLogic.mix 实现逐行一致
```

**怎么判**：GUI 对照是**直观复核**，不是判据本身——最终结论仍以 `verify.py` 的 sha256 一致 + 0 字节差异为准（SCRIPT「验证」）。

---

## 决策流程

```
图形工具在流程里的位置（判定结论永远来自 SCRIPT/CLI 的量化判据）：
  SCRIPT/CLI 判定 ──► 是哪一代？
       │
       ├─ 一代 ──► jadx 读壳类源码（看 KEY/MAGIC/布局，理解机制）
       ├─ 二代 ──► jadx 直接打开必装载失败（这本身就是佐证）；回填后再用 jadx 复核锚点
       ├─ VMP ──► jadx 看 Vmp.run 退化形态（B11 可读化）；解释器逻辑须动态分析
       └─ B13 ──► IDA/Ghidra 节视图为空；010 Editor ELF 模板高亮 e_shnum=0
```

---

## 负样本回归（图形工具的独立职责：外部交叉验证）

```bash
# apkid：用真实世界的壳特征库交叉验证本工程样本
apkid samples/apks/app_packed_v2.apk
```

实测（apkid 3.1.0，节选）：

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

图形工具的产物（`/tmp/jadx_*`、`/tmp/bw` 等）写在系统临时目录或 `analysis_output/`，不污染 `samples/`；实验台复位仍用 SCRIPT「复位」的 `reset_lab.py`（status / restore / backup），与 GUI 无关。

---

## 踩坑

1. **jadx 对抽取态 dex 装载失败**：`app_packed_v2.apk` 及其解出的 classes.dex 直接喂 jadx 1.5.5 报 `Load failed! No classes for decompile!`——不是文件损坏（detect.py 能正常解析、unzip 体积正常），是 jadx 拒绝"insns 全 0"的形态。**判读**：装载失败 + 体积正常 = 抽取型加固的旁证；要看反编译结果，先回填（SCRIPT 路线）或看黄金样本。
2. **binwalk 3.1.1 存 PNG 依赖 Kaleido**：本机 Kaleido 缺 `mf.dll` 时 `-p` 生成 0 字节 PNG 并报 DXVA 警告；`-E` 的交互图（浏览器打开）不受影响。要么修 Kaleido、要么截图替代。
3. **binwalk 不直接读 APK 内条目**：对 `assets/ijm_payload.bin` 算熵须先 `unzip` 解出；对单文件直接 `apkutil.py entropy`（CLI 路线）更省事，两工具结果一致（7.869）。
4. **apkid 对自造样本必然识别不到壳**：见「负样本回归」——这不是误报，是自造样本不带真实厂商特征的必然结果，恰好实证了循环论证边界。
5. **jadx 输出目录含绝对路径注释**：反编译产物的 `JADX INFO: loaded from:` 行带本机绝对路径，公开分享反编译产物时注意裁剪（对齐「零绝对路径」约定）。
6. **中文乱码**：jadx/binwalk 输出若有乱码，同 CLI 路线设 `PYTHONIOENCODING=utf-8`（PowerShell `$env:PYTHONIOENCODING='utf-8'`）。
