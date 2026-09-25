# 爱加密加固 · 逆向学习工程（Ajiami Hardening Lab）

> 工程根目录：`ajiami`（本 README 所在目录；下文所有命令都在此执行）
>
> 一句话定位：本工程用**自造的"类爱加密"样本**，把 Android DEX 加固的**三代演化**——
> 原理 → 结构特征 → 判定方法 → 脚本脱壳 → 手动脱壳 → 验证 —— 全链路搬到本地，做到**可编译、可量化、可复现**。
>
> 三条硬约束：
> 1. **先确定性规则，再谈 LLM**：判定与脱壳都是手写结构分析，不依赖任何大模型。
> 2. **基于 evidence**：所有判定落在**结构特征**（字节偏移、空方法率、熵、缺失类），**绝不靠文件名/字符串**。
> 3. **配置外置**：工具链由 `build/locate.sh` 自动探测，`build/env.sh` 只做可选覆盖；
>    脚本与构建配置里不含任何写死的绝对路径，换机器/换目录都能跑（README 里的 `cd` 示例除外）。
>
> **阅读顺序**：先跑 §3 的脚本把结果跑出来（知道"能解开"），再用 §4 手动流程搞清楚"为什么能解开"。
> 脚本只是手动步骤的自动化，反过来先死磕字节容易只见树木不见森林。
>
> 黄金指的是未加固时的原始dex

---

## 0. 为什么不用真实爱加密

真实爱加密需要把 APK 上传到其官网才能加壳，离线**无法复现**、也无法逐字节对照。
本工程因此**自造等价样本**：用同一套壳代码（`shell/`）套到业务 App（`app/`）上，
产出的加固形态与真实产品同构，但整条链路都在本地跑通、可反复改、可验证。

样本分三代 + 一个字符串混淆变种，覆盖从"整体加密"到"对抗朴素判定的混淆"的完整光谱。

### 0.1 三分钟跑一遍（最小闭环）

```bash
cd ajiami

# ① 判定：这是哪一代壳？（只做结构体检，不修改任何文件）
python tools/detect.py samples/app_packed_v1.apk
#   => 【判据 B】B1 高熵 asset / B6 无业务类 / B7 Manifest 声明类缺失
#   => 结论：已加固：DEX 整体加密型（一代）

# ② 脱壳：一代用 unpack_v1.py；--pristine 给黄金样本，解完立刻比对
python tools/unpack_v1.py samples/app_packed_v1.apk analysis_output/unpack_v1_dex.dex --pristine samples/classes_orig.dex
#   => [4] dex 魔数校验 b'dex\n037\x00'   [6] 与黄金 classes_orig.dex 对照: 完全一致 ✓

# ③ 验证：独立于脱壳脚本自检（sha256 / 锚点 / 字节差异三项）
python tools/verify.py analysis_output/unpack_v1_dex.dex samples/classes_orig.dex
#   => [1] sha256 一致 ✓   [2] 锚点 11/11   [3] 无差异 ✓   => 还原成功
```

判定 → 脱壳 → 验证三步走通，就说明环境 OK；每一步的细节见 §3，手动复现见 §4。
二/三代样本把 `app_packed_v1.apk` 换成 `app_packed_v2.apk` / `app_packed_v3.apk`、
把 `unpack_v1.py` 换成 `unpack_v2.py`、黄金样本换成 `samples/classes_merged_orig.dex` 即可（选型见 §7）。

---

## 1. 工程结构

```
ajiami/
├── build/env.sh            # 工具链/密钥/签名 集中配置
├── app/                    # 业务 App 源码（含 AJM-ANCHOR-0000..0010 分析锚点）
├── shell/                  # 类爱加密壳源码（ProxyApplication / PayloadLoader / Crypto 等）
├── build/                  # 各阶段产物：target/shell/merged 的 dex、pack 中间产物
├── tools/                  # 分析/脱壳/判定/复位工具（见 §3）
│   ├── dexlib.py           # 手写 DEX 解析/改写（无外部库）
│   ├── crypto_lab.py       # 与壳 Crypto.java 字节级一致的加解密
│   ├── apkutil.py          # APK/zip 读写、熵计算
│   ├── envload.py          # 从 build/env.sh 读配置注入环境（免 source）
│   ├── packer.py           # 三代加壳器
│   ├── make_variant.py     # 字符串混淆变种生成
│   ├── detect.py           # 双判据判定（A 朴素字符串 / B 结构）
│   ├── unpack_v1.py        # 一代脱壳（静态）
│   ├── unpack_v2.py        # 二/三代脱壳（回填侧表）
│   ├── verify.py           # 还原 dex 与黄金样本逐字节对照
│   ├── walkthrough.py      # 字节偏移版"手动复现"字段指南
│   └── reset_lab.py        # 实验台 备份/状态/复位（pristine/ + sha256 清单）
├── samples/                # 干净基线样本（已固化进 pristine/）
├── pristine/               # samples/ 的 sha256 清单备份
├── analysis_output/        # 脱壳还原产物
└── logs/                   # 实操日志（detect_run.txt 等）
```

---

## 2. 知识手册：三代演化的原理与结构特征

### 2.0 Ajiami 完整保护体系总览

Ajiami **不能简单理解成一个普通的"DEX 壳"**，其保护体系是**多层叠加**的：

```
Ajiami
├── DEX 保护      整体加密 / 代码分离 / 函数抽取+加密 / 动态还原 / DEX VMP
├── Native 保护   SO 加壳 / SO Linker / SO 防调用 / SO VMP
├── Java → Native Java2CPP
└── 对抗          防调试 / 防注入 / 防 Hook / 完整性校验 / 签名保护
```

本工程的**样本**覆盖 DEX 保护主线（整体加密 → 函数抽取 → 选择性抽取 → 字符串混淆）；
§2.5 起补齐其余部分的**知识框架与识别方法**（需 NDK/真机的部分已标注"待扩展"）。

**贯穿全局的两条分析原则**：

1. **DEX 保护与 Native 保护往往不是独立存在的**，可能形成
   `壳 DEX → Native SO → 数据载荷 → 解密/执行 → DEX/函数恢复` 的链条。
   所以不能只研究 Java/Smali，必须同时进入 ELF/SO。
2. **不要只盯 `classes.dex`**，要同时检查 `assets/`、`lib/`、`res/` 与其他非标准数据文件。

### 2.1 一代 · DEX 整体加密（Whole-DEX Encryption）

**原理**：业务 `classes.dex` 整体加密，塞进 `assets/`；APK 里的 `classes.dex` 退化成极小**壳**，
入口 `Application` 指向壳的 `ProxyApplication`，运行期解密并用 `DexClassLoader` 动态加载真 dex。

**结构特征**
- `classes.dex` 里**没有任何业务类**，只有壳类。
- 存在 `assets/<高熵文件>`（本工程 `ijm_payload.bin`，熵 **7.869** bit/byte）。
- payload 容器：`[int32_le 声明长度][4B magic 'AJM\x01'][XOR 流密文]`。
- Manifest 声明的业务 Activity 在**所有 `classes*.dex` 的并集**里**根本不存在**（强证据；定性为一代还需配合高熵载荷）。

**判定**：B1 + B6 + B7 → 一代整体加密。（代号含义见 §6 命名约定；注意触发「一代」结论的是 B6 或 B7，B1 为辅助信号）

B1：高熵asset

B6：无业务类 + 高熵asset

B7：Manifest声明类 vs dex实际类差集

### 2.2 二代 · 类抽取（Method/Class Extraction）

**原理**：保留类名/方法名，但把每个方法的 `code_item.insns` **抽空成 `0x00`**（dalvik opcode `0x00` 就是 nop，
所以 dex 仍合法、仍可加载），真实指令加密后存进 `assets/` 侧表（magic `AJMT`），运行期按 `code_off` 回填。

**结构特征**
- 大量"有 `code_item` 但 `insns` 全 0"的方法 → **空方法率**（本工程 **22/44 = 50%**）。
- 侧表条目：`u4 class_idx | u4 method_idx | u4 code_off | u4 insns_len | insns_len 字节密文`。

**判定**：空方法率 > 40%（判据 B3）。

### 2.3 三代 · 选择性抽取 + 混淆 + 诱饵（Evasion）

**原理**：二代"全量抽取 + 高整体空率"太好识别，三代改为：
- **只抽敏感类**（本工程只抽 `SecretLogic` + `TokenUtil`）→ **整体空率压到阈值以下**（8/44 = **18.18%**）；
- **资源名混淆**：侧表改名为看起来正常的 `brand_res_v3.dat`；
- **诱饵文件**：低熵假配置 `config.txt`，专门让"按熵找 payload"的朴素判据误报。

**结构特征**：整体空率虽低，但存在**局部 100% 空方法类**（`SecretLogic` 4/4、`TokenUtil` 4/4）→ 需**下钻单类**（判据 B3\*）。

### 2.4 变种样本 · 字符串混淆（教学要点）

`make_variant.py` 把含家族标记的串做**等长字母表倒序映射**（`ijiami`→`rqrznr`、`ProxyApplication`→`KilcbZkkorxzgrlm`）：
- **判据 A（朴素字符串）完全失效**；
- **判据 B（结构）一个字节都没变**，照常命中。
> 这正是"禁止只靠字符串下结论"的原因。

### 2.5 DEX VMP（虚拟化）—— 与"抽取"最关键的区别

**原理**：原始 DEX 指令 → 转换 → Ajiami **自定义字节码** → Ajiami 虚拟机解释器 → 执行。
官方表示**每次加固可随机使用不同的自定义指令集**，因此**不能依赖一个永久固定的 opcode 映射**。

**静态特征**（关键）
```
类名 / 方法名 / 字段   → 还在
真实 Dalvik 指令       → 已不是原来的形式
```
> **JADX 能看到类 ≠ JADX 能恢复原始 Java 逻辑。**

**与"函数抽取"的对照（务必分清）**

| | 抽取（二代） | DEX VMP |
|---|---|---|
| `code_item.insns` | 全 `0x00`（nop） | **非零**，是对解释器的 `invoke-static` 调用 |
| 侧表/载荷内容 | **合法 dalvik 指令** | **自定义字节码**（不是合法 dalvik） |
| 空方法率 B3 | 升高 → **可检出** | **不升高 → B3 直接失效！** |
| 恢复方式 | 把 dalvik 指令回填即可 | 必须逆向**自定义 opcode / dispatch / handler** |

> **教学点**：本工程判据 B3（空方法率）对 VMP **完全失效**。
> 识别 VMP 要靠：方法体是"调用解释器"的异常形态 + `assets/` 存在自定义字节码载荷 + 存在解释器类/SO。

**处理思路**：定位虚拟机 → 分析 opcode / dispatch / handler。

**本工程样本实测（`samples/app_vmp.apk`，`bash build/build_vmp.sh` 生成）**

```
[classes.dex] 2456 bytes, entropy=4.9180
     class_defs=2  methods=10(with code 10, empty 0)  空方法率=0.00%
     家族字符串命中: ['ijiami']
【判据 A · 朴素字符串】命中家族字符串 ['ijiami']      ← 因包名 com.ijiami.vmp
【判据 B · 结构】无命中
>> 结论：未加固（或至少没有上述任一种特征）           ← 漏报！
```

> **这是本工程最有价值的一个反例**：
> - 判据 **B 完全漏报** —— 空方法率 0%（VMP 的 `insns` 不是全 0），没有高熵 asset，没有代理 Application；
> - 判据 **A 反而命中** —— 只因为包名里恰好有 `ijiami` 字样。
>
> 也就是说，**A 与 B 各有盲区、正好互补**：变种样本上 A 漏报、B 命中；VMP 样本上 B 漏报、A 命中。
> 结论只能是：**判定必须多层证据叠加，任何单一指标都不可押注**。
>
> 真正识别 VMP 要看：方法体是否只是"调用解释器"（`invoke-static` 到 `Vmp.run` 这类），
> 以及是否存在**非法 dalvik 的自定义字节码**载荷（`PROG_MIX` 这类 `byte[]`）。

### 2.6 独立数据载荷 + 多 SO 执行链（不要只盯 classes.dex）

实际样本中出现过：
```
assets/
├── ijiami.ajm
└── ijiami.dat
lib/
├── libijmDataEncryption.so
├── libexec.so
├── libexecmain.so
└── libijm-emulator.so
```
标准 DEX 中只剩少量壳类。概括为：**缩壳 DEX + 独立数据载荷 + Native 执行链**。

**因此**分析时要同时检查：
```
assets/    ← 大型高熵文件
lib/*/     ← 加固执行 / 数据处理相关 SO
res/       ← 非标准数据
其他非标准数据文件
```
熵检查：`binwalk -E libxxx.so`（熵高 = 字节分布极随机，多为加密/压缩）。

### 2.7 Native 保护：SO 加壳 / SO Linker / SO 防调用 / SO VMP

官方把 **SO Linker** 明确列为 SO 保护技术，与 SO 加壳、SO 防调用、SO VMP 并列。

- **SO 加壳**：真实 SO 被加密/压缩，运行期由壳解密并加载。
- **SO Linker**：存在**非标准的 Native 加载/链接结构**，即"Ajiami 自己参与的 SO 加载/链接逻辑"，
  区别于普通 Android linker。分析要点：
  ```
  SO 从哪里取得 → 谁负责映射 → 谁负责解析 → 什么时候完成重定位 → 真正代码什么时候开始执行
  ```
- **SO 防调用**：**正常 App 内部调用**与**外部直接调用/分析 Native 接口**可能结果不同。
  所以不能只问"这个函数在哪里"，还要观察"**这个函数在什么调用环境下才能正常执行**"。
- **SO VMP**：Native 层虚拟化。

> 样本状态：本工程**暂无 SO 样本**（需 NDK 编译），本节为知识框架，待扩展。

### 2.8 Java2CPP（Java → Native）

官方公开：Java 代码 → 转换成 C++ → 编译 → SO。
```
原本：Java → DEX
变成：Java → C++ → SO
```
结果：**DEX 中的 Java 代码减少**，真正逻辑转移到 **Native SO**。

**分析特征**
```
DEX 非常干净
+ SO 异常庞大/复杂
+ Java 业务逻辑明显减少
        ⇒ 考虑 Java2CPP
```
**处理思路**：减少对 DEX 的关注，转向对应 SO。
> 注意：Java2CPP 同样会让**空方法率判据 B3 失效**（业务代码根本不在 DEX 里）。

### 2.9 双重 VMP（DEX VMP + SO VMP）

```
Java/Dex → DEX VMP → Native → SO VMP
```
官方描述为"DEX VMP + ELF VMP 的全方位保护"。
**若一个样本同时出现 DEX 虚拟化 + Native 虚拟化，不能只分析其中一层。**

### 2.10 字符串保护（DEX 字符串加密）

Ajiami 提供 **DEX 字符串加密**：JADX 里**关键 URL / 密钥 / 类名 / 错误信息 / 业务字符串**
可能无法直接搜索到。

**处理思路**：从"静态字符串搜索"转向
```
字符串使用点 → 运行时解密 → 真实字符串
```
> 与 §2.4 的区别：§2.4 的变种做的是**等长替换混淆**（串还在、只是变形、长度不变）；
> 字符串**加密**更强——静态完全不可读，必须找到解密点。

### 2.11 完整性保护 / 签名保护

官方明确提供：**DEX 文件防篡改 / SO 文件防篡改 / 资源文件防篡改 / 签名保护**。

因此：
```
修改 APK → 重新打包 → 运行异常
```
**可能不是代码改错，而是完整性校验被触发。**

**分析重点**
```
APK / DEX / SO → Hash / CRC / 签名 / 特征值 → 校验 → 通过 / 退出
```

### 2.12 反调试 / 反注入 / 反 Hook

官方明确提供：防 Java 层动态调试、防 C 层动态调试、防代码注入、防 Hook、防内存代码注入。

**常见现象**
```
正常启动 → 附加调试器 → 异常退出
正常运行 → 动态 Hook    → 崩溃/退出
```
**分析原则**：把**反调试 / 反注入 / 反 Hook 作为独立模块**分析，
**不要把它们混入 DEX 恢复逻辑**——否则会把"环境检测"误判成"业务/还原逻辑"。

### 2.13 样本识别检查表

拿到疑似 Ajiami 的 APK，优先检查：

| 检查对象 | Ajiami 相关特征 |
|---|---|
| `classes.dex` | 业务类大量消失、壳类极少（公开案例：仅剩约 4 个壳类、DEX 约 14KB） |
| `assets/` | 可能存在独立的大型加密载荷（`*.ajm` / `*.dat` / 高熵文件） |
| `lib/` | 可能出现加固执行/数据处理相关 SO |
| DEX 方法 | 可能存在函数抽取/保护 |
| Native | 可能承担 DEX 恢复或 VMP |
| ClassLoader | 关注动态加载 |
| 内存 | 关注运行时恢复 |
| Java 代码 | 可能被 Java2CPP 转移 |
| DEX 指令 | 可能进入 VMP |
| SO 指令 | 可能进入 SO VMP |
| 启动 | 可能触发完整性/环境检查 |
| 调试 | 可能触发反调试/反注入 |

> 反向提醒：JADX 里"只有几个奇怪的类"**并不代表 App 真的只有几个类**，
> 反而可能是**业务 DEX 被移出标准 DEX**。

### 2.14 保护方式 → 处理思路映射

| # | 保护方式 | 处理思路 |
|---|---|---|
| ① | DEX 整体加密 | 寻找运行时解密/加载位置 → 观察恢复后的 DEX |
| ② | DEX 函数抽取 | 寻找函数动态恢复点 → 观察运行时恢复的 code |
| ③ | DEX VMP | 定位虚拟机 → 分析 opcode / dispatch / handler |
| ④ | SO 加壳 | 分析 Native 加载/初始化 → 定位真实 Native 执行区域 |
| ⑤ | SO Linker | 分析自定义加载/链接过程 → 确认真实 SO 映射和执行位置 |
| ⑥ | SO VMP | 定位 Native 虚拟机 → 分析 Native 虚拟指令执行 |
| ⑦ | Java2CPP | 减少对 DEX 的关注 → 转向对应 SO |
| ⑧ | 字符串加密 | 定位字符串解密点 → 观察运行时明文 |
| ⑨ | 完整性保护 | 定位校验逻辑 → 分析校验对象和触发条件 |
| ⑩ | 反调试/反 Hook | 先识别触发机制 → 再进行动态分析 |

**本工程样本覆盖度**：已覆盖 ①（整体加密）、②（函数抽取 / 选择性抽取）、③（DEX VMP 教学模型）+ 字符串混淆；
④ SO 加壳 / ⑤ SO Linker 已由 **B13** 自动识别（含 NDK 正负样本）；⑦ Java2CPP 已由 **B12** 自动识别；
⑥ SO VMP 与 ⑧⑨⑩ 目前为**知识框架**，需动态/真机（待扩展）。

---

## 3. 脚本脱壳实战（先跑通）

> 本章全部命令都在工程根目录 `ajiami/` 下执行，全部单行。
> Windows 下用 PowerShell 或 Git Bash 均可（`.sh` 脚本在 PowerShell 里要写成 `bash build/build_target.sh` 这种形式）。
> 若中文输出乱码：先 `set PYTHONIOENCODING=utf-8`（PowerShell 用 `$env:PYTHONIOENCODING='utf-8'`）。

### 3.1 三步流水线总览

```
判定（哪一代）  →  脱壳（按代选脚本）  →  验证（是否真还原）
detect.py           unpack_v1 / v2          verify.py
```

一代（整体加密）用 `unpack_v1.py`，二代/三代（类抽取）用 `unpack_v2.py`——**选错脚本会直接报找不到标记**，
所以先跑 `detect.py` 不是形式主义。

**一代样本**（`app_packed_v1.apk`，黄金是 `classes_orig.dex`）：

```
python tools/detect.py samples/app_packed_v1.apk
python tools/unpack_v1.py samples/app_packed_v1.apk analysis_output/unpack_v1_dex.dex --pristine samples/classes_orig.dex
python tools/verify.py analysis_output/unpack_v1_dex.dex samples/classes_orig.dex
```

**二代样本**（`app_packed_v2.apk`，黄金是 `classes_merged_orig.dex`）：

```
python tools/detect.py samples/app_packed_v2.apk
python tools/unpack_v2.py samples/app_packed_v2.apk analysis_output/unpack_v2_dex.dex --pristine samples/classes_merged_orig.dex
python tools/verify.py analysis_output/unpack_v2_dex.dex samples/classes_merged_orig.dex
```

**三代样本**（`app_packed_v3.apk`，黄金同样是 `classes_merged_orig.dex`）：

```
python tools/detect.py samples/app_packed_v3.apk
python tools/unpack_v2.py samples/app_packed_v3.apk analysis_output/unpack_v3_dex.dex --pristine samples/classes_merged_orig.dex
python tools/verify.py analysis_output/unpack_v3_dex.dex samples/classes_merged_orig.dex
```

**字符串混淆变种**（`app_packed_v2_variant.apk`，黄金必须是混淆版 `build/variant/merged_orig_variant.dex`）：

```
python tools/detect.py samples/app_packed_v2_variant.apk
python tools/unpack_v2.py samples/app_packed_v2_variant.apk analysis_output/unpack_v2_variant_dex.dex --pristine build/variant/merged_orig_variant.dex
python tools/verify.py analysis_output/unpack_v2_variant_dex.dex build/variant/merged_orig_variant.dex
```

> 一次性跑完全部 5 个样本的判定：
> `python tools/detect.py samples/app_orig.apk samples/app_packed_v1.apk samples/app_packed_v2.apk samples/app_packed_v3.apk samples/app_packed_v2_variant.apk`

### 3.2 `detect.py` · 判定是哪一代壳

**作用**：对一个 APK（或裸 dex）做结构体检，输出"是不是壳 + 哪一代 + 命中的判据"，**不修改任何文件**。

```
python tools/detect.py samples/app_packed_v1.apk samples/app_packed_v2.apk samples/app_packed_v3.apk
```

| 参数 | 含义 |
|------|------|
| 位置参数（1..n） | APK 或 dex 路径，**可以一次传多个**；相对路径按工程根解析 |
| `--json` | 输出机器可读 JSON（其余 `--xxx` 开头的参数会被忽略） |
| 无参数 | 打印脚本文档并返回退出码 1（当用法提示看） |

实测输出（`app_packed_v1.apk`，节选）：

```
--- ZIP 条目 ---
  classes.dex                                    6548  5.1449
  assets/ijm_payload.bin                         4532  7.869      ← 第三列就是熵
--- AndroidManifest（aapt2 xmltree 精确解析）---
  application = com.ijiami.shell.ProxyApplication
  activitys  : com.demo.target.MainActivity
--- dex 特征 ---
       class_defs=6  methods=22(with code 22, empty 0)  空方法率=0.00%
       动态加载字符串: ['DexClassLoader', 'loadClass']
--- 判定 ---
  【判据 A · 朴素字符串】命中家族字符串 ['ProxyApplication', 'ijiami', 'ijm_payload']
  【判据 B · 结构】B1 高熵 asset(assets/ijm_payload.bin, 7.869 bit/byte) —— 存在加密 payload
  【判据 B · 结构】B4 manifest 声明的 Application=com.ijiami.shell.ProxyApplication 在 dex 里是个"小 Application"(2 方法) 且 dex 引用了动态加载类 ['DexClassLoader', 'loadClass'] —— Application 被代理
  【判据 B · 结构】B6 所有 dex 的并集中都没有 App 自身包(com.demo.target)的业务类，且存在高熵 asset —— 真 dex 只能藏在 asset 里，判定为一代整体加密
  【判据 B · 结构】B7 AndroidManifest 声明了 2 个类，其中 1 个在所有 classes*.dex 的并集中都不存在 —— 需由运行期动态加载提供（强证据，但定性为一代还需配合 B1/B6 的载荷证据）
      缺失：com.demo.target.MainActivity
  >> 结论：已加固：DEX 整体加密型（一代）
```

**逐段怎么读**：
1. **ZIP 条目**：看 `classes.dex` 是否异常小、`assets/` 下是否多出文件；第三列是熵，> 7.5 基本是加密/压缩。
2. **AndroidManifest**：`application` 若指向壳类 → 被代理；同时记下它声明了哪些业务类。
3. **dex 特征**：`class_defs` / 空方法率 / 是否引用 `DexClassLoader`。
4. **判定**：**只看判据 B**。判据 A 是给"朴素做法"做对照用的（变种上必然漏报）。
5. **结论行**决定下一步用哪个脱壳脚本。

三代样本会额外打印**下钻信息**（这是三代的唯一抓手）：

```
  【判据 B · 结构】B3* 整体空方法率仅 18.2%，但存在局部空方法类 —— 需下钻到单类
      → Lcom/demo/target/SecretLogic; 4/4; Lcom/demo/target/TokenUtil; 4/4
```

### 3.3 `unpack_v1.py` · 一代整体加密脱壳

**作用**：从 APK（或单独的 payload 文件）取出加密 dex，解密并写出还原 dex。

```
python tools/unpack_v1.py samples/app_packed_v1.apk analysis_output/unpack_v1_dex.dex --pristine samples/classes_orig.dex
```

| 参数 | 含义 |
|------|------|
| 第 1 个位置参数 | 输入：APK **或** 单独的 payload 文件（如 `samples/payload_v1.bin`） |
| 第 2 个位置参数 | 输出：还原后的 dex 路径 |
| `--pristine <dex>` | **可选**黄金对照 dex；给了就顺带做 sha256 比对，不给就只还原不比对 |

真实输出（每一行对应脚本内部的一步）：

```
[1] 从 APK 取出 payload: assets/ijm_payload.bin  (4532 bytes)
[2] 头部: decl_len=4524  magic=b'AJM\x01'
[3] 解密后长度 = 4524
[4] dex 魔数校验: b'dex\n037\x00'
[5] 已写出: analysis_output/unpack_v1_dex.dex
    sha256 = e330d2998de45a680a5a3cd415d1e83290378cc15584b2c2831518028c588cc1
[6] 与黄金 classes_orig.dex 对照: 完全一致 ✓
```

**逐行怎么读**：
- `[2]` `decl_len` 是壳声明的原始 dex 长度，`magic` 必须是 `AJM\x01`（定位 payload 靠它，不靠文件名）。
- `[3]` 解密后长度应等于 `decl_len`；**对不上说明密钥/算法错了**。
- `[4]` 还原出的开头必须是 `dex\n037\0`——这是"解对了"的最快判据（对应 §4 步骤 7 的手算）。
- `[6]` 与黄金一致 = 本次脱壳成功。

### 3.4 `unpack_v2.py` · 二代/三代类抽取脱壳

**作用**：定位 `AJMT` 侧表，解密后把指令回填到 dex 的 `code_item.insns`，重算校验值并写出。

它有两种调用形态，脚本按第 1 个参数自动判断：

```
# 形态 A：直接喂 APK（常用）
python tools/unpack_v2.py samples/app_packed_v3.apk analysis_output/unpack_v3_dex.dex --pristine samples/classes_merged_orig.dex

# 形态 B：已有抽取后的 dex + 单独侧表文件
python tools/unpack_v2.py samples/extracted_v3.dex samples/codetable_v2.bin analysis_output/out.dex
```

| 参数 | 含义 |
|------|------|
| `a` | APK（走形态 A），或已抽取的 dex（走形态 B） |
| `b` | 形态 A 下是**输出 dex**；形态 B 下是**侧表文件** |
| `c` | 仅形态 B 使用：输出 dex 路径 |
| `--pristine <dex>` | 黄金对照 dex，用于立即比对 sha256 |

真实输出（`app_packed_v3.apk`）：

```
[1] 在 APK 里定位侧表: assets/brand_res_v3.dat  (572 bytes)
[2] 解析侧表...
    侧表条目数 = 8
[3] 把指令回填到 dex 的 code_item.insns 区...
    成功回填 8 个方法
[4] 重算 checksum/signature 完成
[5] 已写出: analysis_output/unpack_v3_dex.dex
    sha256 = 7527307217b96ea2fa0628fc4d7170851f45302b2910166cb6847eb40656f94d
    还原后：空方法数 = 0 / 44
[6] 与黄金 classes_merged_orig.dex 对照: 完全一致 ✓
```

**逐行怎么读**：
- `[1]` 侧表是**按 `AJMT` 魔数扫出来的**，不是按文件名——所以三代改名 `brand_res_v3.dat`、
  变种改名 `rqn9xlwvh.yrm` 都照样能定位（这是抗混淆的关键，详见 §9 踩坑 3）。
- `[3]` 回填条数应等于 `[2]` 的条目数；少一个都说明某个 `code_off` 对不上。
- `[4]` 先 `sha1(data[32:])` 算 signature、后 `adler32(data[12:])` 算 checksum，顺序反了 dex 会 Bad checksum。
- `[5]` **还原后空方法数必须是 0**；不为 0 就是没回填干净。

### 3.5 `verify.py` · 验证是否真的还原

**作用**：把还原 dex 与黄金样本做三项对照，**不依赖脱壳脚本的自述**，独立判定成败。

```
python tools/verify.py analysis_output/unpack_v3_dex.dex samples/classes_merged_orig.dex
```

| 参数 | 含义 |
|------|------|
| 第 1 个位置参数 | 还原出来的 dex |
| 第 2 个位置参数 | 黄金样本 dex（未加固时的原始 dex） |

真实输出：

```
还原：analysis_output/unpack_v3_dex.dex
黄金：samples/classes_merged_orig.dex
[1] sha256: 一致 ✓
[2] 锚点字符串: 还原 11 个 / 黄金 11 个
    全部锚点都在 ✓
[3] 无差异 ✓

=> 结论：还原成功，与黄金样本完全一致
```

**三项检查分别说明**：
1. **sha256**：最强判据，一致即逐字节相同。
2. **锚点字符串**：业务 App 里预埋的 `AJM-ANCHOR-0000..0010`；**缺一个就说明没真解开**（哪怕长度对）。
   注意变种样本的黄金是"字符串混淆版"，锚点数会显示为 0/0，属正常。
3. **字节差异**：不一致时给出差异字节数 + 首个差异偏移——这是定位"哪一步写错了"的入口。

### 3.6 `walkthrough.py` · 字节偏移指南（脚本 → 手动的桥）

**作用**：**不改任何文件**，只打印"用十六进制编辑器到哪个偏移看、看到什么算什么"，
把你从脚本世界带进 §4 的手动世界。

```
python tools/walkthrough.py samples/app_packed_v1.apk
python tools/walkthrough.py samples/app_packed_v2.apk
```

| 参数 | 含义 |
|------|------|
| 位置参数 | 目标 APK |
| 自动分流 | 命中 `AJM\x01` → 走一代流程；命中 `AJMT` → 走二/三代流程；都没有 → 提示"非本工程产物"并退出码 1 |

### 3.7 `reset_lab.py` · 实验台复位

**作用**：把 `samples/` 固化成基线（含 sha256 清单），随时可查/可还原，避免"样本被自己玩坏后没法对照"。

```
python tools/reset_lab.py backup
python tools/reset_lab.py status
python tools/reset_lab.py restore
python tools/reset_lab.py restore --force
```

| 子命令 | 行为 |
|--------|------|
| `backup` | 把 `samples/` 全量复制进 `pristine/` 并写 sha256 清单 `MANIFEST` |
| `status` | 逐项对照清单，输出 `OK/DIFF/MISSING/EXTRA` 计数；有 DIFF/MISSING 时退出码 1 |
| `restore` | 用 `pristine/` 副本覆盖回 `samples/`；**默认跳过"与清单一致"的文件** |
| `restore --force` | 忽略当前状态，强制覆盖全部 |

> 改样本、跑新实验前先 `backup`；结果对不上时先 `status`，能立刻区分"是我改坏了样本"还是"脱壳逻辑错了"。

### 3.8 脱壳结果对照表（实测）

| 还原文件 | 黄金样本 | sha256（一致） | 锚点 | 结论 |
|----------|----------|---------------|------|------|
| `unpack_v1_dex.dex` | `samples/classes_orig.dex` | `e330d2998d…588cc1` | 11/11 | ✅ 完全一致 |
| `unpack_v2_dex.dex` | `samples/classes_merged_orig.dex` | `7527307217…56f94d` | 11/11 | ✅ 完全一致 |
| `unpack_v3_dex.dex` | `samples/classes_merged_orig.dex` | `7527307217…56f94d` | 11/11 | ✅ 完全一致 |
| `unpack_v2_variant_dex.dex` | `build/variant/merged_orig_variant.dex` | `5e4ee0a006…ec6621` | 0/0（均被混淆） | ✅ 完全一致 |

> 变种的黄金必须是**字符串混淆版**的合并 dex，因为还原出来的是带混淆字符串的 dex。

---

## 4. 手动脱壳全流程（再用十六进制编辑器走一遍）

> 本节只用**通用工具**：`unzip` / `aapt2` / `xxd`（或任意十六进制编辑器）/ 熵工具。
> 目的是让你**亲手走一遍脚本做的每一步**，而不是只会跑脚本。
> （PowerShell 下 `xxd` 可用 `Format-Hex -Path <文件> -Offset <偏移> -Count <长度>` 替代。）
> 每一步都能在 §3 的脚本输出里找到对应项。

### 4.1 步骤 1 · 拆包看条目：找"多出来的东西"（≈ `detect.py` 的 ZIP 段）

```
unzip -l samples/app_packed_v1.apk
```

实测（`app_packed_v1.apk`）：

```
  Length      Date    Time    Name
---------  ---------- -----   ----
     2308  1980-01-01 00:00   AndroidManifest.xml
       40  1980-01-01 00:00   resources.arsc
     6548  1980-01-01 00:00   classes.dex          ← 只有壳，异常小
     4532  1980-01-01 00:00   assets/ijm_payload.bin   ← 多出来的高熵文件
      506  1980-01-01 00:00   META-INF/AJMLAB.SF
```

**看什么 / 怎么判**：`assets/` 下出现莫名文件 + `classes.dex` 异常小 → 高度可疑。

### 4.2 步骤 2 · 读 Manifest：找被代理的 Application（≈ `detect.py` 的 Manifest 段）

```
aapt2 dump xmltree --file AndroidManifest.xml samples/app_packed_v1.apk
```

> Git Bash 下直接管道给 `grep`/`head` 偶发 `RAW: Check new_pages != nullptr failed: VirtualAlloc failed` 崩溃。
> 先重定向到文件再读：`aapt2 dump xmltree --file AndroidManifest.xml samples/app_packed_v1.apk > /tmp/manifest.txt`。

实测（关键片段）：

```
E: application (line=15)
  A: android:name(0x01010003)="com.ijiami.shell.ProxyApplication"
      A: android:name(0x01010003)="ijiami_real_application"
      A: android:value(0x01010024)="com.demo.target.MainApplication"
  E: activity (line=27)
    A: android:name(0x01010003)="com.demo.target.MainActivity"
```

**看什么 / 怎么判**：
- `application` 的 `android:name` 不是业务的 `MainApplication`，而是一个壳类 → **Application 被代理**；
- meta-data `ijiami_real_application` 指向真正的 `MainApplication`（壳留的"真身"线索）；
- 记下 Manifest 声明的类清单（`ProxyApplication`、`MainActivity`），**步骤 6 要和 dex 里的类对比**。

### 4.3 步骤 3 · 算熵：找加密 payload（≈ `detect.py` 的熵列）

用任意能算 Shannon 熵的工具（`binwalk -E`、010 Editor 熵视图等），对每个 `assets/` 文件算熵：

| 文件 | 熵 (bit/byte) | 判读 |
|------|---------------|------|
| `assets/ijm_payload.bin`（v1） | 7.869 | 接近满熵 → 加密/压缩 payload |
| `assets/ijm_codes.bin`（v2） | 6.49 | 侧表（XOR 后，非满熵） |
| `assets/config.txt`（v3 诱饵） | 4.18 | 低熵明文 → **诱饵**，别被骗 |

**怎么判**：> 7.5 基本可认定加密/压缩；但**三代会放低熵诱饵**，所以熵只是线索之一，必须结合结构判据。

### 4.4 步骤 4 · 读 dex 头：定位各表（字节偏移）（≈ `dexlib.py`）

```
xxd -l 112 samples/classes_orig.dex        # dex header 恒为 0x70 = 112 字节
```

实测（`classes_orig.dex`）：

```
00000000  64 65 78 0a 30 33 37 00 29 b6 73 37 d8 26 19 80  dex.037.).s7.&..
00000010  8a b7 75 43 11 b9 fa b8 c1 d7 05 e0 73 e6 13 45  ..uC........s..E
00000020  ac 11 00 00 70 00 00 00 78 56 34 12 00 00 00 00  ....p...xV4.....
00000030  00 00 00 00 00 11 00 00 59 00 00 00 70 00 00 00  ........Y...p...
00000040  17 00 00 00 d4 01 00 00 12 00 00 00 30 02 00 00  ............0...
00000050  09 00 00 00 08 03 00 00 27 00 00 00 50 03 00 00  ........'...P...
00000060  07 00 00 00 88 04 00 00 44 0c 00 00 68 05 00 00  ........D...h...
```

**DexHeader 偏移表**（小端）：

| 偏移 | 字段 | 本例实测值 |
|------|------|-----------|
| `0x00` | magic[8] | `dex\n037\0` |
| `0x08` | checksum (adler32 of data[12:]) | `29 b6 73 37` |
| `0x0C` | signature[20] (sha1 of data[32:]) | `d8 26 19 80 …` |
| `0x20` | file_size | `ac 11 00 00` = **4524** |
| `0x24` | header_size | `70 00 00 00` = **0x70** |
| `0x28` | endian_tag | `78 56 34 12` = 0x12345678 |
| `0x34` | map_off | `0x1100` |
| `0x38 / 0x3C` | string_ids_size / off | 0x59=**89** / `0x70` |
| `0x40 / 0x44` | type_ids_size / off | 0x17=23 / `0x1D4` |
| `0x48 / 0x4C` | proto_ids_size / off | 0x12=18 / `0x230` |
| `0x50 / 0x54` | field_ids_size / off | 9 / `0x308` |
| `0x58 / 0x5C` | method_ids_size / off | 0x27=39 / `0x350` |
| `0x60 / 0x64` | **class_defs_size / off** | **7** / `0x488` |
| `0x68 / 0x6C` | data_size / off | `0xC44` / `0x568` |

`class_defs_size = 7` 与判定工具的 `class_defs=7` 完全对得上 —— 这就是"手算 vs 工具"互相验证。

### 4.5 步骤 5 · 判断类抽取：看 `code_item.insns` 是不是全 0（**核心**）

**code_item 布局**（`code_off` 为起点）：

| 偏移 | 字段 | 大小 |
|------|------|------|
| `+0x00` | registers_size | u2 |
| `+0x02` | ins_size | u2 |
| `+0x04` | outs_size | u2 |
| `+0x06` | tries_size | u2 |
| `+0x08` | debug_info_off | u4 |
| `+0x0C` | **insns_size**（单位 u2 code unit） | u4 |
| `+0x10` | **insns**（真实指令，`insns_size*2` 字节） | — |

> 所以：**insns 区偏移 = `code_off + 16`**。

以二代样本里 `SecretLogic->mix`（`code_off = 0xE00`，`insns_size = 57` → 114 字节）为例，
对比**抽取后**与**黄金样本**的同一偏移：

```
# 抽取后（samples/extracted_v2.dex）→ 全 0（被抽成 nop）
xxd -s 0xE10 -l 64 samples/extracted_v2.dex
00000e10: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000e20: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000e30: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000e40: 0000 0000 0000 0000 0000 0000 0000 0000  ................

# 抽取前黄金（samples/classes_merged_orig.dex）→ 真实字节码
xxd -s 0xE10 -l 64 samples/classes_merged_orig.dex
00000e10: 0000 2200 2600 7010 5300 0000 6e20 5500  ..".&.p.S...n U.
00000e20: 2000 0c02 1a00 c300 6e20 5500 0200 0c02   .......n U.....
00000e30: 6e20 5500 3200 0c02 6e10 5600 0200 0c02  n U.2...n.V.....
00000e40: 1403 c59d 1c81 1200 6e10 5200 0200 0a01  ........n.R.....
```

**怎么判**：`insns` 区全 `00` 且 `insns_size > 0` → 该方法被抽取。
数一数有多少个这样的 code_item，除以有 code 的方法总数，就是**空方法率**。

> 三代的坑：整体空率可能只有 18%，必须**按类下钻**——
> 本工程 `SecretLogic` 4/4、`TokenUtil` 4/4 全空，其余类完好。

### 4.6 步骤 6 · 比对 Manifest 声明类 vs dex 实际类（决定性证据）

把步骤 2 得到的 Manifest 类清单，与步骤 4 解析出的 dex 类列表做**差集**：

| 样本 | Manifest 声明 | dex 里是否存在 | 结论 |
|------|--------------|---------------|------|
| v1 | `com.demo.target.MainActivity` | **不存在** | 只能由运行期动态加载 → **一代实锤** |
| v2 | `MainActivity` 等 | 存在（但方法体全空） | 不是一代，是**类抽取** |

**怎么判**：声明了但 dex 里没有 → 运行期必然动态加载（判据 B7）；
声明了且 dex 里有、但方法体空 → 类抽取（判据 B3）。

### 4.7 步骤 7 · 手算 XOR 解密 payload（可逐字节验算）（≈ `unpack_v1.py` 的 `[2][3][4]`）

```
xxd -l 16 samples/payload_v1.bin
00000000: ac11 0000 414a 4d01 3e58 0518 d01f bc64  ....AJM.>X.....d
```

拆解：
- `[0:4]` = `ac 11 00 00` → **4524** = 声明的原始 dex 长度
- `[4:8]` = `41 4a 4d 01` → **`AJM\x01`** magic
- `[8:]` = XOR 流密文

密钥 `KEY = 5A 3C 7F 11 E4 29 8D 63`，第 i 字节：`c ^ KEY[i % 8] ^ (i & 0xFF)`。
手算前 4 字节验证（应还原出 dex 魔数）：

```
i=0:  0x3E ^ 0x5A ^ 0x00 = 0x64  → 'd'
i=1:  0x58 ^ 0x3C ^ 0x01 = 0x65  → 'e'
i=2:  0x05 ^ 0x7F ^ 0x02 = 0x78  → 'x'
i=3:  0x18 ^ 0x11 ^ 0x03 = 0x0A  → '\n'
                                   → "dex\n" ✓
```

**怎么判**：算出 `"dex\n037\0"` 就说明密钥和算法都对了，可继续解出完整 dex。

### 4.8 步骤 8 · 回填指令 + 重算校验值（≈ `unpack_v2.py` 的 `[3][4]`）

- **回填**：按侧表每条目的 `code_off`，把解密后的 insns 写回 `dex[code_off + 16 : +16 + insns_size*2]`。
- **重算校验值（顺序不能反！）**：
  1. `signature = sha1(data[32:])` —— **先算**
  2. `checksum  = adler32(data[12:])` —— **后算**（它覆盖含 signature 的区域）

> 先算 checksum 再改 signature，checksum 就对应了旧值，dex 会被判 Bad checksum。

### 4.9 步骤 9 · 验证还原结果（≈ `verify.py`）

- **sha256 对照**：还原 dex 与黄金样本是否逐字节一致；
- **锚点检查**：原始样本里的 `AJM-ANCHOR-*` 字符串是否都在（缺 = 没真解开）；
- **差异定位**：若不一致，给出差异字节数 + 首个差异偏移。

### 4.10 手动分析速查表

| 步骤 | 看什么 | 判读 | 对应脚本 |
|------|--------|------|----------|
| 1 拆包 | assets 莫名文件、dex 异常小 | 可疑 | `detect.py` ZIP 段 |
| 2 Manifest | application 被代理？声明了哪些类 | 代理壳 + 类清单 | `detect.py` Manifest 段 |
| 3 熵 | assets 文件熵 | >7.5 加密；低熵可能是诱饵 | `detect.py` 熵列 |
| 4 dex 头 | class_defs_size 等 | 定位各表 | `dexlib.py` |
| 5 类抽取 | insns 是否全 0 | 全 0 = 被抽取；算空方法率 | `detect.py` 空方法率 |
| 6 类差集 | 声明的类是否缺失 | 缺失 = 动态加载（一代） | 判据 B7 |
| 7 解密 | 是否还原出 `dex\n` | 密钥/算法正确 | `unpack_v1.py` |
| 8 回填 | insns 写回 + 重算校验 | 先 sha1 后 adler32 | `unpack_v2.py` |
| 9 验证 | 与黄金是否一致 | 一致 = 还原成功 | `verify.py` |

九步对应的完整命令（可直接复制，按顺序对应上表）：

```
# 步骤 1 · 拆包看条目
unzip -l samples/app_packed_v1.apk

# 步骤 2 · 读 Manifest，看 Application 是否被代理
aapt2 dump xmltree --file AndroidManifest.xml samples/app_packed_v1.apk

# 步骤 3 · 算熵（最省事的做法是看 detect.py 输出的 ZIP 条目第三列）
python tools/detect.py samples/app_packed_v1.apk

# 步骤 4 · 读 dex 头（header 恒为 112 字节）
xxd -l 112 samples/classes_orig.dex

# 步骤 5 · 看 insns 是否被抽空（insns 区 = code_off + 16 = 0xE00 + 16 = 0xE10）
xxd -s 0xE10 -l 64 samples/extracted_v2.dex
xxd -s 0xE10 -l 64 samples/classes_merged_orig.dex

# 步骤 6 · 类差集（Manifest 声明 vs dex 实际）：看判定输出里的 B7 段
python tools/detect.py samples/app_packed_v1.apk

# 步骤 7 · 手算 XOR 解密，验证密钥
xxd -l 16 samples/payload_v1.bin

# 步骤 8 · 回填 + 重算校验（十六进制编辑器手工做，或用脚本对照）
python tools/unpack_v2.py samples/app_packed_v2.apk analysis_output/unpack_v2_dex.dex --pristine samples/classes_merged_orig.dex

# 步骤 9 · 验证还原结果
python tools/verify.py analysis_output/unpack_v2_dex.dex samples/classes_merged_orig.dex
```

---

## 5. 量化特征对照表（实测）

| 样本 | 加固类型 | class_defs | methods(总/有码/空) | 空方法率 | 高熵 asset | 代理 Application | 缺失类 | 结论 |
|------|----------|-----------|---------------------|----------|-----------|-----------------|--------|------|
| `app_orig.apk` | 未加固 | 7 | 23/22/0 | 0.00% | 无 | 否 | 无 | **未加固** |
| `app_packed_v1.apk` | 一代整体加密 | 6 | 22/22/0 | 0.00% | `ijm_payload.bin` 7.869 | 是 | `MainActivity` | **一代整体加密** |
| `app_packed_v2.apk` | 二代类抽取 | 13 | 45/44/22 | 50.00% | `ijm_codes.bin` 6.49 | 是 | — | **二代类抽取** |
| `app_packed_v3.apk` | 三代选择性 | 13 | 45/44/8 | 18.18% | `brand_res_v3.dat` 6.68 | 是 | — | **二代类抽取** |
| `app_packed_v2_variant.apk` | 二代(变) | 13 | 45/44/22 | 50.00% | `rqn9xlwvh.yrm` 6.49 | 是 | 壳类 | **二代类抽取** |

---

## 6. 判定规则（detect.py 的 B1–B9）

**代号命名约定（先看懂这个，下面每条才不抽象）**

- 前缀 **`A` / `B`** 取自 `detect.py` 的「双判据」设计（`detect.py:9–11`）：
  - **`A` = 判据 A · 朴素字符串**（搜家族串 `ijiami` / `ProxyApplication`，易错）；
  - **`B` = 判据 B · 结构/统计**（看 dex 结构特征，核心路径）。
  带 `B` 前缀即声明「这条证据来自结构侧，不是易错的字符串侧」。
- 数字 **1–9** 是 B 路径的「判定清单槽位」（有序编号），每条结构特征占一个稳定 ID，方便在代码（`detect.py` 对应行）和文档间来回锚定。
- **特殊代号**：
  - **B2** 是**故意保留的错误示范**（只看类数量下结论），在 `app_orig.apk` 上会误报，用来对比证明 B 路径为何可靠（`detect.py:302`）；
  - **B5** 是**占位未用**，预留扩展（`detect.py:329`）；
  - **B3\*** 不是新规则，而是 **B3 的三代子情形**（整体空率压到阈值下、需下钻单类）。
- 为什么用代号而非整句文字：① 紧凑——`B1+B6+B7` 一个指纹锁定一代完整证据集；② 可追溯——每个代号都是回 `detect.py` 具体行 + 某结构特征的稳定锚点；③ 可解释——检测器打印「具体哪几条签名被点亮」，判定过程可被复盘，而不是吐黑盒结论。

- **判据 A · 朴素字符串**：搜 `ProxyApplication` / `ijiami` / `loadClass` 等。**在变种上必然漏报**，仅作对照。
- **判据 B · 结构**（核心）：
  - **B1** 高熵 asset（> 7.5 bit/byte）→ 存在加密 payload
  - **B3** 空方法率 > 40% → 类抽取（二代）
  - **B3\*** 整体空率低但存在**局部 100% 空方法类** → 下钻单类（三代）
  - **B4** `application` 是"小 Application"且 dex 引用 `DexClassLoader`/`loadClass` → 被代理
  - **B6** 所有 dex 并集中都没有 **App 自身包**的业务类 + 高熵 asset → 一代整体加密
  - **B7** Manifest 声明的类在**所有 `classes*.dex` 的并集**中都不存在 → 需运行期动态加载（**强证据，但定性为一代还需配合 B1/B6 的载荷证据**）
  - **B8** 存在已知壳/加固厂商特征的 SO（`SUSPECT_SO` 名单）→ Native 侧加固信号

> 早期用 `class_defs <= 8` 的朴素阈值会把 `app_orig`（7 个类）**误判为壳**，已改用 B7 消除误报。

**判据失效边界（务必记住）**——B3「空方法率」只对**抽取型**有效：

| 场景 | `insns` 形态 | 空方法率 B3 | 能否靠 B3 检出 |
|---|---|---|---|
| 抽取（二代/三代） | 全 `0x00`（nop） | 升高（50% / 局部 100%） | ✅ 能 |
| **DEX VMP**（§2.5） | 非零（调用解释器的 `invoke-static`） | **不升高** | ❌ **失效** |
| **Java2CPP**（§2.8） | 业务代码根本不在 DEX 里 | **不升高** | ❌ **失效** |

> 后两种要靠"**方法体内容异常 + `assets/` 有非 dalvik 载荷 + 存在解释器/SO**"来识别（见 §2.13 检查表）。
> 这也解释了为什么判定必须**多层证据叠加**，而不是押注单一指标。

**B7 依赖 aapt2**（要精确解析二进制 AndroidManifest），`detect.py` 的查找顺序：

1. 环境变量 `AJ_AAPT2`（显式指定某个版本时用，路径不存在则忽略）
2. 系统 `PATH` 里的 `aapt2`（**默认路径，换机器/换 SDK 版本都不会失效**）
3. 都没有 → stderr 打一次 `[warn]`，**降级为字符串启发式，不崩**

> 也就是说：**没有 aapt2 时 B7 整条判据不可用**，涉及 B7 的结论必须保证 `aapt2` 在 PATH。

| 代号 | 含义                              | 备注                                                         |
| :--- | :-------------------------------- | :----------------------------------------------------------- |
| B1   | 高熵 asset                        | 最表层信号                                                   |
| B2   | **错误示范**（只看类数量下结论）  | 故意保留的「负对照」，在 app_orig 上会误报 (`detect.py:302`) |
| B3   | 空方法率 > 40%                    | 二代                                                         |
| B3*  | 整体空率低但局部 100% 空方法      | B3 的子情形，三代                                            |
| B4   | 代理 Application                  |                                                              |
| B5   | 占位未用                          | 预留扩展 (`detect.py:329`)                                   |
| B6   | 无 App 自身包业务类 + 高熵 asset   | 一代（包名从 manifest 组件推导）                             |
| B7   | Manifest 声明类 vs **所有 dex 并集** | 强证据，定性需配合 B1/B6                                    |
| B8   | 已知壳厂商 SO（SUSPECT_SO 名单）   | Native 侧信号，需进 ELF 确认                                 |
| B9   | SO 熵异常（> 7.5）                | 仅「需人工复核」提示，**不参与定性**                          |

---

### 6.1 真实 APK 上的教训（本工具曾被自我样本"验成正确"）

> **背景**：本工具的 6 个样本全是自己合成的——单 dex、类数 6~13、包名 `com/demo`、
> 教科书式干净。用它做验证属于**循环论证**：检测器在自己设计的样本上当然全对。
> 第一次拿一个真实未加固 APK（普通 AndroidX App）来跑，立刻误报成「一代整体加密」。

**实测数据**（某个真实普通 App，无加固）：

```
classes.dex 6454 类 / classes2.dex 249 / classes3.dex 4 / classes4.dex 786 → 共 7493 类
manifest 声明类：ProfileInstallReceiver, InitializationProvider, MainActivity
所有 dex 并集比对 → missing = 0            （真实：全部存在）
只比对主 dex      → missing = 2            （原实现：误报！）
```

**四个根因，逐条记住**：

| # | 缺陷 | 为什么在合成样本上看不出来 | 真实 APK 上的后果 |
|---|---|---|---|
| 1 | B7 只比对主 dex（`dxs[0]`），忽略 `classes2/3/4.dex` | 合成样本全是单 dex | AndroidX 组件被分到次级 dex → 被当成「缺失」→ 误报一代 |
| 2 | B6 业务类判断写死 `'com/demo'` | 合成样本就是 `com/demo` | 对任意真实 App `biz` 恒为空，**只要有个高熵 asset 就误报一代**（比 #1 更隐蔽） |
| 3 | `SUSPECT_SO` 定义了从未引用；`f['libs']` 采了从不判定 | 合成样本没有 SO | Native 层对判定完全不可见，与 §2.0 原则 1「必须进入 SO」直接矛盾 |
| 4 | 兜底结论写「**未加固**」 | 合成样本覆盖了所有已知 pattern | 把「没看到已知特征」说成「没有加固」，VMP / Java2CPP 会被放过去 |

**修正后的自我保护机制**（都在 `detect.py` 里）：

- 凡「某类是否存在」的判断，一律用**所有 dex 的并集**（`all_dex_classes`）。
- App 自身包名从 **manifest 四大组件**推导，**必须排除 `application` 类本身**——
  加固 App 的 Application 就是壳的代理类（`com.ijiami.shell.ProxyApplication`），
  它必然存在于 dex，把它算成业务包会让 B6 永远不命中（这是修 #1 时引入的回归，已修）。
- 包名推导还会剔除库/框架前缀（`LIB_PREFIXES`：`android.` / `androidx.` / `kotlin.` …），
  否则任何一个 AndroidX 组件都会让 App 包名集合失准。
- 结论阶梯改为**要求证据互相印证**：`B6 且 B7` 才能定一代；单独 B7 只给
  「疑似 DEX 动态加载」。不再由单一判据押注定性。
- 兜底措辞从「未加固」改为「**未见已知加固特征（不等于未加固）**」，并强制打印
  `COVERAGE_NOTICE` 认知边界，明确列出本工具**不覆盖**的方案。

**方法论结论（比这四个 bug 更重要）**：

> 「没有检测到」和「确认没有」是两件完全不同的事。
> 检测器的失败有两种对称的形态：**过度声称**（把正常 App 判成壳）和
> **过度信任**（把不认识的方案判成安全）。只防一边是不够的。
> 任何判定工具都必须：① 有**外部负样本**验证（不能只用自己生成的样本）；
> ② 显式声明**认知边界**，而不是让兜底结论假装全知。

> 已知不覆盖、需人工介入的方案：DEX VMP / Java2CPP / SO Linker / SO VMP /
> 字符串加密 / 完整性校验 / 反调试反 Hook（见 §2.5–2.14）。
> `app_vmp.apk` 就是「不明方案被放过」的教学样本——它的正确输出应当是
> 「未见已知加固特征」而不是「未加固」。

---

### 6.2 负样本工程与回归断言（把"修好了"固化成"可验证"）

> 光有负样本仍会烂。**它们必须配一条自动断言**，否则三个月后重构时
> 把 `main = dxs[0]` 改回去，没人会发现 —— 而且失效是**静默**的。

**构建负样本**

```bash
# 生成两个陷阱样本（多 dex / 合法高熵 asset），源码在 neg/
bash build/build_negatives.sh
#   => samples/neg_multidex.apk     多 dex，manifest 声明的组件类放在 classes2.dex
#   => samples/neg_highentropy.apk  多 dex + 合法但高熵的 asset（随机数据，非加密 dex）
```

**跑双向回归断言**

```bash
python tools/check_negatives.py
#   => 结果：全部通过（正向 5 项 / 负向 3 项）
```

断言是**双向**的，只做一边都会出错：

| 方向 | 检查什么 | 防的是什么 |
|---|---|---|
| 正向 | v1/v2/v3/variant 必须被判成对应代次；`app_vmp` 必须被判 VMP | 防止"为了消除误报改过头"，把真壳漏掉 |
| 负向 | 四个干净样本绝不允许被判成「已加固」，且不得命中 B6/B7/B8/B11/B12/B13 | 防止把多 dex / 高熵资源 / 合法 native 库这类正常形态误判成壳 |

**负样本的价值立刻兑现：它当场挖出了第 5 个根因**

`neg_multidex.apk` 第一次跑，输出 `缺失：.MainActivity` —— 注意那个**前导点**。

Manifest 允许写相对类名 `.MainActivity`，它会隐式展开成 `package + name`（即
`com.demo.neg.MainActivity`）。而 `aapt2_xmltree` 取的是**原始字符串**，拿它和 dex 里的
`com.demo.neg.*` 比对必然不相等 → B7 误报。**大量真实 App 的 manifest 都这么写**，
这是比多 dex 更普遍的误报源。

修法（`detect.py` 的 `aapt2_xmltree`）：解析 `<manifest package="...">`，把以 `.` 开头
（或不含 `.`）的类名补成全限定名。

> 这条**不是靠推理想到的，是靠负样本跑出来的** —— 这就是必须建负样本的理由。

**本轮新增的判据与机制**

| 代号 | 含义 | 定位 |
|---|---|---|
| B11 | 多个极短方法体汇聚调用同一个「大方法」→ **疑似 DEX VMP** | 终于补上了 §2.5 文档说"B3 失效"却无补偿规则的窟窿 |
| B12 | native 方法占比 ≥ 30% → **疑似 Java2CPP / 重度 native 化** | 对应 §2.8 |
| notes | 反分析能力痕迹 / SO 熵异常 / 未解析 SO | **不参与定性**，只提示"需人工" |

B11 的三条硬约束是**实测逼出来的**（初版在正常 App 上误报、在真 VMP 上漏检，双输）：

1. 目标不得属于库/框架包 —— 否则 `java.lang.Object.<init>` 会被每个构造函数汇聚命中
   （`app_orig` 实测 5 个 caller，任何 App 都触发）；
2. 排除 `<init>` / `<clinit>` —— 构造链是天然的伪汇聚；
3. 目标自身必须是大方法（≥ 30 code unit）—— 解释器才有这个体积。
   实测：`com.ijiami.vmp.Vmp.run` = **196 units**，被保护的 `mix`/`twist` 各 11 units。

反分析串清单也被实测砍过：`META-INF/` 看着像签名校验，实际任何处理 zip/apk 的代码都会有，
在真实 App 上直接误报 → 已剔除，`/proc/self/maps`、`/data/local/tmp` 同理。

---

## 7. 决策流程（拿到样本先走这张图）

```
判定：python tools/detect.py <apk>
 ├─ B6 / B7 命中（dex 里没有业务类 + 高熵 asset；或 Manifest 声明的类在 dex 里缺失）
 │     └─► 一代「DEX 整体加密」→ tools/unpack_v1.py
 └─ B3 / B3* 命中（空方法率 > 40%；或整体空率低但存在局部 100% 空方法类）
       └─► 二代 / 三代「类抽取」→ tools/unpack_v2.py

收尾：python tools/verify.py <还原 dex> <黄金样本>
      sha256 一致 + 锚点齐全 + 0 字节差异 = 真还原
```

| 命令 | 作用 | 关键参数 / 预期输出 |
|---|---|---|
| `python tools/detect.py <apk>` | 结构体检，判定是不是壳、哪一代 | 可一次传多个文件；`--json` 输出机器可读。看最后的「>> 结论」行 |
| `python tools/unpack_v1.py <apk> <输出 dex>` | 一代：取加密 payload → 解密 → 写出还原 dex | `--pristine <黄金 dex>` 顺带做 sha256 比对；`[6] 与黄金…完全一致 ✓` |
| `python tools/unpack_v2.py <apk> <输出 dex>` | 二代/三代：按 `AJMT` 侧表回填 `insns` | `--pristine <黄金 dex>`；`[5] 还原后空方法数 = 0` |
| `python tools/verify.py <还原 dex> <黄金 dex>` | 独立于脱壳脚本的三项自检 | sha256 / 锚点 `AJM-ANCHOR-*` / 差异字节数+首个偏移 |

**选错脚本会怎样**：一代样本喂给 `unpack_v2.py`、或二/三代喂给 `unpack_v1.py`，
脚本只会报「找不到标记」，**不会自动切换**——所以先跑 `detect.py` 不是形式主义（见 §3.1）。

---

## 8. 从零构建样本（可选；样本已预生成）

```
bash build/build_target.sh
bash build/build_shell.sh
bash build/build_merged.sh
bash build/pack.sh
```

| 脚本 | 作用 | 依赖 |
|------|------|------|
| `build/locate.sh` | **工具链自动探测**：JAVA_HOME / SDK / NDK / build-tools / platform / python，工程根由脚本自身位置推导（不写死路径） | — |
| `build/env.sh` | 只做**可选覆盖**并导出 `AJ_*`；不指定就全走 `locate.sh` 探测。**自己不编译任何东西** | locate.sh |
| `build/env.sh.example` | 环境模板（不含真实路径），换机器时复制为 `env.sh` | — |
| `build_target.sh` | 编译**业务 App**（javac→d8→aapt2→zipalign→签名）→ `classes_orig.dex`(黄金) + `app_orig.apk` | 无 |
| `build_shell.sh` | 编译**壳** → `shell_classes.dex` + 壳骨架 | 无 |
| `build_merged.sh` | **业务+壳编进同一个 dex**（二代/三代必需）→ `merged_classes.dex` | target + shell |
| `pack.sh` | 加壳总装：三代产物 + 组装签名 3 个 APK + 生成变种 | merged |
| `build_vmp.sh` | 编译 **DEX VMP 教学样本** → `samples/app_vmp.apk`（独立源码树 `vmp/`） | 无（独立） |

```
bash build/build_vmp.sh
python tools/detect.py samples/app_vmp.apk
```

> 依赖关系：`build_target` → `build_shell` → `build_merged` → `pack`，必须**按此顺序跑**。
> `build_vmp.sh` 是**独立的**，随时可单独跑；它不改动 `app/src`，不会破坏黄金样本对照。
> 它们内部会自己加载 `env.sh`（进而 `locate.sh`），不要手动 `source`（PowerShell 里也没有 `source`）。
> 只想练脱壳的话跳过本章，直接用 `samples/` 里已生成好的样本。

**工具链不写死**（四档优先级，见 `build/locate.sh`）：

| 工具 | 优先级（从高到低） |
|---|---|
| JDK | 环境变量 `JAVA_HOME` > PATH 里的 `javac`/`java` 反推 |
| SDK | `ANDROID_HOME` > `ANDROID_SDK_ROOT` > PATH 里的 `aapt2`/`adb` 反推 |
| NDK | `ANDROID_NDK_HOME` > `NDK_ROOT` > `<SDK>/ndk/<最新版>` |
| build-tools / platform | 自动取 `<SDK>` 下版本号最大的那个 |
| aapt2 | `AJ_AAPT2` > PATH 里的 `aapt2`（换 SDK 版本也不会失效） |
| python | 环境变量 `PYTHON` > PATH 里的 `python` |

任一档都拿不到时脚本会**直接报错**，并告诉你该设哪个环境变量——不会默默用错版本。

---

## 9. 踩坑

**DEX / 脱壳**
1. **`finalize()` 顺序不能反**：先 `sha1(data[32:])` 再 `adler32(data[12:])`；反了 dex 报 Bad checksum。
2. **payload 头部顺序**：`[int32_le 长度][magic AJM\x01][密文]`，magic 在**偏移 4**（不在 0）。
3. **侧表查找靠 magic 不靠文件名**：三代改名 `brand_res_v3.dat`、变种改名 `rqn9xlwvh.yrm`，按 `AJMT` 魔数扫描照样能定位。
4. **变种黄金样本缺失**：需补跑字符串混淆版合并 dex，否则变种群验证会"对照失败"。
5. **判据 B7 替代朴素阈值**：避免把正常小 App 误判为壳。
6. **诱饵文件**：三代会放低熵 `config.txt`，"按熵找 payload"会误报，必须结合结构判据。
7. **脚本选型**：一代用 `unpack_v1.py`、二/三代用 `unpack_v2.py`，喂错脚本只会报"找不到标记"，不会自动切换。

**工具链（构建时）**
8. `d8.jar` 没有 `Main-Class` → 用 `java -cp d8.jar com.android.tools.r8.D8`。
9. `java`/`javac` 不认 Git Bash 的 `/d/xxx` 路径 → 一律写**盘符风格**（`X:/xxx`）；`build/locate.sh` 已统一转换。
10. `javac` 26 下 `-bootclasspath` 与 `-target` 不能同时出现 → 只用 `-classpath`。
11. `d8 --output` 不接受不存在的目录 → 给 `.zip` 或先 `mkdir`。

**环境**
12. 中文输出乱码 → 设 `PYTHONIOENCODING=utf-8`（PowerShell：`$env:PYTHONIOENCODING='utf-8'`）。
13. 本机只有 `python`，没有 `python3`（见全局约定）。
14. **aapt2 经管道会崩**：Git Bash 下 `aapt2 dump xmltree --file AndroidManifest.xml samples/app_packed_v1.apk | grep application` 偶发 `VirtualAlloc failed`；先重定向到文件再读。
15. **Windows 程序要用盘符风格路径**：`xxd`/`unzip` 是 Git Bash 工具能吃 `/d/...`，但 `aapt2`、`binwalk.exe` 这类 Windows 程序不行，会被当成当前盘符下的相对路径；传给它们的路径统一用 `X:/...`。

---

## 10. 命令速查

```bash
# 判定（一次可传多个样本，只看结构特征，不改任何文件）
python tools/detect.py samples/app_packed_v1.apk samples/app_packed_v2.apk samples/app_packed_v3.apk

# 一代脱壳：整体加密 → 解密 payload → 写出还原 dex
python tools/unpack_v1.py samples/app_packed_v1.apk analysis_output/unpack_v1_dex.dex --pristine samples/classes_orig.dex

# 二代/三代脱壳：按 AJMT 侧表把指令回填进 code_item.insns
python tools/unpack_v2.py samples/app_packed_v3.apk analysis_output/unpack_v3_dex.dex --pristine samples/classes_merged_orig.dex

# 验证：sha256 + 锚点 + 字节差异，三项独立于脱壳脚本自检
python tools/verify.py analysis_output/unpack_v3_dex.dex samples/classes_merged_orig.dex

# 字节偏移指南（不改文件，只告诉你去哪个偏移看、看到什么算什么）
python tools/walkthrough.py samples/app_packed_v1.apk

# 复位：status 查环境是否被练脏 / restore 还原样本 / backup 刷新基线
python tools/reset_lab.py status
python tools/reset_lab.py restore
python tools/reset_lab.py backup
```

| 脚本 | 作用 | 备注 |
|---|---|---|
| `detect.py` | 结构判定（B1–B7） | 决定下一步用哪个脱壳脚本 |
| `unpack_v1.py` | 一代整体加密脱壳 | 定位靠 payload 魔数 `AJM\x01`，不靠文件名 |
| `unpack_v2.py` | 二代/三代类抽取脱壳 | 定位靠侧表魔数 `AJMT`，改名/混淆都不影响 |
| `verify.py` | 还原结果三项自检 | 最强判据是 sha256 与黄金样本一致 |
| `walkthrough.py` | 手动复现的字节偏移指南 | 脚本世界 → 手动世界的桥（§4） |
| `reset_lab.py` | 备份 / 状态 / 回归 | `pristine/` + sha256 清单 |

---

## 11. 小结

- **加固在演化，判定本质不变**：从"dex 整体不在"到"方法体被抽空"，识别的始终是**结构异常**。
- **可量化才能可信**：空方法率 0%/50%/18.18%、熵 7.869/6.49、sha256 逐字节一致——每步都有数字。
- **先脚本后手动**：脚本给你"正确答案"，手动给你"为什么"；两者在每一段输出上都能互相对照（见 §4.10）。

---

## 12. 一句话记住

> **加固在演化，判定本质不变**——识别的始终是「结构异常」：dex 整体不在 / 方法体被抽空 / 类清单对不上。
> 一代找 payload，二代找侧表，三代还要下钻单类；无论哪一代，最后都用 `verify.py` 与黄金样本逐字节对照收尾。
