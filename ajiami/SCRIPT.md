# SCRIPT.md — 脚本方法：用 detect / unpack / verify 完成判定与脱壳

> 本文件与 `MANUAL.md` **结构完全平行**（§0–§8 一一对应），只讲「脚本怎么做」。
> 所有判定与脱壳都靠 `tools/` 下的 Python 脚本（纯标准库，无外部依赖），不依赖任何大模型。
> 想亲手走一遍每一步、搞清楚「为什么」的同学，去读 `MANUAL.md`（用 unzip / aapt2 / xxd / 熵工具复现）。
>
> 阅读顺序建议：先 §3 把结果跑出来（知道「能解开」），再看 §4 还原，最后用 §5 验证。

---

## 0. 概述与三分钟跑一遍

**项目定位**：本工程用自造的「类爱加密」样本，把 Android DEX 加固的**三代演化**（原理 → 结构特征 → 判定 → 脚本脱壳 → 验证）全链路搬到本地，做到**可编译、可量化、可复现**。

**三条硬约束**
1. **先确定性规则，再谈 LLM**：判定与脱壳都是手写结构分析，不依赖大模型。
2. **基于 evidence**：所有判定落在**结构特征**（字节偏移、空方法率、熵、缺失类），绝不靠文件名/字符串。
3. **配置外置**：工具链由 `build/locate.sh` 自动探测，脚本里不含写死绝对路径。

### 0.1 三分钟跑一遍（脚本版 · 一代样本最小闭环）

```bash
cd ajiami

# ① 判定：这是哪一代壳？（只做结构体检，不修改任何文件）
python tools/detect.py samples/apks/app_packed_v1.apk
#   => 【判据 B】B1 高熵 asset / B6 无业务类 / B7 Manifest 声明类缺失
#   => 结论：已加固：DEX 整体加密型（一代）

# ② 脱壳：一代用 unpack_v1.py；--pristine 给黄金样本，解完立刻比对
python tools/unpack_v1.py samples/apks/app_packed_v1.apk analysis_output/unpack_v1_dex.dex --pristine samples/dex/classes_orig.dex
#   => [4] dex 魔数校验 b'dex\n037\x00'   [6] 与黄金 classes_orig.dex 对照: 完全一致 ✓

# ③ 验证：独立于脱壳脚本自检（sha256 / 锚点 / 字节差异三项）
python tools/verify.py analysis_output/unpack_v1_dex.dex samples/dex/classes_orig.dex
#   => [1] sha256 一致 ✓   [2] 锚点 11/11   [3] 无差异 ✓   => 还原成功
```

判定 → 脱壳 → 验证三步走通，说明环境 OK。二/三代把 `app_packed_v1.apk` 换成 `app_packed_v2.apk` / `app_packed_v3.apk`、把 `unpack_v1.py` 换成 `unpack_v2.py`、黄金换成 `samples/dex/classes_merged_orig.dex` 即可（选型见 §8 决策流程）。

### 0.2 文件与样本索引

`tools/` 关键脚本（详见 §3–§7）：

| 脚本 | 作用 |
|------|------|
| `detect.py` | 结构判定（B1–B13），决定下一步用哪个脱壳脚本 |
| `unpack_v1.py` | 一代整体加密脱壳（取 payload → 解密 → 写 dex） |
| `unpack_v2.py` | 二/三代类抽取脱壳（按 `AJMT` 侧表回填 `insns`） |
| `verify.py` | 还原 dex 与黄金样本三项自检（sha256 / 锚点 / 字节差） |
| `walkthrough.py` | 字节偏移指南（脚本 → 手动的桥，§6） |
| `reset_lab.py` | 实验台备份 / 状态 / 复位（§7） |
| `check_negatives.py` | 双向回归断言（负样本工程，§3.8） |

`samples/` 样本清单：

| 样本 | 代次 / 类型 | 黄金样本（--pristine） |
|------|------------|------------------------|
| `app_orig.apk` | 未加固基线 | — |
| `app_packed_v1.apk` | 一代 · 整体加密 | `samples/dex/classes_orig.dex` |
| `app_packed_v2.apk` | 二代 · 全量抽取 | `samples/dex/classes_merged_orig.dex` |
| `app_packed_v3.apk` | 三代 · 选择性抽取 | `samples/dex/classes_merged_orig.dex` |
| `app_packed_v2_variant.apk` | 二代 · 字符串混淆变种 | `build/variant/merged_orig_variant.dex` |
| `app_vmp.apk` | DEX VMP 教学模型（认知边界） | — |
| `app_so_packed.apk` | SO 加壳 / 自实现 Linker（B13） | — |
| `neg_multidex.apk` / `neg_highentropy.apk` / `neg_native.apk` | 负样本（§3.8） | — |

---

## 1. 工程结构与样本

```
ajiami/
├── build/            # 构建脚本（locate.sh / env.sh / pack.sh / build_vmp.sh / build_negatives.sh）
├── app/             # 业务 App 源码（含 AJM-ANCHOR-0000..0010 分析锚点）
├── shell/           # 类爱加密壳源码（ProxyApplication / PayloadLoader / Crypto）
├── tools/           # 分析/判定/脱壳/验证脚本（本文档主角）
├── samples/         # 干净基线样本（已固化进 pristine/）
├── pristine/        # samples/ 的 sha256 清单备份
├── analysis_output/  # 脱壳还原产物
└── logs/            # 实操日志
```

> 配置全部外置：`build/locate.sh` 自动探测 JDK/SDK/NDK/python，`build/env.sh` 只做可选覆盖；脚本内无写死绝对路径。

---

## 2. 知识点总览（三代演化 + 保护体系）

> 本节只讲**原理**（是什么 / 为什么 / 失效边界）。每小节的「判定」与「脱壳」分别落到 §3 / §4 的脚本演示。

### 2.0 完整保护体系总览

Ajiami 不是普通「DEX 壳」，而是多层叠加：

```
Ajiami
├── DEX 保护      整体加密 / 代码分离 / 函数抽取+加密 / 动态还原 / DEX VMP
├── Native 保护   SO 加壳 / SO Linker / SO 防调用 / SO VMP
├── Java → Native Java2CPP
└── 对抗          防调试 / 防注入 / 防 Hook / 完整性校验 / 签名保护
```

本工程样本覆盖 **DEX 保护主线**（整体加密 → 函数抽取 → 选择性抽取 → 字符串混淆）；其余部分在 §2.5 起补齐**知识框架与识别方法**（需 NDK/真机的标注「待扩展」）。
**两条贯穿原则**：① DEX 与 Native 保护常形成 `壳 DEX → Native SO → 载荷 → 解密/执行 → 恢复` 的链，必须同时进 ELF/SO；② 不只盯 `classes.dex`，要查 `assets/` `lib/` `res/` 与非标准数据文件。

### 2.1 一代 · DEX 整体加密（Whole-DEX Encryption）
**原理**：业务 `classes.dex` 整体加密塞进 `assets/`；APK 里的 `classes.dex` 退化成极小壳，`Application` 指向壳的 `ProxyApplication`，运行期解密用 `DexClassLoader` 动态加载真 dex。
**结构特征**：壳 dex 无业务类；`assets/` 有高熵文件（本工程 `ijm_payload.bin`，熵 **7.869**）；payload 容器 `[int32_le 长度][magic 'AJM\x01'][XOR 密文]`；Manifest 声明的业务类在所有 dex 并集里**不存在**。
**判定 → §3.1**；**脱壳 → §4.1**。

### 2.2 二代 · 类抽取（Method/Class Extraction）
**原理**：保留类名/方法名，把每个 `code_item.insns` 抽空成 `0x00`（dalvik nop，dex 仍合法），真指令加密存进 `assets/` 侧表（magic `AJMT`），运行期按 `code_off` 回填。
**结构特征**：大量 `insns` 全 0 的方法 → **空方法率**（本工程 **22/44 = 50%**）；侧表条目 `u4 class_idx|u4 method_idx|u4 code_off|u4 insns_len|密文`。
**判定 → §3.2**；**脱壳 → §4.2**。

### 2.3 三代 · 选择性抽取 + 混淆 + 诱饵
**原理**：只抽敏感类（`SecretLogic` + `TokenUtil`）→ 整体空率压到 **18.18%（8/44）**；资源名混淆（侧表改名 `brand_res_v3.dat`）；诱饵 `config.txt` 骗「按熵找 payload」。
**结构特征**：整体空率低，但存在**局部 100% 空方法类**（SecretLogic 4/4、TokenUtil 4/4）→ 需**下钻单类**（B3\*）。
**判定 → §3.3**；**脱壳 → §4.2**（同 unpack_v2）。

### 2.4 变种样本 · 字符串混淆
`make_variant.py` 把家族串做**等长字母表倒序映射**（`ijiami`→`rqrznr`）：判据 A（朴素字符串）**完全失效**，判据 B（结构）**一个字节没变**照常命中。这正是「禁止只靠字符串下结论」的活证。
**判定 → §3.4**。

### 2.5 DEX VMP（虚拟化）
**原理**：原始指令 → 自定义字节码 → 自家虚拟机解释器执行；官方称每次加固可换指令集，故无永久固定 opcode 映射。
**静态特征**：类名/方法名/字段还在，但真实 dalvik 指令已不是原形式（是 `invoke-static` 到解释器的调用）。→ 空方法率 **不升高，B3 直接失效**（关键区别）。
**识别**：方法体是「调用解释器」异常形态 + `assets/` 有非 dalvik 自定义字节码 + 解释器类/SO。**本工程 `app_vmp.apk` 是「不明方案被放过」的教学样本**（§3.5），属认知边界。

### 2.6 独立数据载荷 + 多 SO 执行链
真实样本常见 `assets/ijiami.ajm` `lib/libexec.so` 等「缩壳 DEX + 独立载荷 + Native 链」。分析要查 `assets/`（大高熵文件）、`lib/*/`（加固 SO）、`res/`、其它非标准文件。本工程 DEX 样本不含这类独立 SO 载荷，但 detect.py 的 `lib/` 熵列 + §3.6 的 **B13** 已能覆盖 SO 侧。

### 2.7 Native 保护：SO 加壳 / SO Linker / SO 防调用 / SO VMP
**SO Linker**：存在非标准 Native 加载/链接结构（自己按 Program Header 装载，不写标准节头）。本工程已有 SO 样本 `app_so_packed.apk`（NDK 编译、节头表剥离模拟自实现 Linker），由 **B13** 自动识别；SO VMP / SO 防调用仍属知识框架（待扩展）。
**判定 → §3.6**。

### 2.8 Java2CPP（Java → Native）
Java → C++ → SO，DEX Java 代码减少、逻辑转 Native。**识别判据 B12**（native 方法占比 ≥ 30%）。本工程无样本，属知识框架。同样会让 **B3 失效**（业务不在 DEX）。

### 2.9 双重 VMP（DEX VMP + SO VMP）
`Java/Dex → DEX VMP → Native → SO VMP`。同时出现两层虚拟化时**两层都要看**。识别：B11（DEX VMP 汇聚）+ B13（SO 结构异常）同时命中。

### 2.10 字符串加密（DEX 字符串加密）
JADX 里关键 URL/密钥/类名/错误信息可能搜不到。处理：从「静态搜索」转「使用点 → 运行期解密 → 明文」。与 §2.4 区别：§2.4 是等长替换（串还在只是变形），字符串**加密**静态不可读须找解密点。属认知边界（动态还原）。

### 2.11 完整性 / 签名保护
DEX/SO/资源防篡改 + 签名保护。改 APK 重打包运行异常，可能不是代码错而是校验被触发。属认知边界。

### 2.12 反调试 / 反注入 / 反 Hook
防 Java/C 层调试、防注入、防 Hook。现象：附加调试器/动态 Hook → 崩溃退出。**作为独立模块分析，勿混入 DEX 恢复逻辑**。识别：B10 扫反分析痕迹，但真正确认需动态分析。

### 2.13 样本识别检查表
`classes.dex` 业务类大量消失、壳类极少；`assets/` 可能有独立加密载荷；`lib/` 可能有加固 SO；DEX 方法可能抽取；Native 可能承担恢复/VMP；关注动态加载、运行时恢复、完整性/环境检查、反调试。
**反向提醒**：JADX 里「只有几个奇怪的类」不代表 App 真只有几个类，可能业务 DEX 被移出标准 DEX。

### 2.14 保护方式 → 处理思路映射
① 整体加密 → 找运行期解密/加载点；② 函数抽取 → 找动态恢复点；③ DEX VMP → 定位虚拟机分析 opcode/dispatch/handler；④ SO 加壳 → 分析 Native 加载初始化；⑤ SO Linker → 分析自定义加载/链接；⑥ SO VMP → 定位 Native 虚拟机；⑦ Java2CPP → 转向对应 SO；⑧ 字符串加密 → 定位解密点；⑨ 完整性保护 → 定位校验逻辑；⑩ 反调试/反 Hook → 先识别触发机制再动态分析。
**覆盖度**：已覆盖 ① ② ③（教学模型）+ 字符串混淆；④⑤ 由 B13 自动识别；⑦ 由 B12 自动识别；⑥⑧⑨⑩ 为知识框架（待扩展）。

---

## 3. 判定：这是哪一代（脚本 · detect.py）

> `detect.py` 对 APK 或裸 dex 做结构体检，**不修改任何文件**。一次可传多个路径。
> 判据设计：`detect.py:9–11` 起「双判据」——**A**=朴素字符串（易错，仅对照）、**B**=结构/统计（核心路径）。所有结论只看 B。

### 3.1 一代 · 整体加密

```bash
python tools/detect.py samples/apks/app_packed_v1.apk
```

实测输出（节选 dex 特征 + 判定）：

```
[classes.dex] 6548 bytes, magic=dex\n037 , entropy=5.1449
     class_defs=6  methods=22(with code 22, empty 0)  空方法率=0.00%
     家族字符串命中: ['ProxyApplication', 'ijiami', 'ijm_payload']
     Application 类: [{'class': 'Lcom/ijiami/shell/ProxyApplication;', 'methods': 2}]
--- 判定 ---
  【判据 B】B1 高熵 asset(assets/ijm_payload.bin, 7.869 bit/byte) —— 存在加密 payload
  【判据 B】B4 manifest 声明的 Application=com.ijiami.shell.ProxyApplication 在 dex 里是"小 Application"(2 方法) → Application 被代理
  【判据 B】B6 所有 dex 并集都没有业务包 com.demo.target 的类，且存在高熵 asset → 真 dex 藏在 asset 里
  【判据 B】B7 AndroidManifest 声明 2 个类，1 个在所有 classes*.dex 并集里都不存在（缺失 com.demo.target.MainActivity）
  >> 结论：已加固：DEX 整体加密型（一代）
```

**怎么看**：关键在「dex 里**没有**什么」——`B6` 说业务包 `com.demo.target` 的类一个都不在任一 `classes*.dex` 里（只能运行期 `DexClassLoader` 加载），`B7` 说 Manifest 声明的 `MainActivity` 在所有 dex 并集里也找不到。两者叠加 + `B1` 高熵 `assets/ijm_payload.bin`（7.869）坐实「真 dex 加密塞进 asset」。判据 A 的家族串（`ProxyApplication`/`ijiami`）也命中，但它是**辅助信号、非定性依据**。
**失效边界**：`B6/B7` 是强证据但**非独立定性**——单「业务类缺失」会对多 dex / 组件化真实 App 误报，定性一代须**配合 B1 载荷证据**；判据 A 在**变种样本上全部失效**（§3.4），不能押注。

### 3.2 二代 · 类抽取

```bash
python tools/detect.py samples/apks/app_packed_v2.apk
```

实测输出（节选）：

```
[classes.dex] 10284 bytes, entropy=4.8985
     class_defs=13  methods=45(with code 44, empty 22)  空方法率=50.00%
     含空方法的类(按空率排序):
        Lcom/demo/target/Const;                         1/ 1  100%
        Lcom/demo/target/MainActivity;                  3/ 3  100%
        Lcom/demo/target/MainApplication;               2/ 2  100%
        Lcom/demo/target/NativeBridge;                  4/ 4  100%
        Lcom/demo/target/SecretLogic;                   4/ 4  100%
        Lcom/demo/target/Smoke;                         4/ 4  100%
        Lcom/demo/target/TokenUtil;                     4/ 4  100%
--- 判定 ---
  【判据 B】B3 全类空方法率 50.0% > 40% —— 类抽取（二代）
  >> 结论：已加固：类抽取型（二代及以上）
```

**怎么看**：`detect.py` 累加每个 `code_item.insns_size`，算「有 code_item 但指令长 0」的方法占比 = **空方法率**（22/44 = 50%）。`含空方法的类` 列表把**每个类**空率排出——二代是**全量抽取**，7 个业务类**全部 100% 空**。这正是 §2.2 原理里「`insns` 抽空成 `0x00`」的可观测形态。
**失效边界**：`B3` 依赖「`insns` 全 0 的 nop 形态」。一旦改成 **DEX VMP**（`insns` 非零）或 **Java2CPP**（业务不在 DEX），空方法率**降到 0 → B3 直接失效**（§2.5/§2.8）。`B3` 命中只能定性「类抽取型（二代及以上）」，**不能区分二代 vs 三代**——三代靠 `B3*` 下钻（§3.3）。

### 3.3 三代 · 选择性抽取

```bash
python tools/detect.py samples/apks/app_packed_v3.apk
```

实测输出（节选）：

```
[classes.dex] 10284 bytes, entropy=5.0470
     class_defs=13  methods=45(with code 44, empty 8)  空方法率=18.18%
     含空方法的类(按空率排序):
        Lcom/demo/target/SecretLogic;                   4/ 4  100%
        Lcom/demo/target/TokenUtil;                     4/ 4  100%
--- 判定 ---
  【判据 B】B3* 整体空方法率仅 18.2%，但存在局部空方法类 —— 需下钻到单类
      → Lcom/demo/target/SecretLogic; 4/4; Lcom/demo/target/TokenUtil; 4/4
  >> 结论：已加固：类抽取型（二代及以上）
```

**怎么看**：三代只抽**敏感类**，整体空率压到 **18.18%（8/44）**，低于 B3 的 40% 阈值——只看整体率会**漏掉**。关键在 `含空方法的类` 列表：`SecretLogic` 与 `TokenUtil` 是 **4/4 = 100% 空**的**局部空方法类** → 判据 `B3*`：**整体率低但存在 100% 空类 → 选择性抽取（三代）**。
**失效边界**：`B3*` 只在「被抽的类仍有 `code_item` 但 `insns` 为 0」时有效；若连 `code_item` 都被抹（只剩 native 声明），或改成 VMP/Java2CPP，空方法率信号消失，须转动态 trace（§2.5/§2.8）。

### 3.4 变种样本 · 字符串混淆

```bash
python tools/detect.py samples/apks/app_packed_v2_variant.apk
```

实测输出（节选）：

```
[classes.dex] 10284 bytes, entropy=4.9274
     class_defs=13  methods=45(with code 44, empty 22)  空方法率=50.00%
     家族字符串命中: 无
     Application 类: [{'class': 'Lcom/demo/target/MainApplication;', 'methods': 2},
                      {'class': 'Oxln/rqrznr/hsvoo/KilcbZkkorxzgrlm;', 'methods': 2}]
--- 判定 ---
  【判据 A】未命中任何家族字符串          ← ijiami→rqrznr、ProxyApplication→KilcbZkkorxzgrlm 已变形
  【判据 B】B3 全类空方法率 50.0% > 40% —— 类抽取（二代）
  >> 结论：已加固：类抽取型（二代及以上）
```

**怎么看**：`assets/rqn9xlwvh.yrm`（entropy 6.49）是混淆后的侧表名，判据 A 家族串已无处可寻 → **A 完全失效**；但 DEX 结构一个字节没变，空方法率仍 50%、`含空方法的类` 仍 7 个类全 100% 空 → **B 照常命中**。这正是「禁止只靠字符串下结论、必须以结构特征为主」的活证。
**失效边界**：判据 A 可被混淆/加密彻底绕过，但判据 B 也可能被结构层对抗（如 VMP 让空方法率归零）绕过——两者盲区相反、正好互补，结论须 A+B 叠加。

### 3.5 VMP 样本 · 认知边界（B 漏报，A 反命中）

```bash
python tools/detect.py samples/apks/app_vmp.apk
```

实测输出：

```
[classes.dex] 2456 bytes, entropy=4.9180
     class_defs=2  methods=10(with code 10, empty 0)  空方法率=0.00%
     家族字符串命中: ['ijiami']
【判据 A · 朴素字符串】命中家族字符串 ['ijiami']      ← 因包名 com.ijiami.vmp
【判据 B · 结构】无命中
>> 结论：未加固（或至少没有上述任一种特征）           ← 漏报！
```

**怎么看（最有价值反例）**：判据 **B 完全漏报**——空方法率 0%（VMP 的 `insns` 不是全 0）、无高熵 asset、无代理 Application；判据 **A 反而命中**——只因包名恰有 `ijiami`。→ **A 与 B 各有盲区、正好互补**：变种上 A 漏报 B 命中；VMP 上 B 漏报 A 命中。结论只能：**判定须多层证据叠加，单一指标不可押注**。真正识别 VMP 要看方法体是否「调用解释器」（`invoke-static` 到 `Vmp.run`）及是否存在非法 dalvik 的自定义字节码载荷。

### 3.6 SO 样本 · B13（ELF 结构异常）

```bash
python tools/detect.py samples/apks/app_so_packed.apk
```

实测输出（节选 Native 侧 + 判定）：

```
[classes.dex] 1916 bytes, entropy=4.6414
     class_defs=2  methods=13(with code 12, empty 0)  空方法率=0.00%
--- Native 侧 (lib/) ---
  lib/arm64-v8a/libcalc.so                       5320  3.3351
--- 判定 ---
  【判据 B】B13 libcalc.so 的 ELF 结构异常：no_section_headers：共享对象却完全没有节头表 —— 自定义 Linker 的典型形态（自己按 Program Header 装载）；no_dynsym：没有动态符号表，无法被标准 dlopen 解析，疑似自实现符号解析；no_dynstr：没有动态字符串表 —— 疑似 SO 加壳 / 自实现 Linker，需人工进 ELF 层确认
  >> 结论：疑似 SO 加壳 / 自实现 Linker（ELF 结构异常），需 ELF 层确认
```

**怎么看**：`detect.py` 对 `lib/` 下每个 SO 跑 `elfinspect`（纯 Python ELF 解析），检查节头表 / 动态符号表 / 动态字符串表是否缺失。`no_section_headers`（共享对象却完全没有 `.text/.rodata` 等标准节头）是**确定性信号**——正常 NDK `.so` 永远带完整节头，只有自实现 Linker 会自己按 Program Header 装载、不写标准节头。该信号**独立于任何 DEX 判据**。
**失效边界**：`B13` 只看「节头被剥离」这一结构异常。**SO VMP** 的解释器是 SO 里一个普通大函数、ELF 结构正常，静态不可定性（须动态 trace）；「不走汇聚调用」形态的自定义 VMP、精巧字符串加密同理——都列在工具输出「认知边界」里，绝不等于「未加固」。

### 3.7 框架类判据（B10 / B11 / B12 / B13）

`detect.py` 的 B 路径还覆盖以下信号（**均不参与定性**，只提示「需人工」）：

| 代号 | 含义 | 备注 |
| :--- | :--- | :--- |
| B1 | 高熵 asset | 最表层信号 |
| B3 | 空方法率 > 40% | 二代 |
| B3* | 整体空率低但局部 100% 空方法 | B3 子情形，三代 |
| B4 | 代理 Application | |
| B6 | 无 App 自身包业务类 + 高熵 asset | 一代 |
| B7 | Manifest 声明类 vs 所有 dex 并集 | 强证据，定性需配合 B1/B6 |
| B8 | 已知壳厂商 SO（SUSPECT_SO 名单） | Native 侧信号，需进 ELF 确认 |
| B9 | SO 熵异常（> 7.5） | 仅提示「需人工复核」，**不参与定性** |
| B10 | 反分析能力痕迹（反调试/反注入/反 Hook） | 命中列在 `threat_string_hits`，仅提示 |
| B11 | 多个极短方法体汇聚调用同一「大方法」 | **疑似 DEX VMP**（B3 失效时的补偿规则，§2.5） |
| B12 | native 方法占比 ≥ 30% | **疑似 Java2CPP / 重度 native 化**（§2.8） |
| B13 | SO 的 ELF 结构异常（节头被剥离 / 无动态符号表） | **疑似 SO 加壳 / 自实现 Linker**（§2.7） |

> B2 是故意保留的错误示范（只看类数量下结论，在 `app_orig` 上会误报，`detect.py:302`）；B5 占位未用（`detect.py:329`）。

**判据失效边界（务必记）**——B3 只对**抽取型**有效：

| 场景 | `insns` 形态 | 空方法率 B3 | 能否靠 B3 检出 |
|---|---|---|---|
| 抽取（二代/三代） | 全 `0x00`（nop） | 升高（50% / 局部 100%） | ✅ 能 |
| DEX VMP（§2.5） | 非零（调用解释器） | 不升高 | ❌ 失效 |
| Java2CPP（§2.8） | 业务不在 DEX | 不升高 | ❌ 失效 |

### 3.8 一键批量判定 + 负样本回归

```bash
# 一次跑完全部 5 个正向样本
python tools/detect.py samples/apks/app_orig.apk samples/apks/app_packed_v1.apk samples/apks/app_packed_v2.apk samples/apks/app_packed_v3.apk samples/apks/app_packed_v2_variant.apk

# 双向回归断言（正向 5 项 / 负向 3 项）
python tools/check_negatives.py
#   => 结果：全部通过（正向 5 项 / 负向 3 项）
```

负样本是**双向**的：正向防止「为消误报改过头把真壳漏掉」；负向防止把多 dex / 高熵资源 / 合法 native 库误判成壳。`neg_multidex.apk`（Manifest 写相对类名 `.MainActivity` 须补成全限定名）曾当场挖出 B7 误报源——这条**靠负样本跑出来，不是推理想到的**。

---

## 4. 脱壳：按代还原 dex（脚本 · unpack_v1 / unpack_v2）

> 选错脚本只会报「找不到标记」、**不会自动切换**，所以先跑 `detect.py`（§3）不是形式主义。

### 4.1 一代 · unpack_v1.py

```bash
python tools/unpack_v1.py samples/apks/app_packed_v1.apk analysis_output/unpack_v1_dex.dex --pristine samples/dex/classes_orig.dex
```

真实输出（每行对应脚本内部一步）：

```
[1] 从 APK 取出 payload: assets/ijm_payload.bin  (4532 bytes)
[2] 头部: decl_len=4524  magic=b'AJM\x01'
[3] 解密后长度 = 4524
[4] dex 魔数校验: b'dex\n037\x00'
[5] 已写出: analysis_output/unpack_v1_dex.dex
    sha256 = e330d2998de45a680a5a3cd415d1e83290378cc15584b2c2831518028c588cc1
[6] 与黄金 classes_orig.dex 对照: 完全一致 ✓
```

**逐行怎么读**：`[2]` `decl_len` 是声明原始 dex 长，`magic` 必须 `AJM\x01`（定位靠 magic 不靠文件名）；`[3]` 解密后长应等于 `decl_len`，对不上说明密钥/算法错；`[4]` 开头须 `dex\n037\0`——「解对了」最快判据；`[6]` 与黄金一致 = 本次脱壳成功。
**失效边界**：payload 头部顺序是 `[int32_le 长度][magic AJM\x01][密文]`，**magic 在偏移 4 不在 0**；若样本改了 XOR 密钥/算法，`[4]` 魔数校验会失败——此时须进 §6 看字节确认密钥（MANUAL §4.1 手算验证）。

### 4.2 二代 / 三代 · unpack_v2.py

```bash
# 形态 A：直接喂 APK（常用）
python tools/unpack_v2.py samples/apks/app_packed_v3.apk analysis_output/unpack_v3_dex.dex --pristine samples/dex/classes_merged_orig.dex

# 形态 B：已有抽取后的 dex + 单独侧表文件
python tools/unpack_v2.py samples/dex/extracted_v3.dex samples/payloads/codetable_v2.bin analysis_output/out.dex
```

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

**逐行怎么读**：`[1]` 侧表按 `AJMT` 魔数扫出，不靠文件名——三代改名 `brand_res_v3.dat`、变种改名 `rqn9xlwvh.yrm` 都照样定位（抗混淆关键）；`[3]` 回填条数应等于 `[2]` 条目数，少一个说明某 `code_off` 对不上；`[4]` 先 `sha1(data[32:])` 算 signature、后 `adler32(data[12:])` 算 checksum，**顺序反了 dex 会 Bad checksum**；`[5]` **还原后空方法数必须 0**，不为 0 就是没回填干净。
**失效边界**：unpack_v2 依赖侧表 `AJMT` 魔数 + 标准 `code_item` 布局。若样本改成 VMP（无侧表、指令是解释器调用）或 Java2CPP（无 dex 业务），侧表不存在 → 脚本报「找不到标记」，须转动态分析（认知边界）。

### 4.3 变种脱壳（黄金须用混淆版）

```bash
python tools/unpack_v2.py samples/apks/app_packed_v2_variant.apk analysis_output/unpack_v2_variant_dex.dex --pristine build/variant/merged_orig_variant.dex
```

> 变种群的黄金必须是**字符串混淆版**合并 dex（还原出来的是带混淆串的 dex），否则对照会「失败」。这是唯一与 §4.2 不同的注意点。

### 4.4 脱壳结果对照表（实测）

| 还原文件 | 黄金样本 | sha256（一致） | 锚点 | 结论 |
|----------|----------|---------------|------|------|
| `unpack_v1_dex.dex` | `samples/dex/classes_orig.dex` | `e330d2998d…588cc1` | 11/11 | ✅ 完全一致 |
| `unpack_v2_dex.dex` | `samples/dex/classes_merged_orig.dex` | `7527307217…56f94d` | 11/11 | ✅ 完全一致 |
| `unpack_v3_dex.dex` | `samples/dex/classes_merged_orig.dex` | `7527307217…56f94d` | 11/11 | ✅ 完全一致 |
| `unpack_v2_variant_dex.dex` | `build/variant/merged_orig_variant.dex` | `5e4ee0a006…ec6621` | 0/0（均被混淆） | ✅ 完全一致 |

---

## 5. 验证（verify.py · 是否真还原）

```bash
python tools/verify.py analysis_output/unpack_v3_dex.dex samples/dex/classes_merged_orig.dex
```

真实输出：

```
还原：analysis_output/unpack_v3_dex.dex
黄金：samples/dex/classes_merged_orig.dex
[1] sha256: 一致 ✓
[2] 锚点字符串: 还原 11 个 / 黄金 11 个
    全部锚点都在 ✓
[3] 无差异 ✓

=> 结论：还原成功，与黄金样本完全一致
```

**三项检查分别说明**：
1. **sha256**：最强判据，一致即逐字节相同。
2. **锚点字符串**：业务 App 预埋 `AJM-ANCHOR-0000..0010`；**缺一个就说明没真解开**（哪怕长度对）。变种黄金是混淆版，锚点数显示 0/0 属正常。
3. **字节差异**：不一致时给差异字节数 + 首个差异偏移——定位「哪步写错」的入口。

> 验证独立于脱壳脚本，是「自述成败」之外的第二道保险。任何一步对不上，先回 §4 看 `[3]/[5]` 行，再回 §6 看字节。

---

## 6. 字节偏移指南（walkthrough.py · 脚本→手动的桥）

> `walkthrough.py` **不改任何文件**，只打印「用十六进制编辑器到哪个偏移看、看到什么算什么」，把脚本世界带进 MANUAL.md 的手动世界。

```bash
python tools/walkthrough.py samples/apks/app_packed_v1.apk
python tools/walkthrough.py samples/apks/app_packed_v2.apk
```

实测（`app_packed_v1.apk`）：

```
[一代 · 整体加密] payload 位于 APK 内 assets/ijm_payload.bin
  APK 文件内偏移 (local header) = 0x11AD
  payload[0:4]  = int32_le 声明长度 = 4524 (0x11AC)
  payload[4:8]  = magic = b'AJM\x01'
  钥  匙        = XOR(key=5a3c7f11e4298d63, key 每字节再 ^ (i & 0xFF)，i 从 0 计数)
  payload[8:16] 经 XOR 流解密后 = b'dex\n037\x00'  （应为 dex\n037\0）
  手工复现：把这 4524 字节按 XOR 流逐字节还原，即得原始 classes.dex
```

实测（`app_packed_v2.apk` · 节选「被抽空的方法」与「侧表真实指令」）：

```
[二代/三代 · 类抽取] 侧表位于 APK 内 assets/ijm_codes.bin
  APK 文件内偏移 (local header) = 0x172D
  table[0:4]    = magic = b'AJMT'
  table[4:8]    = int32_le 条目数 = 22
  每条目布局：u4 class_idx | u4 method_idx | u4 code_off | u4 insns_len | insns_len 字节密文

  --- dex 内"被抽空"的方法（insns 全 0x00）---
    Lcom/demo/target/SecretLogic;->mix     direct       code_off=0xE00  insns_size=57(=114 字节)
    Lcom/demo/target/MainActivity;->onCreate virtual      code_off=0xC2C  insns_size=56(=112 字节)
    ...（共 22 个，还原后空方法数应为 0）...

  --- 侧表里的真实指令（回填目标 = dex 偏移 code_off + 16）---
    code_off=0xE00  insns_len=114  解密后前 8 字节=0000220026007010 ...
    code_off=0xC2C  insns_len=112  解密后前 8 字节=6f20010043001a04 ...
  手工复现：对每条目按 code_off 定位 code_item，把解密后的 insns 写回
            偏移 code_off+16 起的 insns_size*2 字节，最后重算 checksum/signature。
  还原后空方法数应为 0（当前 22，还原后 0）。
```

**怎么用**：在 MANUAL.md §4 手动复现时，直接用这里给的 `code_off`（如 `0xE00`）去 `xxd -s 0xE10`（=0xE00+16）看 `insns`，再按侧表解密字节回填。`walkthrough.py` 就是「脚本算好的偏移表」，免得自己翻 DEX 头。

### DexHeader 偏移速查（脚本解析同此）

| 偏移 | 字段 | 本例实测值 |
|------|------|-----------|
| `0x00` | magic[8] | `dex\n037\0` |
| `0x08` | checksum (adler32 of data[12:]) | `29 b6 73 37` |
| `0x0C` | signature[20] (sha1 of data[32:]) | `d8 26 19 80 …` |
| `0x20` | file_size | `ac 11 00 00` = **4524** |
| `0x24` | header_size | `70 00 00 00` = **0x70** |
| `0x60 / 0x64` | **class_defs_size / off** | **7** / `0x488` |
| `0x68 / 0x6C` | data_size / off | `0xC44` / `0x568` |

`class_defs_size = 7` 与判定工具的 `class_defs=7` 完全对得上——「脚本 vs 手算」互相验证。

---

## 7. 复位（reset_lab.py · 实验台）

```bash
python tools/reset_lab.py backup      # 把 samples/ 全量复制进 pristine/ 并写 sha256 清单
python tools/reset_lab.py status      # 逐项对照清单，输出 OK/DIFF/MISSING/EXTRA
python tools/reset_lab.py restore     # 用 pristine/ 覆盖回 samples/（默认跳过一致文件）
python tools/reset_lab.py restore --force
```

> 改样本、跑新实验前先 `backup`；结果对不上时先 `status`，能立刻区分「是我改坏了样本」还是「脱壳逻辑错了」。这是把「修好了」固化成「可验证」的关键一环（呼应 §3.8 负样本工程）。

---

## 8. 决策流程 / 踩坑 / 速查

### 8.1 决策流程（拿到样本先走这张图）

```
判定：python tools/detect.py <apk>
 ├─ B6 / B7 命中（dex 里没有业务类 + 高熵 asset；或 Manifest 声明类在 dex 里缺失）
 │     └─► 一代「DEX 整体加密」→ tools/unpack_v1.py
 └─ B3 / B3* 命中（空方法率 > 40%；或整体空率低但存在局部 100% 空方法类）
       └─► 二代 / 三代「类抽取」→ tools/unpack_v2.py
收尾：python tools/verify.py <还原 dex> <黄金样本>
      sha256 一致 + 锚点齐全 + 0 字节差异 = 真还原
```

| 命令 | 作用 | 预期输出 |
|---|---|---|
| `python tools/detect.py <apk>` | 结构体检，判定是不是壳、哪一代 | 看最后「>> 结论」行 |
| `python tools/unpack_v1.py <apk> <out>` | 一代：取加密 payload → 解密 → 写 dex | `--pristine` 时 `[6] 完全一致 ✓` |
| `python tools/unpack_v2.py <apk> <out>` | 二/三代：按 `AJMT` 侧表回填 `insns` | `[5] 还原后空方法数 = 0` |
| `python tools/verify.py <out> <黄金>` | 独立于脱壳的三项自检 | sha256 / 锚点 / 差异 |

**选错脚本会怎样**：一代喂 `unpack_v2`、二/三代喂 `unpack_v1`，脚本只报「找不到标记」不自动切换。

### 8.2 踩坑（脚本 / 判定侧）

1. **`finalize()` 顺序不能反**：先 `sha1(data[32:])` 再 `adler32(data[12:])`；反了 dex 报 Bad checksum。
2. **payload 头部顺序**：`[int32_le 长度][magic AJM\x01][密文]`，magic 在**偏移 4**（不在 0）。
3. **侧表查找靠 magic 不靠文件名**：三代 `brand_res_v3.dat`、变种 `rqn9xlwvh.yrm` 按 `AJMT` 扫描照样定位。
4. **变种黄金样本缺失**：须补跑字符串混淆版合并 dex，否则对照失败。
5. **判据 B7 替代朴素阈值**：避免把正常小 App 误判为壳。
6. **诱饵文件**：三代放低熵 `config.txt`，「按熵找 payload」会误报，须结合结构判据。
7. **脚本选型**：一代 `unpack_v1`、二/三代 `unpack_v2`，喂错只报「找不到标记」。
8. **中文乱码**：`PYTHONIOENCODING=utf-8`（PowerShell `$env:PYTHONIOENCODING='utf-8'`）。
9. **本机只有 `python` 无 `python3`**（见全局约定）。

### 8.3 速查

```bash
# 判定（一次可传多个样本，只看结构特征，不改任何文件）
python tools/detect.py samples/apks/app_packed_v1.apk samples/apks/app_packed_v2.apk samples/apks/app_packed_v3.apk

# 一代脱壳
python tools/unpack_v1.py samples/apks/app_packed_v1.apk analysis_output/unpack_v1_dex.dex --pristine samples/dex/classes_orig.dex

# 二代/三代脱壳
python tools/unpack_v2.py samples/apks/app_packed_v3.apk analysis_output/unpack_v3_dex.dex --pristine samples/dex/classes_merged_orig.dex

# 验证
python tools/verify.py analysis_output/unpack_v3_dex.dex samples/dex/classes_merged_orig.dex

# 字节偏移指南（不改文件）
python tools/walkthrough.py samples/apks/app_packed_v1.apk

# 复位
python tools/reset_lab.py status
python tools/reset_lab.py restore
python tools/reset_lab.py backup
```

**一句话记住**：加固在演化，判定本质不变——识别的始终是「结构异常」：dex 整体不在 / 方法体被抽空 / 类清单对不上。一代找 payload，二代找侧表，三代还要下钻单类；最后用 `verify.py` 与黄金样本逐字节对照收尾。
