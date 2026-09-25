# MANUAL.md — 手脱方法：用通用工具（unzip / aapt2 / xxd / 熵工具）复现每一步

> 本文件与 `SCRIPT.md` **结构完全平行**（§0–§8 一一对应），只讲「通用工具怎么做」。
> 只用 **unzip / aapt2 / xxd / 熵工具 / readelf 或等价 xxd / sha256sum / cmp / grep** 这类任意平台都有的工具，
> 目的是**亲手走一遍脚本做的每一步**，而不是只会跑脚本。配套的一键脚本见 `SCRIPT.md`。
>
> PowerShell 下 `xxd` 可用 `Format-Hex -Path <文件> -Offset <偏移> -Count <长度>` 替代；`aapt2`/`binwalk` 这类 Windows 程序传参要用盘符风格路径（`X:/...`），`unzip`/`xxd`/`sha256sum` 这类 Git Bash 工具可用 `/d/...`。
> 所有命令单行书写，每行用 `# =>` 注释判读。

---

## 0. 概述与三分钟跑一遍

**项目定位**：同 `SCRIPT.md` ——用自造「类爱加密」样本，把 DEX 加固三代演化的判定与脱壳全链路搬到本地。
**三条硬约束**（与脚本版一致）：先确定性规则再谈 LLM；基于 evidence（结构特征）；配置外置。

### 0.1 三分钟跑一遍（手脱版 · 一代最小闭环）

```bash
cd ajiami

# ① 拆包看条目：找"多出来的东西"（异常小的 classes.dex + assets/ 下莫名文件）
unzip -l samples/apks/app_packed_v1.apk
#   => classes.dex 仅 6548 字节（异常小，只有壳）；assets/ijm_payload.bin 4532 字节（多出来的高熵文件）

# ② 读 Manifest：找被代理的 Application（壳类而非业务类）
aapt2 dump xmltree --file AndroidManifest.xml samples/apks/app_packed_v1.apk > /tmp/manifest.txt
grep -i "android:name" /tmp/manifest.txt | head
#   => application 的 android:name="com.ijiami.shell.ProxyApplication"（壳类 → Application 被代理）
#   => activity android:name="com.demo.target.MainActivity"（记下，步骤⑥要和 dex 类对比）

# ③ 算熵：确认 payload 是加密/压缩（> 7.5 基本可认定）
python -c "import math;from collections import Counter;b=open('samples/payloads/payload_v1.bin','rb').read();c=Counter(b);n=len(b);e=-sum((v/n)*math.log2(v/n) for v in c.values());print('entropy=%.4f'%e)"
#   => entropy=7.8690   ← 接近满熵，典型加密 payload
```

三步下来已能定性「一代整体加密」：`classes.dex` 异常小 + `assets/` 高熵 payload + `Application` 被代理。下面 §3 / §4 把每一代、每一步的手工做法铺开。

### 0.2 文件与样本索引

`tools/`（本文档**不使用**，仅列作对照；手脱只用系统通用工具）：

| 工具 | 本文档对应手脱手段 |
|------|--------------------|
| `detect.py` | `unzip -l` + `aapt2` + `xxd` + 熵工具（§3） |
| `unpack_v1.py` | `xxd` 读 payload + 手算 XOR + 写回 dex（§4.1） |
| `unpack_v2.py` | `xxd` 读 `code_item.insns` + 侧表解密 + 回填（§4.2） |
| `verify.py` | `sha256sum` + `cmp` + `grep`（§5） |
| `walkthrough.py` | 手动读 dex 头偏移（§6） |
| `reset_lab.py` | `cp pristine/* samples/`（§7） |

`samples/` 清单与 `SCRIPT.md` §0.2 完全相同（一代 `v1` / 二代 `v2` / 三代 `v3` / 变种 `v2_variant` / VMP `app_vmp` / SO `app_so_packed` / 负样本）。

---

## 1. 工程结构与样本

```
ajiami/
├── samples/         # 干净基线样本（手脱对象）
├── pristine/        # samples/ 的 sha256 清单备份（§7 复位用）
├── analysis_output/  # 脱壳还原产物（写到这里）
├── app/ shell/ build/ tools/ logs/   # 源码/构建/脚本/日志
```

> 手脱时所有产物写到 `analysis_output/`，不污染 `samples/`。配置全部外置，换机器也能跑。

---

## 2. 知识点总览（三代演化 + 保护体系）

> 本节只讲**原理**；每小节的「判定」与「脱壳」分别落到 §3 / §4 的通用工具演示。（正文与 `SCRIPT.md` §2 完全一致，便于单文档自包含。）

### 2.0 完整保护体系总览
Ajiami 是多层叠加：`DEX 保护`（整体加密/代码分离/函数抽取/动态还原/DEX VMP）、`Native 保护`（SO 加壳/SO Linker/SO 防调用/SO VMP）、`Java→Native Java2CPP`、`对抗`（防调试/防注入/防 Hook/完整性校验/签名保护）。本工程样本覆盖 DEX 保护主线；其余在 §2.5 起补齐知识框架。**两条原则**：① DEX 与 Native 常形成链，须同时进 ELF/SO；② 不只盯 `classes.dex`，要查 `assets/` `lib/` `res/` 与非标准文件。

### 2.1 一代 · DEX 整体加密
业务 `classes.dex` 整体加密塞进 `assets/`；`classes.dex` 退化成极小壳，`Application` 指向 `ProxyApplication`，运行期 `DexClassLoader` 加载真 dex。**结构特征**：壳 dex 无业务类；`assets/` 高熵文件（本工程 `ijm_payload.bin` 熵 **7.869**）；payload 容器 `[int32_le 长度][magic 'AJM\x01'][XOR 密文]`；Manifest 声明业务类在所有 dex 并集里不存在。**判定 → §3.1；脱壳 → §4.1。**

### 2.2 二代 · 类抽取
保留类名/方法名，把每个 `code_item.insns` 抽空成 `0x00`（nop，dex 仍合法），真指令加密存进 `assets/` 侧表（magic `AJMT`），运行期按 `code_off` 回填。**结构特征**：空方法率（本工程 **22/44 = 50%**）；侧表条目 `u4 class_idx|u4 method_idx|u4 code_off|u4 insns_len|密文`。**判定 → §3.2；脱壳 → §4.2。**

### 2.3 三代 · 选择性抽取 + 混淆 + 诱饵
只抽敏感类（`SecretLogic`+`TokenUtil`）→ 整体空率压到 **18.18%（8/44）**；资源名混淆（侧表改名 `brand_res_v3.dat`）；诱饵 `config.txt` 骗「按熵找 payload」。**结构特征**：整体空率低，但存在**局部 100% 空方法类**（SecretLogic 4/4、TokenUtil 4/4）→ 需**下钻单类**（B3\*）。**判定 → §3.3；脱壳 → §4.2。**

### 2.4 变种样本 · 字符串混淆
`make_variant.py` 把家族串做**等长字母表倒序映射**（`ijiami`→`rqrznr`）：朴素字符串判定**完全失效**，结构**一个字节没变**照常命中 → 「禁止只靠字符串下结论」的活证。**判定 → §3.4。**

### 2.5 DEX VMP（虚拟化）
原始指令 → 自定义字节码 → 自家虚拟机解释执行；无永久固定 opcode 映射。**静态特征**：类名/方法名/字段还在，但真实 dalvik 指令已不是原形式（`invoke-static` 到解释器）。→ 空方法率**不升高，B3 直接失效**（关键区别）。识别靠：方法体「调用解释器」异常形态 + `assets/` 非 dalvik 自定义字节码 + 解释器类/SO。本工程 `app_vmp.apk` 是「不明方案被放过」教学样本（§3.5），属认知边界。

### 2.6 独立数据载荷 + 多 SO 执行链
真实样本常见 `assets/ijiami.ajm` `lib/libexec.so` 等「缩壳 DEX + 独立载荷 + Native 链」。分析要查 `assets/`（大高熵文件）、`lib/*/`（加固 SO）、`res/`、其它非标准文件。本工程 DEX 样本不含这类独立 SO 载荷，但 §3.6 的 **B13** 已能覆盖 SO 侧。

### 2.7 Native 保护：SO 加壳 / SO Linker / SO 防调用 / SO VMP
**SO Linker**：非标准 Native 加载/链接（自己按 Program Header 装载，不写标准节头）。本工程已有 SO 样本 `app_so_packed.apk`（NDK 编译、节头表剥离模拟自实现 Linker），由 **B13** 自动识别；SO VMP / SO 防调用仍属知识框架（待扩展）。**判定 → §3.6。**

### 2.8 Java2CPP（Java → Native）
Java → C++ → SO，DEX Java 代码减少、逻辑转 Native。**识别**：DEX 干净 + SO 庞大 + 业务减少 → 考虑 Java2CPP；判据 B12（native 占比 ≥ 30%）。本工程无样本，属知识框架。同样让 **B3 失效**。

### 2.9 双重 VMP（DEX VMP + SO VMP）
`Java/Dex → DEX VMP → Native → SO VMP`。两层虚拟化须**两层都看**。

### 2.10 字符串加密
JADX 里关键 URL/密钥/类名/错误信息可能搜不到。处理：从「静态搜索」转「使用点 → 运行期解密 → 明文」。与 §2.4 区别：§2.4 是等长替换（串还在只是变形），字符串**加密**静态不可读须找解密点。属认知边界（动态还原）。

### 2.11 完整性 / 签名保护
DEX/SO/资源防篡改 + 签名保护。改 APK 重打包运行异常，可能不是代码错而是校验被触发。属认知边界。

### 2.12 反调试 / 反注入 / 反 Hook
防 Java/C 层调试、防注入、防 Hook。现象：附加调试器/动态 Hook → 崩溃退出。**作为独立模块分析，勿混入 DEX 恢复逻辑**。

### 2.13 样本识别检查表
`classes.dex` 业务类大量消失、壳类极少；`assets/` 可能有独立加密载荷；`lib/` 可能有加固 SO；DEX 方法可能抽取；Native 可能承担恢复/VMP；关注动态加载、运行时恢复、完整性/环境检查、反调试。**反向提醒**：JADX 里「只有几个奇怪的类」不代表 App 真只有几个类，可能业务 DEX 被移出标准 DEX。

### 2.14 保护方式 → 处理思路映射
① 整体加密 → 找运行期解密/加载点；② 函数抽取 → 找动态恢复点；③ DEX VMP → 定位虚拟机分析 opcode/dispatch/handler；④ SO 加壳 → 分析 Native 加载初始化；⑤ SO Linker → 分析自定义加载/链接；⑥ SO VMP → 定位 Native 虚拟机；⑦ Java2CPP → 转向对应 SO；⑧ 字符串加密 → 定位解密点；⑨ 完整性保护 → 定位校验逻辑；⑩ 反调试/反 Hook → 先识别触发机制再动态分析。
**覆盖度**：已覆盖 ① ② ③（教学模型）+ 字符串混淆；④⑤ 由 B13 自动识别；⑦ 由 B12 自动识别；⑥⑧⑨⑩ 为知识框架（待扩展）。

---

## 3. 判定：这是哪一代（通用工具）

> 本节完全用通用工具复现 `detect.py` 的判定，不运行任何脚本。每代给出**看什么 / 怎么判**，并标注与脚本判据（Bx）的对应关系。

### 3.1 一代 · 整体加密

```bash
# 看 ZIP 条目：classes.dex 异常小 + assets/ 多出来文件
unzip -l samples/apks/app_packed_v1.apk
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

```bash
# 读 Manifest：Application 是否被代理 + 记下声明的业务类
aapt2 dump xmltree --file AndroidManifest.xml samples/apks/app_packed_v1.apk > /tmp/manifest.txt
#   => application android:name="com.ijiami.shell.ProxyApplication"（壳类 → 被代理）
#   => meta-data ijiami_real_application="com.demo.target.MainApplication"（真身线索）
#   => activity android:name="com.demo.target.MainActivity"（步骤⑥要和 dex 类对比）

# 算熵：确认 payload 是加密（> 7.5 基本可认定）
python -c "import math;from collections import Counter;b=open('samples/payloads/payload_v1.bin','rb').read();c=Counter(b);n=len(b);e=-sum((v/n)*math.log2(v/n) for v in c.values());print('entropy=%.4f'%e)"
#   => entropy=7.8690
```

**怎么判（对应 B1/B4/B6/B7）**：`classes.dex` 异常小（只有壳）→ **B4 代理 Application**；`assets/ijm_payload.bin` 熵 7.869 → **B1 高熵 asset（加密 payload）**；壳 dex 里没有 `com.demo.target` 业务类 → **B6**；Manifest 声明 `MainActivity` 在 dex 里找不到 → **B7**。四者叠加坐实「一代整体加密」。
**失效边界**：单「业务类缺失」会对多 dex / 组件化真实 App 误报，定性一代须**配合高熵 asset 证据**；「按文件名找 payload」在变种上彻底失效（§3.4），必须靠结构/熵。

### 3.2 二代 · 类抽取

```bash
# 抽出的 dex 里，用 xxd 看某个方法的 code_item.insns 是不是全 0
# insns 区 = code_off + 16；二代 SecretLogic->mix 的 code_off = 0xE00 → 看 0xE10
xxd -s 0xE10 -l 64 samples/dex/extracted_v2.dex
#   => 00000e10: 0000 0000 0000 0000 ...（全 0x00，被抽成 nop）
```

**怎么判（对应 B3）**：`insns` 区全 `00` 且 `insns_size > 0` → 该方法被抽取。把每个 `code_item` 的 `insns_size` 累加，数「有 code_item 但指令长 0」的方法占比 = **空方法率**。二代是**全量抽取**，所有业务类 100% 空 → 整体空率 50%（22/44）。
> 手算空方法率需逐类清点 `code_item`（用 `dexdump` 或 `xxd` 遍历），脚本 `detect.py` 的 B3 就是把这一步自动化。手动只需**确认存在大量 insns 全 0 的方法**即可定性「类抽取（二代）」。
**失效边界**：依赖「`insns` 全 0 的 nop 形态」。改成 **DEX VMP**（`insns` 非零）或 **Java2CPP**（业务不在 DEX）→ 空方法率归零，**B3 / 手动判定都失效**（§3.5 / §2.8）。

### 3.3 三代 · 选择性抽取

```bash
# 同样看 insns，但三代只抽敏感类；对比黄金样本同一偏移
xxd -s 0xE10 -l 64 samples/dex/extracted_v3.dex        # 抽取后：SecretLogic->mix 全 0
xxd -s 0xE10 -l 64 samples/dex/classes_merged_orig.dex # 黄金：真实字节码
```

**怎么判（对应 B3\*）**：三代整体空率压到 **18.18%（8/44）**，低于 50% 阈值——只看整体会**漏掉**。关键在**下钻单类**：`SecretLogic` 4/4、`TokenUtil` 4/4 是 **100% 空**的**局部空方法类**，其余类完好。这就是判据 **B3\***：**整体率低但存在 100% 空类 → 选择性抽取（三代）**。
> 资源名混淆（`brand_res_v3.dat`）和诱饵（`config.txt`）只改 `assets/` 文件名和熵分布，不影响 DEX 空方法率，所以 B3\* 不受影响——正是「结构判据不靠文件名/字符串」的体现。
**失效边界**：`B3*` 只在「被抽类仍有 `code_item` 但 `insns` 为 0」时有效；若连 `code_item` 被抹或改 VMP/Java2CPP，信号消失，须转动态 trace。

### 3.4 变种样本 · 字符串混淆

```bash
# 读 Manifest：壳类名被等长字母表倒序混淆（ProxyApplication → KilcbZkkorxzgrlm）
aapt2 dump xmltree --file AndroidManifest.xml samples/apks/app_packed_v2_variant.apk > /tmp/m_var.txt
grep -i "android:name" /tmp/m_var.txt | head
#   => Oxln/rqrznr/hsvoo/KilcbZkkorxzgrlm;（原 com.ijiami.shell.ProxyApplication 已变形）

# 算熵：侧表改名后仍是高熵（混淆只改文件名，不改字节）
python -c "import math;from collections import Counter;b=open('samples/payloads/payload_v1_variant.bin','rb').read();c=Counter(b);n=len(b);e=-sum((v/n)*math.log2(v/n) for v in c.values());print('entropy=%.4f'%e)"
#   => entropy=6.49  ← 仍是高熵侧表，只是名字变了
```

**怎么判**：Manifest 里壳类名已变形 → 朴素字符串搜索（`ijiami`/`ProxyApplication`）**完全失效**；但 DEX 结构一个字节没变，空方法率仍 50%（§3.2 同法）→ **结构判定照常命中**。这正是「禁止只靠字符串下结论、必须以结构特征为主」的活证。
**失效边界**：朴素字符串可被混淆/加密彻底绕过；结构判定也可能被 VMP（空方法率归零）绕过——两者盲区相反互补，结论须叠加。

### 3.5 VMP 样本 · 认知边界（手脱也定性不了）

```bash
# 看 ZIP 条目：没有 assets/ 高熵 payload，只有很小的 classes.dex
unzip -l samples/apks/app_vmp.apk
```

实测（`app_vmp.apk`）：

```
  Length      Date    Time    Name
---------  ---------- -----   ----
     1104  1980-01-01 00:00   AndroidManifest.xml
       40  1980-01-01 00:00   resources.arsc
     2456  1980-01-01 00:00   classes.dex          ← 有，且非空方法
      412  1980-01-01 00:00   META-INF/AJMLAB.SF
     1317  1980-01-01 00:00   META-INF/AJMLAB.RSA
      285  1980-01-01 00:00   META-INF/MANIFEST.MF
```

**怎么判（落入认知边界）**：
- `classes.dex` 在（2456 字节），**没有** `assets/` 高熵 payload → 不是一代；
- 用 `xxd`/`dexdump` 看方法体，`insns` **非零**（是调用解释器的 `invoke-static`，不是全 0 的 nop）→ 不是二代/三代抽取；
- 于是**静态结构层面无法定性** → 落入认知边界。真正识别须看：方法体是否「调用解释器」（`Vmp.run` 这类）+ 是否存在非法 dalvik 的自定义字节码载荷（`PROG_MIX` 这类 `byte[]`）。
> 这是最有价值的反例：**A 与 B 各有盲区、正好互补**——变种上 A 漏报 B 命中；VMP 上 B 漏报 A 命中（包名恰有 `ijiami`）。结论只能：判定须多层证据叠加，单一指标不可押注。

### 3.6 SO 样本 · B13（ELF 结构异常，纯 xxd 复现）

```bash
# 先解压出 SO（Windows 程序传参用盘符风格路径）
unzip -o -q samples/apks/app_so_packed.apk "lib/arm64-v8a/libcalc.so" -d analysis_output/so_probe

# 看 ELF 头前 64 字节：重点 e_type / e_shoff / e_shnum
xxd -l 64 analysis_output/so_probe/lib/arm64-v8a/libcalc.so
```

实测（节选 ELF 头前 64 字节）：

```
00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............
00000010: 0300 b700 0100 0000 0000 0000 0000 0000  ................
00000020: 4000 0000 0000 0000 0000 0000 0000 0000  @...............
00000030: 0000 0000 4000 3800 0900 4000 0000 0000  ....@.8...@.....
```

**怎么读（对应 B13）**（小端）：

| 偏移 | 字段 | 本例字节（小端） | 值 |
|------|------|------------------|----|
| `0x10` | `e_type` | `03 00` | **3 = ET_DYN（共享对象）** |
| `0x20` | `e_phoff` | `40 00 00 00 00 00 00 00` | `0x40`（Program Header 在偏移 64，存在 9 个） |
| `0x28` | `e_shoff` | `00 00 00 00 00 00 00 00` | **0 —— 没有节头表** |
| `0x3A` | `e_shentsize` | `40 00` | `0x40` |
| `0x3C` | `e_shnum` | `00 00` | **0 —— 节头数量为 0** |

`e_type=3`（共享对象）却 `e_shoff=0 / e_shnum=0`（完全没有 `.text/.rodata` 等标准节头），是**确定性信号**——正常 NDK `.so` 永远带完整节头，只有自实现 Linker 会自己按 Program Header 装载、不写标准节头。该信号**独立于任何 DEX 判据**，能抓到 UPX 类壳抓不到的自定义 Linker。
> 等价工具：`readelf -h libcalc.so` 会直接显示 `Section header table` 数量为 0；`readelf` 与 `xxd` 结论一致。
**失效边界**：`B13` 只看「节头被剥离」这一结构异常。**SO VMP** 的解释器是 SO 里一个普通大函数、ELF 结构正常，静态不可定性（须动态 trace）；「不走汇聚调用」形态的自定义 VMP、精巧字符串加密同理——都属认知边界，绝不等于「未加固」。

### 3.7 框架类判据（反调试串 / SO 熵 / 汇聚调用）

通用工具也能做 §2.5–§2.12 的**提示性**检查（均不参与定性，只提示「需人工」）：

```bash
# 反分析痕迹（反调试/反注入/反 Hook 字符串）—— 命中只说明"可能有"，须动态确认
strings samples/apks/app_orig.apk 2>/dev/null | grep -Ei "frida|substrate|/proc/self/maps|ptrace|debugger" | head

# SO 熵异常（> 7.5 提示"需人工复核"，B9）—— 对 lib/ 下每个 so 算熵
for f in $(unzip -l samples/apks/app_so_packed.apk | awk '/lib\//{print $4}'); do
  unzip -o -q samples/apks/app_so_packed.apk "$f" -d /tmp/soentropy
  python -c "import math,sys;from collections import Counter;b=open('/tmp/soentropy/$f','rb').read();c=Counter(b);n=len(b);print('$f',round(-sum((v/n)*math.log2(v/n) for v in c.values()),4))"
done
#   => lib/arm64-v8a/libcalc.so 3.3351  ← 这里偏低是因为节头被剥离后多为代码/数据，异常在"结构"不在"熵"

# DEX VMP 汇聚形态（B11）：多个极短方法体汇聚调用同一大方法 —— 用 dexdump 看 invoke 目标
dexdump -d samples/apks/app_vmp.apk 2>/dev/null | grep -i "Vmp.run" | head
```

**失效边界**：以上都只给「线索」，真正定性 VMP / Java2CPP / 字符串加密 / 完整性 / 反调试，必须进**动态分析**——这部分是本工程的认知边界，列为知识框架（待扩展）。

### 3.8 一键批量 + 负样本（手脱对照）

手脱没有「一键脚本」，但可用循环把 §3.1–§3.4 的判断套到所有样本：

```bash
# 对全部样本看 ZIP 条目 + 熵，人工对照 §3 的判读表
for a in samples/apks/app_packed_v1.apk samples/apks/app_packed_v2.apk samples/apks/app_packed_v3.apk samples/apks/app_packed_v2_variant.apk; do
  echo "==== $a ===="; unzip -l "$a" | grep -E "classes.dex|assets/"
done
#   => v1: classes.dex 小 + assets/ijm_payload.bin（一代）
#   => v2: classes.dex 大 + assets/ijm_codes.bin（二代，§3.2 看 insns）
#   => v3: classes.dex 大 + assets/brand_res_v3.dat（三代，§3.3 下钻）
#   => v2_variant: classes.dex 大 + assets/rqn9xlwvh.yrm（变种，§3.4）
```

负样本工程（`neg_multidex` / `neg_highentropy` / `neg_native`）用来防止把多 dex / 高熵资源 / 合法 native 库误判成壳 —— 手脱时若 `unzip -l` 看到多 `classes*.dex` 或合法高熵资源，应**先排除**再下结论（对应 `SCRIPT.md` §3.8 的双向回归）。

---

## 4. 脱壳：按代还原 dex（通用工具）

> 手脱即「用十六进制编辑器/通用工具，把脚本做的每一步亲手做一遍」。

### 4.1 一代 · 手算 XOR 解密 payload

```bash
# 看 payload 头部：前 8 字节 = [int32_le 长度][magic AJM\x01]
xxd -l 16 samples/payloads/payload_v1.bin
#   00000000: ac11 0000 414a 4d01 3e58 0518 d01f bc64  ....AJM.>X.....d
```

拆解（小端）：
- `[0:4]` = `ac 11 00 00` → **4524** = 声明原始 dex 长度
- `[4:8]` = `41 4a 4d 01` → **`AJM\x01`** magic
- `[8:]` = XOR 流密文

密钥 `KEY = 5A 3C 7F 11 E4 29 8D 63`，第 i 字节：`c ^ KEY[i % 8] ^ (i & 0xFF)`。手算前 4 字节验证（应还原出 dex 魔数）：

```
i=0:  0x3E ^ 0x5A ^ 0x00 = 0x64  → 'd'
i=1:  0x58 ^ 0x3C ^ 0x01 = 0x65  → 'e'
i=2:  0x05 ^ 0x7F ^ 0x02 = 0x78  → 'x'
i=3:  0x18 ^ 0x11 ^ 0x03 = 0x0A  → '\n'
                                   → "dex\n" ✓
```

**怎么判**：算出 `"dex\n037\0"` 即密钥/算法都对，可继续解出完整 dex。把 4524 字节按此 XOR 流逐字节还原，即得原始 `classes.dex`，写出到 `analysis_output/unpack_v1_dex.dex`。
**失效边界**：payload 头部顺序是 `[长度][magic AJM\x01][密文]`，**magic 在偏移 4 不在 0**；若样本改了 XOR 密钥/算法，前 4 字节解不出 `dex\n` —— 此时须回 §6 看字节确认密钥。

### 4.2 二代 / 三代 · 手填 insns + 重算校验

```bash
# ① 看抽取后 insns 全 0（抽空前）
xxd -s 0xE10 -l 64 samples/dex/extracted_v2.dex
#   00000e10: 0000 0000 0000 0000 ...（全 0，被抽成 nop）

# ② 看黄金样本同一偏移的真实字节码（回填目标）
xxd -s 0xE10 -l 64 samples/dex/classes_merged_orig.dex
#   00000e10: 0000 2200 2600 7010 5300 0000 6e20 5500  ..".&.p.S...n U.
#   00000e20: 2000 0c02 1a00 c300 6e20 5500 0200 0c02   .......n U.....
```

**回填规则**：侧表每条目按 `code_off`，把解密后的 insns 写回 `dex[code_off + 16 : +16 + insns_size*2]`（insns 区偏移 = `code_off + 16`）。
**重算校验值（顺序不能反！）**：
1. `signature = sha1(data[32:])` —— **先算**
2. `checksum  = adler32(data[12:])` —— **后算**（它覆盖含 signature 的区域）

> 先算 checksum 再改 signature，checksum 对应旧值，dex 会被判 Bad checksum。脚本 `unpack_v2.py` 的 `[4]` 行就是这两步。
**失效边界**：依赖侧表 `AJMT` 魔数 + 标准 `code_item` 布局。若改 VMP（无侧表、指令是解释器调用）或 Java2CPP（无 dex 业务），侧表不存在 → 无法手填，须转动态分析（认知边界）。

### 4.3 变种脱壳
与 §4.2 完全相同（结构一个字节没变），**唯一区别**：回填后的 dex 是带混淆字符串的版本，对照黄金须用 `build/variant/merged_orig_variant.dex`（字符串混淆版），否则逐字节对照失败。

### 4.4 结果对照表（手脱目标）

| 还原目标 | 黄金样本 | 校验 | 锚点 | 结论 |
|----------|----------|------|------|------|
| `analysis_output/unpack_v1_dex.dex`（手算 XOR） | `samples/dex/classes_orig.dex` | sha256 一致 | 11/11 | ✅ 一致 |
| `analysis_output/unpack_v2_dex.dex`（手填 insns） | `samples/dex/classes_merged_orig.dex` | sha256 一致 | 11/11 | ✅ 一致 |
| `analysis_output/unpack_v3_dex.dex`（手填 insns） | `samples/dex/classes_merged_orig.dex` | sha256 一致 | 11/11 | ✅ 一致 |
| `analysis_output/unpack_v2_variant_dex.dex` | `build/variant/merged_orig_variant.dex` | sha256 一致 | 0/0（均被混淆） | ✅ 一致 |

---

## 5. 验证（通用工具 · 是否真还原）

```bash
# ① sha256 对照（最强判据，一致即逐字节相同）
sha256sum analysis_output/unpack_v3_dex.dex samples/dex/classes_merged_orig.dex
#   => 两行哈希必须完全相同

# ② 锚点字符串检查（缺一个就说明没真解开）
grep -c "AJM-ANCHOR" analysis_output/unpack_v3_dex.dex    # 应 = 11
grep -c "AJM-ANCHOR" samples/dex/classes_merged_orig.dex      # 应 = 11

# ③ 字节差异定位（不一致时给首差异偏移）
cmp analysis_output/unpack_v3_dex.dex samples/dex/classes_merged_orig.dex
#   => 无输出 = 完全一致；有输出 = 首个差异偏移，据此回 §4 定位哪步写错
```

**三项分别说明**：① sha256 一致即逐字节相同；② `AJM-ANCHOR-*` 是业务预埋锚点，缺一个说明没真解开（哪怕长度对）；③ `cmp` 给首个差异字节偏移，是定位「哪一步写错」的入口。
> 变种黄金是混淆版，锚点数显示 0/0 属正常。这与 `SCRIPT.md` §5 的 `verify.py` 三项完全对应，只是用通用工具替代脚本。

---

## 6. 字节偏移指南（手动读 dex 头）

> 对应脚本 `walkthrough.py`：这里不靠脚本，自己读 dex 头定位各表。

```bash
# dex header 恒为 0x70 = 112 字节
xxd -l 112 samples/dex/classes_orig.dex
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

**DexHeader 偏移表（小端）**：

| 偏移 | 字段 | 本例实测值 |
|------|------|-----------|
| `0x00` | magic[8] | `dex\n037\0` |
| `0x08` | checksum (adler32 of data[12:]) | `29 b6 73 37` |
| `0x0C` | signature[20] (sha1 of data[32:]) | `d8 26 19 80 …` |
| `0x20` | file_size | `ac 11 00 00` = **4524** |
| `0x24` | header_size | `70 00 00 00` = **0x70** |
| `0x28` | endian_tag | `78 56 34 12` = 0x12345678 |
| `0x38 / 0x3C` | string_ids_size / off | 0x59=**89** / `0x70` |
| `0x40 / 0x44` | type_ids_size / off | 0x17=23 / `0x1D4` |
| `0x48 / 0x4C` | proto_ids_size / off | 0x12=18 / `0x230` |
| `0x50 / 0x54` | field_ids_size / off | 9 / `0x308` |
| `0x58 / 0x5C` | method_ids_size / off | 0x27=39 / `0x350` |
| `0x60 / 0x64` | **class_defs_size / off** | **7** / `0x488` |
| `0x68 / 0x6C` | data_size / off | `0xC44` / `0x568` |

`class_defs_size = 7` 与脚本判定的 `class_defs=7` 完全对得上 ——「手算 vs 工具」互相验证。

**code_item 布局**（`code_off` 为起点），用于 §4.2 定位 insns：

| 偏移 | 字段 | 大小 |
|------|------|------|
| `+0x00` | registers_size | u2 |
| `+0x02` | ins_size | u2 |
| `+0x04` | outs_size | u2 |
| `+0x06` | tries_size | u2 |
| `+0x08` | debug_info_off | u4 |
| `+0x0C` | **insns_size**（单位 u2 code unit） | u4 |
| `+0x10` | **insns**（真实指令，`insns_size*2` 字节） | — |

> 所以：**insns 区偏移 = `code_off + 16`**（即 §3.2 / §4.2 里 `0xE00 + 16 = 0xE10` 的来历）。

---

## 7. 复位（实验台 · 通用工具）

```bash
# 把固化基线 pristine/ 覆盖回 samples/（手脱前先确认 samples/ 是干净基线）
cp -r pristine/. samples/

# 只恢复单个被改坏的样本（例如还原 v2）
cp pristine/apks/app_packed_v2.apk samples/apks/app_packed_v2.apk

# 备份当前样本为新基线（改样本 / 跑新实验前）
cp -r samples/ pristine/
```

> 手脱不改 `samples/` 最佳；若改了，用上面命令复位。`SCRIPT.md` §7 的 `reset_lab.py` 是同一逻辑的脚本化（带 sha256 清单校验），`status` 能立刻区分「样本被改坏」还是「脱壳逻辑错」。

---

## 8. 决策流程 / 踩坑 / 速查

### 8.1 决策流程（手脱版）

```
① unzip -l <apk>                         看 classes.dex 大小 + assets/ 有无莫名文件
② aapt2 dump xmltree ...                 看 Application 是否被代理 + 记下声明类
③ 熵工具 / xxd payload                   看 assets/ 是否高熵加密 payload
④ xxd 读 code_item.insns (code_off+16)   看 insns 是否全 0 → 算空方法率
⑤ 类差集（Manifest 声明 vs dex 实际类）  声明了却不在 dex → 动态加载（一代）
        │
        ├─ ① classes.dex 小 + ③ 高熵 payload + ⑤ 缺失类  ─► 一代整体加密 → §4.1 手算 XOR
        └─ ④ insns 全 0（空方法率>40% 或局部 100% 空）     ─► 二/三代类抽取 → §4.2 手填 insns
收尾：sha256sum + grep AJM-ANCHOR + cmp  ← 与黄金样本逐字节对照
```

### 8.2 踩坑（手脱 / 工具侧）

1. **payload 头部顺序**：`[int32_le 长度][magic AJM\x01][密文]`，**magic 在偏移 4**（不在 0）。
2. **侧表查找靠 magic 不靠文件名**：三代 `brand_res_v3.dat`、变种 `rqn9xlwvh.yrm` 按 `AJMT` 扫描照样定位；手脱时要用 `xxd` 扫 `AJMT` 而非信文件名。
3. **诱饵文件**：三代放低熵 `config.txt`，「按熵找 payload」会误报，须结合结构判据。
4. **insns 区 = code_off + 16**：offset 算错会填错位置。
5. **校验重算顺序**：先 `sha1(data[32:])` 再 `adler32(data[12:])`；反了 dex 报 Bad checksum。
6. **aapt2 经管道会崩**：Git Bash 下 `aapt2 … | grep` 偶发 `VirtualAlloc failed`；先重定向到文件再读。
7. **Windows 程序用盘符风格路径**：`aapt2`/`binwalk`/`readelf` 传 `X:/...`，`unzip`/`xxd`/`sha256sum` 这类 Git Bash 工具可用 `/d/...`。
8. **中文乱码**：`PYTHONIOENCODING=utf-8`（PowerShell `$env:PYTHONIOENCODING='utf-8'`）。
9. **本机只有 `python` 无 `python3`**（见全局约定）。

### 8.3 速查

```bash
# ① 拆包看条目
unzip -l samples/apks/app_packed_v1.apk

# ② 读 Manifest（先重定向避免管道崩溃）
aapt2 dump xmltree --file AndroidManifest.xml samples/apks/app_packed_v1.apk > /tmp/manifest.txt

# ③ 算熵（通用工具验证加密 payload）
python -c "import math;from collections import Counter;b=open('samples/payloads/payload_v1.bin','rb').read();c=Counter(b);n=len(b);print(round(-sum((v/n)*math.log2(v/n) for v in c.values()),4))"

# ④ 看 insns 是否被抽空（insns 区 = code_off + 16 = 0xE00 + 16 = 0xE10）
xxd -s 0xE10 -l 64 samples/dex/extracted_v2.dex
xxd -s 0xE10 -l 64 samples/dex/classes_merged_orig.dex

# ⑤ 类差集：Manifest 声明 vs dex 实际（看判定输出的 B7 段 / aapt2 + dexdump 对比）
aapt2 dump xmltree --file AndroidManifest.xml samples/apks/app_packed_v1.apk

# ⑥ 读 dex 头（header 恒为 112 字节）
xxd -l 112 samples/dex/classes_orig.dex

# ⑦ 验证还原（sha256 + 锚点 + 字节差）
sha256sum analysis_output/unpack_v3_dex.dex samples/dex/classes_merged_orig.dex
grep -c "AJM-ANCHOR" analysis_output/unpack_v3_dex.dex
cmp analysis_output/unpack_v3_dex.dex samples/dex/classes_merged_orig.dex

# ⑧ SO 结构异常（B13）：xxd 读 ELF 头，看 e_type=3 且 e_shoff/e_shnum=0
unzip -o -q samples/apks/app_so_packed.apk "lib/arm64-v8a/libcalc.so" -d analysis_output/so_probe
xxd -l 64 analysis_output/so_probe/lib/arm64-v8a/libcalc.so

# ⑨ 复位
cp -r pristine/. samples/
```

**一句话记住**：加固在演化，判定本质不变——识别的始终是「结构异常」：dex 整体不在 / 方法体被抽空 / 类清单对不上。一代找 payload（手算 XOR），二代找侧表（手填 insns），三代还要下钻单类；最后用 `sha256sum` + `cmp` 与黄金样本逐字节对照收尾。
