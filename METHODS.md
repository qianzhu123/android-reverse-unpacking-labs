# METHODS.md — 逆向分析通用方法集

> 逆向分析中可复用的方法。每条方法回答一个问题，给出**可直接执行的命令**
>（命令本身通用：对任何样本、任何项目都一样，只需替换 `<目标>` 占位符）与
> **实测示例结果**（来自 ajiami lab 现成样本，实际运行后贴入）。
> 各 lab 的 SCRIPT/CLI/GUI 文档负责完整教学；本文只沉淀方法骨架，新 lab 遇到
> 同类问题直接套用命令、对照示例判读。

## 如何判断哪个类是代理组件、哪个是业务本体（不靠类名）

类名是标签，一行配置就能换；调用链是行为，壳要干活就删不掉。代理组件必须执行
「读载荷 → 解密 → 加载本体 → 反射换回真身」，这条链上绑定的系统类 API 改不了名。

```bash
# ① 圈候选：dex 里所有 extends Application 的类（此时候选几乎镜像，分不出谁是谁）
dexdump -d <目标dex> | grep -E "Class descriptor|Superclass" | grep -B1 "android/app/Application"
#   => 壳样本: Class descriptor 'Lcom/ijiami/shell/ProxyApplication;' + Superclass 'Landroid/app/Application;'
#   => 业务样本: Class descriptor 'Lcom/demo/target/MainApplication;' + 同一 Superclass —— 两候选镜像，进 ②

# ② 快筛：整个 dex 里有没有人干壳的事（正常 dex 恒 0 命中，壳 dex 显著非 0）
llvm-strings <目标dex> | grep -E "DexClassLoader|InMemoryDexClassLoader|getAssets|java/lang/reflect|getDir|loadClass"
#   => 壳 dex（classes_shell_v1.dex）命中 7 行：
#      Ldalvik/system/DexClassLoader;  Ljava/lang/reflect/Field;  Ljava/lang/reflect/Method;
#      Ljava/lang/reflect/Array;  getAssets  getDir  loadClass
#   => 业务 dex（classes_orig.dex）0 命中（grep exit=1，无输出 —— 这正是"正常"的判读，
#      不是命令出错；提示符标红是 oh-my-posh 对任何非零退出码的显示习惯）

# ③ 定性：逐候选看方法体 invoke 调用链的形状
#   <候选> 填什么：步骤①输出的每个 Application 子类的"类简名 + 生命周期方法"。
#   生命周期方法优先 attachBaseContext（壳最早在这里动手）；
#   若该候选没有 attachBaseContext（业务类常只有 onCreate），就换成它实际有的那个。
#   ①圈出 N 个候选，③就跑 N 次，每次把 grep 模式换成 "<候选1>.attachBaseContext"、
#   "<候选2>.onCreate"……逐个对比调用链形状，谁出现壳序列谁就是代理。
dexdump -d <目标dex> | grep -A40 "<候选>.attachBaseContext" | grep invoke
#   实测（merged dex，①圈出两个候选：MainApplication / ProxyApplication）：
#   候选1 填 MainApplication——它没有 attachBaseContext，只有 onCreate：
dexdump -d samples/dex/classes_merged_orig.dex | grep -A40 "MainApplication.onCreate" | grep invoke
#     => invoke-super Application;.onCreate   ← 仅此一行：无加载/解密/反射 → 业务本体
#   候选2 填 ProxyApplication（attachBaseContext 存在）：
dexdump -d samples/dex/classes_merged_orig.dex | grep -A40 "ProxyApplication.attachBaseContext" | grep invoke
#     => 壳的完整调用链（每条实测）：
#      invoke-super  Application;.attachBaseContext        ← 标准开场
#      invoke-static PayloadLoader;.readAsset              ← ① 读 assets 加密 payload
#      invoke-static Crypto;.decrypt                       ← ② 解密
#      invoke-static PayloadLoader;.writePrivate           ← ③ 落地私有目录
#      invoke-static ShellClassLoader;.getInstance        ← ④ 拿类加载器
#      invoke-virtual ShellClassLoader;.install           ←    DexClassLoader 动态加载
#      invoke-static ApplicationSwap;.run                  ← ⑤ 反射换回真 Application
#   注意：候选不存在的方法填进去会 0 命中（grep exit=1 无输出，提示符标红属正常），
#   不是命令出错——换该候选实际拥有的生命周期方法名再试即可（用 ③ 之前的
#   dexdump 输出里能看到每个类有哪些方法；"Class descriptor"块下的
#   "name : 'attachBaseContext'" 等行就是候选各自的方法清单）。
```

判读：③ 里出现「读asset → 变换byte[] → 动态加载 → 反射」序列 = 代理（壳）；
只有 `invoke-super` 生命周期调用 = 业务本体。中间环节的类叫什么都无关。
混淆变种类名全糊（ProxyApplication→KilcbZkkorxzgrlm）时 ②③ 照常命中——指纹在
系统类引用与调用形状上，不在名字里。

失效边界：逻辑全进 SO 时 Java 链退化成 `System.loadLibrary` + JNI 声明（转 ELF 层）；
壳自身被 VMP 时退化为一句"调用解释器"（转动态）；接口名拼串时 method_ids 直接引用消失
（拼串原料仍在字符串池，② 的 strings 与 ③ 的 dexdump 两条腿都查）。抽取型壳只抽业务、
绝不抽自己的加载器，所以代理组件的调用链原样保留，是最稳定的锚点。

## 如何判断目标被加壳/加固（不靠字符串）

朴素字符串判据会被混淆一次全灭；结构判据改格式才能抹掉。两套并跑，结论只看结构。

```bash
# A 判据（字符串，仅辅助——变种样本上实证全灭，不可押注）
llvm-strings <目标> | grep -E "<家族特征串>"
#   => 壳样本命中 'ijiami' 'ProxyApplication' 等串；混淆变种样本命中 0 —— A 判据失效的活证

# B 判据（结构，定性）——判据族与量化阈值：
#  B1 载荷：非标准条目熵 >7.5 进嫌疑名单（只缩范围；诱饵低熵文件自然落选）
#  B3 抽取：空方法率（有 code_item 但 insns 全 0 的方法占比）>40% → 类抽取
#  B3* 三代选择性抽取：整体空率低于阈值但存在局部 100% 空方法类 → 须下钻单类
#  B6/B7 声明vs实有：Manifest 声明的组件类在所有 classes*.dex 并集里缺失 ≥1 即异常
dexdump -d <目标dex> | grep -E "<结构异常字段>"
#   => 判定工具逐项输出 B1/B3/B6/B7 的命中情况与量化值（熵、空方法率、缺失类名）
```

判读：正常程序的声明类必然全部实有（宿主系统硬约束），缺失 ≥1 = 本体运行期才加载。
绝对值阈值（文件多大、类多少）永远不可靠——判定靠交叉验证，不靠大小。
单一交叉验证不独立定性：类缺失须叠加载荷证据（B1）才判"整体加密"。

## 如何定位被藏起来的载荷

三问权重递增：多大（体积 ≈ 合理本体 + 容器头，第一旁证）→ 多乱（熵缩范围）→
解开是什么（魔数定性——按容器 magic 扫全部条目，**不靠文件名**；解出本体魔数即自我揭示）。

```bash
# 列全部条目（不只盯主文件——assets/lib/res 与非标准条目都在嫌疑范围）
unzip -l <目标apk>
#   => 壳样本: assets/ijm_payload.bin 4532 bytes  ← 多出来的条目；业务 dex 4524 + 容器头 8 = 4532，体积旁证

# 逐条目算熵
python <熵计算脚本> <目标apk> <条目名>
#   => assets/ijm_payload.bin 熵 7.869（>7.5 进嫌疑）；三代诱饵 config.txt 熵 4.177（低熵，落选）

# 魔数扫描（头部，定性）
xxd <嫌疑条目> | head -4
#   => 一代 payload: 偏移 4 处 magic 'AJM\x01'，偏移 0 处 int32_le 长度 4524
#   => 三代侧表改名 brand_res_v3.dat、变种改乱码名——按 magic 'AJMT' 扫照样命中，改名无效
```

诱饵（低熵、无 magic）被魔数扫描自然排除；侧表改名不影响按 magic 定位。

## 如何验证还原是否真的成功

独立于还原逻辑实现的三步，不信工具自述：

```bash
sha256sum <还原产物> <黄金样本>     # ① 逐字节一致
#   => 两者哈希相同 → 还原成功
llvm-strings <还原产物> | grep -c "<锚点串>"   # ② 预埋锚点必须全部回归，缺一即失败
#   => 业务源码预埋的锚点串（如 AJM-ANCHOR-0000..0010 共 11 个）计满 11 才算数
cmp <还原产物> <黄金样本>           # ③ 差异定位：不一致时给差异字节数+首偏移
#   => "no differences" 或列出差异块 —— "哪步写错"的排查入口
```

## 工程纪律

每个判据必须配双向回归：正向样本（壳）必命中、负样本（多 dex / 高熵资源 / 合法 native
等正常形态）必不命中——误报多由负样本当场挖出，不是推理想到的（`.MainActivity` 相对类名
造成的假缺失、多 dex 并集遗漏，都是负样本当场挖出的真实误报）。检测工具必须显式声明
认知边界（不覆盖哪些方案），"未见已知特征"永远不等于"未加固"。

---

# 动态分析通用方法集（真实目标路线，配 `PROMPT-REAL.md`）

> 上面是**静态**判据篇（自建样本、byte-for-byte 可复现）。下面沉淀**外部真实目标**的动态方法：
> 无源码、无 golden，验证靠 **oracle**。示例取自 `uncrackable-l1` / `uncrackable-l2` 实测。

## 如何读被混淆的方法签名（别猜 overload）

方法名混淆（`a`/`b`/`c`）时，`.overload('...')` 靠猜必错。**先问活着的 JVM 要真实签名**：

```javascript
// frida/enumerate.js 核心：让目标自己报出每个方法的原型
Java.enumerateLoadedClasses({ onMatch: function (name) {
  if (name.indexOf('<包名片段>') < 0) return;
  Java.use(name).class.getDeclaredMethods().forEach(function (m) {
    console.log(name + '.' + m.getName() + '(' +
      m.getParameterTypes().map(function (t){return t.getName();}).join(',') +
      ') -> ' + m.getReturnType().getName());
  });
}, onComplete: function(){} });
```
#   => MainActivity.a(java.lang.String) -> void        ← 真校验函数（名字是 a，不是 verify）
#   => a.b.a(android.content.Context) -> boolean [static]  ← root 检测
#   => CodeCheck.bar([B) -> boolean                     ← native 校验（收 byte[]，不是 String）

**判读**：拿到的原型直接抄进 `.overload(...)`；`[B`=`byte[]`。**没有这步就动手 hook，必踩
"argument types do not match"。**

## 如何绕过"让插桩本身失败"的反调试

真实目标的反调试常在 native 层 `fork`+`ptrace`，在 Frida 下**目标进程直接崩**——
`onCreate` 抛 `Bad file descriptor` 并 abort（`uncrackable-l2` 实测）。绕过是**动态分析的前提**：

```bash
# 先确认症状：跑一次带日志的动态，抓 logcat 里的崩溃点
adb logcat -c
<注入脚本运行一次>
adb logcat -d | grep -iE "AndroidRuntime|abort|Bad file descriptor|ptrace"
#   => RuntimeException: Bad file descriptor  at MainActivity.onCreate   ← 反调试触发
```

```javascript
// 绕法①：stub 掉 native 初始化包装（Java 层），让 walk 链不执行到反调试
//   ⚠️ init() 若返回 void，实现体里绝不能 return 值（否则 "expected return value compatible with void"）
Java.use('...MainActivity').init.overload().implementation = function () { /* void，不 return */ };
```
```javascript
// 绕法②：native 校验常藏在一个全局"门限位"后面，stub 后门限位没置位 → 校验恒 false
//   必须自己把门限位写回 1（这是 l2 的解题关键）
var base = Module.findBaseAddress('libfoo.so');
Memory.writeU8(base.add(0x400c), 1);   // 偏移来自反汇编：bar 开头 cmpb $1, 0x400c
```

**判读**：门限位偏移从反汇编 `cmpb/je` 分支读出（自建 lab 用 `llvm-objdump -d`，GUI 用 Ghidra）。
写回后校验才可能翻真。**"stub 了反调试但校验还失败" 十有八九是漏了门限位。**

## 如何用 oracle 验证（没有 golden 时）

自建样本靠 `pristine/` byte 对比；真实目标**没有基准**，用**行为/产物 oracle**——一个"当且仅当成功才为真"的外部可观测事实：

| oracle | 判据 | l1/l2 实测 |
|---|---|---|
| 产物 | 静态 `.rodata`/表里直接可读的密钥 | l2：`llvm-objdump -s -j .rodata` → `"Thanks for all the fish"` |
| 算法 | 调**目标自身**的校验函数，看布尔翻转 | l1：`A.a(secret)=true`；l2：`CodeCheck.bar(secret)=true` |
| 状态 | App 跨过某项检查（界面/状态变化） | 反调试绕过后 onCreate 不再 abort |
| 协议 | 抓包字段正确 | （网络类目标适用） |

**关键纪律：必配负控**——错误输入必须得到相反结果，否则 oracle 可能恒真：

```javascript
console.log('[oracle] ...' , check(secret));        // 期望 true
console.log('[oracle-neg] ...', check('wrong'));    // 期望 false —— 证明 oracle 有区分度
```
#   => [oracle] CodeCheck.bar("Thanks for all the fish") = true
#   => [oracle-neg] CodeCheck.bar("nope-not-it") = false

**没有负控的 oracle 不算验证。** 并且：**别把常量抄进 JS 重算**——调目标自己的函数（l1 用 APP
的 `AES.a()`、`a.b()` 算明文），证明你理解的是**调用关系**而非抄常数。

## 如何理解"主动调用"而非"移植算法"

```javascript
// ❌ 反例：把密文/密钥/算法全搬进 JS 重算 —— 证明不了你理解了目标
// ✅ 正例：借目标的函数替你干活
var enc = Base64.decode(密文B64, 0);
var key = A.b(hex密钥);          // 调目标的 hex→bytes
var dec = AES.a(key, enc);       // 调目标的 AES
```

## 环境指纹（真实目标的"可复现"锚点）

自建样本用 `pristine/` + sha256 复现；**真实目标用环境指纹**——不记就别谈可复现：

```
设备型号 + Android 版本 + ABI · ROM/root 状态 · frida-server 版本 · host frida/objection/python 版本 · 样本 sha256
#   => 例：Android Emulator x86_64 / Android 14 (SDK34) / frida-server 16.5.9 / host frida 16.5.9
```

**最常见的坑：host frida 与 frida-server 版本不一致** → `Java is not defined`（17.x 尤其）。
**两端必须同版本**（实测 16.5.9）。

## 动态方法论纪律

- **先拿签名再 hook**：`.overload` 靠猜必错，先 enumerate。
- **反调试是前提，不是附加**：目标在插桩下崩 → 先绕反调试，再谈校验。
- **门限位要自己置位**：stub 掉 native 初始化后，检查它留下的全局标志。
- **oracle 必配负控**：无负控的"成功"可能是恒真。
- **调目标自身函数**：别移植常数，理解调用关系。
- **记环境指纹**：真实目标的可复现性靠它，不靠 golden。
- **授权与不重分发**：第三方样本只记 sha256 + 来源 + 结论，样本入 .gitignore（见 `PROMPT-REAL.md`）。

