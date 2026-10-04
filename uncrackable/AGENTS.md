# uncrackable · 项目文档（给智能体）

> 用途：新会话要动这个子项目时，把本文件整份贴给智能体即可开工。
> 学习路线见 `TUTORIAL.md`；每关操作手册见 `l*/SCRIPT.md`。

## 这是什么

用 **OWASP MASTG UnCrackable（外部真实目标）**做**动态逆向**练习的 lab 家族。
与仓库其余"自建样本、静态、可复现"的 lab 互补：这里是**无源码、无黄金样本**的真实目标，
验证方式是 **behavior/artifact oracle**（不是 byte 对比）。规则见仓库根 `PROMPT-REAL.md`。

## 目录

```
uncrackable/
├── README.md / TUTORIAL.md  家族总览 / 学习路线（l1→l2→l3）
├── tools/hook_run.py         ★ 共享 Frida 运行器（spawn+sideload）
├── tools/frida-server-16.5.9-android-x86_64(.xz)   设备端 server（gitignored）
├── l1/  l2/  l3/            每关：SCRIPT/CLI/GUI + samples/(gitignored) + pristine/provenance.json + frida/ + logs/
```

## 三关状态

| 关 | 新增能力 | 结果 | 密钥/结论 |
|---|---|---|---|
| l1 | Java+AES+root 检测 | ✅ 已解 | `I want to believe` |
| l2 | native `strncmp` + fork/ptrace 反调试 + `.bss` 门限区 | ✅ 已解 | `Thanks for all the fish` |
| l3 | native + **构造函数级反篡改看门狗线程** | ⚠️ **WIP 未通过** | 静态已逆清，动态被挡 |

## 环境（唯一权威在仓库根 `README.md`「Real-target lab environment setup」）

- **frida 版本铁律**：host（`../../.venv`）与 device（frida-server）**都锁 16.5.9**——不一致会 `Java is not defined`。
- venv 在**仓库根** `reverse/.venv`（frida 装这里，**不装全局**）。
- 起模拟器 + 推 frida-server 的完整命令见上述 README 节。

```bash
# 1) 环境起了之后，跑一关（在 l1 目录下）
cd uncrackable/l1
../../.venv/Scripts/python.exe ../tools/hook_run.py \
    --package owasp.mstg.uncrackable1 --script frida/solve.js --seconds 8
#   => [recovered] secret = "I want to believe"
#   => [oracle] uncrackable1.a.a(secret) = true
```

## 三关要点（agent 直接可用）

**l1（Java 层）**
- 先 `enumerate.js` 拿**真实方法签名**（类名混淆成 `a/b/c`，别猜 `.overload`）。
- **spawn 门控**：绕 root 检测要在 `System.exit` 之前装好。
- **主动调用**：借目标自己的 `AES.a()`/`a.b()` 解密，不把常数抄进 JS。
- oracle：`uncrackable1.a.a(secret)==true`；负控：错误输入 `==false`。

**l2（native 层）**
- 静态：`llvm-nm -D` 拿 JNI 导出 → `llvm-objdump` 看 `bar` 的 `strncmp(input, secret, 23)` 与门限位
  `cmpb $1, [0x400c]` → `llvm-objdump -s -j .rodata` 直读密钥。
- 动态：`init()` 的 `fork`+`ptrace` 在 Frida 下让 `onCreate` 抛 `Bad file descriptor` → **stub `init()`**；
  之后 `bar` 仍恒 false，因为门限位没置 → **`Memory.writeU8(base+0x400c, 1)`**。
- oracle：`CodeCheck.bar(secret)==true`（收 `byte[]`，用 `Java.array('byte',…)`；实例方法用 `Java.choose`/`$new()`）。

**l3（WIP，卡点）**
- 静态已确定：`bar = input[i] == keyTable[i] ^ plaintext[i]`（`keyTable` 来自 Java `xorkey`，`plaintext` 由 `bar` 运行期解到栈上）。
- 动态被挡：反篡改是**构造函数里 `pthread_create` 起的看门狗线程**（早于任何 Java 代码），检测到就 `raise(SIGABRT)`。
  已试：pthread_create 钩子换 stub、`fork/ptrace` 中和、Java 侧全量 stub——**均未清除，进程仍早期 SIGSEGV**。
- 攻关方向（`l3/SCRIPT.md §8`）：① `frida -f` 更早注入；② frida-server 改名/打补丁规避检测；
  ③ 换低版本 Android 让完整性校验自洽；④ GUI 里把构造函数**所有**反篡改路径列全再逐条灭。

## 铁律与坑

- **第三方样本零入库**：`samples/` 的 apk/so/dex **gitignored**，只留 `pristine/provenance.json`（来源+授权+环境指纹+结论）。
- **真实目标用 oracle 验证**，不搞 byte 对比；**结论必配负控**；没 oracle 的只能标 **hypothesis**（l3 即如此）。
- `device not found` → 用 `frida.get_usb_device()` / `-U`，不是 `get_device('usb')`。
- **Git Bash 路径改写** → `adb push` 前 `MSYS_NO_PATHCONV=1`。
- 别建近平行目录：新关卡放 `uncrackable/lN/`，不要 `uncrackable-lN/`。

## 上下文入口

- 学习路线：`TUTORIAL.md`；家族总览：`README.md`；环境：仓库根 `README.md`
- l3 攻关：`l3/SCRIPT.md §8`；规则：仓库根 `PROMPT-REAL.md`、`METHODS.md`
