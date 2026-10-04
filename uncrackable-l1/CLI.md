# uncrackable-l1 · CLI 路线（通用命令）

> 遵循 `PROMPT-REAL.md`。本文件只用**通用命令**（adb / frida / frida-trace / unzip /
> llvm-strings / dexdump），**不调用本仓库 tools/*.py**（那是 SCRIPT.md 的路线）。
> 目标：`owasp.mstg.uncrackable1`（OWASP UnCrackable L1）。

## §0 概览

- **定位**：不用本仓库脚本，纯命令行复现「装目标 → 起 frida → 静态定性 → 动态验证」。
- **目标清单**：同 SCRIPT.md §0。

## §1 Lab 布局

同 SCRIPT.md §1（三文档 + samples/pristine/tools/build/frida/logs）。

## §2 知识点

- **CLI 路线要自己拼出 SCRIPT 路线里脚本做的事**：adb 部署、frida CLI 注入。
- **frida CLI 与 host frida 版本必须一致**：`frida --version` 应等于 server 版本。

## §3 静态侦察

```bash
# ① 工具链四级解析：llvm-* 已在 PATH（随 NDK 下发，裸 strings 不存在）
LS=$(command -v llvm-strings)

# ② 提取 dex
unzip -o -j samples/apks/UnCrackable-Level1.apk classes.dex -d samples/dex/

# ③ 字符串定位（只定位，不判决）
"$LS" samples/dex/classes.dex | grep -iE "root|magisk|secret|system/bin"
#   => /system/bin/.ext/.su · /system/xbin/daemonsu · Root detected! · This is the correct secret.

# ④ 反汇编定性（dexdump 随 build-tools 下发，取最新版目录）
DD="$ANDROID_HOME/build-tools/$(ls "$ANDROID_HOME/build-tools" | sort -V | tail -1)/dexdump"
"$DD" -d samples/dex/classes.dex | grep -nE "Class descriptor|name +: '|type +: '" | head -60
```

**读数**：`sg.vantagepoint.uncrackable1.a.a(String)->boolean` 是校验本体；它内部
`Base64.decode` → `a.b`(hex) → `a.a.a`(AES) → `equals`。密钥/密文都是二次编码的低熵串，
所以 grep 搜不到明文——这正是"静态只能定位、不能判决"的实证。

## §4 动态分析（通用命令）

```bash
# 环境：ADB 四级解析（ANDROID_HOME / ANDROID_SDK_ROOT 已设；否则 <SDK>/platform-tools/adb）
ADB="${ANDROID_HOME:-$ANDROID_SDK_ROOT}/platform-tools/adb"
EMU="${ANDROID_HOME:-$ANDROID_SDK_ROOT}/emulator/emulator"

# ① 起模拟器（已建好的 AVD），无头
"$EMU" -avd n4tive_lab -no-window -no-audio -no-boot-anim -gpu swiftshader_indirect &
"$ADB" wait-for-device
# 等 sys.boot_completed=1
"$ADB" shell getprop sys.boot_completed        # => 1

# ② 起 frida-server（模拟器可 adb root）
"$ADB" root
"$ADB" push .tools/frida-server-16.5.9-android-x86_64 /data/local/tmp/frida-server
"$ADB" shell "chmod 755 /data/local/tmp/frida-server; nohup /data/local/tmp/frida-server >/dev/null 2>&1 &"
"$ADB" shell "ps -A | grep frida"              # => frida-server

# ③ 装目标
"$ADB" install -r samples/apks/UnCrackable-Level1.apk   # => Success

# ④ 用 frida CLI 注入（host frida 与 server 同为 16.5.9）
frida-ps -U | grep -i uncrackable               # 验证连通
frida -U -f owasp.mstg.uncrackable1 -l frida/solve.js --runtime=v8
#   => [recovered] secret = "I want to believe"
#   => [oracle] uncrackable1.a.a(secret) = true
#   => [oracle-neg] ... = false
```

## §5 验证标准

同 SCRIPT.md §5：算法 oracle（`A.a(secret)==true`）+ 负控（错误输入 `==false`）。
CLI 路线用 `frida -l solve.js` 观察同样的两行输出即算通过。

## §6 决策流

同 SCRIPT.md §6。

## §7 可重复练习

- 设备/版本指纹见 `pristine/provenance.json`；重跑只需 §4 的 ④（server 已在跑）。
- 清理：`analysis_output/` 可删；APK 从 `pristine/provenance.json` 的 url 重下并核对 sha256。

## §8 坑与速查

| 坑 | 根因 | 修法 |
|---|---|---|
| `su: invalid uid/gid '-c'` | 模拟器无 `su -c` 语法 | 直接 `adb root` 后用 root shell |
| `failed to copy ... C:/Program Files/Git/...` | Git Bash 把 `/data/...` 转成 Windows 路径 | 设 `MSYS_NO_PATHCONV=1`，或用 Windows 风格路径 |
| `device not found`（frida） | 用了 `frida.get_device('usb')` | 用 `get_usb_device()` 或 `-U` |
| `Java is not defined` | host frida 17.x 与 server 版本不匹配 | 两端统一 16.5.9 |
