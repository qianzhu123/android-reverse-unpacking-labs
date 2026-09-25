#!/usr/bin/env bash
# env.sh — 本工程工具链配置（第三档：可选覆盖层）
#
# 四档优先级：
#   ① 命令行参数   ② 环境变量   ③ 本文件（可选覆盖）   ④ 自动探测 build/locate.sh
# 默认一行都不用改：工具链全部自动探测。只有要钉住"某个版本 / 某个路径"时才在这里 export。
# 新机器直接复制 build/env.sh.example 为 build/env.sh 即可（模板里不含任何真实路径）。
#
# 【本机踩坑 1】javac / java / aapt2 是 Windows 程序，不认 Git Bash 的 /d/... 路径，
#               传给它们的路径必须写成盘符风格（X:/...），所以用 $ROOT_W 而不是 $ROOT。
# 【本机踩坑 2】d8.jar 没有 Main-Class，`java -jar d8.jar` 报 no main manifest attribute；
#               必须用 java -cp d8.jar com.android.tools.r8.D8（locate.sh 里的 D8() 已封装）。
# 【本机踩坑 3】d8 的 --output 不接受不存在的目录，必须给 .zip/.jar 结尾，或先 mkdir。
# 【本机踩坑 4】javac 26 下 -bootclasspath 与 -target/-source 不能同时出现；只用 -classpath android.jar。
# 【本机踩坑 5】Git Bash 若缺 coreutils（ls / find / grep 报 command not found），
#               把 Git Bash 安装目录下的 usr/bin 加进 PATH 即可（不要写死路径）。

source "$(dirname "${BASH_SOURCE[0]}")/locate.sh"

# ---- 需要覆盖时在这里写（默认全部注释，走自动探测）----
# export JAVA_HOME="<JDK 根目录>"
# export ANDROID_HOME="<SDK 根目录>"
# export ANDROID_NDK_HOME="<NDK 根目录>"
# export BT="$ANDROID_HOME/build-tools/<版本>"      # 钉住某个 build-tools 版本
# export PYTHON="<python 解释器路径>"

# 签名配置（lab 自用，与工具链无关）
KEYSTORE="$ROOT_W/build/lab.keystore"
KEY_ALIAS="ajmlab"
KEY_STOREPASS="ajmlab123"
KEY_KEYPASS="ajmlab123"

# 导出给 Python 工具（tools/mkapk.py 会用）
export AJ_JAVA="$JAVA"
export AJ_ZIPALIGN="$ZIPALIGN"
export AJ_APKSIGNER_JAR="$APK_SIGNER_JAR"
# AJ_AAPT2 不强制导出：PATH 里已有 aapt2 时 detect.py 直接用 PATH 的版本，
# 换机器 / 换 SDK 版本都不会失效。需要指定某个 aapt2 时手动 export AJ_AAPT2=... 即可覆盖。
# export AJ_AAPT2="$AAPT2"
export AJ_KEYSTORE="$KEYSTORE"
export AJ_KEY_ALIAS="$KEY_ALIAS"
export AJ_STOREPASS="$KEY_STOREPASS"
export AJ_KEYPASS="$KEY_KEYPASS"

# 构建前强制检查：缺什么就报错，并说明该设哪个环境变量（不会默默用错版本）
locate_require JAVA SDK PY
