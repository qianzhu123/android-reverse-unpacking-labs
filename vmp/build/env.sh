#!/usr/bin/env bash
# env.sh.example — 环境配置模板（不含任何真实路径，可直接复制到新机器）
#
# 来源：自 ajiami/build/env.sh.example 移植，改为本 lab 的前缀 VMP_ 与签名配置。
# 用法：cp build/env.sh.example build/env.sh
#      然后**只取消注释你真正需要覆盖的那几行**；其余保持注释，走自动探测。
#
# 四档优先级（靠前者覆盖靠后者）：
#   ① 命令行参数   --ndk / --aapt2 / --python ...
#   ② 环境变量     JAVA_HOME / ANDROID_HOME / ANDROID_NDK_HOME / NDK_ROOT / PYTHON ...
#   ③ 本文件       （可选覆盖层）
#   ④ 自动探测     build/locate.sh：PATH → SDK/NDK 标准布局 → 版本号取最新

source "$(dirname "${BASH_SOURCE[0]}")/locate.sh"

# ---- JDK ----
# 不写就自动探测：JAVA_HOME → PATH 里的 javac/java 反推
# export JAVA_HOME="<JDK 根目录>"

# ---- Android SDK ----
# 不写就自动探测：ANDROID_HOME / ANDROID_SDK_ROOT → PATH 里的 aapt2/adb 反推
# export ANDROID_HOME="<SDK 根目录>"

# ---- Android NDK（SO/ARM 层样本要交叉编译，必需）----
# 不写就自动探测：ANDROID_NDK_HOME / NDK_ROOT → <SDK>/ndk/<最新版本>
# export ANDROID_NDK_HOME="<NDK 根目录>"

# ---- 钉住某个 build-tools 版本（不写则自动取最新）----
# export BT="$ANDROID_HOME/build-tools/<版本>"

# ---- python 解释器 ----
# 不写就自动探测：PYTHON → PATH 里的 python
# export PYTHON="<python 解释器路径>"

# ---- aapt2（Python 侧 detect_vm.py 用；不写则优先用 PATH 里的）----
# export VMP_AAPT2="<aapt2 路径>"

# 签名配置（lab 自用，一般不用改）
KEYSTORE="$ROOT_W/build/lab.keystore"
KEY_ALIAS="calc"
KEY_STOREPASS="calclab123"
KEY_KEYPASS="calclab123"

export VMP_JAVA="$JAVA"
export VMP_ZIPALIGN="$ZIPALIGN"
export VMP_APKSIGNER_JAR="$APK_SIGNER_JAR"
export VMP_KEYSTORE="$KEYSTORE"
export VMP_KEY_ALIAS="$KEY_ALIAS"
export VMP_STOREPASS="$KEY_STOREPASS"
export VMP_KEYPASS="$KEY_KEYPASS"

locate_require JAVA SDK PY
