#!/usr/bin/env bash
# build_android.sh — 从 src/target.c 编译原始 .so
# 用法：在项目根目录执行  bash build/build_android.sh
#
# NDK 不写死：默认由 build/locate.sh 自动探测；要指定版本就设 NDK_ROOT 或 ANDROID_NDK_HOME。
set -e
source "$(dirname "${BASH_SOURCE[0]}")/locate.sh"
locate_require NDK
cd "$ROOT"

# ARM32（主练习目标：UPX 打包用的就是它）
# 注意用 --hash-style=sysv --pack-dyn-relocs=none，减少 NDK r27 的 RELR/GNU-hash，
# 让老版本 UPX 也更容易识别（本环境里官方 UPX 4.2.4 仍只打包 ET_EXEC，见 README）。
"$CLANG" --target=armv7a-linux-androideabi21 -shared -fPIC -O2 \
  -Wl,--hash-style=sysv -Wl,--pack-dyn-relocs=none \
  -o libtarget_orig.so src/target.c

# ARM64（对照/参考，仅作源码对照；官方 UPX 4.2.4 不打包 ET_DYN）
"$CLANG" --target=aarch64-linux-android21 -shared -fPIC -O2 \
  -o libtarget_orig_arm64.so src/target.c

echo "[+] built libtarget_orig.so (arm32) + libtarget_orig_arm64.so (arm64)"
