#!/usr/bin/env bash
# build_negatives.sh — 构建「负样本」：干净但【几乎能触发】判据的 APK
#
# 为什么需要它（务必先看 §6.1）：本项目所有样本都是自己合成的正样本，
# 只拿它们验证 detect.py 属于循环论证。负样本是把"维修改对了"变成
# "可回归验证"的唯一手段 —— 它们是专门用来触发历史误报的陷阱。
#
#   neg_multidex     manifest 声明的 Provider/Receiver 类放在 classes2.dex
#                    → 守住 B7：不得因"类不在主 dex"就判壳
#   neg_highentropy  同上 + 一个合法但高熵的 asset（随机数据，非加密 dex）
#                    → 守住 B6/B1：不得因"有高熵文件"就判一代
#                    同时 mix/twist 是"极短方法调同一个小 helper"的外观，
#                    → 守住 B11(VMP)：helper 体积小，不是解释器
#
# 用法（项目根目录）：bash build/build_negatives.sh
set -e
source build/env.sh
cd "$ROOT_W"

mkdir -p build/neg/classes build/neg/classes_lib build/neg/dex build/neg/dex_lib samples

echo "== [1/6] javac：业务类(主 dex) + 组件类(次级 dex) 分别编译 =="
"$JAVAC" -source 11 -target 11 -nowarn -classpath "$ANDROID_JAR" -d build/neg/classes neg/src/com/demo/neg/*.java
"$JAVAC" -source 11 -target 11 -nowarn -classpath "$ANDROID_JAR" -d build/neg/classes_lib neg/libsrc/com/demo/negsupport/*.java

echo "== [2/6] d8：产出两个独立 dex =="
rm -f build/neg/dex/biz.zip build/neg/dex/lib.zip
D8 --lib "$ANDROID_JAR" --output build/neg/dex/biz.zip --min-api $MIN_SDK build/neg/classes/com/demo/neg/*.class
D8 --lib "$ANDROID_JAR" --output build/neg/dex/lib.zip --min-api $MIN_SDK build/neg/classes_lib/com/demo/negsupport/*.class
python tools/apkutil.py extract-dex build/neg/dex/biz.zip build/neg/biz.dex
python tools/apkutil.py extract-dex build/neg/dex/lib.zip build/neg/lib.dex

echo "== [3/6] aapt2 link：用 neg/AndroidManifest.xml 生成 APK 骨架 =="
rm -f build/neg/raw.apk
"$AAPT2" link -I "$ANDROID_JAR" --manifest neg/AndroidManifest.xml -o build/neg/raw.apk --min-sdk-version $MIN_SDK --target-sdk-version $TARGET_SDK

echo "== [4/6] 组装 neg_multidex.apk（组件类在 classes2.dex）=="
python tools/mkneg.py build/neg/raw.apk build/neg/neg_multidex_unaligned.apk --dex classes.dex=build/neg/biz.dex --dex classes2.dex=build/neg/lib.dex

echo "== [5/6] 生成"合法但高熵"asset，组装 neg_highentropy.apk =="
python -c "import random; random.seed(42); open('build/neg/data_blob.bin','wb').write(bytes(random.getrandbits(8) for _ in range(65536)))"
python tools/mkneg.py build/neg/raw.apk build/neg/neg_highentropy_unaligned.apk --dex classes.dex=build/neg/biz.dex --dex classes2.dex=build/neg/lib.dex --asset assets/data_blob.bin=build/neg/data_blob.bin

echo "== [6/6] zipalign + 签名 =="
if [ ! -f "$KEYSTORE" ]; then
  "$KEYTOOL" -genkeypair -v -keystore "$KEYSTORE" -alias "$KEY_ALIAS" -keyalg RSA -keysize 2048 -validity 10950 -storepass "$KEY_STOREPASS" -keypass "$KEY_KEYPASS" -dname "CN=AJM Lab, OU=Lab, O=AJM, L=Lab, S=Lab, C=CN"
fi
for n in neg_multidex neg_highentropy; do
  "$ZIPALIGN" -f 4 build/neg/${n}_unaligned.apk build/neg/${n}_aligned.apk
  APK_SIGNER sign --ks "$KEYSTORE" --ks-key-alias "$KEY_ALIAS" --ks-pass pass:"$KEY_STOREPASS" --key-pass pass:"$KEY_KEYPASS" --out "samples/${n}.apk" "build/neg/${n}_aligned.apk"
done

echo
echo "[+] samples/neg_multidex.apk     负样本：多 dex，组件类在次级 dex"
echo "[+] samples/neg_highentropy.apk  负样本：多 dex + 合法高熵 asset"
echo "[!] 二者必须被 detect.py 判为「未以『已加固』开头」，见 tools/check_negatives.py"

echo
echo "==================================================================="
echo "== 追加：干净 native 负样本（NDK 缺失时自动跳过）                  =="
echo "==================================================================="
bash build/build_neg_native.sh
