package com.ijiami.shell;

import android.app.Application;
import android.content.Context;

/**
 * 一代壳的骨架：Application 被替换成匣 Application。
 *
 * 真实引擎:
 *   爱加密是把原始 classes.dex 加密后塞进 assets/ 或 lib/ 下，
 *   由代理 Application 在 attachBaseContext 里解密，再用 DexClassLoader 加载，
 *   最后通过反射把 Application 替换回业务 Application。
 *
 * 本工程配套的学习工具:
 *   tools/packer.py   -> 生成被加密的 assets payload, 将 classes.dex 替换为 shell dex
 *   tools/unpack_v1.py-> 用和这里完全一样的算法离线还原 dex
 *
 * 因为本工程离线练习，解密算法采用 XOR + 长度头，便于在十六进制编辑器里手算验证。
 */
public class ProxyApplication extends Application {

    /** string table 中的强特征：判别爱加密家族的重要锚点 */
    public static final String AJM_TAG = "ijiami-shell-v1";

    private static final String PAYLOAD_MAIN = "classes.dex";

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        // ① 定位并解密 payload
        byte[] raw = PayloadLoader.readAsset(base, PayloadLoader.PAYLOAD_NAME);
        byte[] dex = Crypto.decrypt(raw);
        // ② 落地到私有目录
        String out = PayloadLoader.writePrivate(base, PAYLOAD_MAIN, dex);
        // ③ 动态加载
        ShellClassLoader.getInstance(base, out).install();
        // ④ 替换回真实 Application
        ApplicationSwap.run(base, this);
    }
}
