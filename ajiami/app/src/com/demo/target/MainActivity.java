package com.demo.target;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

/**
 * 业务入口。安卓侧依赖只有 Activity / Bundle / Log，保证 javac + d8 能直接编成真 dex。
 *
 * 锚点：
 *  - AJM-ANCHOR-0003   类级常量
 *  - AJM-ANCHOR-0004   onCreate 中的 log 串
 *  - getSecret()       JNI 入口（第二代类抽取后 code_item 会被抽空）
 */
public class MainActivity extends Activity {

    public static final String AJM_ANCHOR_0003 = "AJM-ANCHOR-0003::MainActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.d(Const.LOG_TAG, "AJM-ANCHOR-0004::onCreate");
        TokenUtil token = new TokenUtil();
        String tk = token.buildToken(AJM_ANCHOR_0003);
        SecretLogic logic = new SecretLogic();
        String flag = logic.getFlag(tk);
        Log.d(Const.LOG_TAG, "AJM-ANCHOR-0005::flag=" + flag);
        NativeBridge.probe();
    }

    /** JNI 方法，dex 里只有声明没有实现，用来观察 method 表与 code_item 的关系。 */
    public native String getSecret(String seed);

    public String getSecretFallback(String seed) {
        return SecretLogic.mix(seed, "AJM-ANCHOR-0006::fallback");
    }
}
