package com.demo.calc;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

/**
 * CalcActivity —— 业务入口（各层样本共用同一份「外观」）。
 *
 * 黄金版与各难度受保护版的差异**只在这个 Activity 调用的那个类里**：
 *   · 黄金版   CalcLogic 是明文表达式；
 *   · 受保护版 CalcLogic 变成「调用解释器」，真实逻辑在自定义字节码里。
 *
 * 因此「受保护版是否与黄金版行为一致」可以用同一条 logcat 断言判定：
 *     adb logcat -s CALC
 * 两者必须输出同一行。
 */
public class CalcActivity extends Activity {

    /** 统一日志 tag，供 `adb logcat -s CALC` 过滤（不含任何产品/加固字样）。 */
    public static final String TAG = "CALC";

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);

        int mix = CalcLogic.mix(7, 3);
        int twist = CalcLogic.twist(7);
        int digest = CalcLogic.digest(7, 3);
        String anchor = CalcLogic.anchor1();

        // 单行结构化输出，便于机器比对（黄金版与各样本必须完全一致）
        String line = "mix(7,3)=" + mix
                + " twist(7)=" + twist
                + " digest(7,3)=" + digest
                + " anchor=" + anchor;
        Log.i(TAG, line);

        TextView tv = new TextView(this);
        tv.setText(line);
        setContentView(tv);
    }
}
