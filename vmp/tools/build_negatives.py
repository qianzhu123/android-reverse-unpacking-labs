#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
build_negatives.py — 生成**对抗性负样本**源码（形状接近、但**不是** VMP，用来当场
挖出误报）。

四个负样本，每个都刻意贴着某条判据：

  neg_plain     普通 App（无 VM、无 switch 解释器）          —— 基线
  neg_bigswitch 合法的**大 switch 状态机**（有 switch + 循环）—— 贴 V4/V6，测误报
  neg_hub        多个方法都调用同一个**大工具方法**（无解释器）—— 贴 V1，测「汇聚」误报
  neg_extract    方法体被抽空成 nop（旧式抽取，非 VM）         —— 贴「方法体异常」误报

判定工具在这些样本上**必须不报 VMP**（见 check_negatives.py 的双向断言）。

用法：python tools/build_negatives.py
"""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GEN = os.path.join(ROOT, 'build', 'gen')
NEG = os.path.join(ROOT, 'neg')

ACTIVITY = '''package com.demo.calc;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

/** 入口（负样本共用）。日志 tag 与正式样本一致，便于同一套 oracle。 */
public class CalcActivity extends Activity {

    public static final String TAG = "CALC";

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        int mix = CalcLogic.mix(7, 3);
        int twist = CalcLogic.twist(7);
        int digest = CalcLogic.digest(7, 3);
        String anchor = CalcLogic.anchor1();
        String line = "mix(7,3)=" + mix + " twist(7)=" + twist
                + " digest(7,3)=" + digest + " anchor=" + anchor;
        Log.i(TAG, line);
        TextView tv = new TextView(this);
        tv.setText(line);
        setContentView(tv);
    }
}
'''

# ---- neg_plain / neg_bigswitch / neg_extract：同一份「明文」业务 ——
CALCLOGIC_PLAIN = '''package com.demo.calc;

/** 业务类（明文）：与黄金样本同源，没有虚拟机。 */
public final class CalcLogic {
    public static int mix(int a, int b) { return (((a ^ b) + 17) * 3); }
    public static int twist(int a) { return ((a * 7) - 5); }
    public static int digest(int a, int b) { return (((a * b) ^ (a + b)) + 90); }
    public static String anchor1() { return "ANCHOR-0001:LOGIC-MIX"; }
    public static String anchor2() { return "ANCHOR-0002:LOGIC-DIGEST"; }
    private CalcLogic() { }
}
'''

# 合法的大 switch 状态机：一个真实的「记账/状态转移」方法，有 switch + 循环，
# 但 case 值是密集小集合、没有非 dalvik 载荷、没有 hub 汇聚 —— 不该被判 VMP。
CALCLOGIC_BIGSWITCH = '''package com.demo.calc;

/**
 * 业务类（负样本：合法的大 switch 状态机）。
 *
 * mix/twist/digest 仍是明文；额外提供一个 `Parser` 方法：一个真实的小型状态机
 * （switch + 循环 + 逐字符处理）。它在形状上「像解释器」，但**没有**自定义字节码、
 * **没有** hub 汇聚调用 —— 用来检验判定工具不会把「有大 switch」误判成 VMP。
 */
public final class CalcLogic {

    public static int mix(int a, int b) { return (((a ^ b) + 17) * 3); }
    public static int twist(int a) { return ((a * 7) - 5); }
    public static int digest(int a, int b) { return (((a * b) ^ (a + b)) + 90); }
    public static String anchor1() { return "ANCHOR-0001:LOGIC-MIX"; }
    public static String anchor2() { return "ANCHOR-0002:LOGIC-DIGEST"; }

    /** 一个真实的状态机：对字节串做简单词法求和（不是虚拟机）。 */
    public static int parse(byte[] in) {
        int acc = 0, i = 0, state = 0;
        while (i < in.length) {
            int c = in[i++] & 0xFF;
            switch (state) {
                case 0: if (c == 0x3A) state = 1; else acc += c; break;
                case 1: if (c >= 0x30 && c <= 0x39) { acc += c - 0x30; state = 2; } else state = 0; break;
                case 2: if (c >= 0x30 && c <= 0x39) { acc = acc * 10 + (c - 0x30); } else state = 3; break;
                case 3: state = 0; break;
                default: state = 0; break;
            }
        }
        return acc;
    }

    private CalcLogic() { }
}
'''

# 多个方法都调同一个大工具方法（不是解释器）：贴 V1「汇聚」，但那个大方法
# 里没有 switch、没有非 dalvik 载荷 —— 用来检验「汇聚调用」单独不足以定性。
CALCLOGIC_HUB = '''package com.demo.calc;

/**
 * 业务类（负样本：汇聚调用但非解释器）。
 *
 * 三个业务方法都调用同一个**大工具方法** `norm()`（里面是一堆 if/算术，没有 switch、
 * 没有自定义字节码）。形状上命中「多方法汇聚调用一个大方法」，语义上完全不是 VM。
 */
public final class CalcLogic {

    public static int mix(int a, int b) { return norm(a, b, 1); }
    public static int twist(int a) { return norm(a, 0, 2); }
    public static int digest(int a, int b) { return norm(a, b, 3); }
    public static String anchor1() { return "ANCHOR-0001:LOGIC-MIX"; }
    public static String anchor2() { return "ANCHOR-0002:LOGIC-DIGEST"; }

    /** 一个大工具方法（没有 switch / 没有解释器循环），被上面三个方法汇聚调用。 */
    private static int norm(int a, int b, int k) {
        int x = a + b;
        x = x ^ (x << 3);
        x = x - b * 7;
        if (k == 1) x = (x ^ 0x11) + 1;
        else if (k == 2) x = x * 7 - 5;
        else x = (a * b) ^ (a + b);
        if (x < 0) x = -x;
        x = x + 90;
        x = x ^ (x >>> 2);
        return x;
    }

    private CalcLogic() { }
}
'''


def _w(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)


def emit():
    cases = {
        'plain': CALCLOGIC_PLAIN,
        'bigswitch': CALCLOGIC_BIGSWITCH,
        'hub': CALCLOGIC_HUB,
        'extract': CALCLOGIC_PLAIN,       # 抽取版源码同 plain，机器码由 build_negatives 抽空
    }
    for name, logic in cases.items():
        pkg = os.path.join(GEN, 'neg_' + name, 'com', 'demo', 'calc')
        _w(os.path.join(pkg, 'CalcActivity.java'), ACTIVITY)
        _w(os.path.join(pkg, 'CalcLogic.java'), logic)
    return list(cases)


def main():
    names = emit()
    print('neg sources ->', ', '.join('build/gen/neg_%s/' % n for n in names))
    return 0


if __name__ == '__main__':
    sys.exit(main())
