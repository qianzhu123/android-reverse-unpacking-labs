package com.demo.negnative;

/**
 * 正常 native 应用的最小壳：声明一个 NDK .so，调用其中 1 个 native 方法。
 * 这是真实 App（如计算器 libcalculator.so）的常态 —— 绝不能因此被判壳。
 */
public class MainActivity {
    static {
        System.loadLibrary("calc");
    }

    // 唯一一个 native 方法：模拟正常 App 调用 NDK 计算。
    // 关键：native 占比必须被大量普通 Java 方法压住，B12(Java2CPP) 才不误报。
    public native int nativeAdd(int a, int b);

    public int run() {
        return nativeAdd(2, 3);
    }
}
