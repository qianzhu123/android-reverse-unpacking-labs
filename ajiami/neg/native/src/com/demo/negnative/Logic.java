package com.demo.negnative;

/**
 * 一批普通（非 native）Java 方法，唯一目的是把 native 占比压到 30% 以下，
 * 让 neg_native 成为一个"有 native lib 的正常 App"而非"Java2CPP"，
 * 从而真正考验 B12 / B13 在干净 Native 场景下会不会误报。
 */
public class Logic {
    public int compute(int x) { return x * x + 1; }
    public int transform(int x) { return (x << 1) ^ 0x55; }
    public int aggregate(int[] xs) {
        int s = 0;
        for (int v : xs) s += v;
        return s;
    }
    public boolean validate(int x) { return x > 0 && x < 1000; }
    public String describe(int x) { return "v=" + x; }
    public double ratio(int a, int b) { return b == 0 ? 0.0 : (double) a / b; }
    public int combine(int a, int b) { return compute(a) + transform(b); }
    public void sideEffect() { /* no-op，仅增加方法数以拉低 native 占比 */ }
}
