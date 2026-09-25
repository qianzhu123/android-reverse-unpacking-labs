package com.demo.neg;
/** 干净的业务逻辑：方法体都是真实算法，不是解释器调用。 */
public class NegLogic {
    private int seed = 7;
    public static String tag() { return "neg-clean"; }
    public String banner() { return "NEG-ANCHOR-0001"; }
    public int add(int a, int b) { return a + b + seed; }
    /** mix/twist 是「极短方法 + 调用同一个小 helper」的外观，
     *  用来守住 B11(VMP) 不误报：helper 体积小不是解释器。 */
    public int mix(int a, int b) { return helper(a, b); }
    public int twist(int a, int b) { return helper(b, a); }
    private int helper(int a, int b) { int t = a + b; return t * 2; }
}
