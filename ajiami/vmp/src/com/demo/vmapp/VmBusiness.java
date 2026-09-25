package com.demo.vmapp;

import com.ijiami.vmp.Vmp;

/**
 * 业务类：真实算法以"自定义字节码"表达，DEX 里只剩对 Vmp.run 的调用。
 *
 * 静态分析（JADX）能看到 mix / twist 这些方法名，但**看不到原始 Java 逻辑** ——
 * 这正是 README §2.5 说的：
 *     "JADX 能看到类 ≠ JADX 能恢复原始 Java 逻辑"。
 *
 * 同时保留一个普通方法 plainAdd 作为对照：它的 dalvik 指令直接在 DEX 里，
 * 用来在十六进制编辑器里对比"VMP 方法"与"正常方法"的方法体差异。
 */
public class VmBusiness {

    /** ((a ^ b) + 0x11) * 3 —— 以自定义字节码表达 */
    private static final byte[] PROG_MIX = {
            Vmp.OP_LOADARG, 0x00,
            Vmp.OP_LOADARG, 0x01,
            Vmp.OP_XOR,
            Vmp.OP_PUSH, 0x11,
            Vmp.OP_ADD,
            Vmp.OP_PUSH, 0x03,
            Vmp.OP_MUL,
            Vmp.OP_RET
    };

    /** (a * 7) - 5 */
    private static final byte[] PROG_TWIST = {
            Vmp.OP_LOADARG, 0x00,
            Vmp.OP_PUSH, 0x07,
            Vmp.OP_MUL,
            Vmp.OP_PUSH, 0x05,
            Vmp.OP_SUB,
            Vmp.OP_RET
    };

    /** VMP 化方法 1：方法体 = 调用解释器 */
    public static int mix(int a, int b) {
        return Vmp.run(PROG_MIX, new int[]{a, b});
    }

    /** VMP 化方法 2 */
    public static int twist(int a) {
        return Vmp.run(PROG_TWIST, new int[]{a});
    }

    /** 对照：普通方法，dalvik 指令直接在 DEX 里 */
    public static int plainAdd(int a, int b) {
        return a + b;
    }

    /** 分析锚点，用于验证 DEX 完整性 */
    public static String banner() {
        return "AJM-ANCHOR-9001:VMP";
    }

    public static String tag() {
        return "AJM-ANCHOR-9002:VMP-BUSINESS";
    }
}
