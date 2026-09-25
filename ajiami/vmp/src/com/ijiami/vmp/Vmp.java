package com.ijiami.vmp;

/**
 * Vmp —— 本工程的 DEX VMP 教学模型（简化版）。
 *
 * 对应 Ajiami 官方描述的思路（见 README §2.5）：
 *     原始 DEX 指令 → 转换 → 自定义字节码 → 虚拟机解释器 → 执行
 *
 * 三个必须记住的点：
 *   1. DEX 里看得到 类名 / 方法名，但方法体只有一句"调用解释器"，
 *      真实逻辑以"自定义字节码"形式存在 —— 它**不是合法 dalvik 指令**。
 *   2. code_item.insns **不是全 0**（这一点与二代"抽取"根本不同），
 *      所以"空方法率 B3"判据对 VMP **完全失效**。
 *   3. 官方表示每次加固可随机使用不同的自定义指令集，
 *      因此不能依赖一个永久固定的 opcode 映射（这里为教学方便写成固定值）。
 */
public final class Vmp {

    public static final byte OP_LOADARG = 0x01;   // 取参数 args[imm]
    public static final byte OP_PUSH    = 0x02;   // 压入立即数
    public static final byte OP_XOR     = 0x03;
    public static final byte OP_ADD     = 0x04;
    public static final byte OP_MUL     = 0x05;
    public static final byte OP_SUB     = 0x06;
    public static final byte OP_RET     = (byte) 0xFF;

    private static final int[] STACK = new int[64];

    /** 自定义字节码解释器：真实业务逻辑不在 DEX 的 dalvik 指令里，而在传入的 code 里。 */
    public static int run(byte[] code, int[] args) {
        int sp = 0;
        int i = 0;
        while (i < code.length) {
            byte op = code[i++];
            switch (op) {
                case OP_LOADARG:
                    STACK[sp++] = args[code[i++] & 0xFF];
                    break;
                case OP_PUSH:
                    STACK[sp++] = code[i++] & 0xFF;
                    break;
                case OP_XOR: {
                    int b = STACK[--sp], a = STACK[--sp];
                    STACK[sp++] = a ^ b;
                    break;
                }
                case OP_ADD: {
                    int b = STACK[--sp], a = STACK[--sp];
                    STACK[sp++] = a + b;
                    break;
                }
                case OP_MUL: {
                    int b = STACK[--sp], a = STACK[--sp];
                    STACK[sp++] = a * b;
                    break;
                }
                case OP_SUB: {
                    int b = STACK[--sp], a = STACK[--sp];
                    STACK[sp++] = a - b;
                    break;
                }
                case OP_RET:
                    return STACK[--sp];
                default:
                    throw new IllegalStateException("bad opcode: " + op);
            }
        }
        throw new IllegalStateException("missing OP_RET");
    }

    private Vmp() { }
}
