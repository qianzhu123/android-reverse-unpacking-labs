package com.demo.calc;

/**
 * CalcLogic —— 黄金业务逻辑（**明文**，没有任何虚拟机）。
 *
 * 由 tools/vmgen.py 从「表达式规范」（tools/vmlang.py 的 PROGRAMS）生成，
 * 与各难度受保护样本是同一份语义：同一组测试向量必须得到同一组结果。
 *
 * 锚点串 ANCHOR-* 用于确认「还原出来的确实是这段业务」。
 *
 * 不要手改本文件：改 tools/vmlang.py 的 PROGRAMS 后重新跑
 *     python tools/vmgen.py emit
 */
public final class CalcLogic {

    /** mix —— ((a ^ b) + 0x11) * 3 */
    public static int mix(int a, int b) {
        return (((a ^ b) + 17) * 3);
    }

    /** twist —— (a * 7) - 5 */
    public static int twist(int a) {
        return ((a * 7) - 5);
    }

    /** digest —— ((a * b) ^ (a + b)) + 0x5A */
    public static int digest(int a, int b) {
        return (((a * b) ^ (a + b)) + 90);
    }

    /** 分析锚点（golden 与各样本共用）；刻意不含 "vmp"/产品名等可见特征串 */
    public static String anchor1() { return "ANCHOR-0001:LOGIC-MIX"; }
    public static String anchor2() { return "ANCHOR-0002:LOGIC-DIGEST"; }

    private CalcLogic() { }
}
