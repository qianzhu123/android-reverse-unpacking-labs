package com.demo.target;

/**
 * 冒烟入口：整个 lab 的「一类锚点」。
 *
 * 锚点说明（练习时用来验证脱壳是否真的成功）：
 *  1) 字符串：AJM-ANCHOR-0001 / AJM-ANCHOR-0002 这两个常量一定出现在原始 dex 的
 *     string_data 区，脱壳还原后必须能在还原 dex 里重新 string_ids 到它。
 *  2) 方法体：onCreate / buildBanner 的 code_item 是第二代「类抽取」的受害者，
 *     instructions 会被抽空，还原后应能逐字节对上原始 dex。
 */
public class Smoke {

    public static final String TAG = "AJM-ANCHOR-0001";

    public static String banner() {
        // 返回串本身也是锚点：它在 string_ids 里可被直接检索
        return "AJM-ANCHOR-0002::smoke-banner";
    }

    public static int checksumOf(String s) {
        int sum = 0;
        for (int i = 0; i < s.length(); i++) {
            // 故意用乘法，避免被优化成 String.hashCode 内联，保证 code_item 有足够指令
            sum = sum * 31 + s.charAt(i);
        }
        return sum & 0x7fffffff;
    }

    public static void main(String[] args) {
        System.out.println(TAG + " / " + banner() + " / " + checksumOf(banner()));
    }
}
