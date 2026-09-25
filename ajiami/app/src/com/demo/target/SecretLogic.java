package com.demo.target;

/** 核心业务逻辑：壳商最想保护的东西，也是判定「是否真的脱壳成功」的黄金锚点。 */
public class SecretLogic {

    private final String seed;

    public SecretLogic() {
        this.seed = "AJM-ANCHOR-0008::secret-seed";
    }

    public String getFlag(String token) {
        String mixed = mix(seed, token);
        // AJM-ANCHOR-0009 这个串必须能在还原后的 dex 里重新出现
        return "AJM-ANCHOR-0009::flag{" + mixed + "}";
    }

    public static String mix(String a, String b) {
        int h = 0x811c9dc5;
        String s = a + "|" + b;
        for (int i = 0; i < s.length(); i++) {
            h ^= s.charAt(i);
            h = (h * 0x01000193) & 0x7fffffff;
        }
        return Integer.toString(h, 16);
    }

    /** 带分支的方法：方便肉眼确认 code_item 回填后的指令是否完整。 */
    public int classify(int v) {
        if (v < 0) {
            return -1;
        }
        if (v == 0) {
            return 0;
        }
        if (v < 100) {
            return 1;
        }
        return 2;
    }
}
