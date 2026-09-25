package com.demo.target;

/** 纯 Java 计算逻辑，指令多、分支多，最适合用来做「类抽取 → 回填还原」的字节对照。 */
public class TokenUtil {

    private static final byte[] TABLE = {
            (byte) 0x63, (byte) 0x7c, (byte) 0x77, (byte) 0x7b, (byte) 0xf2, (byte) 0x6b,
            (byte) 0x6f, (byte) 0xc5, (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2b,
    };

    public String buildToken(String seed) {
        int acc = Smoke.checksumOf(seed);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            int idx = (acc >> (i * 3)) & 0x0b;
            sb.append(Integer.toHexString(TABLE[idx] & 0xff));
        }
        return "AJM-ANCHOR-0007::" + sb.toString();
    }

    public int twist(int v, int rounds) {
        int x = v;
        for (int i = 0; i < rounds; i++) {
            x ^= (x << 13) & 0xffffffff;
            x ^= x >>> 17;
            x ^= (x << 5) & 0xffffffff;
        }
        return x;
    }
}
