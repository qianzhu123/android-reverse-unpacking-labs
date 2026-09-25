package com.ijiami.shell;

/**
 * 一代加密：4 字节小端长度头 + XOR 流。
 *
 * 之所以故意选 XOR：
 *   - 便于在 010 Editor 里手算验证（不用倒推 AES 密钥）
 *   - 加密强度跟"这是不是壳"这件事无关，重点是/dex 在哪里被加密/被读出来
 *
 * 格式：
 *   [0..4)   int32_le   原始 dex 长度
 *   [4..8)   magic     0x41 0x4A 0x4D 0x01  ("AJM\x01")
 *   [8..)    XOR(key) 后的 dex 数据
 */
public final class Crypto {

    private static final byte[] KEY = {
            (byte) 0x5A, (byte) 0x3C, (byte) 0x7F, (byte) 0x11,
            (byte) 0xE4, (byte) 0x29, (byte) 0x8D, (byte) 0x63,
    };

    public static final byte[] MAGIC = {0x41, 0x4A, 0x4D, 0x01};

    private Crypto() {
    }

    public static byte[] encrypt(byte[] plain) {
        byte[] out = new byte[plain.length + 8];
        putInt(out, 0, plain.length);
        System.arraycopy(MAGIC, 0, out, 4, 4);
        for (int i = 0; i < plain.length; i++) {
            out[8 + i] = (byte) (plain[i] ^ KEY[i & 7] ^ (i & 0xff));
        }
        return out;
    }

    public static byte[] decrypt(byte[] packed) {
        if (packed.length < 8) {
            return new byte[0];
        }
        int len = getInt(packed, 0);
        byte[] out = new byte[len];
        int n = Math.min(len, packed.length - 8);
        for (int i = 0; i < n; i++) {
            out[i] = (byte) (packed[8 + i] ^ KEY[i & 7] ^ (i & 0xff));
        }
        return out;
    }

    private static void putInt(byte[] b, int off, int v) {
        b[off] = (byte) (v & 0xff);
        b[off + 1] = (byte) ((v >> 8) & 0xff);
        b[off + 2] = (byte) ((v >> 16) & 0xff);
        b[off + 3] = (byte) ((v >> 24) & 0xff);
    }

    private static int getInt(byte[] b, int off) {
        return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8)
                | ((b[off + 2] & 0xff) << 16) | ((b[off + 3] & 0xff) << 24);
    }
}
