package com.ijiami.shell;

import android.content.Context;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

/** payload 的读 / 写 helpers。 */
public final class PayloadLoader {

    /** assets 下加密 dex 的名字。练习时注意：真实壳商很少用明文的后缀。 */
    public static final String PAYLOAD_NAME = "ijm_payload.bin";

    private PayloadLoader() {
    }

    public static byte[] readAsset(Context ctx, String name) {
        try {
            InputStream in = ctx.getAssets().open(name);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                bos.write(buf, 0, n);
            }
            in.close();
            return bos.toByteArray();
        } catch (Throwable t) {
            return new byte[0];
        }
    }

    public static String writePrivate(Context ctx, String name, byte[] data) {
        try {
            File dir = ctx.getDir("ijm_oat", Context.MODE_PRIVATE);
            File f = new File(dir, name);
            FileOutputStream fos = new FileOutputStream(f);
            fos.write(data);
            fos.close();
            return f.getAbsolutePath();
        } catch (Throwable t) {
            return "";
        }
    }
}
