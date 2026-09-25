package com.demo.target;

/** JNI 桥：真实加固 APK 里，解密逻辑往往就藏在这条 System.loadLibrary 后面。 */
public final class NativeBridge {

    private static final String SO_NAME = "ajm-target";

    private static boolean loaded = false;

    private NativeBridge() {
    }

    public static synchronized void probe() {
        try {
            System.loadLibrary(SO_NAME);
            loaded = true;
        } catch (Throwable t) {
            // 练习环境里不关心是否真能加载，这里只作为 dex 中的静态锚点
            loaded = false;
        }
    }

    public static boolean nativeReady() {
        return loaded;
    }
}
