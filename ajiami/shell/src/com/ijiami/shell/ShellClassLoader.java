package com.ijiami.shell;

import android.content.Context;

import java.io.File;
import java.lang.reflect.Array;
import java.lang.reflect.Field;

import dalvik.system.DexClassLoader;

/**
 * 加载器：决定"解密出来的 dex 以什么方式被塞进 ClassLoader 链"。
 *
 * 一代加固最典型的判别点：
 *   classes.dex 里没有任何业务类，但运行时 /proc/self/maps 里多了一个 dex/apk
 *   —> 这一定是动态加载，脱壳要从 ClassLoader 链入手（而不是只看 dex 文件）。
 */
public final class ShellClassLoader {

    private static volatile ShellClassLoader sInstance;

    private final DexClassLoader loader;

    private ShellClassLoader(String dexPath, Context ctx) {
        File oat = ctx.getDir("ijm_oatdex", Context.MODE_PRIVATE);
        loader = new DexClassLoader(dexPath, oat.getAbsolutePath(), null,
                ctx.getClassLoader().getParent());
    }

    public static ShellClassLoader getInstance(Context ctx, String dexPath) {
        if (sInstance == null) {
            synchronized (ShellClassLoader.class) {
                if (sInstance == null) {
                    sInstance = new ShellClassLoader(dexPath, ctx);
                }
            }
        }
        return sInstance;
    }

    public Class<?> find(String name) throws ClassNotFoundException {
        return loader.loadClass(name);
    }

    /** 把自己插到 LoadedApk.mClassLoader 前面，让业务类可以被找到。 */
    public void install() {
        try {
            Class<?> atClazz = Class.forName("android.app.ActivityThread");
            Field f = Reflection.fieldOf(atClazz, "sCurrentActivityThread");
            Object at = f.get(null);
            Object pkg = at.getClass().getMethod("getPackageInfoNoCheck", android.content.pm.ApplicationInfo.class,
                    Class.forName("android.content.res.CompatibilityInfo"))
                    .invoke(at, null, null);
            Field cl = Reflection.fieldOf(pkg.getClass(), "mClassLoader");
            cl.setAccessible(true);
            cl.set(pkg, loader);
        } catch (Throwable ignored) {
            // 练习环境下跑不到这里
        }
    }

    /** 占位，用于保留 Array 的引用路径（便于在脱壳 trace 里观察）。 */
    static Object[] empty() {
        return (Object[]) Array.newInstance(Object.class, 0);
    }
}
