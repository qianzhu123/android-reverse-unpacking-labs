package com.ijiami.shell;

import android.app.Application;
import android.content.Context;

import java.lang.reflect.Field;

/**
 * 把 Application 从匣换回业务 Application。
 *
 * 这是 gc 型脱壳机（frida-dexdump 之类）最关心的时刻：
 * 此刻进程里同时存在匣 dex 与被解密的业务 dex，
 * 只要在这个点 dump ClassLoader 就能拿到完整原始 dex。
 */
public final class ApplicationSwap {

    /** 真实业务 Application 的类名，真实壳里通常写在 AndroidManifest meta-data 中。 */
    public static final String REAL_APPLICATION = "com.demo.target.MainApplication";

    private ApplicationSwap() {
    }

    public static void run(Context base, Application shellApp) {
        try {
            Class<?> real = Class.forName(REAL_APPLICATION);
            Object inst = real.newInstance();
            replace(base, shellApp, inst);
            replaceInner(shellApp, inst);
            java.lang.reflect.Method attach = android.app.Application.class
                    .getDeclaredMethod("attach", Context.class);
            attach.setAccessible(true);
            attach.invoke(inst, base);
            android.app.Application appInst = (android.app.Application) inst;
            appInst.onCreate();
        } catch (Throwable ignored) {
            // 离线练习环境不会真的跑到这里
        }
    }

    private static void replace(Context base, Application from, Object to) {
        try {
            Field f = Reflection.fieldOf(from.getClass(), "mBase");
            android.app.Application app = (android.app.Application) to;
            Class<?> cw = Class.forName("android.content.ContextWrapper");
            Field mf = Reflection.fieldOf(cw, "mBase");
            mf.set(app, base);
        } catch (Throwable ignored) {
        }
    }

    private static void replaceInner(Application shellApp, Object to) {
        try {
            Class<?> atClazz = Class.forName("android.app.ActivityThread");
            Field f = Reflection.fieldOf(atClazz, "sCurrentActivityThread");
            Object at = f.get(null);
            Field mi = Reflection.fieldOf(atClazz, "mInitialApplication");
            mi.set(at, to);
        } catch (Throwable ignored) {
        }
    }
}
