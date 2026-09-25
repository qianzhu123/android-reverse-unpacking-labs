package com.demo.target;

import android.app.Application;

/**
 * 业务本体的 Application —— 加固后它会被"藏"起来。
 *
 * 最直观的一代加固判据：
 *   打包前 AndroidManifest 里 android:name 指向它；
 *   加固后指向 com.ijiami.shell.ProxyApplication（或别的代理类）。
 *   代理类所在的 classes.dex 里完全没有业务代码 —— 只有几百 K 的加载逻辑。
 */
public class MainApplication extends Application {

    @Override
    public void onCreate() {
        super.onCreate();
        // AJM-ANCHOR-0010
    }
}
