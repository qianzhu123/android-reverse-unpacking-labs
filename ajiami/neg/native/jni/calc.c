#include <jni.h>

/*
 * 一个最普通的 NDK 共享库：1 个 JNI 导出函数 + JNI_OnLoad。
 * 用 NDK clang 编出来后，经 elfinspect 检查应当是 anomalies=[]（干净 NDK 产物），
 * 用来锁住 B13 的"干净 SO 不误报"路径；它与真实计算器 App 的 libcalculator.so 同理。
 */

JNIEXPORT jint JNICALL
Java_com_demo_negnative_MainActivity_nativeAdd(JNIEnv *env, jobject thiz, jint a, jint b) {
    return a + b;
}

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;
    (void)reserved;
    return JNI_VERSION_1_6;
}
