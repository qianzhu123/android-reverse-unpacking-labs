/*
 * target.c — 360 加固练习工程的样本源码
 *
 * 设计目标（与 PROMPT.md 一致）：
 *   - 用本机 NDK 从同一份源码编译，保证"加壳前/后"代码与字符串一致，脱壳后可逐字节对照。
 *   - 放置明确的"分析锚点"：特征字符串 / JNI_OnLoad / RegisterNatives / 业务函数，
 *     用来验证脱壳是否真的成功（脱壳后的 .so 必须能找回这些锚点）。
 *
 * 本文件刻意保留可压缩、有真实控制流的代码（循环/校验/字符串），
 * 这样 UPX（360 native 壳的历史基础）才有足够内容可压，体积对比才明显。
 */
#include <jni.h>
#include <string.h>
#include <stdio.h>

/* 模拟 360 native 层携带的策略/签名表（由 build/gen_policy.py 生成）。
 * 提供可观体积让 UPX 可打包，也是脱壳后的真实数据锚点。 */
#include "policy_inc.h"

/* ===== 分析锚点（脱壳后必须能找回）===== */
static const char* SECRET_KEY     = "JiaguLab-2026-SECRET-KEY";
static const char* FLAG           = "flag{jiagu_unpacking_is_fun}";
static const char* NATIVE_CLASS   = "com/aegis/NativeLib";
/* 360 加固 lab 的 payload 标记：脱壳后可见，用于确认样本身份。
 * 用数组（而非 const char* 指针）定义，保证 -O2 不会把初始化串优化掉。 */
static const char PAYLOAD_MARKER[] = "360jiagu_lab_payload_marker_v1";

/* 业务函数：真实可执行代码，保证 .so 有足够可压缩内容 */
static jstring getFlag(JNIEnv* env, jobject thiz) {
    (void)thiz;
    char buf[128];
    int acc = 0;
    size_t n = strlen(FLAG);
    for (size_t i = 0; i < n; i++) {
        acc = (acc * 31 + FLAG[i]) & 0xffff;
        buf[i] = (char)(FLAG[i] ^ (acc & 0x0f));
    }
    buf[n] = '\0';
    (void)buf; /* 上面的变换只是制造真实代码流，最终回传原始 FLAG 串 */
    return (*env)->NewStringUTF(env, FLAG);
}

static jboolean check_license(JNIEnv* env, jobject thiz, jstring key) {
    (void)thiz;
    const char* k = (*env)->GetStringUTFChars(env, key, 0);
    if (!k) return JNI_FALSE;
    jboolean ok = (jboolean)(strcmp(k, SECRET_KEY) == 0);
    (*env)->ReleaseStringUTFChars(env, key, k);
    return ok;
}

/* blob_selfcheck：样本自校验桩，脱壳后也应可见。
 * 用 volatile 指针逐字节读取，强制编译器把标记串/策略表保留在 .rodata（否则 -O2 会优化掉）。 */
static jint blob_selfcheck(JNIEnv* env, jobject thiz) {
    (void)env; (void)thiz;
    const char * volatile p = PAYLOAD_MARKER;   /* volatile：禁止常量折叠 */
    jint sum = 0;
    for (int i = 0; p[i] != '\0'; i++)
        sum = (sum + (jint)(unsigned char)p[i]) & 0xff;
    const char * volatile pb = POLICY_BLOB;      /* 同时遍历策略表，保留体积锚点 */
    for (int i = 0; pb[i] != '\0'; i++)
        sum = (sum + (jint)(unsigned char)pb[i]) & 0xff;
    return sum;
}

/* RegisterNatives 注册表：脱壳后在 IDA 里应能看到 调用链
 *   JNI_OnLoad -> RegisterNatives -> getFlag -> check_license */
static JNINativeMethod gMethods[] = {
    {"getFlag",      "()Ljava/lang/String;",  (void*)getFlag},
    {"checkLicense", "(Ljava/lang/String;)Z", (void*)check_license},
    {"selfCheck",    "()I",                    (void*)blob_selfcheck},
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    (void)reserved;
    JNIEnv* env = NULL;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;
    jclass clazz = (*env)->FindClass(env, NATIVE_CLASS);
    if (clazz == NULL)
        return JNI_ERR;
    if ((*env)->RegisterNatives(env, clazz, gMethods,
                                (jint)(sizeof(gMethods) / sizeof(gMethods[0]))) < 0)
        return JNI_ERR;
    return JNI_VERSION_1_6;
}
