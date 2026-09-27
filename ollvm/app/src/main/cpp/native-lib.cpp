#include <jni.h>
#include <string>

static std::string decode_secret() {
    const unsigned char blob[] = {0x10,0x14,0x13,0x05,0x09,0x1f,0x19,0x08,0x1f,0x0e,0x67,0x35,0x36,0x36,0x2c,0x37,0x77,0x34,0x3b,0x2e,0x33,0x2c,0x3f,0x00};
    const unsigned char key = 0x5a; std::string out;
    for (size_t i = 0; blob[i] != 0; ++i) out.push_back(static_cast<char>(blob[i] ^ key));
    return out;
}

extern "C" JNIEXPORT jstring JNICALL Java_com_example_ollvmlab_MainActivity_nativeSecret(JNIEnv* env, jobject) {
    std::string s = decode_secret(); return env->NewStringUTF(s.c_str());
}

extern "C" JNIEXPORT jint JNICALL Java_com_example_ollvmlab_MainActivity_nativeOpaque(JNIEnv*, jobject, jint input) {
    int x = input * 3 + 1; // Deliberately simple baseline for comparing with OLLVM passes.
    if (((x ^ 0x55) + 7) % 2 == 0) x += 0x10; else x -= 0x0b;
    for (int i = 0; i < 3; ++i) x = (x ^ (i * 13 + 3)) + 1;
    return x;
}
