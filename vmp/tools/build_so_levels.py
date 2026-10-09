#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
build_so_levels.py — 生成 S1..S3 三个 **SO/ARM64 虚拟机**样本的 Java + C 源码。

与 L1..L5（纯 DEX）不同，这三层的解释器是 **native(.so)**：JNI 导出 mix/twist/digest，
真实逻辑在 SO 里的自定义字节码（.rodata）与 native 分派器里。

三层难度（native 分派形态）：

    S1  经典 switch 分派：一个中心 while+switch，handler 规模一目了然
    S2  运行期装配分派：handler 地址表由 init 在运行期拼出来，opcode→handler 用
        计算的映射，静态没有 switch、只有间接跳转（blr xN）
    S3  **Threaded / computed-goto**：没有中心分派，处理器之间直接互相跳（basic block
        网），静态看不到单一解释器函数

字节码来自和黄金样本**同一份规范**（vmlang），所以语义等价是结构性的。

产物：
    build/gen/so_S1/com/demo/calc/{CalcActivity.java,CalcLogic.java}
    build/gen/so_S1/native/core.c
    samples/payloads/so_S1.map.json

用法：python tools/build_so_levels.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vmlang
import vmgen

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GEN = os.path.join(ROOT, 'build', 'gen')
PAYLOADS = os.path.join(ROOT, 'samples', 'payloads')
SO_LEVELS = ['S1', 'S2', 'S3']
SO_NAME = 'calc'          # 三层都用同一个库名（样本内不含层号，避免名字泄题）

# SO 三层的字节码 opcode 表（与 C 模板里的 case 常量一致：RET 用 0xFF）
SO_OPMAP = {'LOADARG': 0x01, 'PUSH': 0x02, 'XOR': 0x03,
            'ADD': 0x04, 'MUL': 0x05, 'SUB': 0x06, 'RET': 0xFF}


def so_bytecode():
    """用 SO 专用 opmap 汇编三层的字节码（与 C 模板 case 常量一致）。"""
    toks = vmgen.level_tokens('L1')
    return {name: vmlang.assemble(t, SO_OPMAP) for name, t in toks.items()}



def _w(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)


def _carr(b, per=16):
    """bytes -> C 数组初始化串。"""
    out = []
    for i in range(0, len(b), per):
        out.append('    ' + ', '.join('0x%02X' % x for x in b[i:i + per]) + ',')
    return '\n'.join(out)


def _cintarr(b, per=12):
    out = []
    for i in range(0, len(b), per):
        out.append('    ' + ', '.join('%d' % x for x in b[i:i + per]) + ',')
    return '\n'.join(out)


# ---------------------------------------------------------------- Java 侧（三层一致）
ACTIVITY = '''package com.demo.calc;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

/** 入口。与黄金版共用同一条 CALC 日志，便于比对受保护样本是否行为一致。 */
public class CalcActivity extends Activity {

    public static final String TAG = "CALC";

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        int mix = CalcLogic.mix(7, 3);
        int twist = CalcLogic.twist(7);
        int digest = CalcLogic.digest(7, 3);
        String anchor = CalcLogic.anchor1();

        String line = "mix(7,3)=" + mix
                + " twist(7)=" + twist
                + " digest(7,3)=" + digest
                + " anchor=" + anchor;
        Log.i(TAG, line);
        TextView tv = new TextView(this);
        tv.setText(line);
        setContentView(tv);
    }
}
'''

CALCLOGIC_NATIVE = '''package com.demo.calc;

/**
 * CalcLogic —— 业务类（native 实现）。
 *
 * mix/twist/digest 都是 **native 声明** —— 方法体不在 DEX 里，真实逻辑在 SO 中。
 * 一旦业务大规模退化成 native 声明，静态 DEX 侧就到头了，必须转 ELF 层。
 */
public final class CalcLogic {

    static { System.loadLibrary("%(lib)s"); }

    public static native int mix(int a, int b);
    public static native int twist(int a);
    public static native int digest(int a, int b);

    public static String anchor1() { return "ANCHOR-0001:LOGIC-MIX"; }
    public static String anchor2() { return "ANCHOR-0002:LOGIC-DIGEST"; }

    private CalcLogic() { }
}
'''


# ---------------------------------------------------------------- S1：中心 switch
C_S1 = r'''/* S1 —— SO/ARM64 虚拟机（第一档：中心 switch 分派）。
 *
 * 一个 while + 一个大 switch：每条自定义指令 -> 一个 case。静态反汇编里
 * 「一个大函数 + 一张跳转表 + 循环」就是它的形态。
 *
 * 自定义字节码放在 .rodata（只读数据段），运行时被解释执行。
 * 程序语义与黄金样本同源（同一份规范 -> 同一段字节码）。
 */
#include <jni.h>
#include <string.h>

typedef struct {
    const unsigned char *code;
    int len;
    int pc;
    int sp;
    int st[64];
    const int *args;
} VC;

static const unsigned char P_MIX[] = {
%(mix)s};

static const unsigned char P_TWIST[] = {
%(twist)s};

static const unsigned char P_DIGEST[] = {
%(digest)s};

static int vmr(VC *v) {
    while (v->pc < v->len) {
        int op = v->code[v->pc++];
        switch (op) {
            case 0x01: v->st[v->sp++] = v->args[v->code[v->pc++]]; break;
            case 0x02: v->st[v->sp++] = v->code[v->pc++]; break;
            case 0x03: { int b = v->st[--v->sp], a = v->st[--v->sp]; v->st[v->sp++] = a ^ b; break; }
            case 0x04: { int b = v->st[--v->sp], a = v->st[--v->sp]; v->st[v->sp++] = a + b; break; }
            case 0x05: { int b = v->st[--v->sp], a = v->st[--v->sp]; v->st[v->sp++] = a * b; break; }
            case 0x06: { int b = v->st[--v->sp], a = v->st[--v->sp]; v->st[v->sp++] = a - b; break; }
            case 0xFF: return v->st[--v->sp];
            default: return 0;
        }
    }
    return 0;
}

static int call(const unsigned char *code, int len, const int *args) {
    VC v;
    memset(&v, 0, sizeof(v));
    v.code = code; v.len = len; v.args = args;
    return vmr(&v);
}

JNIEXPORT jint JNICALL
Java_com_demo_calc_CalcLogic_mix(JNIEnv *e, jclass c, jint a, jint b) {
    int args[2] = { (int) a, (int) b };
    return call(P_MIX, (int) sizeof(P_MIX), args);
}

JNIEXPORT jint JNICALL
Java_com_demo_calc_CalcLogic_twist(JNIEnv *e, jclass c, jint a) {
    int args[1] = { (int) a };
    return call(P_TWIST, (int) sizeof(P_TWIST), args);
}

JNIEXPORT jint JNICALL
Java_com_demo_calc_CalcLogic_digest(JNIEnv *e, jclass c, jint a, jint b) {
    int args[2] = { (int) a, (int) b };
    return call(P_DIGEST, (int) sizeof(P_DIGEST), args);
}
'''

# ---------------------------------------------------------------- S2：运行期装配分派
C_S2 = r'''/* S2 —— SO/ARM64 虚拟机（第二档：运行期装配分派）。
 *
 * 没有 switch：每条自定义指令对应一个小 handler 函数，分派靠一张**运行期拼出来的**
 * 函数指针表 + 一个计算出来的 opcode->槽位映射。静态反汇编里看不到中心 switch，
 * 只看到一句间接调用（blr xN），目标是运行期才确定的地址。
 */
#include <jni.h>
#include <string.h>

typedef struct {
    const unsigned char *code;
    int len;
    int pc;
    int sp;
    int st[64];
    const int *args;
} VC;

typedef int (*handler_t)(VC *);

static const unsigned char P_MIX[] = {
%(mix)s};

static const unsigned char P_TWIST[] = {
%(twist)s};

static const unsigned char P_DIGEST[] = {
%(digest)s};

static int op_load(VC *v) { v->st[v->sp++] = v->args[v->code[v->pc++]]; return 1; }
static int op_push(VC *v) { v->st[v->sp++] = v->code[v->pc++]; return 1; }
static int op_xor(VC *v)  { int b = v->st[--v->sp], a = v->st[--v->sp]; v->st[v->sp++] = a ^ b; return 1; }
static int op_add(VC *v)  { int b = v->st[--v->sp], a = v->st[--v->sp]; v->st[v->sp++] = a + b; return 1; }
static int op_mul(VC *v)  { int b = v->st[--v->sp], a = v->st[--v->sp]; v->st[v->sp++] = a * b; return 1; }
static int op_sub(VC *v)  { int b = v->st[--v->sp], a = v->st[--v->sp]; v->st[v->sp++] = a - b; return 1; }
static int op_ret(VC *v)  { return 2; }

/* 运行期装配：槽位表与 opcode 映射都在 init 里算出来 */
static handler_t SLOT[8];
static unsigned char OPMAP[256];
static int READY = 0;

static void assemble(void) {
    /* handler 地址按一个固定的打乱顺序放进槽位表 */
    handler_t tmp[7];
    tmp[0] = op_sub;  tmp[1] = op_load; tmp[2] = op_ret; tmp[3] = op_xor;
    tmp[4] = op_add;  tmp[5] = op_mul;  tmp[6] = op_push;
    /* 槽位顺序再按一个常数列重排，静态看不到最终布局 */
    static const unsigned char ORD[7] = { 3, 0, 5, 1, 6, 2, 4 };
    for (int i = 0; i < 7; i++) SLOT[i] = tmp[ORD[i]];
    /* opcode -> 槽位：运行期反解出每个 handler 落在哪个槽 */
    unsigned char slot_of[7];
    for (int i = 0; i < 7; i++) slot_of[ORD[i]] = (unsigned char) i;
    for (int i = 0; i < 256; i++) OPMAP[i] = 0xFF;
    OPMAP[0x01] = slot_of[1];  /* op_load */
    OPMAP[0x02] = slot_of[6];  /* op_push */
    OPMAP[0x03] = slot_of[3];  /* op_xor  */
    OPMAP[0x04] = slot_of[4];  /* op_add  */
    OPMAP[0x05] = slot_of[5];  /* op_mul  */
    OPMAP[0x06] = slot_of[0];  /* op_sub  */
    OPMAP[0xFF] = slot_of[2];  /* op_ret  */
    READY = 1;
}

static int vmr(VC *v) {
    if (!READY) assemble();
    while (v->pc < v->len) {
        int op = v->code[v->pc++];
        int slot = OPMAP[op];
        if (slot == 0xFF) return 0;
        int r = SLOT[slot](v);        /* 间接调用：目标运行期才确定 */
        if (r == 2) return v->st[--v->sp];
    }
    return 0;
}

static int call(const unsigned char *code, int len, const int *args) {
    VC v;
    memset(&v, 0, sizeof(v));
    v.code = code; v.len = len; v.args = args;
    return vmr(&v);
}

JNIEXPORT jint JNICALL
Java_com_demo_calc_CalcLogic_mix(JNIEnv *e, jclass c, jint a, jint b) {
    int args[2] = { (int) a, (int) b };
    return call(P_MIX, (int) sizeof(P_MIX), args);
}

JNIEXPORT jint JNICALL
Java_com_demo_calc_CalcLogic_twist(JNIEnv *e, jclass c, jint a) {
    int args[1] = { (int) a };
    return call(P_TWIST, (int) sizeof(P_TWIST), args);
}

JNIEXPORT jint JNICALL
Java_com_demo_calc_CalcLogic_digest(JNIEnv *e, jclass c, jint a, jint b) {
    int args[2] = { (int) a, (int) b };
    return call(P_DIGEST, (int) sizeof(P_DIGEST), args);
}
'''

# ---------------------------------------------------------------- S3：threaded / computed-goto
C_S3 = r'''/* S3 —— SO/ARM64 虚拟机（第三档：threaded / computed-goto）。
 *
 * 没有中心分派函数：每个处理器是一个带标签的代码块，执行完直接跳到下一个处理器
 * （goto *label），形成一张 basic block 网。静态上找不到「单一解释器 + 跳转表」的
 * 形态，控制流被摊平成一堆互相跳转的块。
 */
#include <jni.h>
#include <string.h>

typedef struct {
    const unsigned char *code;
    int len;
    int pc;
    int sp;
    int st[64];
    const int *args;
    int ret;
} VC;

static const unsigned char P_MIX[] = {
%(mix)s};

static const unsigned char P_TWIST[] = {
%(twist)s};

static const unsigned char P_DIGEST[] = {
%(digest)s};

static int vmr(VC *v) {
    static const void *LBL[256] = {
        [0x01] = &&L_LOAD, [0x02] = &&L_PUSH, [0x03] = &&L_XOR,
        [0x04] = &&L_ADD,  [0x05] = &&L_MUL,  [0x06] = &&L_SUB,
        [0xFF] = &&L_RET,  [0x00] = &&L_END,
    };
    static const void *DNEXT[256] = { 0 };
    #define NEXT() do { int op_ = v->code[v->pc++]; goto *LBL[op_]; } while (0)

    if (v->pc >= v->len) goto L_END;
    { int op0 = v->code[v->pc++]; goto *LBL[op0]; }

L_LOAD: v->st[v->sp++] = v->args[v->code[v->pc++]]; NEXT();
L_PUSH: v->st[v->sp++] = v->code[v->pc++];          NEXT();
L_XOR:  { int b = v->st[--v->sp], a = v->st[--v->sp]; v->st[v->sp++] = a ^ b; NEXT(); }
L_ADD:  { int b = v->st[--v->sp], a = v->st[--v->sp]; v->st[v->sp++] = a + b; NEXT(); }
L_MUL:  { int b = v->st[--v->sp], a = v->st[--v->sp]; v->st[v->sp++] = a * b; NEXT(); }
L_SUB:  { int b = v->st[--v->sp], a = v->st[--v->sp]; v->st[v->sp++] = a - b; NEXT(); }
L_RET:  v->ret = v->st[--v->sp]; goto L_END;
L_END:  return v->ret;
    #undef NEXT
}

static int call(const unsigned char *code, int len, const int *args) {
    VC v;
    memset(&v, 0, sizeof(v));
    v.code = code; v.len = len; v.args = args;
    return vmr(&v);
}

JNIEXPORT jint JNICALL
Java_com_demo_calc_CalcLogic_mix(JNIEnv *e, jclass c, jint a, jint b) {
    int args[2] = { (int) a, (int) b };
    return call(P_MIX, (int) sizeof(P_MIX), args);
}

JNIEXPORT jint JNICALL
Java_com_demo_calc_CalcLogic_twist(JNIEnv *e, jclass c, jint a) {
    int args[1] = { (int) a };
    return call(P_TWIST, (int) sizeof(P_TWIST), args);
}

JNIEXPORT jint JNICALL
Java_com_demo_calc_CalcLogic_digest(JNIEnv *e, jclass c, jint a, jint b) {
    int args[2] = { (int) a, (int) b };
    return call(P_DIGEST, (int) sizeof(P_DIGEST), args);
}
'''

TEMPLATES = {'S1': C_S1, 'S2': C_S2, 'S3': C_S3}
NOTES = {
    'S1': 'native VM, central while+switch dispatch, bytecode in .rodata',
    'S2': 'native VM, runtime-assembled handler table + computed opcode map (indirect call)',
    'S3': 'native VM, threaded/computed-goto dispatch (basic-block net, no central switch)',
}


def emit(level):
    # SO 三层统一用 SO_OPMAP（与 C 模板 case 常量一致；RET=0xFF）
    bc = so_bytecode()
    pkg = os.path.join(GEN, 'so_' + level, 'com', 'demo', 'calc')
    nat = os.path.join(GEN, 'so_' + level, 'native')

    _w(os.path.join(pkg, 'CalcActivity.java'), ACTIVITY)
    _w(os.path.join(pkg, 'CalcLogic.java'), CALCLOGIC_NATIVE % {'lib': SO_NAME})
    _w(os.path.join(nat, 'core.c'), TEMPLATES[level] % {
        'mix': _carr(bc['mix']), 'twist': _carr(bc['twist']), 'digest': _carr(bc['digest'])})

    with open(os.path.join(PAYLOADS, 'so_%s.map.json' % level), 'w', encoding='utf-8') as f:
        json.dump({'level': level, 'opmap': SO_OPMAP, 'note': NOTES[level]}, f, indent=2)
    return NOTES[level]


def main():
    for lv in SO_LEVELS:
        print('%-3s %s' % (lv, emit(lv)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
