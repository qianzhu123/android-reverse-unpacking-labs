#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
build_levels.py — 生成 L1..L5 各难度的 DEX-VM 样本源码 + 载荷。

每层一个目录（用「层号」而非描述性名字；判据靠结构，不靠层号/名字，见 detect_vm.py）：

    build/gen/level_N/com/demo/calc/CalcActivity.java  入口（各层一致）
    build/gen/level_N/com/demo/calc/CalcLogic.java     业务类（方法体 = 调解释器）
    build/gen/level_N/com/demo/calc/Core.java          解释器（L5 无此类）
    samples/payloads/level_N.bin                       自定义字节码
    samples/payloads/level_N.map.json                  opmap 原始值（文档/工具用）

各层难度（分派形态）：

    L1  规则 packed-switch，opcode 0x01..0xFF，字节码写在源码数组里
    L2  同 L1 分派，但字节码外置 assets/core_a.dat 且 XOR 加密
    L3  **无 switch**：opcode 经 int[] 表映射到一组 handler，Method[] **反射 invoke**
    L4  超算子（一条 handler 顶多条逻辑指令）+ opcode 每次生成随机、不连续
    L5  **内联 VM**：没有 Core.run，三个业务方法各自内嵌一份解释器循环

顶层约定：L1..L4 里 CalcLogic 的每个方法体只有一句 `Core.run(<id>, args)`
（判据 V1「汇聚调用」抓的形态）；L5 刻意打破它。

用法（lab 根目录执行）：python tools/build_levels.py
"""

import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vmlang
import vmgen

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GEN = os.path.join(ROOT, 'build', 'gen')
PAYLOADS = os.path.join(ROOT, 'samples', 'payloads')
LEVELS = ['L1', 'L2', 'L3', 'L4', 'L5']

BASE = ['LOADARG', 'PUSH', 'XOR', 'ADD', 'MUL', 'SUB', 'RET']


def _w(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)


def _arr(b):
    return ','.join(str(x if x < 128 else x - 256) for x in b)


# ---------------------------------------------------------------- 公共模板
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
%(init)s
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

CALCLOGIC = '''package com.demo.calc;

/**
 * CalcLogic —— 业务类。每个方法体只有一句「调用 Core.run」：真实运算逻辑不在
 * 这段 dalvik 指令里，而以别的形式存在。类名/方法名还在，方法体被换成解释器调用。
 */
public final class CalcLogic {

    private static final int M_MIX = 0;
    private static final int M_TWIST = 1;
    private static final int M_DIGEST = 2;

    public static int mix(int a, int b) { return Core.run(M_MIX, new int[]{a, b}); }
    public static int twist(int a) { return Core.run(M_TWIST, new int[]{a}); }
    public static int digest(int a, int b) { return Core.run(M_DIGEST, new int[]{a, b}); }

    public static String anchor1() { return "ANCHOR-0001:LOGIC-MIX"; }
    public static String anchor2() { return "ANCHOR-0002:LOGIC-DIGEST"; }

    private CalcLogic() { }
}
'''


def _expr_cases(opmap, st='st', arg='args', code='code', pc='i', sp='sp'):
    """由 opmap 生成 switch case 列表（支持基础指令与超算子）。"""
    out = []
    for name, val in opmap.items():
        if name == 'LOADARG':
            body = '%s[%s++] = %s[%s[%s++] & 0xFF]; break;' % (st, sp, arg, code, pc)
        elif name == 'PUSH':
            body = '%s[%s++] = %s[%s++] & 0xFF; break;' % (st, sp, code, pc)
        elif name == 'XOR':
            body = '{ int y = %s[--%s], x = %s[--%s]; %s[%s++] = x ^ y; break; }' % (st, sp, st, sp, st, sp)
        elif name == 'ADD':
            body = '{ int y = %s[--%s], x = %s[--%s]; %s[%s++] = x + y; break; }' % (st, sp, st, sp, st, sp)
        elif name == 'MUL':
            body = '{ int y = %s[--%s], x = %s[--%s]; %s[%s++] = x * y; break; }' % (st, sp, st, sp, st, sp)
        elif name == 'SUB':
            body = '{ int y = %s[--%s], x = %s[--%s]; %s[%s++] = x - y; break; }' % (st, sp, st, sp, st, sp)
        elif name == 'ADDK':
            body = '%s[%s - 1] = %s[%s - 1] + (%s[%s++] & 0xFF); break;' % (st, sp, st, sp, code, pc)
        elif name == 'MULK':
            body = '%s[%s - 1] = %s[%s - 1] * (%s[%s++] & 0xFF); break;' % (st, sp, st, sp, code, pc)
        elif name == 'XORK':
            body = '%s[%s - 1] = %s[%s - 1] ^ (%s[%s++] & 0xFF); break;' % (st, sp, st, sp, code, pc)
        elif name == 'ADDMUL':
            body = ('{ int v = %s[%s++] & 0xFF, c = %s[%s++] & 0xFF;'
                    ' int a0 = %s[--%s]; %s[%s++] = (a0 * v) + c; break; }'
                    % (code, pc, code, pc, st, sp, st, sp))
        elif name == 'RET':
            body = 'return %s[--%s];' % (st, sp)
        else:
            raise ValueError(name)
        out.append('                case 0x%02X: %s' % (val, body))
    return '\n'.join(out)


def _inline_body(opmap, progarr):
    """L5 用：把解释器循环**直接内联进方法体**（每个业务方法各一份，无共享 hub）。"""
    cases = _expr_cases(opmap)
    return '''{
        byte[] code = %s;
        int[] st = new int[64];
        int sp = 0, i = 0;
        while (i < code.length) {
            int op = code[i++] & 0xFF;
            switch (op) {
%s
                default: return 0;
            }
        }
        return 0;
    }''' % (progarr, cases)


# ---------------------------------------------------------------- L1 / L4：packed-switch 解释器
CORE_SWITCH = '''package com.demo.calc;

/**
 * Core —— 解释器（packed-switch 形态：opcode 用一个规则 switch 分派）。
 *
 * STACK 是全局栈；run 被 CalcLogic 的每个业务方法汇聚调用。
 */
public final class Core {

    private static final byte[] P_MIX = {%(p_mix)s};
    private static final byte[] P_TWIST = {%(p_twist)s};
    private static final byte[] P_DIGEST = {%(p_digest)s};

    private static final int[] STACK = new int[64];

    public static int run(int id, int[] args) {
        byte[] code = (id == 0) ? P_MIX : (id == 1) ? P_TWIST : P_DIGEST;
        int sp = 0, i = 0;
        while (i < code.length) {
            int op = code[i++] & 0xFF;
            switch (op) {
%(cases)s
                default: return 0;
            }
        }
        return 0;
    }

    private Core() { }
}
'''

# ---------------------------------------------------------------- L2：assets + XOR
CORE_L2 = '''package com.demo.calc;

import android.content.Context;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/**
 * Core —— 解释器（第二档：字节码**不在源码里**，外置到 assets 的一个资源文件，并
 * 经过一层 XOR 加密）。
 *
 * 静态只看到一段高熵资源。解壳要点：找到「读 assets → XOR 解密」这一步。
 */
public final class Core {

    private static final int[] STACK = new int[64];
    private static byte[] CACHE;

    private static final String RES = "%(res)s";
    private static final byte[] KEY = {%(key)s};

    /** 入口在 onCreate 里调一次：把载荷读进来。 */
    public static void init(Context ctx) { load(ctx); }

    private static byte[] load(Context ctx) {
        if (CACHE != null) return CACHE;
        try {
            // 注意：不能用 in.available() 当长度 —— assets 走 AssetManager 解压流时
            // available() 可能先返回 0，读出来就是空的（本 lab 踩过：同一份样本时好时坏）。
            // 正确做法是读到 EOF。
            InputStream in = ctx.getAssets().open(RES);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[512];
            int n;
            while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
            in.close();
            byte[] raw = bos.toByteArray();
            byte[] out = new byte[raw.length];
            for (int i = 0; i < raw.length; i++) {
                out[i] = (byte) (raw[i] ^ KEY[i %% KEY.length]);
            }
            CACHE = out;
            return out;
        } catch (Exception e) {
            return new byte[0];
        }
    }

    public static int run(int id, int[] args) {
        byte[] all = CACHE;
        if (all == null || all.length < 3) return 0;
        int[] lens = { all[0] & 0xFF, all[1] & 0xFF, all[2] & 0xFF };
        int off = 3;
        for (int k = 0; k < id; k++) off += lens[k];
        int end = off + lens[id];

        int sp = 0, i = off;
        while (i < end) {
            int op = all[i++] & 0xFF;
            switch (op) {
%(cases)s
                default: return 0;
            }
        }
        return 0;
    }

    private Core() { }
}
'''

# ---------------------------------------------------------------- L3：反射分派
_HANDLER_DEF = {
    'LOADARG': '    static int h0(byte[] c, int[] r, int[] st, int[] a) { st[r[1]++] = a[c[r[0]++] & 0xFF]; return 1; }',
    'PUSH':    '    static int h1(byte[] c, int[] r, int[] st, int[] a) { st[r[1]++] = c[r[0]++] & 0xFF; return 1; }',
    'XOR':     '    static int h2(byte[] c, int[] r, int[] st, int[] a) { int y = st[--r[1]], x = st[--r[1]]; st[r[1]++] = x ^ y; return 1; }',
    'ADD':     '    static int h3(byte[] c, int[] r, int[] st, int[] a) { int y = st[--r[1]], x = st[--r[1]]; st[r[1]++] = x + y; return 1; }',
    'MUL':     '    static int h4(byte[] c, int[] r, int[] st, int[] a) { int y = st[--r[1]], x = st[--r[1]]; st[r[1]++] = x * y; return 1; }',
    'SUB':     '    static int h5(byte[] c, int[] r, int[] st, int[] a) { int y = st[--r[1]], x = st[--r[1]]; st[r[1]++] = x - y; return 1; }',
    'RET':     '    static int h6(byte[] c, int[] r, int[] st, int[] a) { return 2; }',
}
_HORDER = ['LOADARG', 'PUSH', 'XOR', 'ADD', 'MUL', 'SUB', 'RET']

CORE_L3 = '''package com.demo.calc;

import java.lang.reflect.Method;

/**
 * Core —— 解释器（第三档：**没有 switch**）。
 *
 * opcode 先经一张 int[] 表映射成「handler 序号」，再由一张 Method[] 表**反射 invoke**
 * 到对应的小方法。分派目标既不在 switch 里、也不在同一个大函数里 —— 静态看是
 * 「遍历 Method[] 逐个 invoke」。去虚拟化要先把 opcode→handler 映射恢复出来。
 */
public final class Core {

    private static final byte[] P_MIX = {%(p_mix)s};
    private static final byte[] P_TWIST = {%(p_twist)s};
    private static final byte[] P_DIGEST = {%(p_digest)s};

    private static final int[] STACK = new int[64];
    static final int[] DISPATCH = new int[256];
    private static Method[] HM;

    private static synchronized void ensureInit() {
        if (HM != null) return;
        try {
%(dispfill)s
            Class<?>[] sig = new Class<?>[]{byte[].class, int[].class, int[].class, int[].class};
            HM = new Method[] {
%(methodrefs)s
            };
        } catch (Exception e) {
            HM = null;
        }
    }

%(handlers)s

    public static int run(int id, int[] args) {
        ensureInit();
        if (HM == null) return 0;
        byte[] code = (id == 0) ? P_MIX : (id == 1) ? P_TWIST : P_DIGEST;
        int[] regs = new int[]{0, 0};
        while (regs[0] < code.length) {
            int op = code[regs[0]++] & 0xFF;
            try {
                int r = (Integer) HM[DISPATCH[op]].invoke(null, code, regs, STACK, args);
                if (r == 2) return STACK[--regs[1]];
            } catch (Exception e) {
                return 0;
            }
        }
        return 0;
    }

    private Core() { }
}
'''


# ---------------------------------------------------------------- L5：内联 VM
CALCLOGIC_INLINE = '''package com.demo.calc;

/**
 * CalcLogic —— 业务类（第五档：**内联 VM**）。
 *
 * 这里**没有**一个被大家汇聚调用的 Core.run/interp：三个业务方法各自内嵌了一份完整
 * 的解释器循环（各自带自己的字节码）。静态上「一个 hub 被多个极短方法调用」的形态
 * 消失 —— 汇聚类判据（V1）在此失效，只能靠「多个方法体内含同一组 switch case」(V5)。
 */
public final class CalcLogic {

    private static final byte[] P_MIX = {%(p_mix)s};
    private static final byte[] P_TWIST = {%(p_twist)s};
    private static final byte[] P_DIGEST = {%(p_digest)s};

    public static int mix(int a, int b) {
        int[] args = new int[]{a, b};
        %(body_mix)s
    }

    public static int twist(int a) {
        int[] args = new int[]{a};
        %(body_twist)s
    }

    public static int digest(int a, int b) {
        int[] args = new int[]{a, b};
        %(body_digest)s
    }

    public static String anchor1() { return "ANCHOR-0001:LOGIC-MIX"; }
    public static String anchor2() { return "ANCHOR-0002:LOGIC-DIGEST"; }

    private CalcLogic() { }
}
'''


# ---------------------------------------------------------------- 各层生成
def emit_L1(opmap, bc, pkg):
    _w(os.path.join(pkg, 'CalcActivity.java'), ACTIVITY % {'init': ''})
    _w(os.path.join(pkg, 'CalcLogic.java'), CALCLOGIC)
    _w(os.path.join(pkg, 'Core.java'), CORE_SWITCH % {
        'p_mix': _arr(bc['mix']), 'p_twist': _arr(bc['twist']),
        'p_digest': _arr(bc['digest']), 'cases': _expr_cases(opmap, st='STACK')})
    _write_payload('L1', bc)
    return 'inline bytecode; regular packed-switch; opcodes 0x01..0xFF'


def emit_L2(opmap, bc, pkg):
    rng = random.Random(0)
    key = bytes(rng.randrange(1, 256) for _ in range(16))
    # 明文载荷 = [len_mix,len_twist,len_digest] + 三段字节码；asset 存的是整块密文
    plain = bytes([len(bc['mix']), len(bc['twist']), len(bc['digest'])])         + bc['mix'] + bc['twist'] + bc['digest']
    enc = bytes(b ^ key[i % len(key)] for i, b in enumerate(plain))
    with open(os.path.join(PAYLOADS, 'level_L2.bin'), 'wb') as f:
        f.write(enc)   # 与样本 assets/core_a.dat 内容一致（密文）
    with open(os.path.join(PAYLOADS, 'level_L2.plain.bin'), 'wb') as f:
        f.write(plain)  # 解密后明文（文档/答案用）
    _w(os.path.join(pkg, 'CalcActivity.java'),
       ACTIVITY % {'init': '        Core.init(getApplicationContext());\n'})
    _w(os.path.join(pkg, 'CalcLogic.java'), CALCLOGIC)
    _w(os.path.join(pkg, 'Core.java'), CORE_L2 % {'res': 'core_a.dat', 'key': _arr(key),
        'cases': _expr_cases(opmap, st='STACK', code='all')})
    return 'bytecode in assets/core_a.dat (XOR key=%s)' % key.hex()


def emit_L3(opmap, bc, pkg):
    dispfil = []
    for name in _HORDER:
        dispfil.append('            DISPATCH[0x%02X] = %d;' % (opmap[name], _HORDER.index(name)))
    methodrefs = []
    for i in range(len(_HORDER)):
        methodrefs.append('                Core.class.getDeclaredMethod("h%d", sig),' % i)
    handlers = '\n'.join(_HANDLER_DEF[n] for n in _HORDER)
    _w(os.path.join(pkg, 'CalcActivity.java'), ACTIVITY % {'init': ''})
    _w(os.path.join(pkg, 'CalcLogic.java'), CALCLOGIC)
    _w(os.path.join(pkg, 'Core.java'), CORE_L3 % {
        'p_mix': _arr(bc['mix']), 'p_twist': _arr(bc['twist']), 'p_digest': _arr(bc['digest']),
        'dispfill': '\n'.join(dispfil),
        'methodrefs': '\n'.join(methodrefs),
        'handlers': handlers})
    _write_payload('L3', bc)
    return 'no switch; opcode->handler via int[] table + Reflection Method[] invoke'


def emit_L4(opmap, bc, pkg):
    _w(os.path.join(pkg, 'CalcActivity.java'), ACTIVITY % {'init': ''})
    _w(os.path.join(pkg, 'CalcLogic.java'), CALCLOGIC)
    _w(os.path.join(pkg, 'Core.java'), CORE_SWITCH % {
        'p_mix': _arr(bc['mix']), 'p_twist': _arr(bc['twist']),
        'p_digest': _arr(bc['digest']), 'cases': _expr_cases(opmap, st='STACK')})
    _write_payload('L4', bc)
    cases = sorted(opmap.values())
    return 'super-ops + randomized non-contiguous opcodes: %s' % \
        ' '.join('0x%02X' % v for v in cases)


def emit_L5(opmap, bc, pkg):
    _w(os.path.join(pkg, 'CalcActivity.java'), ACTIVITY % {'init': ''})
    _w(os.path.join(pkg, 'CalcLogic.java'), CALCLOGIC_INLINE % {
        'p_mix': _arr(bc['mix']), 'p_twist': _arr(bc['twist']),
        'p_digest': _arr(bc['digest']),
        'body_mix': _inline_body(opmap, 'P_MIX'),
        'body_twist': _inline_body(opmap, 'P_TWIST'),
        'body_digest': _inline_body(opmap, 'P_DIGEST')})
    _write_payload('L5', bc)
    return 'inline VM in each business method (no Core hub)'


def _write_payload(level, bc):
    with open(os.path.join(PAYLOADS, 'level_%s.bin' % level), 'wb') as f:
        f.write(bytes([len(bc['mix']), len(bc['twist']), len(bc['digest'])]))
        f.write(bc['mix'] + bc['twist'] + bc['digest'])


EMIT = {'L1': emit_L1, 'L2': emit_L2, 'L3': emit_L3, 'L4': emit_L4, 'L5': emit_L5}


def main():
    for lv in LEVELS:
        opmap = vmgen.level_opmap(lv)
        bc = vmgen.level_bytecode(lv)
        # 清掉上一层残留（否则改形态后旧类会一起编进 dex，e.g. L5 的内联版里混进旧 Core）
        base = os.path.join(GEN, 'level_' + lv)
        if os.path.isdir(base):
            import shutil
            shutil.rmtree(base)
        pkg = os.path.join(base, 'com', 'demo', 'calc')
        note = EMIT[lv](opmap, bc, pkg)
        with open(os.path.join(PAYLOADS, 'level_%s.map.json' % lv), 'w', encoding='utf-8') as f:
            json.dump({'level': lv, 'opmap': opmap, 'note': note}, f, indent=2)
        print('%-4s %s' % (lv, note))
    return 0


if __name__ == '__main__':
    sys.exit(main())
