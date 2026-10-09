// trace_dispatch.js — 动态路线：从样本**运行期**取真值（字节码 / opcode→handler 映射）
//
// 用途：静态跑不通的档（L3 反射分派 / L4 融合算子 / S2 运行期装配 / S3 threaded），
// 用这个脚本在设备上把「解释器实际拿到的本机字节码」和「opcode→handler 映射」打出来，
// 再回静态路线核实「静态能推出多少」。
//
// 前置：目标必须是**动态版（dyn）**—— 只有 app_lN_dbg.apk 里带 `CalcActivity.peek(int)`
//       与 `Core.peekCode/wipe`（正式样本故意不带，见 build/build_dyn.sh 的注释）。
//
// 运行（host frida 与设备 frida-server 必须同版本，本仓 = 16.5.9）：
//   python tools/trace_vm.py --package com.demo.calc --script frida/trace_dispatch.js
//
// **只观察、不修改目标行为**：只调 peek()（读一次载荷，样本自己随即清空）+ 读静态字段，
// 不在进程里留任何东西。
//
// 输出（机器可解析）：
//   [prog] id=0 len=12 hex=010001010302110402030507
//   [dispatch] opcode=0x03 -> slot=2
//   [hm] slot=2 -> h2
//   [done] ...

Java.perform(function () {
  // spawn 后 script.load() 早于 onCreate；等 2.5s 让 Activity 跑起来（L2 的载荷才会就位）
  setTimeout(function () {
  try {
    function hex(bs) {
        var s = '';
        for (var i = 0; i < bs.length; i++) {
            var b = (bs[i] & 0xFF).toString(16);
            s += (b.length < 2 ? '0' : '') + b;
        }
        return s;
    }

    // 读 Java 数组：用 java.lang.reflect.Array（frida 16.x 对 raw Java 数组不直接暴露 .length）
    var JArr = Java.use('java.lang.reflect.Array');
    function readJavaArray(a) {
        if (!a) return null;
        try {
            var n = JArr.getLength(a), out = [];
            for (var i = 0; i < n; i++) out.push(JArr.get(a, i).toString());
            return out;
        } catch (e) { return null; }
    }
    // HM[i] 的 toString() 形如 "static int com.demo.calc.Core.h2(byte[],int[],int[],int[])"
    function handlerName(s) {
        var m = /Core\.(h\d+)\(/.exec(s);
        return m ? m[1] : s;
    }

    function num(x) { return parseInt(String(x), 10); }

    function staticField(cls, name) {
        try {
            var f = cls.class.getDeclaredField(name);
            f.setAccessible(true);
            return f.get(null);
        } catch (e) { return null; }
    }

    var Act = null, Core = null;
    try { Act = Java.use('com.demo.calc.CalcActivity'); } catch (e) {}
    try { Core = Java.use('com.demo.calc.Core'); } catch (e) {}

    // L2 的载荷是运行期从 assets 读+解密进 CACHE 的 —— spawn 早于 onCreate 时还拿不到。
    // 最稳的做法：hook 样本自己的 Core.init(Context)，等它跑过一次再往下走。
    var initCtx = null;
    if (Core && Core.init) {
        try {
            Core.init.implementation = function (ctx) {
                initCtx = ctx;
                return this.init(ctx);
            };
        } catch (e) { /* 有些层没有 init */ }
    }

    // ---- 1) 本机字节码（dyn 版才有 peek；样本内部随即 wipe）----
    if (Act && Act.peek) {
        // 若 init 还没被 Activity 调过，就用已捕获的 Context 主动补一次（拿到再放回去）
        if (initCtx && Core && Core.init) {
            var probe0 = null;
            try { probe0 = Act.peek(0); } catch (e) {}
            if (!probe0 || probe0.length === 0) {
                try { Core.init(initCtx); } catch (e) {}
            }
        }
        for (var id = 0; id < 3; id++) {
            try {
                var bs = Act.peek(id);
                if (bs && bs.length > 0) {
                    send('[prog] id=' + id + ' len=' + bs.length + ' hex=' + hex(bs));
                } else {
                    send('[prog] id=' + id + ' (empty)');
                }
            } catch (e) { send('[prog] id=' + id + ' ERR ' + e); }
        }
    } else {
        send('[prog] no CalcActivity.peek — 不是 dyn 版（L5 无 Core，用 devirt_dex.py 静态解）');
    }

    if (!Core) { send('[done] no Core (L5 inline VM) — static route covers it'); return; }

    // ---- 2) L3 的 opcode→slot 与 slot→handler ----
    var disp = readJavaArray(staticField(Core, 'DISPATCH'));
    var hm = readJavaArray(staticField(Core, 'HM'));
    if (hm === null) {
        // ensureInit 还没跑过 -> 先让解释器跑一次（调 mix 就会触发）
        try { Java.use('com.demo.calc.CalcLogic').mix(0, 0); } catch (e) {}
        disp = readJavaArray(staticField(Core, 'DISPATCH'));
        hm = readJavaArray(staticField(Core, 'HM'));
    }
    if (disp) {
        // DISPATCH 是 256 项、默认全 0 的表；只有被装配过的 opcode 才有意义。
        // 装配区是从 0x01 起的连续段（未装配项恒为 0）—— 用「连续前缀」判定，再与
        // 本次取到的字节码求交，只报真正用到的 opcode。
        var used = {};
        for (var b = 0; b < 3; b++) {
            try {
                var bs2 = Act.peek(b);
                if (bs2) for (var k = 0; k < bs2.length; k++) used[bs2[k] & 0xFF] = true;
            } catch (e) {}
        }
        var maxOp = 0;
        for (var op = 1; op < disp.length; op++) {
            if (num(disp[op]) === op - 1) { maxOp = op; } else { break; }
        }
        for (var op2 = 1; op2 <= maxOp; op2++) {
            send('[dispatch] opcode=0x' + (op2 < 16 ? '0' : '') + op2.toString(16) +
                 ' -> slot=' + num(disp[op2]));
        }
        send('[dispatch] assigned opcode range = 0x01..0x' + maxOp.toString(16) +
             ' (out of 256; the rest stay default-0)');
    } else {
        send('[dispatch] no DISPATCH field (L1/L2/L4 用 switch，不是反射分派)');
    }

    if (hm) {
        for (var i = 0; i < hm.length; i++) {
            send('[hm] slot=' + i + ' -> ' + handlerName(hm[i]));
        }
    }
    // ---- 合成结论行：opcode -> handler（这正是 L3「静态跑不通」要拿的那张表）----
    if (disp && hm) {
        for (var op = 1; op <= maxOp; op++) {
            var slot = num(disp[op]);
            var name = handlerName(hm[slot] || '');
            if (name) {
                send('[opmap] opcode=0x' + (op < 16 ? '0' : '') + op.toString(16) +
                     ' -> slot=' + slot + ' -> ' + name);
            }
        }
    }

    // ---- 3) handler 原型（反射拿不到字节码，但名字+参数能对上静态读出的 hN）----
    try {
        Core.class.getDeclaredMethods().forEach(function (m) {
            if (/^h\d+$/.test(m.getName())) {
                send('[handler] ' + m.getName() + ' params=' +
                     m.getParameterTypes().map(function (t) { return t.getName(); }).join(','));
            }
        });
    } catch (e) {}

    // 读完了：显式清空载荷（dyn 版才有 wipe），进程里不留东西
    try { if (Act && Act.wipe) Act.wipe(); } catch (e) {}
    send('[done] dynamic probe finished (nothing left in-process)');
  } catch (e) { send('[fatal] ' + e + ' | ' + (e.stack || '')); }
  }, 2500);
});
