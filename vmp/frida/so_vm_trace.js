// so_vm_trace.js — 动态路线（SO/ARM64 层）：从运行期取 native 解释器的真值
//
// 用途：静态无中心 switch 的档 —— S2（运行期装配 handler 表）/ S3（threaded）。
// 静态只能判「分派不是中心 switch」；真值必须从运行期取。
//
// 本脚本按 `模块基址 + 符号偏移` 读目标内存（符号偏移由 `llvm-nm` 得到，见下表）：
//   · S2  有 OPMAP[256]（byte，opcode→slot）与 SLOT[8]（函数指针，slot→handler 地址）
//         —— 拼出 opcode → handler 地址，**这就是静态拿不到的那张表**；
//         再把 handler 偏移喂回 `llvm-objdump -d`，即得每条 opcode 的语义。
//   · S1/S3 没有分派表（S1 是比较级联、S3 是 threaded），但有 P_MIX/P_TWIST/P_DIGEST
//         三段**只读字节码**——本脚本把它们的原始字节 dump 出来。
//         S1 的 opcode 语义静态已能还原（devirt_so.py）；S3 需要 Stalker 追控制流（见文末）。
//
// 运行（host frida 与设备 frida-server 同版本，本仓 = 16.5.9）：
//   python tools/trace_vm.py --package com.demo.calc --script frida/so_vm_trace.js
//
// **只读内存、不改目标。** 换构建后符号偏移会变，需重新 `llvm-nm` 取。

var SYM = {
    // 每个 .so 的符号偏移（llvm-nm 得到；换构建后必须重取 —— 各档编译选项不同，偏移不同）
    S1: { P_MIX: 0x548, P_TWIST: 0x554, P_DIGEST: 0x55d },
    S2: { OPMAP: 0x4089, SLOT: 0x4190, P_MIX: 0x550, P_TWIST: 0x55c, P_DIGEST: 0x565 },
    S3: { P_MIX: 0x5d0, P_TWIST: 0x5dc, P_DIGEST: 0x5e5 },
};

var LIB = 'libcalc.so';

function base() {
    try {
        var m = Process.findModuleByName(LIB);
        if (m) return m.base;
    } catch (e) {}
    try { return Module.findBaseAddress(LIB); } catch (e) { return null; }
}

function hex(u8) {
    var s = '';
    for (var i = 0; i < u8.length; i++) s += (u8[i] < 16 ? '0' : '') + u8[i].toString(16);
    return s;
}

function readBytecode(b, off, n) {
    // 注意：P_* 是**定长 C 数组**（不是 NUL 结尾）——不能按 0x00 截断，
    // 因为 LOADARG 的参数就是 0x00。这里按给定长度读，精确长度取自 llvm-nm 的符号大小。
    try {
        var u8 = new Uint8Array(b.add(off).readByteArray(n || 24));
        send('[so] bytecode @0x' + off.toString(16) + ' (' + u8.length + 'B) hex=' + hex(u8));
    } catch (e) { send('[so] read @0x' + off.toString(16) + ' ERR ' + e); }
}

function dump() {
    var b = base();
    if (!b) { send('[so] ' + LIB + ' not loaded yet'); return; }
    send('[so] ' + LIB + ' base=' + b);

    // ---- S2：运行期装配的分派表 ----
    var s2 = SYM.S2, isS2 = false;
    try {
        var opm = new Uint8Array(b.add(s2.OPMAP).readByteArray(256));
        var assigned = 0;
        for (var i = 0; i < 256; i++) if (opm[i] !== 0xFF) assigned++;
        if (assigned >= 4) {
            isS2 = true;
            send('[so] profile = S2 (handler table assembled at runtime)');
            for (var op = 0; op < 256; op++) {
                if (opm[op] !== 0xFF) {
                    send('[so] opcode=0x' + (op < 16 ? '0' : '') + op.toString(16) +
                         ' -> slot=' + opm[op]);
                }
            }
            for (var sl = 0; sl < 7; sl++) {
                var p = b.add(s2.SLOT).add(sl * 8).readPointer();
                send('[so] slot=' + sl + ' -> handler=0x' + p.sub(b).toString(16));
            }
            send('[so] 把 handler 偏移喂回: llvm-objdump -d <so> --start-address=<off>');
        }
    } catch (e) { /* 不是 S2（没有可写表）*/ }

    // ---- S1/S3：只读字节码（无中心表；分派形态用 devirt_so.py 静态判）----
    if (!isS2) {
        // 选 S1 还是 S3 的符号偏移：两套都试读，取「像 VM 字节码」的那套
        // （P_MIX 必然以 0x01/LOADARG 开头，且能以 0x00 正确截断）
        function looksLikeVm(off) {
            try {
                var b0 = new Uint8Array(b.add(off).readByteArray(1))[0] & 0xFF;
                return b0 === 0x01 || b0 === 0x65;   // S1/S3 的 P_MIX 从 0x01 起
            } catch (e) { return false; }
        }
        var which = looksLikeVm(SYM.S1.P_MIX) ? 'S1' : (looksLikeVm(SYM.S3.P_MIX) ? 'S3' : null);
        if (!which) {
            send('[so] profile = S1/S3? (P_MIX offsets 对不上，可能换了构建 -> 重取 llvm-nm)');
            send('[so] finished');
            return;
        }
        send('[so] profile = ' + which + ' (no central dispatch table)');
        var OFF = SYM[which];
        readBytecode(b, OFF.P_MIX, which === 'S1' ? 12 : 12);
        readBytecode(b, OFF.P_TWIST, 9);
        readBytecode(b, OFF.P_DIGEST, 15);
        if (which === 'S3') {
            send('[so] note: S3 是 threaded 分派 —— 无表；要 opcode→handler 需 Stalker 追 basic block');
            send('[so] note: 见本文件末尾的 Stalker 示例（需先定位 vmr 入口偏移）');
        } else {
            send('[so] note: S1 的 opcode 语义静态已能还原（见 devirt_so.py 的 7/7）');
        }
    }
}

setTimeout(function () {
    try { dump(); } catch (e) { send('[fatal] ' + e + ' | ' + (e.stack || '')); }
    send('[done] so_vm_trace finished');
}, 2500);

// ---- S3（threaded）怎么继续：Stalker 追控制流 ----
// threaded 分派 = 处理器之间直接跳（没有中心表）。要还原 opcode→handler，只能
// 在解释器入口挂 Stalker，记录执行到的基本块序列，再把这些块与 .rodata 的字节码对齐：
//
//   var vmr = base().add(0x1a20);            // vmr 入口偏移（llvm-nm / objdump 取）
//   Stalker.follow(Process.getCurrentThreadId(), {
//     transform: function (iterator) {
//       var insn = iterator.next();
//       if (insn.mnemonic === 'br' || insn.mnemonic === 'brk') {
//         iterator.putCallout(function (ctx) { send('[s3] br -> ' + ctx.pc); });
//       }
//       iterator.keep();
//     }
//   });
//
// 本脚本不自动开 Stalker（开销大、且需要先定位 vmr 入口）——留作练习。
