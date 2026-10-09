// so_vm_trace.js — 动态 trace SO/ARM64 层的 native 解释器分派（S2 / S3 的兜底）
//
// 用途：S2（运行期装配 handler 表）/ S3（threaded 分派）静态没有稳定 case 边界，
// 用这个脚本在 libcalc.so 的 VM 循环里下 hook，把「实际执行的 handler 地址序列」打出来,
// 再按地址反查 .text 里的处理块（llvm-objdump），恢复 opcode→handler 映射。
//
// 运行：
//   frida -U -f com.demo.calc -l frida/so_vm_trace.js --no-pause
//
// 只观察、不修改目标行为。

var lib = null;
try { lib = Process.findModuleByName ? Process.findModuleByName('libcalc.so')
                                     : Module.findBaseAddress('libcalc.so') && { base: Module.findBaseAddress('libcalc.so'), name: 'libcalc.so' };
} catch (e) {}

function base() {
    try { return Module.findBaseAddress('libcalc.so'); } catch (e) { return null; }
}

// 通法：在 .text 段里对「间接调用/跳转」指令（blr xN / br xN）下 Stalker 或
// Interceptor，记录目标地址。这里给一个最小可用的示例 —— 实际偏移随构建而变，
// 建议先用 tools/devirt_so.py 的输出拿到分派函数偏移，再填进来。
function arm() {
    var b = base();
    if (!b) { send('[!] libcalc.so not loaded'); return; }
    send('[base] libcalc.so @ ' + b);
    send('[hint] 用 tools/devirt_so.py 的输出确定分派函数偏移，再在此处 Interceptor.attach');
    // 示例（偏移需按样本填写）：
    // Interceptor.attach(b.add(0x1234), {
    //   onEnter: function (args) { send('[dispatch] op = ' + this.context.x8); }
    // });
}

setTimeout(arm, 500);
