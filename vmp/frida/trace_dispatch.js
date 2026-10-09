// trace_dispatch.js — 动态 trace DEX 层解释器的分派（静态搞不定时的兜底）
//
// 用途：L3（反射分派）/ L4（融合算子）静态还原不出完整 opcode 映射时，用这个脚本
// 在设备上把「每次 run(...) 收到的 id 与字节码」和「解释器实际走的 opcode 序列」打出来。
//
// 运行（真机/模拟器，需与 host frida 同版本，see build/env.sh.example）：
//   frida -U -f com.demo.calc -l frida/trace_dispatch.js --no-pause
//
// 注意：本脚本只**观察**，不改目标行为；输出的字节码/opcode 序列喂给
// tools/devirt_dex.py 的 --json 结果人工比对，或直接人工还原语义。

Java.perform(function () {
    var seen = {};

    function hookReader(clazzName) {
        try {
            var C = Java.use(clazzName);
            // 解释器里读字节码的那一步（不同实现可能叫 load/run）——遍历全部静态方法，
            // 对「参数含 byte[] 或 int[]」的方法挂 trace，通用且不依赖方法名。
            C.class.getDeclaredMethods().forEach(function (m) {
                var name = m.getName();
                if (!seen[clazzName + '.' + name]) {
                    seen[clazzName + '.' + name] = true;
                    send('[method] ' + clazzName + '.' + name + ' '
                         + m.getParameterTypes().map(function (t) { return t.getName(); }).join(','));
                }
            });
        } catch (e) { /* 类不存在就跳过 */ }
    }

    Java.enumerateLoadedClasses({
        onMatch: function (name) {
            if (name.indexOf('com.demo.calc') === 0) hookReader(name);
        },
        onComplete: function () { send('[done] dispatch trace armed'); }
    });
});
