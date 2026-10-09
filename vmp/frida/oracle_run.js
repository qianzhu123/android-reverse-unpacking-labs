// oracle_run.js — 行为 oracle：对比「受保护样本」与「黄金样本」在同一组输入下的结果
//
// 用途：在设备上主动调用 CalcLogic 的三个方法（无论它是明文还是 VM 实现），
// 打印结果。四个值必须与黄金基线完全一致：
//     mix(7,3)=63  twist(7)=44  digest(7,3)=121
// 同时也打一组「负控」错误输入，证明 oracle 有区分度（不是恒真）。
//
// 运行：
//   frida -U -f com.demo.calc -l frida/oracle_run.js --no-pause
//
// 与 logcat 的关系：样本自己也会往 logcat 打同一行（tag CALC）；本脚本的价值是
// 「不依赖样本是否走到 onCreate」，可主动调方法。

Java.perform(function () {
    var C = Java.use('com.demo.calc.CalcLogic');
    function call(name, args) {
        try {
            return C[name].apply(C, args);
        } catch (e) {
            return 'ERR:' + e;
        }
    }
    send('[oracle] mix(7,3)   = ' + call('mix', [7, 3]) + '   (expect 63)');
    send('[oracle] twist(7)   = ' + call('twist', [7]) + '   (expect 44)');
    send('[oracle] digest(7,3)= ' + call('digest', [7, 3]) + '   (expect 121)');
    send('[oracle-neg] mix(0,0)= ' + call('mix', [0, 0]) + '   (expect 51 ≠ 63，负控)');
});
