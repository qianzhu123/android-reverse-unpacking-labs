/*
 * solve.js — UnCrackable-Level2 solve (native check + anti-debug bypass)
 *
 * Target facts recovered statically (see SCRIPT.md):
 *   libfoo.so exports:
 *     Java_sg_vantagepoint_uncrackable2_MainActivity_init   void  // fork + ptrace (anti-debug)
 *     Java_sg_vantagepoint_uncrackable2_CodeCheck_bar       boolean([B)  // strncmp(input, secret, 23)
 *   secret bytes in .rodata @0x11c0: "Thanks for all the fish" (exactly 23 chars)
 *
 * Two fixes learned the hard way (recorded in SCRIPT.md §8):
 *   - init returns void  → stub must not `return <value>`
 *   - bar takes byte[]   → build a Java byte array, not a JS string
 */
Java.perform(function () {
    function log() { console.log.apply(console, arguments); }

    // ---- 1. neutralize the native anti-debug (fork/ptrace) by stubbing init -------
    try {
        var Main = Java.use('sg.vantagepoint.uncrackable2.MainActivity');
        Main.init.overload().implementation = function () {
            log('[bypass] MainActivity.init() stubbed (native anti-debug skipped)');
            // void return — no value
        };
        log('[+] stubbed MainActivity.init()');
    } catch (e) { log('[!] init stub: ' + e); }

    // ---- 2. call the app's own native check with a byte[] -------------------------
    setTimeout(function () {
        Java.perform(function () {
            var CC;
            try { CC = Java.use('sg.vantagepoint.uncrackable2.CodeCheck'); }
            catch (e) { log('[!] CodeCheck load: ' + e); return; }

            function toBytes(s) {
                var a = [];
                for (var i = 0; i < s.length; i++) a.push(s.charCodeAt(i) & 0xff);
                return Java.array('byte', a);
            }

            // bar() returns false unless the global gate byte at .bss 0x400c == 1.
            // Real init() sets it only after the anti-debug passes; since we stubbed
            // init, we set the gate ourselves — this is the crux of the bypass.
            var base = Module.findBaseAddress('libfoo.so');
            if (base !== null) {
                Memory.writeU8(base.add(0x400c), 1);
                log('[bypass] libfoo.so base=' + base + ' gate[+0x400c]=1');
            } else {
                log('[!] libfoo.so not found');
            }

            try {
                Java.choose('sg.vantagepoint.uncrackable2.CodeCheck', {
                    onMatch: function (inst) {
                        log('[oracle] CodeCheck.bar("Thanks for all the fish") = ' +
                            inst.bar(toBytes('Thanks for all the fish')));
                        log('[oracle-neg] CodeCheck.bar("nope-not-it") = ' +
                            inst.bar(toBytes('nope-not-it')));
                    },
                    onComplete: function () { log('[oracle] done'); }
                });
            } catch (e) { log('[!] bar() call: ' + e); }
        });
    }, 2500);
});
