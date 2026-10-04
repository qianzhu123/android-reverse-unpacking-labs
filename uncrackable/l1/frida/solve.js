/*
 * solve.js — UnCrackable-Level1 solve via ACTIVE INVOCATION (real-target lab, PROMPT-REAL.md)
 *
 * Source-level facts recovered from dexdump (analysis_output/classes.dump.txt), not guessed:
 *   sg.vantagepoint.uncrackable1.a.a(String) -> boolean   // input.equals(new String(AES-decrypt))
 *       encrypted = Base64.decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=")   // string@0007
 *       keyBytes  = uncrackable1.a.b("8d127684cbc37c17616d806cf50473cc")           // string@0008, hex->bytes
 *       plain     = sg.vantagepoint.a.a.a(keyBytes, encrypted)                     // AES (byte[],byte[])->byte[]
 *   sg.vantagepoint.a.b.a(Context) -> boolean              // root check (early, calls System.exit)
 *   sg.vantagepoint.a.c.a()/.b()/.c() -> boolean           // more root/debug checks
 *
 * Strategy: bypass the guards, then re-run the app's OWN decryption by active invocation —
 * we do not transplant constants into JS; we call the app's function with the app's inputs.
 * Oracle: uncrackable1.a.a(recovered) must return true (the app's own check).
 */
Java.perform(function () {
    function log() { console.log.apply(console, arguments); }

    // ---- 1. guards: force every check to false, before resume() ------------------
    try {
        Java.use('sg.vantagepoint.a.b').a.overload('android.content.Context').implementation =
            function () { return false; };
        log('[+] bypass a.b.a(Context)');
    } catch (e) { log('[!] a.b: ' + e); }
    try {
        var C = Java.use('sg.vantagepoint.a.c');
        ['a', 'b', 'c'].forEach(function (n) {
            C[n].overload().implementation = function () { return false; };
        });
        log('[+] bypass a.c.a()/.b()/.c()');
    } catch (e) { log('[!] a.c: ' + e); }

    // ---- 2. drive the app's own decryption --------------------------------------
    setTimeout(function () {
        Java.perform(function () {
            var Base64 = Java.use('android.util.Base64');
            var AES    = Java.use('sg.vantagepoint.a.a');
            var A      = Java.use('sg.vantagepoint.uncrackable1.a');

            var encB64 = '5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=';
            var keyHex = '8d127684cbc37c17616d806cf50473cc';

            var enc = Base64.decode(encB64, 0);
            var key = A.b(keyHex);                 // app's own hex->bytes
            var dec = AES.a(key, enc);             // app's own AES
            var secret = Java.use('java.lang.String').$new(dec);
            log('[recovered] secret = "' + secret + '"');

            // Oracle: the app's own check must return true.
            var ok = A.a(secret);
            log('[oracle] uncrackable1.a.a(secret) = ' + ok);

            // Negative control: a wrong input must return false (proves the oracle discriminates).
            var wrong = A.a('definitely-not-the-secret');
            log('[oracle-neg] uncrackable1.a.a("definitely-not-the-secret") = ' + wrong);
        });
    }, 2000);
});
