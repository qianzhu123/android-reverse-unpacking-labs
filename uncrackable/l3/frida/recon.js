/* recon.js — L3: find libfoo, hook the post-decrypt point, capture the plaintext. */
function log() { console.log.apply(console, arguments); }

function findFoo() {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
        if (mods[i].name.indexOf('foo') >= 0) return mods[i];
    }
    return null;
}

setTimeout(function () {
    var m = findFoo();
    log('[*] modules named *foo*: ' + (m ? (m.name + ' @ ' + m.base) : 'none yet'));
    if (!m) { log('[*] all modules: ' + Process.enumerateModules().map(function(x){return x.name;}).join(',')); return; }

    Interceptor.attach(m.base.add(0x3aaa), {
        onEnter: function () {
            var u8 = new Uint8Array(Memory.readByteArray(this.context.rsp, 24));
            var s = ''; for (var i = 0; i < 24; i++) s += String.fromCharCode(u8[i]);
            log('[plaintext@bar+0x3a] "' + s + '"');
        }
    });

    Java.perform(function () {
        setTimeout(function () {
            Java.perform(function () {
                Java.choose('sg.vantagepoint.uncrackable3.CodeCheck', {
                    onMatch: function (inst) {
                        try { log('[call] bar(dummy) = ' + inst.bar(Java.array('byte', [0x41,0x41]))); }
                        catch (e) { log('[!] bar: ' + e); }
                    },
                    onComplete: function () { log('[recon] done'); }
                });
            });
        }, 1200);
    });
}, 2500);
