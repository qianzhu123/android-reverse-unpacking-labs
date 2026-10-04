/* solve.js — L3 (anti-tamper + anti-debug + native check).
 * libfoo has two libc-level defences started at load:
 *   - a watchdog thread (start_routine libfoo+0x37c0) that logs "Tampering detected!" and aborts;
 *   - a fork() + ptrace self-attach anti-debug (child branch at 0x3948).
 * We neutralize both at the libc layer BEFORE the constructors run (script loads pre-resume):
 * neuter any pthread_create whose routine lies inside libfoo's text, and make fork()/ptrace()
 * harmless. Then stub the Java checks (verifyLibs / root / isDebuggable / native init), force
 * the bar() counter gate, drive bar() to build the plaintext, and verify bar(plaintext)==true. */
function log() { console.log.apply(console, arguments); }
var _pe = Module.findExportByName('libc.so','pthread_exit');
var pthreadExit = _pe ? new NativeFunction(_pe,'void',['pointer']) : null;
function foo(){ var m=null; Process.enumerateModules().forEach(function(x){ if(x.name.indexOf('foo')>=0) m=x; }); return m; }

// raw thread routine stub: xor eax,eax; ret  (a clean pthread start routine)
var stub = Memory.alloc(Process.pageSize);
Memory.patchCode(stub, 8, function (c) { c.writeByteArray([0x31,0xc0,0xc3]); });
var pc = Module.findExportByName('libc.so', 'pthread_create');
if (pc) Interceptor.attach(pc, { onEnter: function (a) {
    var m = foo();
    if (m && !a[2].isNull() && a[2].compare(m.base) >= 0 && a[2].compare(m.base.add(0x8000)) < 0) {
        log('[bypass] pthread_create(libfoo+' + a[2].sub(m.base) + ') -> stub');
        a[2] = stub;
    }
}});
var fk = Module.findExportByName('libc.so', 'fork');
if (fk) Interceptor.replace(fk, new NativeCallback(function () { return -1; }, 'int', []));    // take parent path
var pt = Module.findExportByName('libc.so', 'ptrace');
if (pt) Interceptor.replace(pt, new NativeCallback(function () { return 0; }, 'long', ['int','int','pointer','pointer']));

Java.perform(function () {
    ['java.lang.System','java.lang.Runtime'].forEach(function (c) { try { var K = Java.use(c);
        if (K.exit) K.exit.overload('int').implementation = function (n) { log('[trap] '+c+'.exit('+n+')'); }; } catch (e) {} });
    try { Java.use('android.os.Process').killProcess.overload('int').implementation = function(p){ log('[trap] killProcess'); }; } catch(e){}
    try { Java.use('sg.vantagepoint.uncrackable3.MainActivity').init.overload('[B').implementation = function(){ log('[bypass] init([B)'); }; } catch(e){ log('[!] init: '+e); }
    try { Java.use('sg.vantagepoint.uncrackable3.MainActivity').verifyLibs.overload().implementation = function(){ log('[bypass] verifyLibs()'); }; } catch(e){ log('[!] verifyLibs: '+e); }
    try { Java.use('sg.vantagepoint.uncrackable3.MainActivity').showDialog.overload('java.lang.String').implementation = function(s){ log('[dialog] '+s); }; } catch(e){ log('[!] showDialog: '+e); }
    try { Java.use('sg.vantagepoint.util.IntegrityCheck').isDebuggable.overload('android.content.Context').implementation = function(){ return false; }; } catch(e){}
    try { var RD = Java.use('sg.vantagepoint.util.RootDetection');
        ['checkRoot1','checkRoot2','checkRoot3'].forEach(function(n){ try{ RD[n].overload().implementation=function(){ return false; }; }catch(e){} }); } catch(e){}

    setTimeout(function () {
        var m = foo(); if (!m) { log('[!] libfoo not loaded'); return; }
        log('[*] libfoo @ ' + m.base);
        var cap = null;
        Interceptor.attach(m.base.add(0x3aaa), { onEnter: function () {
            var u8 = new Uint8Array(Memory.readByteArray(this.context.rsp, 24)); var s='';
            for (var i=0;i<24;i++) s += String.fromCharCode(u8[i]); cap = s; log('[plaintext] "'+s+'"'); }});
        Memory.writeU32(m.base.add(0x705c), 2);
        Java.perform(function () {
            var CC; try { CC = Java.use('sg.vantagepoint.uncrackable3.CodeCheck'); } catch(e){ log('[!] CC: '+e); return; }
            var inst; try { inst = CC.$new(); } catch(e){ log('[!] $new: '+e); return; }
            var d=[]; for (var i=0;i<24;i++) d.push(0);
            try { log('[call] bar(zeros) = ' + inst.bar(Java.array('byte', d))); } catch(e){ log('[!] bar1: '+e); }
            if (cap) { var g=[]; for (var i=0;i<cap.length;i++) g.push(cap.charCodeAt(i));
                try { log('[oracle] bar(plaintext) = ' + inst.bar(Java.array('byte', g))); } catch(e){ log('[!] bar2: '+e); } }
        });
    }, 1500);
});
