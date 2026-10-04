/* probe.js — timed liveness: when do libfoo + target classes appear? */
function log() { console.log.apply(console, arguments); }
[500, 1500, 3000, 5000, 8000].forEach(function (t) {
    setTimeout(function () {
        var foo = 'no';
        try { Process.enumerateModules().forEach(function (x) { if (x.name.indexOf('foo') >= 0) foo = x.base.toString(); }); } catch (e) { foo = 'err:' + e; }
        var cc = 'no'; try { Java.use('sg.vantagepoint.uncrackable3.CodeCheck'); cc = 'yes'; } catch (e) { cc = 'no'; }
        var ma = 'no'; try { Java.use('sg.vantagepoint.uncrackable3.MainActivity'); ma = 'yes'; } catch (e) { ma = 'no'; }
        log('t=' + t + 'ms  libfoo=' + foo + '  CodeCheck=' + cc + '  MainActivity=' + ma);
    }, t);
});
