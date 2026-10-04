/* probe.js — minimal liveness probe for L2: proves the Java bridge attached and
 * lists the target's own classes regardless of obfuscation filter. */
console.log('[probe] script loaded');
setTimeout(function () {
    console.log('[probe] 500ms — entering Java.perform');
    Java.perform(function () {
        console.log('[probe] Java.perform OK, enumerating');
        var n = 0;
        Java.enumerateLoadedClasses({
            onMatch: function (name) {
                if (name.indexOf('uncrackable2') >= 0) {
                    n++;
                    try {
                        var C = Java.use(name);
                        C.class.getDeclaredMethods().forEach(function (m) {
                            console.log(name + '.' + m.getName() + '(' +
                                m.getParameterTypes().map(function (t) { return t.getName(); }).join(',') +
                                ') -> ' + m.getReturnType().getName());
                        });
                    } catch (e) { console.log('[!] ' + name + ': ' + e); }
                }
            },
            onComplete: function () { console.log('[probe] enumeration complete, matched=' + n); }
        });
    });
}, 500);
