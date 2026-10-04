/*
 * enumerate.js — print every invoked method signature for the target (ground truth).
 *
 * Why: the target's method names are obfuscated (a/b/c) and the dex-level prototypes
 * in dexdump are easy to misread. This asks the LIVE JVM for the real signatures, so
 * hooks are written against truth, not guesses.
 */
setTimeout(function () {
    Java.perform(function () {
        var Modifier = Java.use('java.lang.reflect.Modifier');
        Java.enumerateLoadedClasses({
            onMatch: function (name) {
                if (name.indexOf('vantagepoint') < 0) return;
                try {
                    var C = Java.use(name);
                    C.class.getDeclaredMethods().forEach(function (m) {
                        var params = m.getParameterTypes().map(function (t) { return t.getName(); }).join(',');
                        console.log(name + '.' + m.getName() + '(' + params + ') -> ' +
                            m.getReturnType().getName() +
                            (Modifier.isStatic(m.getModifiers()) ? '  [static]' : ''));
                    });
                } catch (e) { console.log('[!] ' + name + ': ' + e); }
            },
            onComplete: function () {}
        });
    });
}, 1200);
