// Run: frida -U -f com.example.ollvmlab -l frida/frida-hook.js --no-pause
Java.perform(function () {
  const MainActivity = Java.use('com.example.ollvmlab.MainActivity');
  MainActivity.nativeSecret.implementation = function () {
    const value = this.nativeSecret();
    console.log('[nativeSecret] ' + value);
    return value;
  };
  MainActivity.nativeOpaque.implementation = function (input) {
    const result = this.nativeOpaque(input);
    console.log('[nativeOpaque] input=' + input + ' result=' + result);
    return result;
  };
});
