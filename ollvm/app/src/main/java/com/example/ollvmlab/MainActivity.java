package com.example.ollvmlab;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.TextView;

public class MainActivity extends Activity {
    static { System.loadLibrary("ollvmlab"); }
    private static final byte[] XOR_BLOB = { 0x10, 0x1b, 0x0c, 0x1b, 0x05, 0x02, 0x15, 0x08, 0x05, 0x09, 0x1f, 0x19, 0x08, 0x1f, 0x0e };
    private static final int XOR_KEY = 0x5a;
    private native String nativeSecret();
    private native int nativeOpaque(int input);

    @Override public void onCreate(Bundle state) {
        super.onCreate(state); setContentView(R.layout.activity_main);
        TextView output = findViewById(R.id.output);
        Button plain = findViewById(R.id.plainButton), xor = findViewById(R.id.xorButton), nativeBtn = findViewById(R.id.nativeButton), opaque = findViewById(R.id.opaqueButton);
        plain.setOnClickListener(v -> show(output, "PLAIN_SECRET=ollvm-lab:static-string"));
        xor.setOnClickListener(v -> { StringBuilder b = new StringBuilder(); for (byte x : XOR_BLOB) b.append((char)(x ^ XOR_KEY)); show(output, "JAVA_XOR=" + b); });
        nativeBtn.setOnClickListener(v -> show(output, "JNI_SECRET=" + nativeSecret()));
        opaque.setOnClickListener(v -> show(output, "OPAQUE_RESULT=" + nativeOpaque(7)));
    }
    private void show(TextView output, String value) { output.setText(value); Log.i("OLLVM_LAB", value); }
}
