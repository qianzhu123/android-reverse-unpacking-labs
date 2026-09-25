package com.demo.neg;
import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;
public class MainActivity extends Activity {
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        NegLogic logic = new NegLogic();
        TextView tv = new TextView(this);
        tv.setText(NegLogic.tag() + " " + logic.twist(3, 4));
        setContentView(tv);
    }
    public int add(int a, int b) { return new NegLogic().add(a, b); }
}
