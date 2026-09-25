package com.demo.negsupport;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
/** 模拟 AndroidX 那种「声明在 manifest、实现在次级 dex」的 Provider。 */
public class NegProvider extends ContentProvider {
    public boolean onCreate() { return true; }
    public Cursor query(Uri u, String[] p, String s, String[] a, String o) { return null; }
    public String getType(Uri u) { return "vnd.demo.neg"; }
    public Uri insert(Uri u, ContentValues v) { return null; }
    public int delete(Uri u, String s, String[] a) { return 0; }
    public int update(Uri u, ContentValues v, String s, String[] a) { return 0; }
}
