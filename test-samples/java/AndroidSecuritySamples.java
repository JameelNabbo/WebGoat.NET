package com.test.vulnerable;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.webkit.WebView;
import android.webkit.WebSettings;
import android.util.Log;

/**
 * Android-Specific Vulnerability Test Samples
 * Tests: WebView JavaScript enabled, insecure SharedPreferences,
 *        hardcoded secrets, logging sensitive data
 */
public class AndroidSecuritySamples extends Activity {

    private static final String API_KEY = "AIzaSyD-hardcoded-api-key-12345";

    // 1. WebView with JavaScript enabled (potential XSS)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView webView = new WebView(this);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);

        // Load URL from intent (untrusted source)
        String url = getIntent().getStringExtra("url");
        webView.loadUrl(url);
    }

    // 2. Insecure SharedPreferences for sensitive data
    public void saveCredentials(String username, String password) {
        SharedPreferences prefs = getSharedPreferences("user_prefs", MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString("username", username);
        editor.putString("password", password);
        editor.apply();
    }

    // 3. Logging sensitive information
    public void loginUser(String username, String password) {
        Log.d("AUTH", "Login attempt: user=" + username + " pass=" + password);
        // perform login...
    }

    // 4. Implicit intent leaking data
    public void shareData(String sensitiveData) {
        Intent intent = new Intent(Intent.ACTION_SEND);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_TEXT, sensitiveData);
        startActivity(intent);
    }

    // 5. Exported activity without permission check
    // AndroidManifest: <activity android:name=".AndroidSecuritySamples" android:exported="true" />
}
