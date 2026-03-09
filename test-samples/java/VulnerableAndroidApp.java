package com.example.android.vulnerable;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.webkit.WebSettings;
import android.webkit.WebView;

import java.io.*;
import java.net.*;
import java.util.Random;

/**
 * INTENTIONALLY VULNERABLE Android application - Test file for SAST scanner.
 */
public class VulnerableAndroidApp extends Activity {

    private static final String apiKey = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe";
    private WebView webView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setupWebView();
        handleDeepLink();
    }

    // ============ WEBVIEW SECURITY ============
    private void setupWebView() {
        webView = new WebView(this);
        WebSettings settings = webView.getSettings();

        // VULN: JavaScript enabled in WebView
        settings.setJavaScriptEnabled(true);

        // VULN: File access enabled
        settings.setAllowFileAccess(true);
        settings.setAllowFileAccessFromFileURLs(true);
        settings.setAllowUniversalAccessFromFileURLs(true);

        // VULN: JavaScript interface exposed
        webView.addJavascriptInterface(new WebAppInterface(), "Android");
    }

    // ============ INTENT SPOOFING ============
    private void handleDeepLink() {
        Intent intent = getIntent();
        String url = intent.getStringExtra("url");

        // VULN: Unvalidated intent data used in WebView
        if (url != null) {
            webView.loadUrl(url);
        }

        // VULN: Sensitive data in SharedPreferences
        String token = intent.getStringExtra("token");
        SharedPreferences prefs = getSharedPreferences("app_prefs", MODE_PRIVATE);
        prefs.edit().putString("auth_token", token).apply();
    }

    // ============ INSECURE NETWORK ============
    private void sendPasswordToServer(String password) throws Exception {
        // VULN: Hardcoded credentials
        String secret = "my-app-secret-key-2024";

        // VULN: Insecure random for nonce
        Random random = new Random();
        String nonce = String.valueOf(random.nextLong());

        // VULN: Weak hash
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-1");
        byte[] hash = md.digest(password.getBytes());

        // VULN: SSRF - URL from user input
        String serverUrl = getIntent().getStringExtra("server");
        URL url = new URL(serverUrl + "/api/login");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
    }

    // ============ EXPORTED COMPONENT ============
    private void configureComponent() {
        // VULN: Exported component
        // In real Android, this would be in manifest
        android.content.ComponentName component = new android.content.ComponentName(this, VulnerableAndroidApp.class);
    }

    // ============ SQL INJECTION (SQLite) ============
    public void queryUser(String userId) {
        // VULN: SQL injection in SQLite
        android.database.sqlite.SQLiteDatabase db = null;
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        db.rawQuery(query, null);
    }

    // ============ PATH TRAVERSAL ============
    public void readFile(String filename) throws IOException {
        // VULN: Path traversal
        File file = new File(getFilesDir(), filename);
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[1024];
        fis.read(data);
    }

    // ============ EMPTY CATCH ============
    public void parseConfig() {
        try {
            // some risky operation
            int x = Integer.parseInt("abc");
        } catch (Exception e) {
            // VULN: Empty catch block
        }
    }

    // Inner class for JavaScript interface
    private class WebAppInterface {
        @android.webkit.JavascriptInterface
        public String getToken() {
            SharedPreferences prefs = getSharedPreferences("app_prefs", MODE_PRIVATE);
            return prefs.getString("auth_token", "");
        }
    }
}
