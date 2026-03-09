package com.example.vulnerable

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.os.Bundle
import android.webkit.WebView

class VulnerableActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // VULN: WebView JavaScript enabled
        val webView = WebView(this)
        webView.settings.javaScriptEnabled = true

        // VULN: WebView file access
        webView.settings.allowFileAccess = true

        // VULN: JavaScript interface
        webView.addJavascriptInterface(JsBridge(), "Android")

        // VULN: SharedPreferences for sensitive data
        val prefs = getSharedPreferences("user_prefs", Context.MODE_PRIVATE)
        val token = intent.getStringExtra("auth_token")
        prefs.edit().putString("password", token).apply()

        // VULN: Intent data used without validation
        val userId = intent.getStringExtra("userId")
        loadUserProfile(userId!!)

        // VULN: Broadcast receiver without permission
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                val data = intent.getStringExtra("data")
                processData(data)
            }
        }
        registerReceiver(receiver, IntentFilter("com.example.ACTION"))
    }

    private fun loadUserProfile(userId: String) { /* ... */ }
    private fun processData(data: String?) { /* ... */ }
}

class JsBridge {
    fun getData(): String = "sensitive data"
}

// VULN: TrustManager that accepts all certificates
class TrustAllManager : javax.net.ssl.X509TrustManager {
    override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {}
    override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {}
    override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
}
