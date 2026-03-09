package com.example.kmm

import kotlinx.coroutines.*
import kotlin.native.concurrent.SharedImmutable

// =============================================================================
// 35. KMM (Kotlin Multiplatform) Security Issues
// =============================================================================

// VULN: KMM expect crypto function
expect fun encryptData(data: ByteArray, key: ByteArray): ByteArray
expect fun decryptData(data: ByteArray, key: ByteArray): ByteArray
expect fun hashPassword(password: String): String

// VULN: KMM expect secure storage
expect fun storeToken(token: String)
expect fun storePassword(password: String)

// VULN: SharedImmutable annotation
@SharedImmutable
val globalConfig = mapOf("debug" to "true")

class PlatformSecurityManager {
    fun checkPlatform() {
        // VULN: Platform-specific code without security parity check
        if (Platform.isAndroid) {
            // Android-specific handling
        } else if (Platform.isIOS) {
            // iOS-specific handling
        }
    }

    fun saveCredentials(username: String, password: String) {
        // VULN: NSUserDefaults for sensitive data (iOS)
        NSUserDefaults.standardUserDefaults.setObject(password, forKey = "password")

        // VULN: localStorage for sensitive data (JS)
        localStorage.setItem("token", "secret-jwt-token-here")
    }
}

// =============================================================================
// 34. Jetpack Compose WebView Security
// =============================================================================
// Simulated Compose annotations
annotation class Composable

@Composable
fun WebViewScreen(url: String) {
    // VULN: WebView in Compose with JS enabled
    AndroidView(factory = { context ->
        WebView(context).apply {
            settings.javaScriptEnabled = true
            // VULN: addJavascriptInterface in Compose
            addJavascriptInterface(MyJsInterface(), "Android")
            // VULN: loadUrl with user-controlled URL
            loadUrl("$url")
        }
    })
}

class MyJsInterface {
    @android.webkit.JavascriptInterface
    fun getData(): String = "sensitive_data"
}

// =============================================================================
// 25. Missing Input Validation in API handlers
// =============================================================================
class ApiHandlers {
    fun handleUserRegistration(name: String, email: String, age: String) {
        // VULN: No input validation on any parameters
        val user = createUser(name, email, age.toInt())
        saveUser(user)
    }

    fun handleProcessPayment(amount: String, cardNumber: String) {
        // VULN: No validation on payment data
        processPayment(amount.toDouble(), cardNumber)
    }

    fun handleDeleteUser(userId: String) {
        // VULN: No validation on userId before deletion
        deleteFromDatabase(userId)
    }

    private fun createUser(name: String, email: String, age: Int) = mapOf("name" to name)
    private fun saveUser(user: Map<String, String>) {}
    private fun processPayment(amount: Double, cardNumber: String) {}
    private fun deleteFromDatabase(userId: String) {}
}

// =============================================================================
// 26. Information Disclosure
// =============================================================================
class ErrorHandler {
    fun handleError(e: Exception): String {
        // VULN: Stack trace in response
        return e.stackTrace.joinToString("\n")
    }

    fun logError(e: Exception) {
        // VULN: printStackTrace
        e.printStackTrace()
    }

    fun getVersion(): String {
        // VULN: Debug mode flag
        val debug = true
        return if (debug) "v1.0.0-debug" else "v1.0.0"
    }
}

// =============================================================================
// 37. Clipboard Vulnerability
// =============================================================================
class ClipboardHelper {
    fun copyPassword(password: String) {
        // VULN: Sensitive data to clipboard
        val clipboard = android.content.ClipboardManager()
        val clipData = android.content.ClipData.newPlainText("password", password)
        clipboard.setPrimaryClip(clipData)
    }
}

// =============================================================================
// Compose-specific multiline WebView (multi-line detection test)
// =============================================================================
@Composable
fun BrowserView(pageUrl: String) {
    AndroidView(
        factory = { ctx ->
            android.webkit.WebView(ctx).apply {
                javaScriptEnabled = true
                loadUrl(pageUrl)
            }
        },
        update = { webView ->
            webView.loadUrl(pageUrl)
        }
    )
}

// =============================================================================
// 39. Exposed Debug Endpoints
// =============================================================================
class DebugRoutes {
    fun setupRoutes() {
        // VULN: Debug endpoint
        get("/debug/heap") {
            respondText("heap dump")
        }

        // VULN: Admin endpoint
        post("/admin/reset-db") {
            respondText("database reset")
        }

        // VULN: Internal endpoint
        get("/internal/metrics") {
            respondText("system metrics")
        }
    }
}
