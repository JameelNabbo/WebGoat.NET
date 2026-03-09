package com.example.vulnerable

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.webkit.WebView
import android.webkit.JavascriptInterface
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import java.io.*
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.sql.DriverManager
import java.util.Random
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

// =============================================================================
// 1. SQL Injection
// =============================================================================
class UserRepository(private val dbUrl: String) {
    fun findUser(username: String): User? {
        val conn = DriverManager.getConnection(dbUrl)
        // VULN: SQL Injection via string concatenation
        val query = "SELECT * FROM users WHERE username = '$username'"
        val rs = conn.createStatement().executeQuery(query)
        return null
    }

    fun searchUsers(searchTerm: String): List<User> {
        val conn = DriverManager.getConnection(dbUrl)
        // VULN: SQL Injection via string template
        val stmt = conn.createStatement()
        stmt.executeQuery("SELECT * FROM users WHERE name LIKE '%${searchTerm}%'")
        return emptyList()
    }

    fun deleteUser(id: String) {
        val conn = DriverManager.getConnection(dbUrl)
        // VULN: SQL Injection via concatenation
        conn.createStatement().executeUpdate("DELETE FROM users WHERE id = " + id)
    }
}

// =============================================================================
// 2. Command Injection
// =============================================================================
class SystemUtils {
    fun pingHost(host: String): String {
        // VULN: Command injection via Runtime.exec
        val process = Runtime.getRuntime().exec("ping -c 3 $host")
        return process.inputStream.bufferedReader().readText()
    }

    fun convertFile(inputPath: String, outputPath: String) {
        // VULN: Command injection via ProcessBuilder
        val pb = ProcessBuilder("convert", inputPath, outputPath)
        pb.start()
    }

    fun runCustomCommand(userCommand: String) {
        // VULN: Direct command execution with user input
        Runtime.getRuntime().exec(arrayOf("/bin/sh", "-c", userCommand))
    }
}

// =============================================================================
// 3. Code Injection
// =============================================================================
class ScriptRunner {
    fun evaluateExpression(expr: String) {
        // VULN: ScriptEngine with user input
        val engine = javax.script.ScriptEngineManager().getEngineByName("javascript")
        engine.eval(expr)
    }

    fun loadPlugin(className: String) {
        // VULN: Dynamic class loading with user input
        val clazz = Class.forName("com.plugins.$className")
        val instance = clazz.getDeclaredConstructor().newInstance()
    }
}

// =============================================================================
// 4. XSS
// =============================================================================
class WebController {
    fun renderUserProfile(userName: String): String {
        // VULN: XSS via string template in HTML
        return """
            <html>
            <body>
                <h1>Welcome, $userName</h1>
                <script>var user = "$userName";</script>
            </body>
            </html>
        """.trimIndent()
    }
}

// =============================================================================
// 5. Path Traversal
// =============================================================================
class FileService {
    fun readFile(fileName: String): String {
        // VULN: Path traversal via File() with user input
        val file = File("/uploads/$fileName")
        return file.readText()
    }

    fun downloadFile(path: String): ByteArray {
        // VULN: Path traversal via FileInputStream
        val fis = FileInputStream("/data/$path")
        return fis.readBytes()
    }
}

// =============================================================================
// 6. Deserialization
// =============================================================================
class DataProcessor {
    fun deserializeObject(data: ByteArray): Any {
        // VULN: ObjectInputStream deserialization
        val ois = ObjectInputStream(ByteArrayInputStream(data))
        return ois.readObject()
    }

    fun parseJson(jsonStr: String): Config {
        // VULN: Gson deserialization of untrusted data
        return com.google.gson.Gson().fromJson(jsonStr, Config::class.java)
    }
}

// =============================================================================
// 7. SSRF
// =============================================================================
class ApiProxy {
    fun fetchUrl(userUrl: String): String {
        // VULN: SSRF via URL() with user input
        val url = URL("$userUrl/api/data")
        val conn = url.openConnection() as HttpURLConnection
        return conn.inputStream.bufferedReader().readText()
    }
}

// =============================================================================
// 8. Hardcoded Secrets
// =============================================================================
object AppConfig {
    // VULN: Hardcoded credentials
    val API_KEY = "sk-ant-api03-realkey123456789abcdefghijklmnop"
    val DB_PASSWORD = "SuperSecret123!"
    val JWT_SECRET = "my-jwt-secret-key-do-not-share-2024"
    val AWS_ACCESS_KEY = "AKIAFAKEKEY1234567890"
    private val password = "admin_password_123"
    val connectionString = "mongodb://admin:p4ssw0rd@localhost:27017/mydb"
}

// =============================================================================
// 9. Weak Cryptography
// =============================================================================
class CryptoUtils {
    fun hashPassword(password: String): ByteArray {
        // VULN: MD5 is weak
        val md = MessageDigest.getInstance("MD5")
        return md.digest(password.toByteArray())
    }

    fun hashToken(token: String): ByteArray {
        // VULN: SHA-1 is weak
        return MessageDigest.getInstance("SHA1").digest(token.toByteArray())
    }

    fun encrypt(data: ByteArray, key: ByteArray): ByteArray {
        // VULN: DES is weak
        val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "DES"))
        return cipher.doFinal(data)
    }

    fun encryptAesEcb(data: ByteArray, key: ByteArray): ByteArray {
        // VULN: ECB mode
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        return cipher.doFinal(data)
    }
}

// =============================================================================
// 10. Insecure Random
// =============================================================================
class TokenGenerator {
    fun generateToken(): String {
        // VULN: java.util.Random is not cryptographically secure
        val random = java.util.Random()
        val token = (1..32).map { random.nextInt(36).toString(36) }.joinToString("")
        return token
    }

    fun generateOtp(): String {
        // VULN: Math.random for security token
        val otp = (Math.random() * 1000000).toInt().toString().padStart(6, '0')
        return otp
    }
}

// =============================================================================
// 11. Insecure TLS
// =============================================================================
class InsecureHttpClient {
    fun createClient(): javax.net.ssl.SSLContext {
        // VULN: TrustAll certificates
        val trustAllCerts = arrayOf(object : javax.net.ssl.X509TrustManager {
            override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
        })

        val sc = javax.net.ssl.SSLContext.getInstance("TLS")
        // VULN: SSLContext with null trust manager
        sc.init(null, trustAllCerts, java.security.SecureRandom())

        // VULN: Hostname verifier bypass
        val hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
        return sc
    }
}

// =============================================================================
// 12. Logging Sensitive Data
// =============================================================================
class AuthService {
    fun login(username: String, password: String): Boolean {
        // VULN: Logging password
        Log.d("AuthService", "Login attempt: user=$username password=$password")
        println("Authentication with password: $password")
        return true
    }

    fun processException(e: Exception) {
        // VULN: Stack trace exposure
        e.printStackTrace()
    }
}

// =============================================================================
// 13-16. Android Security Issues
// =============================================================================
class VulnerableActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val webView = WebView(this)
        // VULN: WebView JavaScript enabled
        webView.settings.javaScriptEnabled = true
        // VULN: WebView file access
        webView.settings.allowFileAccess = true
        webView.settings.allowUniversalAccessFromFileURLs = true
        // VULN: JavascriptInterface
        webView.addJavascriptInterface(JsBridge(), "Android")

        // VULN: SharedPreferences with sensitive data
        val prefs = getSharedPreferences("auth", MODE_WORLD_READABLE)
        val token = prefs.getString("token", "")
        val sharedPrefsPassword = prefs.getString("password", "")

        // VULN: Implicit intent with sensitive data
        val intent = Intent()
        intent.putExtra("password", password)
        // VULN: Broadcast without permission
        sendBroadcast(intent)

        // VULN: Intent data force-unwrap
        val deepLinkData = intent.data.toString()!!
        val userId = intent.getStringExtra("userId")!!

        // VULN: WebView loading user-controlled URL
        val userUrl = intent.getStringExtra("url") ?: ""
        webView.loadUrl("$userUrl")

        // VULN: PendingIntent with FLAG_MUTABLE
        val pendingIntent = android.app.PendingIntent.getActivity(
            this, 0, intent, android.app.PendingIntent.FLAG_MUTABLE
        )
    }

    inner class JsBridge {
        @JavascriptInterface
        fun getToken(): String = "secret_token_value"
    }
}

// =============================================================================
// 17. Android Crypto Issues
// =============================================================================
class InsecureCrypto {
    fun encrypt(data: String): ByteArray {
        // VULN: Static IV
        val iv = IvParameterSpec("1234567890123456".toByteArray())
        val key = SecretKeySpec("0123456789abcdef".toByteArray(), "AES")
        // VULN: AES/ECB mode
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key, iv)
        return cipher.doFinal(data.toByteArray())
    }
}

// =============================================================================
// 20. Coroutine Safety Issues
// =============================================================================
class DataManager {
    var sharedCounter = 0  // VULN: Mutable shared state
    val items = mutableListOf<String>()

    suspend fun processData() {
        kotlinx.coroutines.coroutineScope {
            // VULN: GlobalScope usage
            kotlinx.coroutines.GlobalScope.launch {
                sharedCounter++
                items.add("item")
            }

            // VULN: runBlocking
            kotlinx.coroutines.runBlocking {
                Thread.sleep(1000)
            }
        }
    }
}

// =============================================================================
// 21. Null Safety Bypass (excessive !!)
// =============================================================================
class NullUnsafeCode {
    fun processData(input: Map<String, Any?>) {
        val name = input.get("name")!!
        val age = input.get("age")!!
        val email = input.get("email")!!
        val phone = input.get("phone")!!
        val address = input.get("address")!!
        val city = input.get("city")!!
        val state = input.get("state")!!
        val zip = input.get("zip")!!
        val country = input.get("country")!!
        val company = input.get("company")!!
        val title = input.get("title")!!
    }
}

// =============================================================================
// 22. Open Redirect
// =============================================================================
class RedirectController {
    fun handleRedirect(redirectUrl: String) {
        // VULN: Open redirect
        respondRedirect("$redirectUrl")
    }
}

// =============================================================================
// 23. JWT Issues
// =============================================================================
class JwtHandler {
    // VULN: JWT none algorithm
    val algorithm = "none"

    fun createToken(userId: String): String {
        // VULN: Weak JWT secret
        val secret = "weak"
        return io.jsonwebtoken.Jwts.builder()
            .setSubject(userId)
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS256, "shortkey")
            .compact()
    }
}

// =============================================================================
// 24. Race Conditions
// =============================================================================
class ConcurrentProcessor {
    // VULN: Non-concurrent HashMap in threaded context
    val cache = HashMap<String, Any>()
    val results = ArrayList<String>()

    fun process(items: List<String>) {
        items.forEach {
            Thread {
                cache[it] = computeExpensive(it)
                results.add(it)
            }.start()
        }
    }

    private fun computeExpensive(item: String): Any = item.uppercase()
}

// =============================================================================
// 28. Timing Attack
// =============================================================================
class ApiKeyValidator {
    fun validateKey(providedKey: String, expectedKey: String): Boolean {
        // VULN: String equality for secret comparison
        return providedKey == expectedKey
    }

    fun checkToken(token: String): Boolean {
        val expectedToken = getStoredToken()
        // VULN: equals() for token comparison
        return token.equals(expectedToken)
    }

    private fun getStoredToken(): String = "stored_token"
}

// =============================================================================
// 29. Mass Assignment
// =============================================================================
data class UserDTO(
    val name: String,
    val email: String,
    val role: String,      // VULN: sensitive field
    val isAdmin: Boolean,  // VULN: sensitive field
    val salary: Double     // VULN: sensitive field
)

class UserController {
    fun createUser(jsonBody: String) {
        // VULN: Mass assignment - data class with sensitive fields from JSON
        val user = com.google.gson.Gson().fromJson(jsonBody, UserDTO::class.java)
    }
}

// =============================================================================
// 30. CORS Misconfiguration
// =============================================================================
class CorsConfig {
    fun configure() {
        // VULN: CORS allows all origins
        val allowedOrigins = listOf("*")
    }
}

// =============================================================================
// 31. Unsafe Reflection
// =============================================================================
class PluginLoader {
    fun loadPlugin(pluginName: String) {
        // VULN: Dynamic class loading with user input
        val clazz = Class.forName("com.plugins.$pluginName")
        val method = clazz.java.getDeclaredMethod("$pluginName")
    }
}

// =============================================================================
// 33. Firebase Misconfiguration
// =============================================================================
class FirebaseConfig {
    // VULN: Firebase API key in source
    val firebase_apiKey = "AIzaSyDOCAbC123dEf456GhI789jKl012-MnO"

    fun initFirebase() {
        // VULN: Anonymous auth
        com.google.firebase.auth.FirebaseAuth.getInstance().signInAnonymously()
    }
}

// =============================================================================
// 36. Insecure Storage
// =============================================================================
class InsecureStorage {
    fun saveCredentials(username: String, password: String) {
        // VULN: Writing sensitive data to external storage
        val file = File(android.os.Environment.getExternalStorageDirectory(), "creds.txt")
        file.writeText("password=$password")
    }
}

// =============================================================================
// 38. Deep Link Vulnerability
// =============================================================================
class DeepLinkHandler {
    fun handleDeepLink(intent: Intent) {
        // VULN: Deep link data used directly without validation
        val action = intent.data.host!!
        val path = intent.data.getQueryParameter("redirect")
    }
}

// =============================================================================
// 40. XXE
// =============================================================================
class XmlProcessor {
    fun parseXml(xmlInput: String) {
        // VULN: XML parsing without XXE protection
        val factory = javax.xml.parsers.DocumentBuilderFactory.newInstance()
        val builder = factory.newDocumentBuilder()
        val doc = builder.parse(java.io.ByteArrayInputStream(xmlInput.toByteArray()))
    }
}

// Helper data classes
data class User(val id: String, val name: String)
data class Config(val setting: String)
