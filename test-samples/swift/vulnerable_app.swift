// ============================================================================
// Offensive360 Swift SAST Scanner - Comprehensive Test Samples
// This file contains intentionally vulnerable Swift code for testing
// ALL 20 vulnerability categories of the scanner.
// ============================================================================

import Foundation
import UIKit
import WebKit
import Security
import LocalAuthentication
import JavaScriptCore
import CommonCrypto
import CryptoKit
import CoreData
import SwiftUI

// ============================================================================
// 1. SQL Injection
// ============================================================================

class DatabaseManager {
    var db: OpaquePointer?

    func getUserById(id: String) -> String? {
        // VULN: SQL injection via string interpolation
        let query = "SELECT * FROM users WHERE id = '\(id)'"
        db?.execute(query)
        return nil
    }

    func searchUsers(name: String) {
        // VULN: SQL injection via concatenation
        let query = "SELECT * FROM users WHERE name = '" + name + "'"
        database.execute(query)
    }

    func fetchWithPredicate(userInput: String) {
        // VULN: NSPredicate format string injection
        let predicate = NSPredicate(format: "name == %@", userInput)
        let unsafePredicate = NSPredicate(format: "name == '\(userInput)'")
    }

    func rawQuery(userId: String) {
        // VULN: Raw query with interpolation
        let result = raw("SELECT email FROM accounts WHERE user_id = \(userId)")
    }
}

// ============================================================================
// 2. Command Injection
// ============================================================================

class CommandRunner {
    func runCommand(userCommand: String) {
        // VULN: Process creation
        let process = Process()

        // VULN: Dynamic launch path from user input
        process.launchPath = "/bin/\(userInput)"

        // VULN: Arguments from user input
        process.arguments = ["-c", "\(userInput)"]
        process.launch()
    }

    func executeShell(input: String) {
        // VULN: system() with dynamic args
        system("ls -la \(input)")
    }
}

// ============================================================================
// 3. Code Injection
// ============================================================================

class ScriptRunner {
    func evaluateUserScript(script: String) {
        // VULN: JavaScript evaluation with user input
        let context = JSContext()!
        context.evaluateScript("var result = \(script)")
    }

    func dynamicExpression(userFormula: String) {
        // VULN: NSExpression with user input
        let expr = NSExpression(format: "price * \(userFormula)")
    }
}

// ============================================================================
// 4. XSS (Cross-Site Scripting)
// ============================================================================

class WebViewManager: UIViewController {
    var webView: WKWebView!

    func loadUserContent(htmlContent: String) {
        // VULN: Loading raw HTML string in WebView
        webView.loadHTMLString(htmlContent, baseURL: nil)
    }

    func legacyWebView() {
        // VULN: Deprecated UIWebView
        let oldWebView = UIWebView(frame: .zero)
    }

    func executeJS(userData: String) {
        // VULN: evaluateJavaScript with interpolated data
        webView.evaluateJavaScript("document.getElementById('name').innerHTML = '\(userData)'")
    }
}

// ============================================================================
// 5. Path Traversal
// ============================================================================

class FileService {
    func readFile(userInput: String) {
        // VULN: FileManager with user-controlled path
        let data = FileManager.default.contents(atPath: "\(userInput)")

        // VULN: File read with user-controlled path
        let content = String(contentsOfFile: "/data/\(userInput)", encoding: .utf8)
    }

    func saveFile(name: String) {
        // VULN: Path construction with user input
        let url = documentsDir.appendingPathComponent("\(userInput)/file.txt")
    }
}

// ============================================================================
// 6. Insecure Data Storage
// ============================================================================

class StorageManager {
    func saveCredentials(password: String, token: String) {
        // VULN: Sensitive data in UserDefaults
        UserDefaults.standard.set(password, forKey: "userPassword")
        UserDefaults.standard.set(token, forKey: "authToken")

        // VULN: Generic UserDefaults usage
        UserDefaults.standard.set("some_value", forKey: "preference")
    }

    func keychainConfig() {
        // VULN: Keychain accessibility review
        let query: [String: Any] = [
            kSecAttrAccessible as String: kSecAttrAccessibleAlways
        ]
    }

    func writeToFile(data: Data) {
        // VULN: Unencrypted file write
        data.write(toFile: "/tmp/sensitive.plist", atomically: true)
    }

    func backupConfig() {
        // VULN: File included in backup
        var url = getDocumentsURL()
        url.isExcludedFromBackup = false
    }

    func coreDataUsage() {
        // VULN: Core Data without encryption check
        let container = NSPersistentContainer(name: "UserData")
        let context = NSManagedObjectContext(concurrencyType: .mainQueueConcurrencyType)
    }

    func disabledFileProtection() {
        // VULN: File protection disabled
        try? FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.none],
            ofItemAtPath: sensitiveFilePath
        )
    }
}

// ============================================================================
// 7. Insecure Communication
// ============================================================================

class NetworkManager {
    // VULN: ATS disabled in Info.plist representation
    let atsConfig = "NSAllowsArbitraryLoads = true"

    func makeRequest() {
        // VULN: Plaintext HTTP URL
        let url = URL(string: "http://api.example.com/users")!

        // VULN: Default URLSession
        URLSession.shared.dataTask(with: url) { data, response, error in
            // handle response
        }.resume()
    }

    func weakTLS() {
        // VULN: Weak TLS version
        let config = URLSessionConfiguration.default
        config.tlsMinimumSupportedProtocol = .tlsProtocol1
    }

    func customTrust() {
        // VULN: Insufficient certificate validation
        func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            let trust = challenge.protectionSpace.serverTrust
            completionHandler(.useCredential, URLCredential(trust: trust!))
        }
    }
}

// ============================================================================
// 8. Hardcoded Secrets
// ============================================================================

class ConfigManager {
    // VULN: Hardcoded API key
    let apiKey = "sk-ant-api03-45YuXUTYkq_Zwr97_L-oQNlIBuHcnGSEfUH2ii3p"
    let API_KEY: String = "AIzaSyD-FAKE-KEY-1234567890abcdef"

    // VULN: Hardcoded password/secret/token
    let password = "SuperSecretPassword123!"
    let secret = "my-app-secret-key-do-not-share"
    let authToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    let privateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKg"

    // VULN: Known secret patterns
    let githubToken = "ghp_FAKE_TOKEN_TEST_GITHUB_TOKEN_FOR_TESTING_123434"
    let awsKey = "AKIAIOSFODNN7EXAMPLE1"
    let slackToken = "xoxb-FAKE-TEST-TOKEN"

    // VULN: Database connection string with credentials
    let mongoUrl = "mongodb://admin:password123@db.example.com:27017/mydb"
    let postgresUrl = "postgresql://user:pass@host:5432/db"
}

// ============================================================================
// 9. Weak Cryptography
// ============================================================================

class CryptoManager {
    func hashPassword(password: String) {
        let data = password.data(using: .utf8)!

        // VULN: MD5 usage
        var md5Hash = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        CC_MD5(data.bytes, CC_LONG(data.count), &md5Hash)

        // Also via Insecure namespace
        let digest = Insecure.MD5.hash(data: data)
    }

    func hashToken(token: String) {
        // VULN: SHA-1 usage
        let data = token.data(using: .utf8)!
        var sha1Hash = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        CC_SHA1(data.bytes, CC_LONG(data.count), &sha1Hash)
    }

    func encryptData(plaintext: Data, key: Data) {
        // VULN: DES / deprecated crypto
        var encrypted = [UInt8](repeating: 0, count: plaintext.count + kCCBlockSizeDES)
        CCCrypt(kCCEncrypt, kCCAlgorithmDES, kCCOptionPKCS7Padding,
                key.bytes, key.count, nil,
                plaintext.bytes, plaintext.count,
                &encrypted, encrypted.count, nil)
    }

    func ecbMode() {
        // VULN: ECB mode
        let options = kCCOptionECBMode | kCCOptionPKCS7Padding
    }

    func smallKeySize() {
        // VULN: Weak key size
        let keySize = 128
    }
}

// ============================================================================
// 10. Insecure Random
// ============================================================================

class TokenGenerator {
    func generateToken() -> UInt32 {
        // VULN: Non-cryptographic random
        return arc4random()
    }

    func generateId() -> UInt32 {
        // VULN: arc4random_uniform
        return arc4random_uniform(1000000)
    }

    func legacyRandom() {
        // VULN: C random functions
        srand(UInt32(time(nil)))
        let value = rand()
    }
}

// ============================================================================
// 11. iOS-specific Vulnerabilities
// ============================================================================

class iOSSecurityIssues {
    func pasteboardLeak(sensitiveData: String) {
        // VULN: General pasteboard exposure
        UIPasteboard.general.string = sensitiveData
    }

    func urlSchemeHandling() {
        // VULN: URL scheme potential hijacking
        UIApplication.shared.canOpenURL(URL(string: "myapp://callback")!)
    }

    func keyboardCaching() {
        let textField = UITextField()
        // VULN: Autocorrection enabled on sensitive field
        textField.autocorrectionType = .yes
    }

    func secureTextField() {
        let passwordField = UITextField()
        // VULN: Secure text entry disabled
        passwordField.isSecureTextEntry = false
    }

    func jailbreakCheck() {
        // INFO: Jailbreak detection
        let isJailbroken = FileManager.default.fileExists(atPath: "/Applications/Cydia.app")
    }

    func webViewConfig() {
        let webView = WKWebView()
        // VULN: Permissive WebView config
        webView.allowsBackForwardNavigationGestures = true
    }

    func backgroundSnapshot() {
        // VULN: No background snapshot protection
        func applicationDidEnterBackground(_ application: UIApplication) {
            // Missing blur overlay
        }
    }

    func deepLinkHandler() {
        // VULN: Deep link handler
        func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
            handleDeepLink(url)
            return true
        }
    }
}

// ============================================================================
// 12. SwiftUI-specific
// ============================================================================

struct SecureView: View {
    // VULN: EnvironmentObject injection
    @EnvironmentObject var authManager: AuthManager

    // VULN: Sensitive binding
    @Binding var password: String
    @Binding var secretToken: String

    var body: some View {
        Text("Secure View")
    }
}

// ============================================================================
// 13. Vapor (Server-Side Swift)
// ============================================================================

class VaporApp {
    func configureRoutes() {
        // VULN: CORS allows all origins
        app.middleware.use(CORSMiddleware(configuration: .init(allowedOrigin: .all)))
    }

    func handleRequest(req: Request) {
        // VULN: Direct request input access
        let name = req.query["name"]
        let data = req.content["data"]
    }
}

// ============================================================================
// 14. Network Security
// ============================================================================

class NetworkSecurityConfig {
    // VULN: ATS exception for insecure HTTP
    let exception = "NSExceptionAllowsInsecureHTTPLoads = true"

    // VULN: Weak TLS exception
    let tlsException = "NSTemporaryExceptionMinimumTLSVersion = 1.0"
}

// ============================================================================
// 15. Biometric Authentication Bypass
// ============================================================================

class BiometricAuth {
    func authenticate() {
        // VULN: LAContext usage
        let context = LAContext()

        // VULN: Passcode fallback allowed
        context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)

        // VULN: Client-side only biometric check
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Authenticate") { success, error in
            if success {
                DispatchQueue.main.async {
                    self.unlockApp()
                }
            }
        }
    }
}

// ============================================================================
// 16. Force Unwrap / Crash Risk
// ============================================================================

class CrashRiskExamples {
    func forceTryExample() {
        // VULN: Force try
        let data = try! Data(contentsOf: url)

        // VULN: Force cast
        let viewController = storyboard.instantiateViewController(withIdentifier: "Main") as! MainViewController
    }

    func forceUnwrap() {
        let url: URL? = URL(string: "https://example.com")
        // VULN: Force unwrap
        let data = url!.absoluteString
        let dict: [String: Any]? = nil
        let value = dict!["key"]
    }

    func fatalErrors() {
        // VULN: fatalError usage
        guard let config = loadConfig() else {
            fatalError("Config not found")
        }

        preconditionFailure("Unexpected state")
    }
}

// ============================================================================
// 17. Memory Management
// ============================================================================

class MemoryIssues {
    var completionHandler: (() -> Void)?

    func setupTimer() {
        // VULN: Retain cycle - strong self in closure
        Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { _ in
            self.updateUI()
        }
    }

    func asyncOperation() {
        // VULN: unowned self - crash risk
        performAsync { [unowned self] in
            self.handleResult()
        }
    }
}

// ============================================================================
// 18. JWT Issues
// ============================================================================

class JWTHandler {
    // VULN: Hardcoded JWT
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."

    func validateToken(token: String) {
        // VULN: None algorithm accepted
        let decoded = decode(jwt: token, algorithm: "none")
    }
}

// ============================================================================
// 19. Logging Sensitive Data
// ============================================================================

class LoggingIssues {
    func logCredentials(password: String, token: String) {
        // VULN: Sensitive data in logs
        NSLog("User password: %@", password)
        print("Auth token: \(token)")

        // VULN: NSLog in production
        NSLog("Request completed with status: %d", statusCode)
    }
}

// ============================================================================
// 20. Binary/Misc Security
// ============================================================================

class MiscSecurity {
    func debugSecrets() {
        // VULN: Secrets in DEBUG block
        #if DEBUG
        let adminPassword = "debug_admin_123"
        let testApiKey = "test-key-12345"
        #endif
    }

    func sslDisabled() {
        // VULN: SSL verification disabled
        let config = SSLPinningDisable()
    }

    func unsafeMemory() {
        // VULN: Unsafe pointer operations
        let ptr = UnsafeMutablePointer<Int>.allocate(capacity: 10)
        let raw = UnsafeRawPointer(ptr)
    }

    func emptyErrorHandling() {
        // VULN: Empty catch block
        do {
            try riskyOperation()
        } catch {
            return
        }
    }

    func webViewBridge() {
        // VULN: JavaScript bridge
        let contentController = WKUserContentController()
        contentController.add(self, name: "nativeBridge")
    }

    func insecureDeserialization() {
        // VULN: NSKeyedUnarchiver without secure coding
        let object = NSKeyedUnarchiver.unarchiveObject(with: data)

        // VULN: Secure coding disabled
        let unarchiver = NSKeyedUnarchiver(forReadingFrom: data)
        unarchiver.requiresSecureCoding = false
    }
}

// ============================================================================
// Security-sensitive class for AST analysis
// ============================================================================

class UserCredentialManager {
    var username: String = ""
    var encryptedPassword: Data?

    func login(user: String, pass: String) {
        // This function should trigger AST analysis for missing error handling
        username = user
    }

    func validateSession() {
        // This function should also trigger
        let isValid = checkToken()
    }
}

// String with embedded secrets for AST string analysis
let configString = "password: admin123"
let connectionInfo = "api_key: sk-test-12345"
let pemKey = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhki..."
