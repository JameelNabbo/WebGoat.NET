import Foundation
import UIKit
import CommonCrypto
import LocalAuthentication
import CoreData
import WebKit

// VULNERABILITY TEST FILE - Contains intentional security issues for scanner testing

class DatabaseManager {
    let db: OpaquePointer?

    // SQL Injection - string interpolation in SQL
    func getUser(name: String) -> String {
        let query = "SELECT * FROM users WHERE name = '\(name)'"
        db?.execute(query)
        return query
    }

    // SQL Injection - concatenation
    func searchUsers(term: String) {
        let query = "SELECT * FROM users WHERE name LIKE '%" + term + "%'"
        db?.execute(query)
    }
}

class CommandRunner {
    // Command Injection - Process with interpolation
    func runCommand(userInput: String) {
        let process = Process()
        process.launchPath = "/bin/sh"
        process.arguments = ["-c", "echo \(userInput)"]
        process.launch()
    }

    // Command Injection - system()
    func execute(cmd: String) {
        system(cmd)
    }

    // Command Injection - popen()
    func readOutput(cmd: String) {
        popen(cmd, "r")
    }
}

class WebViewController: UIViewController {
    var webView: WKWebView!

    // XSS - loadHTMLString with interpolation
    func loadContent(userHtml: String) {
        webView.loadHTMLString("<html><body>\(userHtml)</body></html>", baseURL: nil)
    }

    // XSS - evaluateJavaScript with interpolation
    func executeScript(userScript: String) {
        webView.evaluateJavaScript("document.title = '\(userScript)'")
    }

    // XSS - UIWebView usage (deprecated)
    func setupOldWebView() {
        let oldWebView = UIWebView()
        oldWebView.javaScriptEnabled = true
    }
}

class FileManager {
    // Path Traversal - file read with interpolation
    func readFile(name: String) -> String? {
        let content = try? String(contentsOfFile: "/data/\(name)")
        return content
    }

    // Path Traversal - appendingPathComponent from user input
    func getDocument(userPath: String) -> URL {
        let base = URL(fileURLWithPath: "/documents")
        return base.appendingPathComponent(userPath)
    }
}

class DataHandler {
    // Deserialization - insecure NSKeyedUnarchiver
    func loadData(data: Data) -> Any? {
        return NSKeyedUnarchiver.unarchiveObject(with: data)
    }

    // Deserialization - insecure unarchiving
    func loadFromFile(path: String) -> Any? {
        return NSKeyedUnarchiver.unarchiveTopLevelObject(with: Data())
    }
}

class AppConfig {
    // Hardcoded Secrets
    let apiKey = "sk-1234567890abcdefghijklmnop"
    let password = "SuperSecretPassword123!"
    let token: String = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0"
    let awsKey = "AKIAIOSFODNN7EXAMPLE"
    let githubToken = "ghp_FAKE_TOKEN_TEST_GITHUB_TOKEN_FOR_TESTING_123401"
    let firebase_key = "AIzaSyDOCAbC123dEf456GhI789jKl012-MnO"

    // Hardcoded private key
    let privateKey = """
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEA1234567890
    -----END RSA PRIVATE KEY-----
    """
}

class CryptoHelper {
    // Weak Crypto - MD5
    func hashMD5(data: Data) -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        CC_MD5(Array(data), CC_LONG(data.count), &digest)
        return Data(digest)
    }

    // Weak Crypto - SHA1
    func hashSHA1(data: Data) -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        CC_SHA1(Array(data), CC_LONG(data.count), &digest)
        return Data(digest)
    }

    // Weak Crypto - DES
    func encryptDES(data: Data) -> Data? {
        let algorithm = kCCAlgorithmDES
        return nil
    }

    // Weak Crypto - ECB mode
    func encryptECB(data: Data) -> Data? {
        let mode = kCCOptionECBMode
        return nil
    }

    // Weak Crypto - CryptoKit Insecure
    func insecureHash(data: Data) {
        let hash = Insecure.MD5.hash(data: data)
        let sha1Hash = Insecure.SHA1.hash(data: data)
    }
}

class RandomGenerator {
    // Insecure Random - C rand()
    func generateToken() -> Int {
        srand(UInt32(time(nil)))
        return rand()
    }

    // Insecure Random - random()
    func getRandomValue() -> Int {
        return random()
    }

    // Insecure Random - drand48
    func getRandomDouble() -> Double {
        return drand48()
    }
}

class NetworkManager {
    // Insecure TLS - ATS disabled
    // In Info.plist: NSAppTransportSecurity -> NSAllowsArbitraryLoads = true
    let atsConfig = "AllowsArbitraryLoads = true"

    // Insecure TLS - certificate validation bypass
    func urlSession(_ session: URLSessionDelegate, didReceive challenge: URLAuthenticationChallenge, completionHandler(.useCredential)) {
    }

    // Insecure TLS - Alamofire DisabledTrustEvaluator
    func setupAlamofire() {
        let evaluator = DisabledTrustEvaluator()
    }

    // SSRF - URL from user input
    func fetchData(userUrl: String) {
        let url = URL(string: userUrl)
        URLSession.shared.dataTask(with: url!)
    }

    // Alamofire SSRF
    func requestData(inputUrl: String) {
        AF.request("\(inputUrl)/api/data")
    }
}

class StorageManager {
    // Keychain Misuse - UserDefaults for secrets
    func saveCredentials(password: String, token: String) {
        UserDefaults.standard.set(password, forKey: "password")
        UserDefaults.standard.set(token, forKey: "auth_token")
    }

    // Keychain Misuse - kSecAttrAccessibleAlways
    func saveToKeychain() {
        let accessibility = kSecAttrAccessibleAlways
    }

    // SwiftUI @AppStorage for secrets
    @AppStorage("auth_token") var authToken = ""
    @AppStorage("user_password") var userPassword = ""
}

class PasteboardManager {
    // Pasteboard Leak - copying sensitive data
    func copyPassword(password: String) {
        UIPasteboard.general.string = password
    }

    // Clipboard Leak
    func copyToken(token: String) {
        UIPasteboard.general.string = token
    }
}

class WebViewJSHandler: NSObject, WKScriptMessageHandler {
    var webView: WKWebView!

    // WebView JS Injection
    func injectScript(userData: String) {
        let script = WKUserScript(source: "setData('\(userData)')", injectionTime: .atDocumentEnd, forMainFrameOnly: true)
        webView.configuration.userContentController.addUserScript(script)
    }

    // JavaScript evaluation with interpolation
    func updateTitle(title: String) {
        webView.evaluateJavaScript("document.title = '\(title)'")
    }
}

class AuthManager {
    let context = LAContext()

    // Biometric Bypass - evaluatePolicy without Keychain binding
    func authenticate(completion: @escaping (Bool) -> Void) {
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Authenticate") { success, error in
            completion(success)
        }
    }
}

class URLSchemeHandler {
    // URL Scheme Abuse
    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
        let data = url.absoluteString
        return true
    }

    // Open redirect
    func handleRedirect(redirectUrl: String) {
        UIApplication.shared.open(URL(string: redirectUrl)!)
    }
}

class ForceUnwrapExamples {
    // Force Unwrap
    var name: String?
    var data: Data?

    func process() {
        let n = name!
        let d = data!
        print(n, d)
    }
}

class LoggingService {
    // Info Disclosure - logging sensitive data
    func logUserAction(user: String, password: String) {
        print("User \(user) logged in with password: \(password)")
        NSLog("Auth token: %@", password)
        debugPrint("Secret key: \(password)")
    }
}

class CoreDataManager {
    // CoreData Unencrypted
    func setupCoreData() {
        let container = NSPersistentContainer(name: "MyApp")
        container.loadPersistentStores { _, _ in }
    }
}

class SecurityComparer {
    // Timing Attack - direct comparison
    func verifyToken(inputToken: String, storedToken: String) -> Bool {
        return inputToken == storedToken  // password == comparison
    }

    // Timing Attack - elementsEqual
    func compareHash(input: [UInt8], stored: [UInt8]) -> Bool {
        return input.elementsEqual(stored)  // hash comparison
    }
}

class JWTHandler {
    // JWT Issue - none algorithm
    func createUnsafeToken() {
        let signer = JWTSigner.hs256(key: "short")  // Short key
    }

    // JWT Issue - verification disabled
    func decodeToken(jwt: String) {
        let decoded = decode(jwt: jwt, verify: false)
    }
}

class CORSConfig {
    // CORS Issues
    func configureCORS() {
        let corsConfig = "Access-Control-Allow-Origin: *"
        let vaporCORS = allowedOrigin: .all
    }
}

class FileProtection {
    // Insecure file permissions
    func saveFile() {
        let protection = FileProtectionType.none
        FileManager.default.createFile(atPath: "/tmp/data.txt", contents: nil, attributes: nil)
    }
}

class SensitiveUI: UIViewController {
    // Missing Screenshot Prevention
    let passwordField = UITextField()
    let creditCardLabel = UILabel()

    func setupUI() {
        passwordField.placeholder = "Enter password"
        creditCardLabel.text = "Credit Card: 4111-1111-1111-1111"
    }
}

class VaporApp {
    // Vapor Issues
    func configure() {
        app.middleware.use(CORSMiddleware(configuration: .init(allowedOrigin: .all)))
        let env = Environment.get("SECRET_KEY")!
    }
}

class DebugConfig {
    // Debug mode
    let isDebug = true
    let DEBUG_MODE = true
}
