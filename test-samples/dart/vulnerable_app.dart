import 'dart:io';
import 'dart:math';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:sqflite/sqflite.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'package:crypto/crypto.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:hive/hive.dart';
import 'package:provider/provider.dart';
import 'package:firebase_core/firebase_core.dart';

// VULNERABILITY TEST FILE - Contains intentional security issues for scanner testing

// ─── Hardcoded Secrets ───
const String apiKey = "sk-1234567890abcdefghijklmnopqrs";
const String password = "MyHardcodedPassword2026!";
const String awsKey = "AKIAIOSFODNN7EXAMPLE";
const String githubToken = "ghp_FAKE_TOKEN_TEST_GITHUB_TOKEN_FOR_TESTING_123401";
const String firebase_key = "AIzaSyDOCAbC123dEf456GhI789jKl012-MnO";
const String privateKey = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890
-----END RSA PRIVATE KEY-----
""";
const authToken = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123def456";

class DatabaseService {
  late Database db;

  // SQL Injection - rawQuery with interpolation
  Future<List<Map>> getUser(String name) async {
    return await db.rawQuery("SELECT * FROM users WHERE name = '$name'");
  }

  // SQL Injection - rawInsert with interpolation
  Future<int> insertUser(String name, String email) async {
    return await db.rawInsert("INSERT INTO users (name, email) VALUES ('$name', '$email')");
  }

  // SQL Injection - rawUpdate with interpolation
  Future<int> updateUser(String id, String name) async {
    return await db.rawUpdate("UPDATE users SET name = '$name' WHERE id = $id");
  }

  // SQL Injection - rawDelete with concatenation
  Future<int> deleteUser(String id) async {
    return await db.rawDelete("DELETE FROM users WHERE id = " + id);
  }
}

class CommandService {
  // Command Injection - Process.run with interpolation
  Future<ProcessResult> executeCommand(String userInput) async {
    return await Process.run('/bin/sh', ['-c', 'echo $userInput']);
  }

  // Command Injection - Process.start with user input
  Future<Process> startProcess(String requestParam) async {
    return await Process.start('/bin/sh', ['-c', requestParam]);
  }

  // Command Injection - Process.runSync
  ProcessResult runSync(String cmd) {
    return Process.runSync('/bin/sh', ['-c', '$cmd']);
  }
}

class WebViewService extends StatelessWidget {
  final String userContent;

  const WebViewService({required this.userContent});

  @override
  Widget build(BuildContext context) {
    return WebView(
      initialUrl: 'http://example.com/$userContent',
      javascriptMode: JavascriptMode.unrestricted,
      onWebViewCreated: (controller) {
        controller.runJavascript("document.title = '$userContent'");
      },
    );
  }

  // XSS - loadHtmlString with interpolation
  void loadContent(WebViewController controller, String htmlContent) {
    controller.loadHtmlString('<html><body>$htmlContent</body></html>');
  }

  // XSS - flutter_html with interpolation
  Widget renderHtml(String userHtml) {
    return Html(data: '<div>$userHtml</div>');
  }
}

class FileService {
  // Path Traversal - File with user-controlled path
  Future<String> readUserFile(String userPath) async {
    final file = File('/data/$userPath');
    return await file.readAsString();
  }

  // Path Traversal - Directory with interpolation
  Future<List<FileSystemEntity>> listDir(String inputDir) async {
    final dir = Directory('/uploads/$inputDir');
    return dir.listSync();
  }

  // Path Traversal - path join with user input
  String buildPath(String userInput) {
    return path.join('/base', userInput);
  }
}

class CryptoService {
  // Weak Crypto - MD5
  String hashMD5(String data) {
    return md5.convert(utf8.encode(data)).toString();
  }

  // Weak Crypto - SHA1
  String hashSHA1(String data) {
    return sha1.convert(utf8.encode(data)).toString();
  }

  // Weak Crypto - HMAC-MD5
  String hmacMD5(String data, String key) {
    var hmac = Hmac(md5, utf8.encode(key));
    return hmac.convert(utf8.encode(data)).toString();
  }
}

class RandomService {
  // Insecure Random - math.Random without secure
  String generateToken() {
    final random = Random();
    return List.generate(32, (_) => random.nextInt(256).toRadixString(16)).join();
  }

  // Insecure Random - seeded Random
  int getSeededRandom() {
    final random = Random(42);
    return random.nextInt(1000);
  }
}

class NetworkService {
  // Insecure HTTP
  Future<http.Response> fetchData() async {
    return await http.get(Uri.parse('http://api.example.com/data'));
  }

  // Certificate pinning bypass
  HttpClient createInsecureClient() {
    final client = HttpClient();
    client.badCertificateCallback = (cert, host, port) => true;
    return client;
  }

  // SSRF - HTTP GET with user URL
  Future<http.Response> proxyRequest(String userUrl) async {
    return await http.get(Uri.parse(userUrl));
  }

  // Open redirect
  void handleRedirect(String redirectUrl) {
    launchUrl(Uri.parse(redirectUrl));
  }
}

class StorageService {
  // SharedPreferences - storing secrets
  Future<void> saveCredentials(String password, String token) async {
    final prefs = await SharedPreferences.getInstance();
    prefs.setString('password', password);
    prefs.setString('auth_token', token);
  }

  // Hive - unencrypted sensitive data
  void saveToHive(String token) {
    final box = Hive.box('settings');
    box.put('auth_token', token);  // Hive.box with secret/token
  }

  // Insecure local storage - sqflite with sensitive data
  void saveToDB(Database db, String password) {
    db.insert('users', {'password': password});  // sqflite with password/token
  }
}

class WebViewConfig extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return WebView(
      javascriptMode: JavascriptMode.unrestricted,
      onWebViewCreated: (controller) {
        // JavaScript channel
        controller.addJavaScriptChannel('AppBridge',
          onMessageReceived: (JavaScriptMessage message) {
            handleMessage(message.message);
          },
        );
      },
    );
  }

  void handleMessage(String msg) {}
}

class DeepLinkService {
  // Deep Link - getInitialLink
  Future<void> handleDeepLink() async {
    final link = await getInitialLink();
    final uri = Uri.parse(link!);
    final params = uri.queryParameters;
    navigateTo(params['page']!);
  }

  // Deep link stream
  void listenForLinks() {
    linkStream.listen((String? link) {
      handleLink(link!);
    });
  }

  void navigateTo(String page) {}
  void handleLink(String link) {}
}

class FirebaseService {
  // Firebase - Firestore write (check rules)
  void saveData(String userId, Map<String, dynamic> data) {
    FirebaseFirestore.instance.collection('users').doc(userId).set(data);
  }

  // Firebase - config in code
  static const firebaseConfig = {
    'apiKey': 'AIzaSyDOCAbC123dEf456GhI789jKl012-MnO',
  };
}

class NullSafetyBypasses {
  String? name;
  int? age;
  List<String>? items;

  // Null safety bypass with !
  void process() {
    final n = name!;
    final a = age!;
    final first = items!.first;
    print('$n $a $first');
  }
}

class AuthService {
  // Timing Attack - direct comparison
  bool verifyToken(String inputToken, String storedToken) {
    return inputToken == storedToken;  // token == comparison
  }

  // Timing Attack - compareTo
  bool compareSecret(String input, String secret) {
    return input.compareTo(secret) == 0;  // secret comparison
  }
}

class JWTService {
  // JWT - verification disabled
  Map<String, dynamic> decodeToken(String jwt) {
    return JwtDecoder.decode(jwt);  // jwt decoded without verify
  }

  // JWT - none algorithm
  String createToken() {
    return JWT({'sub': 'user'}).sign(algorithm: 'none');
  }

  // JWT - short secret
  void signToken() {
    final jwt = JWT({'sub': 'user'});
    jwt.sign(SecretKey('short'));  // dart_jsonwebtoken SecretKey with short key
  }
}

class StateManagement extends ChangeNotifier {
  // Provider state leak - ChangeNotifier with secrets
  String _authToken = '';
  String _password = '';

  String get authToken => _authToken;  // password/secret/token exposed

  void setCredentials(String token, String password) {
    _authToken = token;
    _password = password;
    notifyListeners();
  }
}

class IsolateService {
  // Isolate - sending sensitive data
  void processInBackground(String token) {
    Isolate.spawn(backgroundTask, token);  // Isolate with token/secret
  }

  // compute with sensitive data
  Future<String> hashPassword(String password) async {
    return await compute(doHash, password);  // compute with password
  }

  static String backgroundTask(String data) => data;
  static String doHash(String data) => data;
}

class PlatformChannelService {
  // Platform channel sending secrets
  void sendToken(String token) {
    const channel = MethodChannel('com.app/auth');
    channel.invokeMethod('setToken', {'token': token});  // MethodChannel with token/key
  }

  // Platform channel executing commands
  void executeNative(String command) {
    const channel = MethodChannel('com.app/system');
    channel.invokeMethod('execute', {'command': command});
  }
}

class LoggingService {
  // Logging sensitive data
  void logAuth(String password, String token) {
    print('User password: $password');
    debugPrint('Auth token: $token');
    print('Secret key: $token');
  }
}

class DebugConfig {
  // Debug mode
  static const isDebug = true;
  void checkMode() {
    if (kDebugMode ?? true) {
      debugPrint('Debug password: secret123');
    }
  }

  // Debug banner
  Widget build() {
    return MaterialApp(
      debugShowCheckedModeBanner: true,
    );
  }
}

class InputValidation {
  // Missing input validation - URI query params
  void handleRequest(Uri uri) {
    final value = uri.queryParameters['action'];
    executeAction(value!);
  }

  void executeAction(String action) {}
}

class FileUploadService {
  // Unvalidated file upload
  Future<void> uploadFile(String filePath) async {
    final file = await MultipartFile.fromPath('file', filePath);
    // No type validation
  }
}
