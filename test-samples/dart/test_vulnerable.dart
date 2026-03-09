// vulnerable_app.dart
// Intentionally vulnerable Dart/Flutter code for SAST scanner testing

import 'dart:io';
import 'dart:convert';
import 'dart:math';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:sqflite/sqflite.dart';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:flutter_html/flutter_html.dart';
import 'package:uni_links/uni_links.dart';

// Hardcoded Secrets
const String apiKey = "sk-live-abc123def456ghi789jkl012mno345pqr678";
const String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
final String password = "SuperSecretP@ssw0rd123!";
final String clientSecret = "cs_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";

// SQL Injection
class DatabaseHelper {
  late Database db;

  Future<List<Map>> searchUser(String userInput) async {
    // SQL injection via rawQuery with string interpolation
    return await db.rawQuery('SELECT * FROM users WHERE name = "$userInput"');
  }

  Future<int> deleteUser(String userId) async {
    // SQL injection via rawDelete with concatenation
    return await db.rawDelete('DELETE FROM users WHERE id = ' + userId);
  }

  Future<void> insertLog(String message) async {
    await db.execute("INSERT INTO logs (msg) VALUES ('$message')");
  }
}

// Command Injection
class SystemUtils {
  Future<String> runCommand(String input) async {
    // Command injection via Process.run with user input
    var result = await Process.run('/bin/sh', ['-c', input]);
    return result.stdout;
  }

  void startProcess(String command) {
    // Command injection via Process.start
    Process.start('/bin/bash', ['-c', command]);
  }
}

// XSS via Html widget
class ContentPage extends StatelessWidget {
  final String userInput;
  const ContentPage({required this.userInput});

  @override
  Widget build(BuildContext context) {
    return Html(data: userInput);  // XSS: renders user HTML without sanitization
  }
}

// XSS via WebView JavaScript
class WebViewPage extends StatefulWidget {
  @override
  _WebViewPageState createState() => _WebViewPageState();
}

class _WebViewPageState extends State<WebViewPage> {
  late WebViewController controller;

  void executeUserScript(String userInput) {
    // XSS via evaluateJavascript with user input
    controller.runJavascript('document.title = "$userInput"');
  }

  @override
  Widget build(BuildContext context) {
    return WebView(
      initialUrl: 'https://example.com',
      javascriptMode: JavascriptMode.unrestricted,  // JS enabled
    );
  }
}

// Path Traversal
class FileManager {
  Future<String> readFile(String filename) async {
    // Path traversal: user-controlled filename
    var file = File('/data/uploads/$filename');
    return await file.readAsString();
  }

  Future<void> saveFile(String path, String content) async {
    var file = File(path);
    await file.writeAsString(content);
  }
}

// Insecure Data Storage
class AuthService {
  Future<void> saveCredentials(String token, String password) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('auth_token', token);        // Sensitive in SharedPreferences
    await prefs.setString('user_password', password);   // Password in SharedPreferences
  }

  Future<void> saveToFile(String secretKey) async {
    var file = File('/data/secrets.json');
    await file.writeAsString(jsonEncode({'secretKey': secretKey}));
  }
}

// Insecure Communication
class ApiClient {
  // Cleartext HTTP
  final String baseUrl = "http://api.example.com/v1";

  void configureClient() {
    // Disable certificate validation
    HttpClient client = HttpClient();
    client.badCertificateCallback = (cert, host, port) => true;
  }

  Future<String> fetchData(String endpoint) async {
    var client = HttpClient();
    // No cert pinning
    var request = await client.getUrl(Uri.parse('$baseUrl/$endpoint'));
    var response = await request.close();
    return await response.transform(utf8.decoder).join();
  }
}

// Weak Cryptography
class CryptoUtils {
  String hashPassword(String password) {
    // Weak hash: MD5
    var bytes = utf8.encode(password);
    var digest = md5.convert(bytes);
    return digest.toString();
  }

  String hashToken(String token) {
    // Weak hash: SHA-1
    var bytes = utf8.encode(token);
    var digest = sha1.convert(bytes);
    return digest.toString();
  }
}

// Insecure Random
class TokenGenerator {
  String generateToken() {
    // Insecure random
    var rng = Random();
    var values = List<int>.generate(32, (i) => rng.nextInt(256));
    return base64Url.encode(values);
  }

  String generateSecureToken() {
    // This is secure
    var rng = Random.secure();
    var values = List<int>.generate(32, (i) => rng.nextInt(256));
    return base64Url.encode(values);
  }
}

// Null Safety Bypass - excessive ! operator usage
class UserProfile {
  String? name;
  String? email;
  Map<String, dynamic>? data;
  List<String>? roles;

  String getDisplayName() {
    return name!;
  }

  String getEmail() {
    return email!;
  }

  int getRoleCount() {
    return roles!.length;
  }

  String getFirstRole() {
    return roles![0];
  }

  dynamic getData(String key) {
    return data![key]!;
  }

  String getNestedValue(String k1, String k2) {
    return (data![k1] as Map)[k2]!.toString();
  }

  bool hasPermission(String perm) {
    return roles!.contains(perm);
  }

  String getFormattedName() {
    return '${name!} <${email!}>';
  }

  int getDataLength() {
    return data!.length;
  }

  String getUpperName() {
    return name!.toUpperCase();
  }

  String getLowerEmail() {
    return email!.toLowerCase();
  }
}

// Insecure Deserialization
class DataProcessor {
  Map<String, dynamic> processResponse(String body) {
    // jsonDecode with untrusted response data
    return jsonDecode(body) as Map<String, dynamic>;
  }
}

// Information Disclosure
class Logger {
  void logLogin(String username, String password) {
    print('Login: user=$username, password=$password');
  }

  void logToken(String token) {
    debugPrint('Auth token: $token');
  }
}

// Flutter-specific: Deep link without validation
class DeepLinkHandler {
  void init() async {
    String? initialLink = await getInitialLink();
    if (initialLink != null) {
      // No validation of the deep link URL
      handleLink(initialLink);
    }
  }

  void handleLink(String url) {
    // Process without validation
  }
}

// Flutter-specific: Platform Channel
class NativeService {
  static const platform = MethodChannel('com.example/native');

  Future<String> getNativeData(String input) async {
    return await platform.invokeMethod('getData', {'input': input});
  }
}

// Firebase Security
class FirebaseConfig {
  static const String apiKey = "AIzaSyBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  static const String messagingSenderId = "123456789012";
  static const String appId = "1:123456789012:web:abcdef1234567890";
}

class FirestoreService {
  final firestore = Firestore.instance;

  Future<void> getData() async {
    var snapshot = await Firestore.instance.collection('users').get();
  }
}

// State Management Leaks
class AuthState extends ChangeNotifier {
  String? token;
  String? password;
  String? sessionId;

  void login(String t, String p) {
    token = t;
    password = p;  // Storing password in state
    notifyListeners();
  }
}

// Crypto Misuse
class EncryptionService {
  // Hardcoded IV
  final iv = IV.fromUtf8('1234567890123456');
  final key = Key.fromUtf8('my-secret-key-1234567890123456');

  // Weak PBKDF2 iterations
  void deriveKey(String password) {
    var pbkdf2 = PBKDF2(password: password, iterations: 1000);
  }
}

// Open Redirect
class NavigationService {
  void openExternalUrl(String url) async {
    // Open redirect: no URL validation
    await launchUrl(Uri.parse(url));
  }

  void openRedirect(String redirect) async {
    await launchUrlString(redirect);
  }
}

// Clipboard Leaks
class ClipboardManager {
  void copyToken(String token) {
    Clipboard.setData(ClipboardData(text: token));
  }
}

// Missing Input Validation
class LoginForm extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Column(children: [
      TextFormField(
        decoration: InputDecoration(labelText: 'Username'),
        // Missing validator
      ),
      TextField(
        decoration: InputDecoration(labelText: 'Password'),
        obscureText: true,
        // Missing validator
      ),
    ]);
  }
}

// Package Security - insecure URL
// url: http://pub.dartlang.org/packages/my_package

// Insecure Communication - more examples
class InsecureClient {
  final endpoints = [
    "http://payments.example.com/process",
    "http://auth.example.com/login",
  ];
}
