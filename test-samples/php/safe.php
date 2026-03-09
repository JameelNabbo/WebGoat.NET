<?php
/**
 * SAST Test Sample: Secure PHP Code Patterns
 * 
 * This file contains secure implementations that should NOT trigger
 * many vulnerabilities (some informational ones are expected).
 */

// Secure SQL with prepared statements
function getUser_secure(PDO $pdo) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
    $stmt->execute([':id' => $_GET['id']]);
    return $stmt->fetch();
}

// Secure command execution with escapeshellarg
function ping_secure() {
    $host = escapeshellarg($_GET['host']);
    $output = [];
    exec("ping -c 3 " . $host, $output);
    return $output;
}

// Secure XSS with htmlspecialchars
function displaySearch_secure() {
    $query = htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');
    echo "Search results for: " . $query;
}

// Secure file operations with basename and realpath
function readFile_secure() {
    $filename = basename($_GET['file']);
    $path = realpath('/var/www/uploads/' . $filename);
    if ($path && str_starts_with($path, '/var/www/uploads/')) {
        return file_get_contents($path);
    }
    return false;
}

// Secure password hashing
function hashPassword_secure($password) {
    return password_hash($password, PASSWORD_ARGON2ID);
}

// Secure password verification
function verifyPassword_secure($input, $hash) {
    return password_verify($input, $hash);
}

// Secure random token
function generateToken_secure() {
    return bin2hex(random_bytes(32));
}

// Secure session start
function startSession_secure() {
    session_start([
        'cookie_httponly' => true,
        'cookie_secure' => true,
        'use_strict_mode' => true,
        'cookie_samesite' => 'Strict',
    ]);
}

// Secure cookie
function setCookie_secure() {
    setcookie('session', 'value', [
        'expires' => time() + 3600,
        'path' => '/',
        'domain' => '.example.com',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}

// Secure hash comparison
function verifyHash_secure($input, $expected) {
    return hash_equals($expected, hash('sha256', $input));
}

// Secure email with validation
function sendEmail_secure() {
    $to = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
    if (!$to) {
        throw new \InvalidArgumentException('Invalid email');
    }
    // Use PHPMailer in production
    mail($to, 'Subject', 'Message');
}

// Secure WordPress query
function wp_secure_query() {
    global $wpdb;
    $id = absint($_GET['id']);
    $results = $wpdb->query($wpdb->prepare("SELECT * FROM wp_posts WHERE ID = %d", $id));
    return $results;
}

// Strict comparison for token
function verifyApiKey_secure($input, $stored) {
    return hash_equals($stored, $input);
}

// Secure redirect with whitelist
function redirect_secure() {
    $allowedPaths = ['/dashboard', '/profile', '/settings'];
    $path = $_GET['redirect'];
    if (in_array($path, $allowedPaths, true)) {
        header("Location: " . $path);
    }
}

// Secure JSON deserialization (json_decode instead of unserialize)
function loadPreferences() {
    $data = $_COOKIE['prefs'];
    $prefs = json_decode($data, true);
    return $prefs;
}
