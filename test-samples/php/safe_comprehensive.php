<?php
/**
 * SAFE PHP TEST FILE
 * Demonstrates secure coding practices for comparison.
 */

namespace App\Controllers;

use App\Models\User;
use PDO;

// Safe: Prepared statements
function searchUsersSafe(PDO $pdo) {
    $name = filter_input(INPUT_GET, 'name', FILTER_SANITIZE_SPECIAL_CHARS);
    $stmt = $pdo->prepare("SELECT * FROM users WHERE name = :name");
    $stmt->execute(['name' => $name]);
    return $stmt->fetchAll();
}

// Safe: Escaped output
function displayUserSafe() {
    $name = htmlspecialchars($_GET['name'] ?? '', ENT_QUOTES, 'UTF-8');
    echo "Welcome, " . $name;
}

// Safe: Whitelisted includes
function loadPageSafe() {
    $allowed = ['home', 'about', 'contact'];
    $page = $_GET['page'] ?? 'home';
    if (in_array($page, $allowed)) {
        include("pages/{$page}.php");
    }
}

// Safe: escapeshellarg
function processFileSafe() {
    $filename = escapeshellarg($_GET['file'] ?? '');
    exec("convert " . $filename . " output.pdf", $output);
}

// Safe: password_hash
function hashPasswordSafe($password) {
    return password_hash($password, PASSWORD_BCRYPT);
}

// Safe: random_int
function generateTokenSafe() {
    return bin2hex(random_bytes(32));
}

// Safe: hash_equals
function verifyHashSafe($input, $storedHash) {
    return hash_equals($storedHash, hash('sha256', $input));
}

// Safe: Strict comparison
function checkTokenSafe($token, $expected) {
    return $token === $expected;
}

// Safe: CSRF token
function handleFormSafe() {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('CSRF token mismatch');
    }
    // Process form
}

// Safe: Session regeneration
function loginSafe($username, $password) {
    if (authenticate($username, $password)) {
        session_regenerate_id(true);
        $_SESSION['user'] = $username;
    }
}

// Safe: URL validation
function redirectSafe() {
    $allowed_hosts = ['example.com', 'www.example.com'];
    $url = $_GET['url'] ?? '/';
    $parsed = parse_url($url);
    if (isset($parsed['host']) && !in_array($parsed['host'], $allowed_hosts)) {
        $url = '/';
    }
    header("Location: " . $url);
}

// Safe: File permissions
function createFileSafe() {
    chmod("/var/www/uploads/data.txt", 0644);
}

// Safe: Validated input
function processOrderSafe() {
    $qty = filter_input(INPUT_POST, 'quantity', FILTER_VALIDATE_INT);
    $price = filter_input(INPUT_GET, 'price', FILTER_VALIDATE_FLOAT);
    if ($qty === false || $price === false) {
        throw new InvalidArgumentException("Invalid input");
    }
    $total = $qty * $price;
    insertOrder($total);
}

// Safe: JSON instead of unserialize
function loadCacheSafe() {
    $data = json_decode($_COOKIE['session_data'] ?? '{}', true);
    return $data;
}

// Safe: Environment variables for secrets
function getDbConfig() {
    return [
        'host' => getenv('DB_HOST'),
        'password' => getenv('DB_PASSWORD'),
        'api_key' => getenv('API_KEY'),
    ];
}

// Safe: XXE prevention
function parseXmlSafe($xmlString) {
    libxml_disable_entity_loader(true);
    $doc = new DOMDocument();
    $doc->loadXML($xmlString, LIBXML_NONET | LIBXML_DTDLOAD);
    return $doc;
}

// Safe: LDAP escape
function searchLdapSafe($conn, $username) {
    $safeUser = ldap_escape($username, '', LDAP_ESCAPE_FILTER);
    return ldap_search($conn, "dc=example,dc=com", "(uid=$safeUser)");
}

// Safe: Using PHPMailer
function sendMailSafe() {
    $to = filter_input(INPUT_POST, 'to', FILTER_VALIDATE_EMAIL);
    if (!$to) {
        throw new InvalidArgumentException("Invalid email");
    }
    // Use PHPMailer instead of mail()
}
