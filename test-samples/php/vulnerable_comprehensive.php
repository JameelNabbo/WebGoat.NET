<?php
/**
 * VULNERABLE PHP TEST FILE
 * Contains intentional vulnerabilities for testing the PHP SAST scanner.
 * DO NOT use this code in production!
 */

namespace App\Controllers;

use App\Models\User;
use App\Services\AuthService;

// ============================================================================
// 1. SQL Injection
// ============================================================================
function searchUsers($conn) {
    $name = $_GET['name'];
    // Vuln: Direct user input in SQL
    $result = mysql_query("SELECT * FROM users WHERE name = '" . $name . "'");

    // Vuln: mysqli with concatenation
    $id = $_POST['id'];
    mysqli_query($conn, "DELETE FROM users WHERE id = $id");

    // Vuln: PDO without prepared statement
    $email = $_REQUEST['email'];
    $pdo->query("SELECT * FROM users WHERE email = '$email'");

    // Vuln: pg_query with user input
    pg_query($conn, "SELECT * FROM orders WHERE user_id = " . $_GET['uid']);
}

// ============================================================================
// 2. Command Injection
// ============================================================================
function processFile() {
    $filename = $_GET['file'];
    // Vuln: exec with user input
    exec("convert " . $filename . " output.pdf", $output);

    // Vuln: system with user input
    system("ls -la " . $_POST['dir']);

    // Vuln: passthru
    passthru("grep " . $_GET['pattern'] . " /var/log/app.log");

    // Vuln: shell_exec
    $result = shell_exec("ping -c 4 " . $_REQUEST['host']);

    // Vuln: popen
    $handle = popen("sort " . $_GET['file'], "r");

    // Vuln: proc_open
    proc_open("php " . $_POST['script'], $descriptors, $pipes);
}

// ============================================================================
// 3. Code Injection
// ============================================================================
function dynamicCode() {
    // Vuln: eval with user input
    eval($_POST['code']);

    // Vuln: assert with user input
    assert($_GET['expr']);

    // Vuln: preg_replace with /e modifier
    $result = preg_replace('/(.*)/e', 'strtolower("\\1")', $input);

    // Vuln: create_function
    $func = create_function('$a', $_POST['body']);

    // Vuln: call_user_func with user input
    call_user_func($_GET['callback'], $data);
}

// ============================================================================
// 4. Cross-Site Scripting (XSS)
// ============================================================================
function displayUser() {
    // Vuln: echo without escaping
    echo "Welcome, " . $_GET['name'];

    // Vuln: print without escaping
    print $_POST['message'];

    echo $_REQUEST['search'];

    // Blade raw output (in template context)
    // {!! $user->bio !!}
}

// ============================================================================
// 5. Path Traversal / File Inclusion
// ============================================================================
function loadPage() {
    // Vuln: include with user input
    include($_GET['page']);

    // Vuln: require with user input
    require($_POST['module']);

    // Vuln: file_get_contents with user path
    $content = file_get_contents($_GET['path']);

    // Vuln: fopen with user input
    $fp = fopen($_REQUEST['log'], 'r');
}

// ============================================================================
// 6. File Upload Vulnerabilities
// ============================================================================
function uploadFile() {
    // Vuln: move_uploaded_file without validation
    $target = "uploads/" . $_FILES['file']['name'];
    move_uploaded_file($_FILES['file']['tmp_name'], $target);
}

// ============================================================================
// 7. Insecure Deserialization
// ============================================================================
class CacheHandler {
    public $file;

    // Vuln: __wakeup with dangerous operation
    public function __wakeup() {
        $content = file_get_contents($this->file);
    }

    // Vuln: __destruct with file operation
    public function __destruct() {
        unlink($this->file);
    }
}

function loadCache() {
    // Vuln: unserialize with user input
    $data = unserialize($_COOKIE['session_data']);

    // Vuln: unserialize from POST
    $obj = unserialize($_POST['payload']);
}

// ============================================================================
// 8. SSRF
// ============================================================================
function fetchUrl() {
    // Vuln: file_get_contents with user URL
    $url = $_GET['url'];
    $content = file_get_contents($url);

    // Vuln: cURL with user URL
    $ch = curl_init($_POST['endpoint']);
    curl_setopt($ch, CURLOPT_URL, $_GET['target']);
}

// ============================================================================
// 9. XXE
// ============================================================================
function parseXml() {
    // Vuln: SimpleXML without entity protection
    $xml = simplexml_load_string($_POST['xml']);

    // Vuln: DOMDocument without entity restriction
    $doc = new DOMDocument();
    $doc->loadXML($_POST['xml']);
}

// ============================================================================
// 10. Hardcoded Secrets
// ============================================================================
$db_password = "SuperSecret123!";
$api_key = "sk-1234567890abcdef1234567890abcdef";
$secret = "my_jwt_secret_key_very_long_string";
$aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
$private_key = "-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAK";

// ============================================================================
// 11. Weak Cryptography
// ============================================================================
function hashPassword($password) {
    // Vuln: md5 for password hashing
    return md5($password);
}

function weakHash($data) {
    // Vuln: sha1 for security
    return sha1($data);
}

function encryptData($data) {
    // Vuln: mcrypt (deprecated)
    $encrypted = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key, $data, MCRYPT_MODE_ECB);

    // Vuln: ECB mode
    $result = openssl_encrypt($data, 'DES-ECB', $key);
}

// ============================================================================
// 12. Insecure Random
// ============================================================================
function generateToken() {
    // Vuln: rand() for security token
    $token = rand(100000, 999999);

    // Vuln: mt_rand for password reset
    $resetCode = mt_rand(0, 999999);

    // Vuln: uniqid for token
    $sessionId = uniqid();
}

// ============================================================================
// 13. Laravel-specific
// ============================================================================
function laravelVulns() {
    // Vuln: Mass assignment
    User::create($_POST['data']);

    // Vuln: Raw SQL
    $users = DB::raw("SELECT * FROM users WHERE name = '$name'");
    $results = DB::select("SELECT * FROM orders WHERE status = '$status'");
}

// APP_DEBUG = true in .env
// 'debug' => true in config

// ============================================================================
// 14. WordPress-specific
// ============================================================================
function wordpressVulns() {
    global $wpdb;
    // Vuln: $wpdb->query without prepare
    $wpdb->query("DELETE FROM wp_posts WHERE ID = $id");
    $wpdb->get_results("SELECT * FROM wp_users WHERE user_login = '$username'");
}

// Vuln: AJAX handler without nonce
add_action('wp_ajax_delete_post', 'handle_delete');
function handle_delete() {
    $id = $_POST['post_id'];
    wp_delete_post($id);
    wp_die();
}

// ============================================================================
// 15. Symfony-specific
// ============================================================================
// APP_ENV=dev
// kernel.debug: true

// ============================================================================
// 16. CodeIgniter-specific
// ============================================================================
class ProductController {
    function search() {
        // Vuln: CI query with concat
        $this->db->query("SELECT * FROM products WHERE name LIKE '%" . $this->input->get('q') . "%'");
    }
}

// ============================================================================
// 17. Type Juggling
// ============================================================================
function checkAuth($inputPassword, $storedHash) {
    // Vuln: loose comparison for password
    if ($inputPassword == $storedHash) {
        return true;
    }

    // Vuln: strcmp bypass
    if (strcmp($inputPassword, $storedHash) == 0) {
        return true;
    }
}

function checkToken($token, $expected) {
    // Vuln: loose comparison for token
    if ($token == $expected) {
        return true;
    }
}

// ============================================================================
// 18. Open Redirect
// ============================================================================
function redirectUser() {
    // Vuln: open redirect with user input
    header("Location: " . $_GET['url']);

    // Vuln: redirect with POST data
    header("Location: " . $_POST['redirect_to']);
}

// ============================================================================
// 19. Session Fixation
// ============================================================================
session_start();
function login($username, $password) {
    // Vuln: no session_regenerate_id after login
    if (authenticate($username, $password)) {
        $_SESSION['user'] = $username;
        $_SESSION['logged_in'] = true;
        // Missing: session_regenerate_id(true);
    }
}

// ============================================================================
// 20. CSRF Missing
// ============================================================================
function handleForm() {
    if ($_POST['action'] == 'transfer') {
        $amount = $_POST['amount'];
        $to = $_POST['to_account'];
        // No CSRF token validation
        transferFunds($to, $amount);
    }
}

// ============================================================================
// 21. Information Disclosure
// ============================================================================
phpinfo();
ini_set('display_errors', 'on');
error_reporting(E_ALL);
var_dump($_GET['debug']);
print_r($_POST['data']);

// ============================================================================
// 22. Insecure File Permissions
// ============================================================================
function createFile() {
    chmod("/var/www/uploads/data.txt", 0777);
    chmod($file, 0666);
}

// ============================================================================
// 23. Missing Input Validation - tested via function analysis
// ============================================================================
function processOrder() {
    $qty = $_POST['quantity'];
    $price = $_GET['price'];
    $total = $qty * $price;
    // No validation at all
    insertOrder($total);
}

// ============================================================================
// 24. Register Globals
// ============================================================================
extract($_GET);
extract($_POST);

// ============================================================================
// 25. Object Injection
// ============================================================================
$data = unserialize($_GET['data']);
$payload = unserialize($_COOKIE['auth']);

// ============================================================================
// 26. LDAP Injection
// ============================================================================
function searchLdap($conn) {
    $username = $_GET['user'];
    ldap_search($conn, "dc=example,dc=com", "(uid=$username)", $_GET['attrs']);
}

// ============================================================================
// 27. Email Injection
// ============================================================================
function sendMail() {
    $to = $_POST['to'];
    $subject = $_POST['subject'];
    mail($to, $subject, "Hello", "From: " . $_POST['from']);
}

// ============================================================================
// 28. Timing Attack
// ============================================================================
function verifyHash($input, $stored_hash) {
    $computed_hash = hash('sha256', $input);
    // Vuln: direct comparison instead of hash_equals
    if ($computed_hash == $stored_hash) {
        return true;
    }
}

function verifySignature($token, $expected_signature) {
    $hmac = hash_hmac('sha256', $token, $secret);
    return $hmac === $expected_signature;  // Should use hash_equals
}

// ============================================================================
// 29. Logging Sensitive Data
// ============================================================================
function logActivity($user, $password) {
    error_log("Login attempt: user=$user, password=$password");
    error_log("Token: " . $token);
}

// ============================================================================
// 30. Missing Authentication
// ============================================================================
function deleteUser($userId) {
    // No auth check
    $db->query("DELETE FROM users WHERE id = ?", [$userId]);
}

function adminUpdateSettings($settings) {
    // No permission check
    foreach ($settings as $key => $value) {
        updateSetting($key, $value);
    }
}

// ============================================================================
// Extra: Backtick Execution
// ============================================================================
$files = `ls -la $dir`;
$who = `whoami`;

// ============================================================================
// Extra: Variable Variables
// ============================================================================
$varName = $_GET['var'];
$$varName = $_GET['value'];

// ============================================================================
// Extra: Heredoc with interpolation
// ============================================================================
$sql = <<<SQL
SELECT * FROM users WHERE name = '$name' AND role = '$role'
SQL;

// Arrow functions
$multiply = fn($x) => $x * $_GET['factor'];

// Null coalescing
$username = $_GET['user'] ?? 'guest';
$config['key'] ??= 'default_secret_key_12345678';

// Spaceship operator (not a vuln, just token test)
$result = $a <=> $b;
