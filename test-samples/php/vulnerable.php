<?php
/**
 * SAST Test Sample: Comprehensive PHP Vulnerabilities
 * 
 * This file contains intentionally vulnerable code to test all 30+ categories
 * of the PHP SAST scanner. DO NOT use this code in production.
 */

// ============================================================================
// 1. SQL Injection
// ============================================================================

// 1a. mysql_query with concatenation
function getUserByName_mysql($conn) {
    $name = $_GET['name'];
    $result = mysql_query("SELECT * FROM users WHERE name = '" . $name . "'");
    return $result;
}

// 1b. mysqli_query with interpolation  
function getUserByName_mysqli($conn) {
    $id = $_POST['id'];
    $result = mysqli_query($conn, "SELECT * FROM users WHERE id = $id");
    return $result;
}

// 1c. PDO::query without prepare
function getUserByEmail($pdo) {
    $email = $_REQUEST['email'];
    $result = $pdo->query("SELECT * FROM users WHERE email = '" . $email . "'");
    return $result;
}

// 1d. WordPress $wpdb->query without prepare
function wp_get_user_data() {
    global $wpdb;
    $user_id = $_GET['user_id'];
    $results = $wpdb->query("SELECT * FROM wp_users WHERE ID = " . $user_id);
    return $results;
}

// ============================================================================
// 2. Command Injection
// ============================================================================

// 2a. exec with user input
function runDiagnostic() {
    $host = $_GET['host'];
    $output = [];
    exec("ping -c 3 " . $host, $output);
    return $output;
}

// 2b. system with user input
function convertFile() {
    $filename = $_POST['filename'];
    system("convert " . $filename . " output.pdf");
}

// 2c. passthru
function viewLog() {
    $logfile = $_GET['log'];
    passthru("cat " . $logfile);
}

// 2d. shell_exec
function dnsLookup() {
    $domain = $_GET['domain'];
    $result = shell_exec("nslookup " . $domain);
    return $result;
}

// 2e. proc_open
function runCustomCommand() {
    $cmd = $_POST['command'];
    $process = proc_open($cmd, [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ], $pipes);
    return stream_get_contents($pipes[1]);
}

// 2f. Backtick operator
function getSystemInfo() {
    $param = $_GET['param'];
    $info = `uname -a $param`;
    return $info;
}

// ============================================================================
// 3. Code Injection
// ============================================================================

// 3a. eval with user input
function calculate() {
    $expression = $_GET['expr'];
    $result = eval("return " . $expression . ";");
    return $result;
}

// 3b. preg_replace with /e modifier
function processTemplate($template) {
    $var = $_POST['var'];
    $result = preg_replace('/\{(\w+)\}/e', '$var', $template);
    return $result;
}

// 3c. assert with user input
function validateCondition() {
    $condition = $_GET['condition'];
    assert($condition);
}

// 3d. create_function (deprecated)
function createCallback() {
    $body = $_POST['callback_body'];
    $fn = create_function('$x', $body);
    return $fn(42);
}

// 3e. call_user_func with user input
function dynamicCall() {
    $func = $_GET['func'];
    $arg = $_GET['arg'];
    return call_user_func($func, $arg);
}

// ============================================================================
// 4. XSS (Cross-Site Scripting)
// ============================================================================

// 4a. echo with user input
function displaySearch() {
    $query = $_GET['q'];
    echo "Search results for: " . $query;
}

// 4b. print with user input
function showName() {
    $name = $_POST['name'];
    print "Welcome, " . $name . "!";
}

// 4c. printf with user input
function formatOutput() {
    $data = $_GET['data'];
    printf("Result: %s", $data);
}

// ============================================================================
// 5-6. Path Traversal / File Inclusion
// ============================================================================

// 5a. include with user input
function loadPage() {
    $page = $_GET['page'];
    include("pages/" . $page);
}

// 5b. require_once with user input
function loadModule() {
    $module = $_GET['module'];
    require_once("modules/" . $module . ".php");
}

// 5c. file_get_contents with user input
function readUserFile() {
    $path = $_GET['file'];
    $content = file_get_contents($path);
    return $content;
}

// 5d. fopen with user input
function openDocument() {
    $doc = $_POST['document'];
    $handle = fopen($doc, 'r');
    return fread($handle, filesize($doc));
}

// 5e. file_put_contents with user input
function saveFile() {
    $filename = $_POST['filename'];
    $content = $_POST['content'];
    file_put_contents("uploads/" . $filename, $content);
}

// 5f. unlink with user input
function deleteFile() {
    $file = $_GET['file'];
    unlink($file);
}

// ============================================================================
// 7. Deserialization / 24. Object Injection
// ============================================================================

// 7a. unserialize with user input, no allowed_classes
function loadUserPrefs() {
    $data = $_COOKIE['preferences'];
    $prefs = unserialize($data);
    return $prefs;
}

// 7b. unserialize from POST
function importData() {
    $serialized = $_POST['data'];
    $obj = unserialize($serialized);
    return $obj;
}

// ============================================================================
// 8. XXE (XML External Entity)
// ============================================================================

// 8a. simplexml_load_string
function parseXMLInput() {
    $xml = file_get_contents('php://input');
    $doc = simplexml_load_string($xml);
    return $doc;
}

// 8b. DOMDocument
function processXML($xmlString) {
    $dom = new DOMDocument();
    $dom->loadXML($xmlString);
    return $dom;
}

// ============================================================================
// 9. SSRF (Server-Side Request Forgery)
// ============================================================================

// 9a. file_get_contents with user URL
function fetchExternalPage() {
    $url = $_GET['url'];
    $content = file_get_contents($url);
    return $content;
}

// 9b. curl with user URL
function curlFetch() {
    $url = $_POST['target_url'];
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}

// ============================================================================
// 10. LDAP Injection
// ============================================================================

function ldapAuthenticate($ldapConn) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $result = ldap_search($ldapConn, "dc=example,dc=com", "(uid=" . $username . ")");
    return $result;
}

// ============================================================================
// 11. Hardcoded Secrets
// ============================================================================

$db_password = "SuperSecret123!";
$api_key = "sk-live-abcdef1234567890";
$api_secret = "very_secret_value_here";

define('DB_PASSWORD', 'ProductionDBPass!');
define('API_SECRET', 'my_api_secret_key_12345');
define('AUTH_TOKEN', 'bearer_token_value_here');

$connection_string = "mysql://root:MyDbP4ss@localhost/production";

// ============================================================================
// 12. Weak Cryptography
// ============================================================================

// 12a. md5 for password hashing
function hashPassword_md5($password) {
    return md5($password);
}

// 12b. sha1 for hashing
function hashPassword_sha1($password) {
    return sha1($password);
}

// 12c. mcrypt (deprecated)
function encryptData_mcrypt($data, $key) {
    return mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_ECB);
}

// 12d. openssl with weak cipher
function encryptData_weak($data, $key) {
    $iv = openssl_random_pseudo_bytes(8);
    return openssl_encrypt($data, 'des-ecb', $key, 0, $iv);
}

// 12e. crypt()
function hashWithCrypt($password) {
    return crypt($password, '$1$salt$');
}

// ============================================================================
// 13. Insecure Random
// ============================================================================

// 13a. rand() for token
function generateToken_rand() {
    return md5(rand());
}

// 13b. mt_rand() for session ID
function generateSessionId() {
    return mt_rand(100000, 999999);
}

// 13c. uniqid for API key
function generateApiKey() {
    return uniqid('api_', true);
}

// 13d. array_rand for password reset
function generateResetCode($chars) {
    $code = '';
    for ($i = 0; $i < 6; $i++) {
        $code .= $chars[array_rand(str_split($chars))];
    }
    return $code;
}

// 13e. shuffle for token
function shuffleToken($chars) {
    $arr = str_split($chars);
    shuffle($arr);
    return implode('', $arr);
}

// ============================================================================
// 14. Laravel-specific
// ============================================================================

// 14a. Model without $fillable/$guarded (mass assignment)
// Simulating Laravel Model usage without namespace
class UserProfile extends \Illuminate\Database\Eloquent\Model {
    protected $table = 'user_profiles';
    // Missing $fillable or $guarded!
}

// 14b. DB::raw with user input
class SearchController {
    public function search() {
        $term = $_GET['q'];
        $results = \DB::raw("SELECT * FROM products WHERE name LIKE '%" . $term . "%'");
        return $results;
    }
    
    // 14c. whereRaw without bindings
    public function filterProducts() {
        $price = $_GET['min_price'];
        $products = \DB::table('products')->whereRaw("price > " . $price)->get();
        return $products;
    }
}

// ============================================================================
// 15. WordPress-specific
// ============================================================================

// 15a. echo without esc_html
function wp_display_title() {
    $title = get_the_title();
    echo $title;
}

// 15b. update_option without nonce (WordPress context)
function wp_save_settings() {
    $value = $_POST['setting_value'];
    update_option('my_plugin_setting', $value);
}

// ============================================================================
// 16. CodeIgniter-specific
// ============================================================================

class MyController extends CI_Controller {
    public function process() {
        // Without XSS filtering
        $name = $this->input->get('name');
        $email = $this->input->post('email');
        echo "Hello " . $name;
    }
}

// ============================================================================
// 17. Symfony-specific  
// ============================================================================

class PageController extends \Symfony\Bundle\FrameworkBundle\Controller\AbstractController {
    public function showAction() {
        $userInput = $_GET['content'];
        $response = new \Symfony\Component\HttpFoundation\Response();
        $response->setContent($userInput);
        return $response;
    }
}

// ============================================================================
// 18. Session Issues
// ============================================================================

// 18a. session_start without secure config
function startSession_insecure() {
    session_start();
    $_SESSION['user'] = 'admin';
}

// 18b. Session fixation - session_id from user
function fixSession() {
    $sessId = $_GET['PHPSESSID'];
    session_id($sessId);
    session_start();
}

// ============================================================================
// 19. File Upload
// ============================================================================

function handleUpload_insecure() {
    $uploadDir = 'uploads/';
    $filename = $_FILES['file']['name'];
    move_uploaded_file(
        $_FILES['file']['tmp_name'],
        $uploadDir . $filename
    );
    echo "File uploaded: " . $filename;
}

// ============================================================================
// 20. Open Redirect
// ============================================================================

// 20a. header Location with GET input
function redirectUser() {
    $url = $_GET['redirect_url'];
    header("Location: " . $url);
    exit;
}

// 20b. header Location with interpolation
function redirectToPage() {
    $page = $_GET['next'];
    header("Location: https://example.com/$page");
    exit;
}

// ============================================================================
// 21. Information Disclosure
// ============================================================================

// 21a. phpinfo
function showServerInfo() {
    phpinfo();
}

// 21b. var_dump
function debugUser($user) {
    var_dump($user);
    print_r($user);
}

// 21c. display_errors On
function enableErrors() {
    ini_set('display_errors', '1');
    error_reporting(E_ALL);
}

// ============================================================================
// 22. Cookie Security
// ============================================================================

// 22a. setcookie without Secure/HttpOnly
function setUserCookie() {
    setcookie('user_id', '12345', time() + 3600, '/');
}

// 22b. setcookie with some flags but missing httponly
function setSessionCookie() {
    setcookie('session', 'abc123', time() + 86400, '/', '', false, false);
}

// ============================================================================
// 23. Type Juggling
// ============================================================================

// 23a. Loose comparison for password
function verifyPassword_loose($inputPassword, $storedHash) {
    $hash = md5($inputPassword);
    if ($hash == $storedHash) {
        return true;
    }
    return false;
}

// 23b. Loose comparison for token
function verifyToken($inputToken, $expectedToken) {
    if ($inputToken == $expectedToken) {
        return true;
    }
    return false;
}

// ============================================================================
// 25. CSRF Missing
// ============================================================================

function processForm() {
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        // No CSRF token validation
        $data = $_POST['data'];
        saveToDatabase($data);
    }
}

// ============================================================================
// 26. Race Conditions (TOCTOU)
// ============================================================================

function safeWriteFile($path, $content) {
    if (file_exists($path)) {
        // Time gap between check and operation
        $currentContent = file_get_contents($path);
    }
    file_put_contents($path, $content);
}

// ============================================================================
// 27. Missing Input Validation
// ============================================================================

class UserService {
    public function createUser($db) {
        $name = $_POST['name'];
        $email = $_POST['email'];
        $age = $_POST['age'];
        // No validation at all!
        $db->insert('users', ['name' => $name, 'email' => $email, 'age' => $age]);
    }
}

// ============================================================================
// 28. Timing Attacks
// ============================================================================

// 28a. strcmp for password comparison
function verifyPassword_strcmp($input, $stored) {
    $password = $input;
    if (strcmp($password, $stored) === 0) {
        return true;
    }
    return false;
}

// 28b. Direct hash comparison with ===
function verifyHash($input, $expected) {
    if (sha1($input) === $expected) {
        return true;
    }
    return false;
}

// ============================================================================
// 29. Email Injection
// ============================================================================

function sendContactEmail() {
    $to = $_POST['email'];
    $subject = $_POST['subject'];
    $message = $_POST['message'];
    $headers = "From: " . $_POST['from_email'];
    
    mail($to, $subject, $message, $headers);
}

// ============================================================================
// 30. Regex DoS
// ============================================================================

// 30a. User-controlled pattern
function searchWithRegex() {
    $pattern = $_GET['pattern'];
    $text = file_get_contents('data.txt');
    preg_match($pattern, $text, $matches);
    return $matches;
}

// 30b. Vulnerable nested quantifier pattern
function validateInput($input) {
    // Vulnerable to ReDoS with nested quantifiers
    if (preg_match('/^(a+)+$/', $input)) {
        return true;
    }
    return false;
}

// 30c. Another ReDoS pattern
function validateEmail_redos($email) {
    // Catastrophic backtracking possible
    if (preg_match('/^([a-zA-Z0-9._-]+)*@([a-zA-Z0-9._-]+)*\.[a-zA-Z]{2,}$/', $email)) {
        return true;
    }
    return false;
}
