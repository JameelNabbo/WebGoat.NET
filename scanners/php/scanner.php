<?php
/**
 * PHP SAST Scanner v1.0.0
 * 
 * AST-based Static Application Security Testing scanner for PHP code.
 * Uses nikic/php-parser for proper AST analysis - NO regex-based detection.
 * 
 * Runs as HTTP server on port 9006.
 * POST /scan - accepts {"files": {"path": "content"}, "scanId": "uuid"}
 * GET /health - returns scanner status
 */

require_once __DIR__ . '/vendor/autoload.php';

use PhpParser\Error;
use PhpParser\NodeDumper;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor;
use PhpParser\NodeVisitorAbstract;
use PhpParser\Node;
use PhpParser\ParserFactory;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\Node\Scalar;

const VERSION = '1.0.0';
const PORT = 9006;
const LANGUAGE = 'PHP';

// ============================================================================
// VULNERABILITY MODEL
// ============================================================================

class Vulnerability implements \JsonSerializable
{
    public string $id;
    public string $title;
    public string $description;
    public string $severity;    // Critical, High, Medium, Low, Info
    public string $confidence;  // High, Medium, Low
    public string $category;
    public string $cwe;
    public string $owasp;
    public string $filePath;
    public int $startLine;
    public int $endLine;
    public int $startColumn;
    public int $endColumn;
    public string $snippet;
    public string $remediation;
    public array $references;

    public function __construct(array $data)
    {
        $this->id = $data['id'] ?? uniqid('PHP-');
        $this->title = $data['title'] ?? '';
        $this->description = $data['description'] ?? '';
        $this->severity = $data['severity'] ?? 'Medium';
        $this->confidence = $data['confidence'] ?? 'Medium';
        $this->category = $data['category'] ?? '';
        $this->cwe = $data['cwe'] ?? '';
        $this->owasp = $data['owasp'] ?? '';
        $this->filePath = $data['filePath'] ?? '';
        $this->startLine = $data['startLine'] ?? 0;
        $this->endLine = $data['endLine'] ?? 0;
        $this->startColumn = $data['startColumn'] ?? 0;
        $this->endColumn = $data['endColumn'] ?? 0;
        $this->snippet = $data['snippet'] ?? '';
        $this->remediation = $data['remediation'] ?? '';
        $this->references = $data['references'] ?? [];
    }

    public function jsonSerialize(): array
    {
        return [
            'id' => $this->id,
            'title' => $this->title,
            'description' => $this->description,
            'severity' => $this->severity,
            'confidence' => $this->confidence,
            'category' => $this->category,
            'cwe' => $this->cwe,
            'owasp' => $this->owasp,
            'filePath' => $this->filePath,
            'startLine' => $this->startLine,
            'endLine' => $this->endLine,
            'startColumn' => $this->startColumn,
            'endColumn' => $this->endColumn,
            'snippet' => $this->snippet,
            'remediation' => $this->remediation,
            'references' => $this->references,
        ];
    }
}

// ============================================================================
// SOURCE/SINK TRACKING HELPERS
// ============================================================================

class TaintTracker
{
    /**
     * Superglobals and functions considered user-input sources.
     */
    private static array $userInputSuperGlobals = [
        '_GET', '_POST', '_REQUEST', '_COOKIE', '_SERVER', '_FILES', '_ENV',
    ];

    private static array $userInputFunctions = [
        'file_get_contents' => true, // when arg is php://input
        'getenv' => true,
        'apache_request_headers' => true,
        'getallheaders' => true,
    ];

    /**
     * Check if an expression represents user input (taint source).
     */
    public static function isUserInput(Node $node): bool
    {
        // $_GET, $_POST, $_REQUEST, $_COOKIE, $_SERVER, $_FILES
        if ($node instanceof Expr\ArrayDimFetch) {
            return self::isUserInput($node->var);
        }

        if ($node instanceof Expr\Variable) {
            if (is_string($node->name) && in_array($node->name, self::$userInputSuperGlobals, true)) {
                return true;
            }
        }

        // filter_input, filter_input_array
        if ($node instanceof Expr\FuncCall) {
            $name = self::getFuncName($node);
            if ($name === 'filter_input' || $name === 'filter_input_array') {
                return true;
            }
        }

        // file_get_contents('php://input')
        if ($node instanceof Expr\FuncCall) {
            $name = self::getFuncName($node);
            if ($name === 'file_get_contents' && !empty($node->args)) {
                $arg = $node->args[0]->value ?? null;
                if ($arg instanceof Scalar\String_ && str_contains($arg->value, 'php://input')) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if an expression involves user input anywhere in the expression tree.
     */
    public static function containsUserInput(Node $node): bool
    {
        if (self::isUserInput($node)) {
            return true;
        }

        // Check concatenation
        if ($node instanceof Expr\BinaryOp\Concat) {
            return self::containsUserInput($node->left) || self::containsUserInput($node->right);
        }

        // Check string interpolation (Encapsed)
        if ($node instanceof Scalar\InterpolatedString) {
            foreach ($node->parts as $part) {
                if ($part instanceof Node && self::containsUserInput($part)) {
                    return true;
                }
            }
        }

        // Check function call arguments (e.g., trim($_GET['x']))
        if ($node instanceof Expr\FuncCall) {
            $name = self::getFuncName($node);
            // These functions don't sanitize
            $passThroughFunctions = [
                'trim', 'ltrim', 'rtrim', 'strtolower', 'strtoupper',
                'substr', 'str_replace', 'strrev', 'ucfirst', 'lcfirst',
                'urldecode', 'rawurldecode', 'base64_decode', 'json_decode',
                'stripslashes', 'nl2br', 'wordwrap', 'sprintf',
            ];
            if (in_array($name, $passThroughFunctions, true)) {
                foreach ($node->args as $arg) {
                    if (self::containsUserInput($arg->value)) {
                        return true;
                    }
                }
            }
        }

        // Variable assigned from user input tracked via scope (simplified - check direct)
        if ($node instanceof Expr\Variable) {
            // Can't fully track without scope analysis, but we check common patterns
            return false;
        }

        // Array dim fetch on user input
        if ($node instanceof Expr\ArrayDimFetch) {
            return self::containsUserInput($node->var);
        }

        // Ternary
        if ($node instanceof Expr\Ternary) {
            $if = $node->if;
            $else = $node->else;
            return ($if && self::containsUserInput($if)) || self::containsUserInput($else);
        }

        // Assign (right side)
        if ($node instanceof Expr\Assign || $node instanceof Expr\AssignOp) {
            return self::containsUserInput($node->expr);
        }

        return false;
    }

    /**
     * Check if the output is sanitized (passed through an escaping function).
     */
    public static function isSanitizedForOutput(Node $node): bool
    {
        if ($node instanceof Expr\FuncCall) {
            $name = self::getFuncName($node);
            $sanitizers = [
                'htmlspecialchars', 'htmlentities', 'strip_tags',
                'esc_html', 'esc_attr', 'esc_url', 'esc_js', 'esc_textarea',
                'wp_kses', 'wp_kses_post', 'sanitize_text_field',
                'sanitize_email', 'sanitize_file_name', 'sanitize_key',
                'sanitize_title', 'sanitize_user', 'absint', 'intval',
                'floatval', 'filter_var',
            ];
            return in_array($name, $sanitizers, true);
        }

        // Cast to int/float
        if ($node instanceof Expr\Cast\Int_ || $node instanceof Expr\Cast\Double) {
            return true;
        }

        return false;
    }

    /**
     * Check if SQL input is properly parameterized.
     */
    public static function isSanitizedForSQL(Node $node): bool
    {
        if ($node instanceof Expr\FuncCall) {
            $name = self::getFuncName($node);
            $sqlSanitizers = [
                'mysql_real_escape_string', 'mysqli_real_escape_string',
                'pg_escape_string', 'pg_escape_literal',
                'intval', 'floatval', 'absint',
            ];
            return in_array($name, $sqlSanitizers, true);
        }

        if ($node instanceof Expr\MethodCall) {
            $methodName = self::getMethodName($node);
            if (in_array($methodName, ['prepare', 'quote', 'escape'], true)) {
                return true;
            }
        }

        if ($node instanceof Expr\Cast\Int_ || $node instanceof Expr\Cast\Double) {
            return true;
        }

        return false;
    }

    public static function getFuncName(Expr\FuncCall $node): ?string
    {
        if ($node->name instanceof Node\Name) {
            return $node->name->toString();
        }
        return null;
    }

    public static function getMethodName(Node $node): ?string
    {
        if (($node instanceof Expr\MethodCall || $node instanceof Expr\StaticCall)
            && $node->name instanceof Node\Identifier) {
            return $node->name->toString();
        }
        return null;
    }

    public static function getPropertyName(Node $node): ?string
    {
        if ($node instanceof Expr\PropertyFetch && $node->name instanceof Node\Identifier) {
            return $node->name->toString();
        }
        return null;
    }
}

// ============================================================================
// AST VISITOR - VULNERABILITY DETECTOR
// ============================================================================

class VulnerabilityVisitor extends NodeVisitorAbstract
{
    private string $filePath;
    private string $sourceCode;
    private array $sourceLines;
    /** @var Vulnerability[] */
    private array $vulnerabilities = [];
    private int $vulnCounter = 0;

    // Track variable assignments for taint propagation
    private array $taintedVars = [];
    // Track class context
    private ?string $currentClass = null;
    private ?string $currentMethod = null;
    // Track if we're inside a Laravel/WordPress/Symfony context
    private bool $isLaravel = false;
    private bool $isWordPress = false;
    private bool $isCodeIgniter = false;
    private bool $isSymfony = false;

    public function __construct(string $filePath, string $sourceCode)
    {
        $this->filePath = $filePath;
        $this->sourceCode = $sourceCode;
        $this->sourceLines = explode("\n", $sourceCode);

        // Detect framework context from source
        $this->isLaravel = str_contains($sourceCode, 'Illuminate\\') || str_contains($sourceCode, 'Laravel\\');
        $this->isWordPress = str_contains($sourceCode, 'wp_') || str_contains($sourceCode, '$wpdb') || str_contains($sourceCode, 'WordPress');
        $this->isCodeIgniter = str_contains($sourceCode, 'CodeIgniter') || str_contains($sourceCode, 'CI_Controller');
        $this->isSymfony = str_contains($sourceCode, 'Symfony\\') || str_contains($sourceCode, 'AbstractController');
    }

    public function enterNode(Node $node)
    {
        // Track class context
        if ($node instanceof Stmt\Class_) {
            $this->currentClass = $node->name ? $node->name->toString() : null;

            // Laravel: Check for mass assignment vulnerability
            if ($this->isLaravel) {
                $this->checkLaravelMassAssignment($node);
            }
        }

        if ($node instanceof Stmt\ClassMethod) {
            $this->currentMethod = $node->name->toString();
        }

        // Track tainted variable assignments
        if ($node instanceof Expr\Assign) {
            $this->trackTaintedAssignment($node);
        }

        // ---- VULNERABILITY CHECKS ----

        // 1. SQL Injection
        $this->checkSQLInjection($node);

        // 2. Command Injection
        $this->checkCommandInjection($node);

        // 3. Code Injection
        $this->checkCodeInjection($node);

        // 4. XSS
        $this->checkXSS($node);

        // 5-6. Path Traversal / File Inclusion
        $this->checkPathTraversal($node);

        // 7. Deserialization
        $this->checkDeserialization($node);

        // 8. XXE
        $this->checkXXE($node);

        // 9. SSRF
        $this->checkSSRF($node);

        // 10. LDAP Injection
        $this->checkLDAPInjection($node);

        // 11. Hardcoded Secrets
        $this->checkHardcodedSecrets($node);

        // 12. Weak Cryptography
        $this->checkWeakCryptography($node);

        // 13. Insecure Random
        $this->checkInsecureRandom($node);

        // 14. Laravel-specific
        if ($this->isLaravel) {
            $this->checkLaravelSpecific($node);
        }

        // 15. WordPress-specific
        if ($this->isWordPress) {
            $this->checkWordPressSpecific($node);
        }

        // 16. CodeIgniter-specific
        if ($this->isCodeIgniter) {
            $this->checkCodeIgniterSpecific($node);
        }

        // 17. Symfony-specific
        if ($this->isSymfony) {
            $this->checkSymfonySpecific($node);
        }

        // 18. Session Issues
        $this->checkSessionIssues($node);

        // 19. File Upload
        $this->checkFileUpload($node);

        // 20. Open Redirect
        $this->checkOpenRedirect($node);

        // 21. Information Disclosure
        $this->checkInformationDisclosure($node);

        // 22. Cookie Security
        $this->checkCookieSecurity($node);

        // 23. Type Juggling
        $this->checkTypeJuggling($node);

        // 24. Object Injection (covered under deserialization)

        // 25. CSRF Missing
        $this->checkCSRFMissing($node);

        // 26. Race Conditions
        $this->checkRaceConditions($node);

        // 27. Missing Input Validation
        $this->checkMissingInputValidation($node);

        // 28. Timing Attacks
        $this->checkTimingAttacks($node);

        // 29. Email Injection
        $this->checkEmailInjection($node);

        // 30. Regex DoS
        $this->checkRegexDoS($node);

        return null;
    }

    public function leaveNode(Node $node)
    {
        if ($node instanceof Stmt\Class_) {
            $this->currentClass = null;
        }
        if ($node instanceof Stmt\ClassMethod) {
            $this->currentMethod = null;
        }
        return null;
    }

    /**
     * @return Vulnerability[]
     */
    public function getVulnerabilities(): array
    {
        return $this->vulnerabilities;
    }

    // ========================================================================
    // VULNERABILITY CHECK METHODS
    // ========================================================================

    /**
     * 1. SQL Injection
     */
    private function checkSQLInjection(Node $node): void
    {
        // mysql_query, mysqli_query with concatenated user input
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);
            $sqlFunctions = [
                'mysql_query', 'mysqli_query', 'mysql_unbuffered_query',
                'pg_query', 'pg_send_query', 'sqlite_query', 'sqlite_exec',
                'mssql_query',
            ];

            if (in_array($name, $sqlFunctions, true) && !empty($node->args)) {
                // For mysqli_query, the SQL is typically the second argument
                $sqlArgIndex = ($name === 'mysqli_query' || $name === 'pg_query') ? 1 : 0;
                $sqlArg = $node->args[$sqlArgIndex]->value ?? $node->args[0]->value;

                if ($this->containsTaintedInput($sqlArg) && !TaintTracker::isSanitizedForSQL($sqlArg)) {
                    $this->addVulnerability([
                        'title' => 'SQL Injection via ' . $name . '()',
                        'description' => "User-controlled input is concatenated into an SQL query passed to {$name}() without proper parameterization or escaping.",
                        'severity' => 'Critical',
                        'confidence' => 'High',
                        'category' => 'SQL Injection',
                        'cwe' => 'CWE-89',
                        'owasp' => 'A03:2021 Injection',
                        'remediation' => 'Use prepared statements with parameterized queries (PDO::prepare() or mysqli_prepare()). Never concatenate user input into SQL strings.',
                        'references' => ['https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
                    ], $node);
                }
            }
        }

        // PDO::query with concatenated input (instead of prepare)
        if ($node instanceof Expr\MethodCall) {
            $methodName = TaintTracker::getMethodName($node);
            if (in_array($methodName, ['query', 'exec'], true) && !empty($node->args)) {
                $sqlArg = $node->args[0]->value;
                if ($this->containsTaintedInput($sqlArg)) {
                    $this->addVulnerability([
                        'title' => 'SQL Injection via PDO::' . $methodName . '()',
                        'description' => "User input is concatenated into SQL passed to {$methodName}(). Use prepare() with bound parameters instead.",
                        'severity' => 'Critical',
                        'confidence' => 'High',
                        'category' => 'SQL Injection',
                        'cwe' => 'CWE-89',
                        'owasp' => 'A03:2021 Injection',
                        'remediation' => 'Use $pdo->prepare() with bound parameters instead of $pdo->query() with concatenated strings.',
                        'references' => ['https://www.php.net/manual/en/pdo.prepared-statements.php'],
                    ], $node);
                }
            }
        }

        // WordPress $wpdb->query without prepare
        if ($node instanceof Expr\MethodCall) {
            $methodName = TaintTracker::getMethodName($node);
            if ($methodName === 'query' && !empty($node->args)) {
                $varNode = $node->var;
                if ($varNode instanceof Expr\Variable && is_string($varNode->name) && $varNode->name === 'wpdb') {
                    $sqlArg = $node->args[0]->value;
                    // Check if it's NOT wrapped in $wpdb->prepare()
                    if (!($sqlArg instanceof Expr\MethodCall && TaintTracker::getMethodName($sqlArg) === 'prepare')) {
                        if ($this->containsTaintedInput($sqlArg) || $this->isStringConcat($sqlArg)) {
                            $this->addVulnerability([
                                'title' => 'SQL Injection via $wpdb->query() without prepare()',
                                'description' => 'WordPress database query uses $wpdb->query() without $wpdb->prepare(), allowing SQL injection.',
                                'severity' => 'Critical',
                                'confidence' => 'High',
                                'category' => 'SQL Injection',
                                'cwe' => 'CWE-89',
                                'owasp' => 'A03:2021 Injection',
                                'remediation' => 'Always use $wpdb->prepare() to parameterize queries: $wpdb->query($wpdb->prepare("SELECT * FROM table WHERE id = %d", $id))',
                                'references' => ['https://developer.wordpress.org/plugins/security/data-validation/#sql-injection'],
                            ], $node);
                        }
                    }
                }
            }
        }
    }

    /**
     * 2. Command Injection
     */
    private function checkCommandInjection(Node $node): void
    {
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);
            $cmdFunctions = [
                'exec' => 'Critical', 'system' => 'Critical', 'passthru' => 'Critical',
                'shell_exec' => 'Critical', 'popen' => 'Critical', 'proc_open' => 'Critical',
                'pcntl_exec' => 'Critical',
            ];

            if (isset($cmdFunctions[$name]) && !empty($node->args)) {
                $cmdArg = $node->args[0]->value;
                if ($this->containsTaintedInput($cmdArg)) {
                    // Check if escapeshellarg/escapeshellcmd is used
                    if (!$this->isShellEscaped($cmdArg)) {
                        $this->addVulnerability([
                            'title' => 'Command Injection via ' . $name . '()',
                            'description' => "User-controlled input is passed to {$name}() without proper escaping, allowing arbitrary command execution.",
                            'severity' => $cmdFunctions[$name],
                            'confidence' => 'High',
                            'category' => 'Command Injection',
                            'cwe' => 'CWE-78',
                            'owasp' => 'A03:2021 Injection',
                            'remediation' => 'Use escapeshellarg() for individual arguments and escapeshellcmd() for complete commands. Prefer using specific PHP functions over shell commands.',
                            'references' => ['https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html'],
                        ], $node);
                    }
                }
            }
        }

        // Backtick operator (ShellExec)
        if ($node instanceof Expr\ShellExec) {
            $hasTaintedPart = false;
            foreach ($node->parts as $part) {
                if ($part instanceof Node && $this->containsTaintedInput($part)) {
                    $hasTaintedPart = true;
                    break;
                }
            }
            if ($hasTaintedPart) {
                $this->addVulnerability([
                    'title' => 'Command Injection via backtick operator',
                    'description' => 'User-controlled input is used inside backtick operator (``), allowing arbitrary command execution.',
                    'severity' => 'Critical',
                    'confidence' => 'High',
                    'category' => 'Command Injection',
                    'cwe' => 'CWE-78',
                    'owasp' => 'A03:2021 Injection',
                    'remediation' => 'Avoid using backtick operators. Use specific PHP functions instead of shell commands.',
                    'references' => ['https://www.php.net/manual/en/language.operators.execution.php'],
                ], $node);
            }
        }
    }

    /**
     * 3. Code Injection
     */
    private function checkCodeInjection(Node $node): void
    {
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);

            // eval() with user input
            if ($node instanceof Expr\Eval_) {
                // Handled below
            }

            // assert() with user input
            if ($name === 'assert' && !empty($node->args)) {
                $arg = $node->args[0]->value;
                if ($arg instanceof Scalar\String_ || $this->containsTaintedInput($arg)) {
                    $this->addVulnerability([
                        'title' => 'Code Injection via assert()',
                        'description' => 'assert() with a string argument evaluates the string as PHP code. With user input this allows arbitrary code execution.',
                        'severity' => 'Critical',
                        'confidence' => $this->containsTaintedInput($arg) ? 'High' : 'Medium',
                        'category' => 'Code Injection',
                        'cwe' => 'CWE-94',
                        'owasp' => 'A03:2021 Injection',
                        'remediation' => 'Pass boolean expressions to assert() instead of strings. Never pass user input to assert().',
                        'references' => ['https://www.php.net/manual/en/function.assert.php'],
                    ], $node);
                }
            }

            // create_function (deprecated, uses eval internally)
            if ($name === 'create_function') {
                $this->addVulnerability([
                    'title' => 'Code Injection via create_function()',
                    'description' => 'create_function() internally uses eval() and is deprecated since PHP 7.2. It allows code injection if any argument contains user input.',
                    'severity' => 'High',
                    'confidence' => 'High',
                    'category' => 'Code Injection',
                    'cwe' => 'CWE-94',
                    'owasp' => 'A03:2021 Injection',
                    'remediation' => 'Replace create_function() with anonymous functions (closures).',
                    'references' => ['https://www.php.net/manual/en/function.create-function.php'],
                ], $node);
            }

            // preg_replace with /e modifier
            if ($name === 'preg_replace' && !empty($node->args)) {
                $patternArg = $node->args[0]->value;
                if ($patternArg instanceof Scalar\String_ && str_contains($patternArg->value, '/e')) {
                    $this->addVulnerability([
                        'title' => 'Code Injection via preg_replace() with /e modifier',
                        'description' => 'The /e modifier in preg_replace() evaluates the replacement string as PHP code. This was removed in PHP 7.0.',
                        'severity' => 'Critical',
                        'confidence' => 'High',
                        'category' => 'Code Injection',
                        'cwe' => 'CWE-94',
                        'owasp' => 'A03:2021 Injection',
                        'remediation' => 'Use preg_replace_callback() instead of preg_replace() with the /e modifier.',
                        'references' => ['https://www.php.net/manual/en/function.preg-replace.php'],
                    ], $node);
                }
            }

            // call_user_func / call_user_func_array with user input
            if (in_array($name, ['call_user_func', 'call_user_func_array'], true) && !empty($node->args)) {
                $callbackArg = $node->args[0]->value;
                if ($this->containsTaintedInput($callbackArg)) {
                    $this->addVulnerability([
                        'title' => 'Code Injection via ' . $name . '()',
                        'description' => "User input controls the callback function name in {$name}(), allowing arbitrary function execution.",
                        'severity' => 'Critical',
                        'confidence' => 'High',
                        'category' => 'Code Injection',
                        'cwe' => 'CWE-94',
                        'owasp' => 'A03:2021 Injection',
                        'remediation' => 'Use a whitelist of allowed function names instead of directly passing user input.',
                        'references' => [],
                    ], $node);
                }
            }
        }

        // eval() expression
        if ($node instanceof Expr\Eval_) {
            $severity = 'High';
            $confidence = 'Medium';
            if ($this->containsTaintedInput($node->expr)) {
                $severity = 'Critical';
                $confidence = 'High';
            }
            $this->addVulnerability([
                'title' => 'Code Injection via eval()',
                'description' => 'eval() executes a string as PHP code. If user input reaches eval(), it allows arbitrary code execution.',
                'severity' => $severity,
                'confidence' => $confidence,
                'category' => 'Code Injection',
                'cwe' => 'CWE-94',
                'owasp' => 'A03:2021 Injection',
                'remediation' => 'Avoid eval() entirely. Use structured alternatives such as json_decode(), template engines, or configuration files.',
                'references' => ['https://www.php.net/manual/en/function.eval.php'],
            ], $node);
        }
    }

    /**
     * 4. XSS (Cross-Site Scripting)
     */
    private function checkXSS(Node $node): void
    {
        // echo/print with unescaped user input
        if ($node instanceof Stmt\Echo_) {
            foreach ($node->exprs as $expr) {
                if ($this->containsTaintedInput($expr) && !TaintTracker::isSanitizedForOutput($expr)) {
                    $this->addVulnerability([
                        'title' => 'Cross-Site Scripting (XSS) via echo',
                        'description' => 'User-controlled input is echoed without proper HTML encoding, allowing XSS attacks.',
                        'severity' => 'High',
                        'confidence' => 'High',
                        'category' => 'Cross-Site Scripting',
                        'cwe' => 'CWE-79',
                        'owasp' => 'A03:2021 Injection',
                        'remediation' => 'Use htmlspecialchars($input, ENT_QUOTES, \'UTF-8\') before outputting user input in HTML context.',
                        'references' => ['https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'],
                    ], $node);
                }
            }
        }

        // print with user input
        if ($node instanceof Expr\Print_) {
            if ($this->containsTaintedInput($node->expr) && !TaintTracker::isSanitizedForOutput($node->expr)) {
                $this->addVulnerability([
                    'title' => 'Cross-Site Scripting (XSS) via print',
                    'description' => 'User-controlled input is printed without proper HTML encoding.',
                    'severity' => 'High',
                    'confidence' => 'High',
                    'category' => 'Cross-Site Scripting',
                    'cwe' => 'CWE-79',
                    'owasp' => 'A03:2021 Injection',
                    'remediation' => 'Use htmlspecialchars($input, ENT_QUOTES, \'UTF-8\') before outputting.',
                    'references' => [],
                ], $node);
            }
        }

        // printf/sprintf/vprintf with user input
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);
            if (in_array($name, ['printf', 'vprintf'], true) && !empty($node->args)) {
                foreach ($node->args as $arg) {
                    if ($this->containsTaintedInput($arg->value) && !TaintTracker::isSanitizedForOutput($arg->value)) {
                        $this->addVulnerability([
                            'title' => 'Cross-Site Scripting (XSS) via ' . $name . '()',
                            'description' => "User input passed to {$name}() without HTML encoding.",
                            'severity' => 'High',
                            'confidence' => 'Medium',
                            'category' => 'Cross-Site Scripting',
                            'cwe' => 'CWE-79',
                            'owasp' => 'A03:2021 Injection',
                            'remediation' => 'Escape user input with htmlspecialchars() before passing to output functions.',
                            'references' => [],
                        ], $node);
                        break;
                    }
                }
            }
        }

        // InlineHTML mixed with PHP (just track for context)
        if ($node instanceof Stmt\InlineHTML) {
            // Inline HTML itself is not a vuln, but we note it for context
        }
    }

    /**
     * 5-6. Path Traversal / File Inclusion (LFI/RFI)
     */
    private function checkPathTraversal(Node $node): void
    {
        // include/require with user input
        if ($node instanceof Stmt\Expression && $node->expr instanceof Expr\Include_) {
            $includeExpr = $node->expr;
            if ($this->containsTaintedInput($includeExpr->expr)) {
                $type = match($includeExpr->type) {
                    Expr\Include_::TYPE_INCLUDE => 'include',
                    Expr\Include_::TYPE_INCLUDE_ONCE => 'include_once',
                    Expr\Include_::TYPE_REQUIRE => 'require',
                    Expr\Include_::TYPE_REQUIRE_ONCE => 'require_once',
                    default => 'include',
                };
                $this->addVulnerability([
                    'title' => "Remote/Local File Inclusion via {$type}",
                    'description' => "User-controlled input determines the file path in {$type}(), allowing an attacker to include arbitrary files (LFI) or remote files (RFI).",
                    'severity' => 'Critical',
                    'confidence' => 'High',
                    'category' => 'File Inclusion',
                    'cwe' => 'CWE-98',
                    'owasp' => 'A03:2021 Injection',
                    'remediation' => 'Never use user input directly in include/require. Use a whitelist of allowed files or map user input to predetermined paths.',
                    'references' => ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion'],
                ], $includeExpr);
            }
        }

        // Also handle bare include expressions (not wrapped in Statement)
        if ($node instanceof Expr\Include_) {
            if ($this->containsTaintedInput($node->expr)) {
                $type = match($node->type) {
                    Expr\Include_::TYPE_INCLUDE => 'include',
                    Expr\Include_::TYPE_INCLUDE_ONCE => 'include_once',
                    Expr\Include_::TYPE_REQUIRE => 'require',
                    Expr\Include_::TYPE_REQUIRE_ONCE => 'require_once',
                    default => 'include',
                };
                // Avoid duplicate if already caught above
                if (!($this->getParentNodeType($node) === 'Stmt_Expression')) {
                    $this->addVulnerability([
                        'title' => "Remote/Local File Inclusion via {$type}",
                        'description' => "User-controlled input determines the file path in {$type}().",
                        'severity' => 'Critical',
                        'confidence' => 'High',
                        'category' => 'File Inclusion',
                        'cwe' => 'CWE-98',
                        'owasp' => 'A03:2021 Injection',
                        'remediation' => 'Use a whitelist of allowed files or map user input to predetermined paths.',
                        'references' => [],
                    ], $node);
                }
            }
        }

        // file_get_contents, file_put_contents, fopen, readfile, file with user input
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);
            $fileFunctions = [
                'file_get_contents', 'file_put_contents', 'fopen', 'readfile',
                'file', 'fgets', 'fread', 'copy', 'rename', 'unlink',
                'rmdir', 'mkdir', 'is_file', 'is_dir', 'is_readable',
                'is_writable', 'glob', 'scandir', 'opendir',
            ];

            if (in_array($name, $fileFunctions, true) && !empty($node->args)) {
                $pathArg = $node->args[0]->value;
                if ($this->containsTaintedInput($pathArg)) {
                    $severity = in_array($name, ['file_put_contents', 'fopen', 'unlink', 'rmdir'], true) ? 'Critical' : 'High';
                    $this->addVulnerability([
                        'title' => "Path Traversal via {$name}()",
                        'description' => "User-controlled input is used as a file path in {$name}(), allowing directory traversal attacks (e.g., ../../etc/passwd).",
                        'severity' => $severity,
                        'confidence' => 'High',
                        'category' => 'Path Traversal',
                        'cwe' => 'CWE-22',
                        'owasp' => 'A01:2021 Broken Access Control',
                        'remediation' => 'Validate and sanitize file paths. Use realpath() and verify the resulting path is within the expected directory. Use basename() to strip directory components.',
                        'references' => ['https://owasp.org/www-community/attacks/Path_Traversal'],
                    ], $node);
                }
            }
        }
    }

    /**
     * 7. Deserialization / 24. Object Injection
     */
    private function checkDeserialization(Node $node): void
    {
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);

            if ($name === 'unserialize' && !empty($node->args)) {
                $arg = $node->args[0]->value;
                $severity = 'High';
                $confidence = 'Medium';

                if ($this->containsTaintedInput($arg)) {
                    $severity = 'Critical';
                    $confidence = 'High';
                }

                // Check if allowed_classes is set (2nd arg)
                $hasAllowedClasses = false;
                if (count($node->args) >= 2) {
                    $hasAllowedClasses = true;
                }

                if (!$hasAllowedClasses) {
                    $this->addVulnerability([
                        'title' => 'Insecure Deserialization via unserialize()',
                        'description' => 'unserialize() without allowed_classes restriction can lead to PHP Object Injection, allowing arbitrary code execution through magic methods (__wakeup, __destruct, __toString).',
                        'severity' => $severity,
                        'confidence' => $confidence,
                        'category' => 'Insecure Deserialization',
                        'cwe' => 'CWE-502',
                        'owasp' => 'A08:2021 Software and Data Integrity Failures',
                        'remediation' => 'Use json_decode() instead of unserialize() for data interchange. If unserialize() is required, use the allowed_classes option: unserialize($data, ["allowed_classes" => false]).',
                        'references' => ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests'],
                    ], $node);
                }
            }
        }
    }

    /**
     * 8. XXE (XML External Entity)
     */
    private function checkXXE(Node $node): void
    {
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);

            // simplexml_load_string / simplexml_load_file without LIBXML_NOENT
            if (in_array($name, ['simplexml_load_string', 'simplexml_load_file', 'dom_import_simplexml'], true)) {
                $hasNoEnt = false;
                foreach ($node->args as $arg) {
                    if ($this->containsConstant($arg->value, 'LIBXML_NOENT') ||
                        $this->containsConstant($arg->value, 'LIBXML_DTDLOAD')) {
                        // LIBXML_NOENT actually ENABLES entity substitution! This is WORSE
                        // But we check for its absence as a common misconfiguration
                    }
                }
                $this->addVulnerability([
                    'title' => 'XML External Entity (XXE) Injection via ' . $name . '()',
                    'description' => 'XML parsing function may be vulnerable to XXE attacks if external entity loading is not explicitly disabled.',
                    'severity' => 'High',
                    'confidence' => 'Medium',
                    'category' => 'XXE Injection',
                    'cwe' => 'CWE-611',
                    'owasp' => 'A05:2021 Security Misconfiguration',
                    'remediation' => 'Disable external entity loading before parsing XML: libxml_disable_entity_loader(true) (PHP < 8.0) or use LIBXML_NONET flag.',
                    'references' => ['https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html'],
                ], $node);
            }
        }

        // DOMDocument::loadXML without disabling entities
        if ($node instanceof Expr\MethodCall) {
            $methodName = TaintTracker::getMethodName($node);
            if (in_array($methodName, ['loadXML', 'loadHTML', 'load'], true)) {
                $this->addVulnerability([
                    'title' => 'Potential XXE via DOMDocument::' . $methodName . '()',
                    'description' => 'DOMDocument XML loading may be vulnerable to XXE if external entities are not disabled.',
                    'severity' => 'High',
                    'confidence' => 'Low',
                    'category' => 'XXE Injection',
                    'cwe' => 'CWE-611',
                    'owasp' => 'A05:2021 Security Misconfiguration',
                    'remediation' => 'Set $doc->substituteEntities = false and use LIBXML_NONET | LIBXML_NOENT flags.',
                    'references' => [],
                ], $node);
            }
        }
    }

    /**
     * 9. SSRF (Server-Side Request Forgery)
     */
    private function checkSSRF(Node $node): void
    {
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);

            // file_get_contents / fopen with user-controlled URL
            if (in_array($name, ['file_get_contents', 'fopen'], true) && !empty($node->args)) {
                $urlArg = $node->args[0]->value;
                if ($this->containsTaintedInput($urlArg)) {
                    // Check if the argument could be a URL (not just a local file path)
                    $this->addVulnerability([
                        'title' => 'Server-Side Request Forgery (SSRF) via ' . $name . '()',
                        'description' => "User-controlled input is used as a URL in {$name}(), allowing an attacker to make requests to internal services or arbitrary external hosts.",
                        'severity' => 'High',
                        'confidence' => 'Medium',
                        'category' => 'SSRF',
                        'cwe' => 'CWE-918',
                        'owasp' => 'A10:2021 Server-Side Request Forgery',
                        'remediation' => 'Validate and whitelist allowed URLs/domains. Use a URL parser to verify the scheme and host. Block internal/private IP ranges.',
                        'references' => ['https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'],
                    ], $node);
                }
            }

            // curl_setopt with CURLOPT_URL from user input
            if ($name === 'curl_setopt' && count($node->args) >= 3) {
                $optArg = $node->args[1]->value;
                if ($this->containsConstant($optArg, 'CURLOPT_URL')) {
                    $urlArg = $node->args[2]->value;
                    if ($this->containsTaintedInput($urlArg)) {
                        $this->addVulnerability([
                            'title' => 'SSRF via curl_setopt() with user-controlled URL',
                            'description' => 'User input is used to set the CURL URL, allowing SSRF attacks against internal services.',
                            'severity' => 'High',
                            'confidence' => 'High',
                            'category' => 'SSRF',
                            'cwe' => 'CWE-918',
                            'owasp' => 'A10:2021 Server-Side Request Forgery',
                            'remediation' => 'Validate and whitelist allowed URLs. Block requests to internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).',
                            'references' => [],
                        ], $node);
                    }
                }
            }
        }
    }

    /**
     * 10. LDAP Injection
     */
    private function checkLDAPInjection(Node $node): void
    {
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);
            $ldapFunctions = ['ldap_search', 'ldap_list', 'ldap_read', 'ldap_add', 'ldap_modify', 'ldap_delete'];

            if (in_array($name, $ldapFunctions, true) && !empty($node->args)) {
                // The filter argument (3rd for search/list/read)
                $filterIdx = in_array($name, ['ldap_search', 'ldap_list', 'ldap_read'], true) ? 2 : 0;
                if (isset($node->args[$filterIdx])) {
                    $filterArg = $node->args[$filterIdx]->value;
                    if ($this->containsTaintedInput($filterArg)) {
                        $this->addVulnerability([
                            'title' => 'LDAP Injection via ' . $name . '()',
                            'description' => "User input is used in the LDAP filter of {$name}() without proper escaping, allowing LDAP injection.",
                            'severity' => 'High',
                            'confidence' => 'High',
                            'category' => 'LDAP Injection',
                            'cwe' => 'CWE-90',
                            'owasp' => 'A03:2021 Injection',
                            'remediation' => 'Use ldap_escape() to properly escape user input in LDAP filters.',
                            'references' => ['https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html'],
                        ], $node);
                    }
                }
            }
        }
    }

    /**
     * 11. Hardcoded Secrets
     */
    private function checkHardcodedSecrets(Node $node): void
    {
        if ($node instanceof Expr\Assign) {
            $var = $node->var;
            $expr = $node->expr;

            if ($var instanceof Expr\Variable && is_string($var->name) && $expr instanceof Scalar\String_) {
                $varName = strtolower($var->name);
                $value = $expr->value;

                // Skip empty, short, or placeholder values
                if (strlen($value) < 6 || in_array($value, ['changeme', 'CHANGEME', 'xxx', 'TODO', 'placeholder', ''], true)) {
                    return;
                }

                $secretPatterns = [
                    'password' => 'Password',
                    'passwd' => 'Password',
                    'pwd' => 'Password',
                    'secret' => 'Secret',
                    'api_key' => 'API Key',
                    'apikey' => 'API Key',
                    'api_secret' => 'API Secret',
                    'access_key' => 'Access Key',
                    'access_token' => 'Access Token',
                    'auth_token' => 'Auth Token',
                    'private_key' => 'Private Key',
                    'db_password' => 'Database Password',
                    'database_password' => 'Database Password',
                    'mysql_password' => 'Database Password',
                    'connection_string' => 'Connection String',
                ];

                foreach ($secretPatterns as $pattern => $secretType) {
                    if (str_contains($varName, $pattern)) {
                        $this->addVulnerability([
                            'title' => "Hardcoded {$secretType} in Source Code",
                            'description' => "A {$secretType} appears to be hardcoded in the variable \${$var->name}. Hardcoded credentials can be extracted from source code or version control.",
                            'severity' => 'High',
                            'confidence' => 'High',
                            'category' => 'Hardcoded Secrets',
                            'cwe' => 'CWE-798',
                            'owasp' => 'A07:2021 Identification and Authentication Failures',
                            'remediation' => 'Store secrets in environment variables, a secure vault (e.g., HashiCorp Vault), or encrypted configuration files. Never hardcode credentials in source code.',
                            'references' => ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
                        ], $node);
                        break;
                    }
                }
            }
        }

        // Also check define() for hardcoded secrets
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);
            if ($name === 'define' && count($node->args) >= 2) {
                $constNameArg = $node->args[0]->value;
                $constValueArg = $node->args[1]->value;
                if ($constNameArg instanceof Scalar\String_ && $constValueArg instanceof Scalar\String_) {
                    $constName = strtolower($constNameArg->value);
                    $value = $constValueArg->value;
                    if (strlen($value) >= 6) {
                        $secretKeywords = ['password', 'secret', 'api_key', 'apikey', 'token', 'private_key', 'db_pass'];
                        foreach ($secretKeywords as $keyword) {
                            if (str_contains($constName, $keyword)) {
                                $this->addVulnerability([
                                    'title' => 'Hardcoded Secret in define() Constant',
                                    'description' => "A secret value appears to be hardcoded in the constant '{$constNameArg->value}'.",
                                    'severity' => 'High',
                                    'confidence' => 'High',
                                    'category' => 'Hardcoded Secrets',
                                    'cwe' => 'CWE-798',
                                    'owasp' => 'A07:2021 Identification and Authentication Failures',
                                    'remediation' => 'Use environment variables: define(\'DB_PASSWORD\', getenv(\'DB_PASSWORD\'));',
                                    'references' => [],
                                ], $node);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * 12. Weak Cryptography
     */
    private function checkWeakCryptography(Node $node): void
    {
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);

            // md5/sha1 for password hashing
            if (in_array($name, ['md5', 'sha1'], true)) {
                $this->addVulnerability([
                    'title' => "Weak Hashing Algorithm: {$name}()",
                    'description' => "{$name}() is cryptographically weak and unsuitable for password hashing or security-sensitive operations. It is vulnerable to collision attacks and can be brute-forced rapidly.",
                    'severity' => 'Medium',
                    'confidence' => 'Medium',
                    'category' => 'Weak Cryptography',
                    'cwe' => 'CWE-328',
                    'owasp' => 'A02:2021 Cryptographic Failures',
                    'remediation' => 'For passwords, use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2ID. For data integrity, use hash(\'sha256\', $data) or stronger.',
                    'references' => ['https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html'],
                ], $node);
            }

            // Deprecated mcrypt functions
            if (str_starts_with($name ?? '', 'mcrypt_')) {
                $this->addVulnerability([
                    'title' => 'Deprecated Cryptography: mcrypt Extension',
                    'description' => 'The mcrypt extension is deprecated since PHP 7.1 and removed in PHP 7.2. It contains known vulnerabilities.',
                    'severity' => 'High',
                    'confidence' => 'High',
                    'category' => 'Weak Cryptography',
                    'cwe' => 'CWE-327',
                    'owasp' => 'A02:2021 Cryptographic Failures',
                    'remediation' => 'Use the openssl extension or the sodium extension (libsodium) for modern cryptographic operations.',
                    'references' => [],
                ], $node);
            }

            // openssl with weak ciphers
            if ($name === 'openssl_encrypt' && !empty($node->args) && count($node->args) >= 2) {
                $cipherArg = $node->args[1]->value;
                if ($cipherArg instanceof Scalar\String_) {
                    $weakCiphers = ['des', 'des-ede', 'rc2', 'rc4', 'bf-ecb', 'des-ecb', 'aes-128-ecb', 'aes-256-ecb'];
                    if (in_array(strtolower($cipherArg->value), $weakCiphers, true)) {
                        $this->addVulnerability([
                            'title' => 'Weak Cipher Algorithm: ' . $cipherArg->value,
                            'description' => "The cipher '{$cipherArg->value}' is considered weak. ECB mode does not provide semantic security, and DES/RC4 have known vulnerabilities.",
                            'severity' => 'High',
                            'confidence' => 'High',
                            'category' => 'Weak Cryptography',
                            'cwe' => 'CWE-327',
                            'owasp' => 'A02:2021 Cryptographic Failures',
                            'remediation' => 'Use AES-256-GCM or AES-256-CBC with HMAC for authenticated encryption.',
                            'references' => [],
                        ], $node);
                    }
                }
            }

            // crypt() with weak algorithms
            if ($name === 'crypt') {
                $this->addVulnerability([
                    'title' => 'Potentially Weak Password Hashing via crypt()',
                    'description' => 'crypt() may use weak hashing algorithms (DES, MD5) depending on the salt format. Use password_hash() instead.',
                    'severity' => 'Medium',
                    'confidence' => 'Low',
                    'category' => 'Weak Cryptography',
                    'cwe' => 'CWE-916',
                    'owasp' => 'A02:2021 Cryptographic Failures',
                    'remediation' => 'Use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2ID.',
                    'references' => [],
                ], $node);
            }
        }
    }

    /**
     * 13. Insecure Random
     */
    private function checkInsecureRandom(Node $node): void
    {
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);
            $insecureRandomFuncs = [
                'rand' => 'rand()',
                'mt_rand' => 'mt_rand()',
                'srand' => 'srand()',
                'mt_srand' => 'mt_srand()',
                'array_rand' => 'array_rand()',
                'shuffle' => 'shuffle()',
                'str_shuffle' => 'str_shuffle()',
                'uniqid' => 'uniqid()',
            ];

            if (isset($insecureRandomFuncs[$name])) {
                $this->addVulnerability([
                    'title' => 'Insecure Random Number Generation: ' . $insecureRandomFuncs[$name],
                    'description' => "{$insecureRandomFuncs[$name]} uses a predictable pseudo-random number generator. Do not use for security-sensitive operations (tokens, passwords, keys).",
                    'severity' => 'Medium',
                    'confidence' => 'Medium',
                    'category' => 'Insecure Randomness',
                    'cwe' => 'CWE-338',
                    'owasp' => 'A02:2021 Cryptographic Failures',
                    'remediation' => 'Use random_bytes() or random_int() for cryptographically secure random values.',
                    'references' => ['https://www.php.net/manual/en/function.random-bytes.php'],
                ], $node);
            }
        }
    }

    /**
     * 14. Laravel-specific vulnerabilities
     */
    private function checkLaravelSpecific(Node $node): void
    {
        // Blade {!! !!} unescaped output (detected as Expr\FuncCall to raw/Js::from)
        if ($node instanceof Expr\MethodCall || $node instanceof Expr\StaticCall) {
            $methodName = TaintTracker::getMethodName($node);

            // DB::raw with user input
            if ($methodName === 'raw' && !empty($node->args)) {
                $arg = $node->args[0]->value;
                if ($this->containsTaintedInput($arg)) {
                    $this->addVulnerability([
                        'title' => 'SQL Injection via DB::raw() with User Input',
                        'description' => 'User input is passed to DB::raw() or whereRaw(), bypassing Laravel\'s query builder parameterization.',
                        'severity' => 'Critical',
                        'confidence' => 'High',
                        'category' => 'SQL Injection',
                        'cwe' => 'CWE-89',
                        'owasp' => 'A03:2021 Injection',
                        'remediation' => 'Use parameterized queries: DB::raw("column = ?", [$value]) or use the query builder: ->where(\'column\', $value).',
                        'references' => ['https://laravel.com/docs/queries#raw-expressions'],
                    ], $node);
                }
            }

            // whereRaw, selectRaw, havingRaw, orderByRaw with user input
            if (in_array($methodName, ['whereRaw', 'selectRaw', 'havingRaw', 'orderByRaw', 'groupByRaw'], true) && !empty($node->args)) {
                $arg = $node->args[0]->value;
                if ($this->containsTaintedInput($arg) && count($node->args) < 2) {
                    $this->addVulnerability([
                        'title' => "SQL Injection via {$methodName}() without Bindings",
                        'description' => "User input is passed to {$methodName}() without parameter bindings, allowing SQL injection.",
                        'severity' => 'Critical',
                        'confidence' => 'High',
                        'category' => 'SQL Injection',
                        'cwe' => 'CWE-89',
                        'owasp' => 'A03:2021 Injection',
                        'remediation' => "Pass bindings as the second argument: ->{$methodName}('column = ?', [\$value])",
                        'references' => [],
                    ], $node);
                }
            }
        }

        // Mass assignment - check for class extending Model without $fillable/$guarded
        // (This is handled in checkLaravelMassAssignment)
    }

    private function checkLaravelMassAssignment(Stmt\Class_ $node): void
    {
        // Check if class extends Model
        if ($node->extends === null) {
            return;
        }
        $parentName = $node->extends->toString();
        if (!in_array($parentName, ['Model', 'Eloquent', 'Authenticatable'], true) &&
            !str_contains($parentName, 'Model')) {
            return;
        }

        $hasFillable = false;
        $hasGuarded = false;

        foreach ($node->stmts as $stmt) {
            if ($stmt instanceof Stmt\Property) {
                foreach ($stmt->props as $prop) {
                    $propName = $prop->name->toString();
                    if ($propName === 'fillable') $hasFillable = true;
                    if ($propName === 'guarded') $hasGuarded = true;
                }
            }
        }

        if (!$hasFillable && !$hasGuarded) {
            $this->addVulnerability([
                'title' => 'Laravel Mass Assignment Vulnerability',
                'description' => "The model '{$node->name}' extends Model but does not define \$fillable or \$guarded, making it vulnerable to mass assignment attacks.",
                'severity' => 'High',
                'confidence' => 'High',
                'category' => 'Mass Assignment',
                'cwe' => 'CWE-915',
                'owasp' => 'A04:2021 Insecure Design',
                'remediation' => 'Define the $fillable array with allowed attributes or $guarded array with protected attributes on the Eloquent model.',
                'references' => ['https://laravel.com/docs/eloquent#mass-assignment'],
            ], $node);
        }
    }

    /**
     * 15. WordPress-specific vulnerabilities
     */
    private function checkWordPressSpecific(Node $node): void
    {
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);

            // Check for unescaped output functions
            if (in_array($name, ['_e', '__'], true) && !empty($node->args)) {
                // These are translation functions, not always vuln, but if echoed without esc_html
                // We check only direct echo of __() without escaping
            }
        }

        // echo without esc_html / esc_attr
        if ($node instanceof Stmt\Echo_) {
            foreach ($node->exprs as $expr) {
                if ($expr instanceof Expr\FuncCall) {
                    $name = TaintTracker::getFuncName($expr);
                    if (in_array($name, ['__', '_e', 'get_the_title', 'get_the_content', 'get_post_meta', 'get_option'], true)) {
                        $this->addVulnerability([
                            'title' => 'WordPress XSS: Unescaped Output of ' . $name . '()',
                            'description' => "The output of {$name}() is echoed without proper escaping. Use esc_html() or esc_attr() to prevent XSS.",
                            'severity' => 'Medium',
                            'confidence' => 'Medium',
                            'category' => 'Cross-Site Scripting',
                            'cwe' => 'CWE-79',
                            'owasp' => 'A03:2021 Injection',
                            'remediation' => "Use esc_html({$name}(...)) for HTML context or esc_attr() for attribute context.",
                            'references' => ['https://developer.wordpress.org/plugins/security/securing-output/'],
                        ], $node);
                    }
                }
            }
        }

        // Check for missing nonce verification in form handlers
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);
            if (in_array($name, ['update_option', 'update_post_meta', 'wp_update_user', 'wp_insert_post', 'wp_delete_post'], true)) {
                // Flag if no wp_verify_nonce nearby (simplified check)
                $this->addVulnerability([
                    'title' => 'WordPress CSRF: ' . $name . '() Without Nonce Verification',
                    'description' => "The state-changing function {$name}() should be protected by wp_verify_nonce() or check_admin_referer() to prevent CSRF attacks.",
                    'severity' => 'Medium',
                    'confidence' => 'Low',
                    'category' => 'CSRF',
                    'cwe' => 'CWE-352',
                    'owasp' => 'A01:2021 Broken Access Control',
                    'remediation' => "Add nonce verification: if (!wp_verify_nonce(\$_POST['_wpnonce'], 'action_name')) { die('Security check failed'); }",
                    'references' => ['https://developer.wordpress.org/plugins/security/nonces/'],
                ], $node);
            }
        }
    }

    /**
     * 16. CodeIgniter-specific vulnerabilities
     */
    private function checkCodeIgniterSpecific(Node $node): void
    {
        if ($node instanceof Expr\MethodCall) {
            $methodName = TaintTracker::getMethodName($node);

            // $this->input->get/post without XSS filtering
            if (in_array($methodName, ['get', 'post', 'get_post'], true)) {
                $varNode = $node->var;
                if ($varNode instanceof Expr\PropertyFetch) {
                    $propName = TaintTracker::getPropertyName($varNode);
                    if ($propName === 'input') {
                        // Check if second argument (xss_clean) is TRUE
                        $hasXssClean = false;
                        if (count($node->args) >= 2) {
                            $xssArg = $node->args[1]->value;
                            if ($xssArg instanceof Expr\ConstFetch && strtolower($xssArg->name->toString()) === 'true') {
                                $hasXssClean = true;
                            }
                        }
                        if (!$hasXssClean) {
                            $this->addVulnerability([
                                'title' => 'CodeIgniter: Input Without XSS Filtering',
                                'description' => "\$this->input->{$methodName}() is called without the XSS filtering parameter set to TRUE.",
                                'severity' => 'Medium',
                                'confidence' => 'Medium',
                                'category' => 'Cross-Site Scripting',
                                'cwe' => 'CWE-79',
                                'owasp' => 'A03:2021 Injection',
                                'remediation' => "Use \$this->input->{$methodName}('field', TRUE) to enable XSS filtering, or apply htmlspecialchars() on output.",
                                'references' => [],
                            ], $node);
                        }
                    }
                }
            }
        }
    }

    /**
     * 17. Symfony-specific vulnerabilities
     */
    private function checkSymfonySpecific(Node $node): void
    {
        if ($node instanceof Expr\MethodCall) {
            $methodName = TaintTracker::getMethodName($node);

            // Response with raw user content
            if ($methodName === 'setContent' && !empty($node->args)) {
                $arg = $node->args[0]->value;
                if ($this->containsTaintedInput($arg)) {
                    $this->addVulnerability([
                        'title' => 'Symfony XSS: Raw User Input in Response',
                        'description' => 'User input is set directly as response content without escaping. Use Twig\'s auto-escaping or htmlspecialchars().',
                        'severity' => 'High',
                        'confidence' => 'Medium',
                        'category' => 'Cross-Site Scripting',
                        'cwe' => 'CWE-79',
                        'owasp' => 'A03:2021 Injection',
                        'remediation' => 'Use Twig templates with auto-escaping or escape output with htmlspecialchars().',
                        'references' => [],
                    ], $node);
                }
            }
        }
    }

    /**
     * 18. Session Issues
     */
    private function checkSessionIssues(Node $node): void
    {
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);

            // session_start() without secure settings
            if ($name === 'session_start') {
                // Check if session config is set via arguments
                $hasSecureConfig = false;
                if (!empty($node->args)) {
                    $hasSecureConfig = true; // Has config array, might be secure
                }
                if (!$hasSecureConfig) {
                    $this->addVulnerability([
                        'title' => 'Session Configuration Not Hardened',
                        'description' => 'session_start() is called without explicit security configuration. Consider setting cookie_httponly, cookie_secure, and use_strict_mode.',
                        'severity' => 'Low',
                        'confidence' => 'Low',
                        'category' => 'Session Security',
                        'cwe' => 'CWE-614',
                        'owasp' => 'A07:2021 Identification and Authentication Failures',
                        'remediation' => 'Configure secure session settings: session_start(["cookie_httponly" => true, "cookie_secure" => true, "use_strict_mode" => true, "cookie_samesite" => "Strict"]);',
                        'references' => ['https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html'],
                    ], $node);
                }
            }

            // session_id() set from user input (session fixation)
            if ($name === 'session_id' && !empty($node->args)) {
                $arg = $node->args[0]->value;
                if ($this->containsTaintedInput($arg)) {
                    $this->addVulnerability([
                        'title' => 'Session Fixation via session_id()',
                        'description' => 'User input is used to set the session ID, allowing session fixation attacks.',
                        'severity' => 'High',
                        'confidence' => 'High',
                        'category' => 'Session Fixation',
                        'cwe' => 'CWE-384',
                        'owasp' => 'A07:2021 Identification and Authentication Failures',
                        'remediation' => 'Never accept session IDs from user input. Use session_regenerate_id(true) after authentication.',
                        'references' => [],
                    ], $node);
                }
            }
        }
    }

    /**
     * 19. File Upload
     */
    private function checkFileUpload(Node $node): void
    {
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);

            if ($name === 'move_uploaded_file') {
                // Check if the destination uses user-controlled filename
                if (count($node->args) >= 2) {
                    $destArg = $node->args[1]->value;
                    if ($this->containsTaintedInput($destArg)) {
                        $this->addVulnerability([
                            'title' => 'Insecure File Upload: User-Controlled Destination',
                            'description' => 'The destination path for move_uploaded_file() contains user input, allowing path traversal or overwriting critical files.',
                            'severity' => 'High',
                            'confidence' => 'High',
                            'category' => 'Insecure File Upload',
                            'cwe' => 'CWE-434',
                            'owasp' => 'A04:2021 Insecure Design',
                            'remediation' => 'Generate a random filename server-side. Validate file type using finfo_file() (not just the extension). Store uploads outside the web root.',
                            'references' => ['https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html'],
                        ], $node);
                    }
                }

                // General file upload warning
                $this->addVulnerability([
                    'title' => 'File Upload Detected: Ensure Proper Validation',
                    'description' => 'move_uploaded_file() is used. Ensure the file type is validated using finfo_file() (MIME check), the extension is whitelisted, and files are stored outside the web root.',
                    'severity' => 'Medium',
                    'confidence' => 'Low',
                    'category' => 'Insecure File Upload',
                    'cwe' => 'CWE-434',
                    'owasp' => 'A04:2021 Insecure Design',
                    'remediation' => 'Validate file MIME type with finfo_file(), whitelist allowed extensions, generate random filenames, and store files outside the web root.',
                    'references' => [],
                ], $node);
            }
        }
    }

    /**
     * 20. Open Redirect
     */
    private function checkOpenRedirect(Node $node): void
    {
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);

            if ($name === 'header' && !empty($node->args)) {
                $headerArg = $node->args[0]->value;

                // Check for "Location: " concatenated with user input
                if ($headerArg instanceof Expr\BinaryOp\Concat) {
                    $left = $headerArg->left;
                    if ($left instanceof Scalar\String_ && str_contains(strtolower($left->value), 'location:')) {
                        if ($this->containsTaintedInput($headerArg->right)) {
                            $this->addVulnerability([
                                'title' => 'Open Redirect via header()',
                                'description' => 'User input controls the Location header redirect URL, allowing phishing attacks by redirecting to malicious sites.',
                                'severity' => 'Medium',
                                'confidence' => 'High',
                                'category' => 'Open Redirect',
                                'cwe' => 'CWE-601',
                                'owasp' => 'A01:2021 Broken Access Control',
                                'remediation' => 'Validate redirect URLs against a whitelist of allowed destinations. Use relative URLs or verify the domain matches your application.',
                                'references' => ['https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'],
                            ], $node);
                        }
                    }
                }

                // Check for interpolated string with Location
                if ($headerArg instanceof Scalar\InterpolatedString) {
                    $hasLocation = false;
                    $hasTaint = false;
                    foreach ($headerArg->parts as $part) {
                        if ($part instanceof Scalar\InterpolatedStringPart && str_contains(strtolower($part->value), 'location:')) {
                            $hasLocation = true;
                        }
                        if ($part instanceof Node && $this->containsTaintedInput($part)) {
                            $hasTaint = true;
                        }
                    }
                    if ($hasLocation && $hasTaint) {
                        $this->addVulnerability([
                            'title' => 'Open Redirect via header()',
                            'description' => 'User input is interpolated into a Location header, allowing open redirect attacks.',
                            'severity' => 'Medium',
                            'confidence' => 'High',
                            'category' => 'Open Redirect',
                            'cwe' => 'CWE-601',
                            'owasp' => 'A01:2021 Broken Access Control',
                            'remediation' => 'Validate redirect URLs against a whitelist of allowed destinations.',
                            'references' => [],
                        ], $node);
                    }
                }
            }
        }
    }

    /**
     * 21. Information Disclosure
     */
    private function checkInformationDisclosure(Node $node): void
    {
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);

            // phpinfo()
            if ($name === 'phpinfo') {
                $this->addVulnerability([
                    'title' => 'Information Disclosure via phpinfo()',
                    'description' => 'phpinfo() exposes detailed PHP configuration, environment variables, and server information. This must never be accessible in production.',
                    'severity' => 'Medium',
                    'confidence' => 'High',
                    'category' => 'Information Disclosure',
                    'cwe' => 'CWE-200',
                    'owasp' => 'A05:2021 Security Misconfiguration',
                    'remediation' => 'Remove phpinfo() calls from production code. If needed for debugging, protect it with authentication and IP restrictions.',
                    'references' => [],
                ], $node);
            }

            // var_dump, print_r, debug_zval_dump, debug_print_backtrace
            if (in_array($name, ['var_dump', 'print_r', 'debug_zval_dump', 'debug_print_backtrace', 'debug_backtrace'], true)) {
                $this->addVulnerability([
                    'title' => 'Debug Output: ' . $name . '()',
                    'description' => "{$name}() outputs detailed debugging information. If accessible in production, it may expose sensitive data structures.",
                    'severity' => 'Low',
                    'confidence' => 'Medium',
                    'category' => 'Information Disclosure',
                    'cwe' => 'CWE-200',
                    'owasp' => 'A05:2021 Security Misconfiguration',
                    'remediation' => 'Remove debugging functions from production code or conditionally enable only in development.',
                    'references' => [],
                ], $node);
            }

            // error_reporting(E_ALL)
            if ($name === 'error_reporting' && !empty($node->args)) {
                $arg = $node->args[0]->value;
                if ($this->containsConstant($arg, 'E_ALL')) {
                    $this->addVulnerability([
                        'title' => 'Verbose Error Reporting Enabled',
                        'description' => 'error_reporting(E_ALL) shows detailed error messages that may expose file paths, database structures, and other sensitive information.',
                        'severity' => 'Low',
                        'confidence' => 'Medium',
                        'category' => 'Information Disclosure',
                        'cwe' => 'CWE-209',
                        'owasp' => 'A05:2021 Security Misconfiguration',
                        'remediation' => 'In production, set error_reporting(0) and log errors to a file: ini_set("log_errors", 1); ini_set("error_log", "/path/to/error.log");',
                        'references' => [],
                    ], $node);
                }
            }

            // ini_set('display_errors', '1')
            if ($name === 'ini_set' && count($node->args) >= 2) {
                $settingArg = $node->args[0]->value;
                $valueArg = $node->args[1]->value;
                if ($settingArg instanceof Scalar\String_ && $settingArg->value === 'display_errors') {
                    if ($valueArg instanceof Scalar\String_ && in_array($valueArg->value, ['1', 'On', 'true'], true)) {
                        $this->addVulnerability([
                            'title' => 'Display Errors Enabled',
                            'description' => 'display_errors is set to On, which shows error details to users including file paths and stack traces.',
                            'severity' => 'Medium',
                            'confidence' => 'High',
                            'category' => 'Information Disclosure',
                            'cwe' => 'CWE-209',
                            'owasp' => 'A05:2021 Security Misconfiguration',
                            'remediation' => 'Set display_errors to Off in production: ini_set("display_errors", "0"); Use log_errors instead.',
                            'references' => [],
                        ], $node);
                    }
                }
            }
        }
    }

    /**
     * 22. Cookie Security
     */
    private function checkCookieSecurity(Node $node): void
    {
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);

            if ($name === 'setcookie') {
                $argCount = count($node->args);

                // setcookie(name, value, expires, path, domain, secure, httponly)
                // In PHP 7.3+, can also accept options array as 3rd arg

                $hasSecure = false;
                $hasHttpOnly = false;

                if ($argCount >= 7) {
                    // Traditional signature
                    $secureArg = $node->args[5]->value ?? null;
                    $httpOnlyArg = $node->args[6]->value ?? null;

                    if ($secureArg instanceof Expr\ConstFetch && strtolower($secureArg->name->toString()) === 'true') {
                        $hasSecure = true;
                    }
                    if ($httpOnlyArg instanceof Expr\ConstFetch && strtolower($httpOnlyArg->name->toString()) === 'true') {
                        $hasHttpOnly = true;
                    }
                } elseif ($argCount >= 3) {
                    // Check if 3rd arg is array (PHP 7.3+ options)
                    $thirdArg = $node->args[2]->value ?? null;
                    if ($thirdArg instanceof Expr\Array_) {
                        foreach ($thirdArg->items as $item) {
                            if ($item->key instanceof Scalar\String_) {
                                $key = strtolower($item->key->value);
                                if ($key === 'secure' && $item->value instanceof Expr\ConstFetch && strtolower($item->value->name->toString()) === 'true') {
                                    $hasSecure = true;
                                }
                                if ($key === 'httponly' && $item->value instanceof Expr\ConstFetch && strtolower($item->value->name->toString()) === 'true') {
                                    $hasHttpOnly = true;
                                }
                            }
                        }
                    }
                }

                if (!$hasSecure) {
                    $this->addVulnerability([
                        'title' => 'Cookie Without Secure Flag',
                        'description' => 'setcookie() is called without the Secure flag. The cookie will be sent over unencrypted HTTP connections.',
                        'severity' => 'Medium',
                        'confidence' => 'Medium',
                        'category' => 'Cookie Security',
                        'cwe' => 'CWE-614',
                        'owasp' => 'A05:2021 Security Misconfiguration',
                        'remediation' => 'Set the Secure flag: setcookie($name, $value, ["secure" => true, "httponly" => true, "samesite" => "Strict"]);',
                        'references' => [],
                    ], $node);
                }

                if (!$hasHttpOnly) {
                    $this->addVulnerability([
                        'title' => 'Cookie Without HttpOnly Flag',
                        'description' => 'setcookie() is called without the HttpOnly flag. The cookie can be accessed by JavaScript, increasing XSS impact.',
                        'severity' => 'Medium',
                        'confidence' => 'Medium',
                        'category' => 'Cookie Security',
                        'cwe' => 'CWE-1004',
                        'owasp' => 'A05:2021 Security Misconfiguration',
                        'remediation' => 'Set the HttpOnly flag to prevent JavaScript access to the cookie.',
                        'references' => [],
                    ], $node);
                }
            }
        }
    }

    /**
     * 23. Type Juggling
     */
    private function checkTypeJuggling(Node $node): void
    {
        // Loose comparison (==) with security-sensitive operations
        if ($node instanceof Expr\BinaryOp\Equal || $node instanceof Expr\BinaryOp\NotEqual) {
            // Check if this is comparing passwords, tokens, hashes, etc.
            $leftName = $this->getVarName($node->left);
            $rightName = $this->getVarName($node->right);

            $sensitiveNames = ['password', 'passwd', 'token', 'hash', 'secret', 'key', 'nonce', 'csrf', 'api_key'];

            $isSensitive = false;
            foreach ($sensitiveNames as $name) {
                if (($leftName && str_contains(strtolower($leftName), $name)) ||
                    ($rightName && str_contains(strtolower($rightName), $name))) {
                    $isSensitive = true;
                    break;
                }
            }

            if ($isSensitive) {
                $op = $node instanceof Expr\BinaryOp\Equal ? '==' : '!=';
                $this->addVulnerability([
                    'title' => "Type Juggling: Loose Comparison ({$op}) on Security Value",
                    'description' => "Loose comparison ({$op}) is used with a security-sensitive value. PHP type juggling can cause '0e123' == '0e456' to evaluate as true, bypassing authentication.",
                    'severity' => 'High',
                    'confidence' => 'Medium',
                    'category' => 'Type Juggling',
                    'cwe' => 'CWE-697',
                    'owasp' => 'A02:2021 Cryptographic Failures',
                    'remediation' => "Use strict comparison (=== / !==) or hash_equals() for comparing security tokens and password hashes.",
                    'references' => ['https://www.php.net/manual/en/types.comparisons.php'],
                ], $node);
            }
        }
    }

    /**
     * 25. CSRF Missing
     */
    private function checkCSRFMissing(Node $node): void
    {
        // Detect form processing without CSRF token validation
        if ($node instanceof Expr\BinaryOp\Identical || $node instanceof Expr\BinaryOp\Equal) {
            // Check for $_SERVER['REQUEST_METHOD'] == 'POST' without CSRF
            $left = $node->left;
            if ($left instanceof Expr\ArrayDimFetch && $left->var instanceof Expr\Variable) {
                if (is_string($left->var->name) && $left->var->name === '_SERVER') {
                    $dim = $left->dim;
                    if ($dim instanceof Scalar\String_ && $dim->value === 'REQUEST_METHOD') {
                        $right = $node->right;
                        if ($right instanceof Scalar\String_ && $right->value === 'POST') {
                            // POST form handler detected - flag if no CSRF pattern nearby
                            $this->addVulnerability([
                                'title' => 'Potential CSRF: POST Handler Without Token Validation',
                                'description' => 'A POST request handler is detected without visible CSRF token validation. Form submissions should include and verify a CSRF token.',
                                'severity' => 'Medium',
                                'confidence' => 'Low',
                                'category' => 'CSRF',
                                'cwe' => 'CWE-352',
                                'owasp' => 'A01:2021 Broken Access Control',
                                'remediation' => 'Generate a CSRF token per session, include it in forms as a hidden field, and validate it on the server before processing.',
                                'references' => ['https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'],
                            ], $node);
                        }
                    }
                }
            }
        }
    }

    /**
     * 26. Race Conditions
     */
    private function checkRaceConditions(Node $node): void
    {
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);

            // file_exists() followed by file operations (TOCTOU)
            if ($name === 'file_exists') {
                $this->addVulnerability([
                    'title' => 'Potential TOCTOU Race Condition',
                    'description' => 'file_exists() check followed by file operation creates a Time-of-Check-Time-of-Use (TOCTOU) race condition. The file state may change between the check and the operation.',
                    'severity' => 'Low',
                    'confidence' => 'Low',
                    'category' => 'Race Condition',
                    'cwe' => 'CWE-367',
                    'owasp' => 'A04:2021 Insecure Design',
                    'remediation' => 'Use atomic operations or file locking (flock()) instead of check-then-act patterns.',
                    'references' => [],
                ], $node);
            }
        }
    }

    /**
     * 27. Missing Input Validation
     */
    private function checkMissingInputValidation(Node $node): void
    {
        // Direct use of $_GET/$_POST in database operations without validation
        if ($node instanceof Expr\MethodCall) {
            $methodName = TaintTracker::getMethodName($node);
            $dbMethods = ['insert', 'update', 'delete', 'save', 'create'];
            if (in_array($methodName, $dbMethods, true) && !empty($node->args)) {
                foreach ($node->args as $arg) {
                    if ($this->containsTaintedInput($arg->value)) {
                        $this->addVulnerability([
                            'title' => "Missing Input Validation Before {$methodName}()",
                            'description' => "User input is passed directly to {$methodName}() without validation or sanitization.",
                            'severity' => 'Medium',
                            'confidence' => 'Medium',
                            'category' => 'Missing Input Validation',
                            'cwe' => 'CWE-20',
                            'owasp' => 'A03:2021 Injection',
                            'remediation' => 'Validate all user input before using it: check types, lengths, ranges, and patterns. Use filter_var() or validation libraries.',
                            'references' => ['https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html'],
                        ], $node);
                        break;
                    }
                }
            }
        }
    }

    /**
     * 28. Timing Attacks
     */
    private function checkTimingAttacks(Node $node): void
    {
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);

            // strcmp/strcasecmp for password comparison
            if (in_array($name, ['strcmp', 'strcasecmp', 'strncmp', 'strncasecmp'], true)) {
                // Check if comparing security-sensitive values
                $hasSensitiveArg = false;
                foreach ($node->args as $arg) {
                    $argName = $this->getVarName($arg->value);
                    if ($argName) {
                        $sensitiveNames = ['password', 'token', 'hash', 'secret', 'key', 'hmac', 'signature', 'digest'];
                        foreach ($sensitiveNames as $sensitive) {
                            if (str_contains(strtolower($argName), $sensitive)) {
                                $hasSensitiveArg = true;
                                break 2;
                            }
                        }
                    }
                }

                if ($hasSensitiveArg) {
                    $this->addVulnerability([
                        'title' => "Timing Attack via {$name}()",
                        'description' => "{$name}() performs byte-by-byte comparison and returns early on mismatch, making it vulnerable to timing attacks when comparing security tokens.",
                        'severity' => 'Medium',
                        'confidence' => 'High',
                        'category' => 'Timing Attack',
                        'cwe' => 'CWE-208',
                        'owasp' => 'A02:2021 Cryptographic Failures',
                        'remediation' => 'Use hash_equals() for constant-time string comparison of security-sensitive values.',
                        'references' => ['https://www.php.net/manual/en/function.hash-equals.php'],
                    ], $node);
                }
            }
        }

        // == / === comparison for passwords/tokens (also timing vulnerable)
        if ($node instanceof Expr\BinaryOp\Identical || $node instanceof Expr\BinaryOp\Equal) {
            $leftName = $this->getVarName($node->left);
            $rightName = $this->getVarName($node->right);

            $hashFunctions = ['md5', 'sha1', 'sha256', 'hash'];
            $leftIsHash = ($node->left instanceof Expr\FuncCall && in_array(TaintTracker::getFuncName($node->left), $hashFunctions, true));
            $rightIsHash = ($node->right instanceof Expr\FuncCall && in_array(TaintTracker::getFuncName($node->right), $hashFunctions, true));

            if ($leftIsHash || $rightIsHash) {
                $this->addVulnerability([
                    'title' => 'Timing Attack: Direct Hash Comparison',
                    'description' => 'Hash values are compared using == or ===, which is vulnerable to timing attacks. Use hash_equals() instead.',
                    'severity' => 'Medium',
                    'confidence' => 'High',
                    'category' => 'Timing Attack',
                    'cwe' => 'CWE-208',
                    'owasp' => 'A02:2021 Cryptographic Failures',
                    'remediation' => 'Use hash_equals($known_hash, $user_hash) for constant-time comparison.',
                    'references' => [],
                ], $node);
            }
        }
    }

    /**
     * 29. Email Injection
     */
    private function checkEmailInjection(Node $node): void
    {
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);

            if ($name === 'mail') {
                // Check 'to' (1st arg), 'subject' (2nd), 'additional_headers' (4th)
                $headerIdx = 3; // 4th argument (0-indexed: 3) = additional headers
                $toIdx = 0;

                // Check 'to' field for injection
                if (isset($node->args[$toIdx]) && $this->containsTaintedInput($node->args[$toIdx]->value)) {
                    $this->addVulnerability([
                        'title' => 'Email Injection via mail() To Field',
                        'description' => 'User input in the "to" parameter of mail() can inject additional recipients or headers via CRLF injection.',
                        'severity' => 'High',
                        'confidence' => 'High',
                        'category' => 'Email Injection',
                        'cwe' => 'CWE-93',
                        'owasp' => 'A03:2021 Injection',
                        'remediation' => 'Validate email addresses with filter_var($email, FILTER_VALIDATE_EMAIL). Strip \\r and \\n from all mail() parameters.',
                        'references' => [],
                    ], $node);
                }

                // Check additional headers for injection
                if (isset($node->args[$headerIdx]) && $this->containsTaintedInput($node->args[$headerIdx]->value)) {
                    $this->addVulnerability([
                        'title' => 'Email Header Injection via mail()',
                        'description' => 'User input in mail() additional_headers parameter allows CRLF injection to add arbitrary headers (Bcc, Cc, etc.).',
                        'severity' => 'High',
                        'confidence' => 'High',
                        'category' => 'Email Injection',
                        'cwe' => 'CWE-93',
                        'owasp' => 'A03:2021 Injection',
                        'remediation' => 'Use a mail library (PHPMailer, SwiftMailer) that handles header encoding properly. Strip CRLF characters from user input.',
                        'references' => [],
                    ], $node);
                }
            }
        }
    }

    /**
     * 30. Regex DoS (ReDoS)
     */
    private function checkRegexDoS(Node $node): void
    {
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);
            $regexFunctions = ['preg_match', 'preg_match_all', 'preg_replace', 'preg_split', 'preg_grep'];

            if (in_array($name, $regexFunctions, true) && !empty($node->args)) {
                $patternArg = $node->args[0]->value;

                // Check if pattern comes from user input
                if ($this->containsTaintedInput($patternArg)) {
                    $this->addVulnerability([
                        'title' => 'Regex DoS: User-Controlled Pattern',
                        'description' => "User input is used as a regex pattern in {$name}(), allowing ReDoS attacks with catastrophic backtracking or invalid patterns.",
                        'severity' => 'High',
                        'confidence' => 'High',
                        'category' => 'Regex DoS',
                        'cwe' => 'CWE-1333',
                        'owasp' => 'A06:2021 Vulnerable and Outdated Components',
                        'remediation' => 'Never use user input directly as a regex pattern. Use preg_quote() to escape user input if it must be part of a pattern, or validate against a whitelist.',
                        'references' => ['https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS'],
                    ], $node);
                }

                // Check for vulnerable patterns (nested quantifiers, alternation)
                if ($patternArg instanceof Scalar\String_) {
                    $pattern = $patternArg->value;
                    // Detect nested quantifiers like (a+)+, (a*)*,  (.+)+
                    if (preg_match('/\([^)]*[+*][^)]*\)[+*]/', $pattern) ||
                        preg_match('/\([^)]*\|[^)]*\)[+*]/', $pattern)) {
                        $this->addVulnerability([
                            'title' => 'Regex DoS: Vulnerable Pattern with Nested Quantifiers',
                            'description' => "The regex pattern contains nested quantifiers or alternation with quantifiers, which can cause catastrophic backtracking (ReDoS).",
                            'severity' => 'Medium',
                            'confidence' => 'Medium',
                            'category' => 'Regex DoS',
                            'cwe' => 'CWE-1333',
                            'owasp' => 'A06:2021 Vulnerable and Outdated Components',
                            'remediation' => 'Simplify the regex pattern to avoid nested quantifiers. Use atomic groups (?>...) or possessive quantifiers where supported.',
                            'references' => [],
                        ], $node);
                    }
                }
            }
        }
    }

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    /**
     * Track variable assignments for taint propagation.
     */
    private function trackTaintedAssignment(Expr\Assign $node): void
    {
        if ($node->var instanceof Expr\Variable && is_string($node->var->name)) {
            if ($this->containsTaintedInput($node->expr)) {
                $this->taintedVars[$node->var->name] = true;
            }
        }
    }

    /**
     * Check if expression contains tainted (user) input, including tracked variables.
     */
    private function containsTaintedInput(Node $node): bool
    {
        // Direct user input
        if (TaintTracker::containsUserInput($node)) {
            return true;
        }

        // Tracked tainted variable
        if ($node instanceof Expr\Variable && is_string($node->name)) {
            if (isset($this->taintedVars[$node->name])) {
                return true;
            }
        }

        // Concat with tainted var
        if ($node instanceof Expr\BinaryOp\Concat) {
            return $this->containsTaintedInput($node->left) || $this->containsTaintedInput($node->right);
        }

        // Interpolated string with tainted var
        if ($node instanceof Scalar\InterpolatedString) {
            foreach ($node->parts as $part) {
                if ($part instanceof Node && $this->containsTaintedInput($part)) {
                    return true;
                }
            }
        }

        // ArrayDimFetch on tainted var
        if ($node instanceof Expr\ArrayDimFetch) {
            return $this->containsTaintedInput($node->var);
        }

        // Function call with tainted argument (pass-through functions)
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);
            $passThroughFunctions = [
                'trim', 'ltrim', 'rtrim', 'strtolower', 'strtoupper',
                'substr', 'str_replace', 'strrev', 'ucfirst', 'lcfirst',
                'urldecode', 'rawurldecode', 'base64_decode', 'json_decode',
                'stripslashes', 'nl2br', 'wordwrap', 'sprintf', 'str_pad',
                'str_repeat', 'implode', 'join', 'chunk_split',
            ];
            if (in_array($name, $passThroughFunctions, true)) {
                foreach ($node->args as $arg) {
                    if ($this->containsTaintedInput($arg->value)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private function isStringConcat(Node $node): bool
    {
        return $node instanceof Expr\BinaryOp\Concat ||
               $node instanceof Scalar\InterpolatedString;
    }

    private function isShellEscaped(Node $node): bool
    {
        if ($node instanceof Expr\FuncCall) {
            $name = TaintTracker::getFuncName($node);
            return in_array($name, ['escapeshellarg', 'escapeshellcmd'], true);
        }
        if ($node instanceof Expr\BinaryOp\Concat) {
            // Check if any part is shell-escaped
            return $this->isShellEscaped($node->right) || $this->isShellEscaped($node->left);
        }
        return false;
    }

    private function containsConstant(Node $node, string $constantName): bool
    {
        if ($node instanceof Expr\ConstFetch && $node->name->toString() === $constantName) {
            return true;
        }
        if ($node instanceof Expr\BinaryOp\BitwiseOr) {
            return $this->containsConstant($node->left, $constantName) || $this->containsConstant($node->right, $constantName);
        }
        return false;
    }

    private function getVarName(Node $node): ?string
    {
        if ($node instanceof Expr\Variable && is_string($node->name)) {
            return $node->name;
        }
        if ($node instanceof Expr\PropertyFetch) {
            return TaintTracker::getPropertyName($node);
        }
        return null;
    }

    private function getParentNodeType(Node $node): string
    {
        // Simplified - we don't track parents in this implementation
        return '';
    }

    private function addVulnerability(array $data, Node $node): void
    {
        $this->vulnCounter++;
        $startLine = $node->getStartLine();
        $endLine = $node->getEndLine();

        $data['id'] = sprintf('PHP-%04d', $this->vulnCounter);
        $data['filePath'] = $this->filePath;
        $data['startLine'] = $startLine;
        $data['endLine'] = $endLine;
        $data['startColumn'] = 0;
        $data['endColumn'] = 0;
        $data['snippet'] = $this->getSnippet($startLine, $endLine);

        $this->vulnerabilities[] = new Vulnerability($data);
    }

    private function getSnippet(int $startLine, int $endLine): string
    {
        $lines = [];
        $contextBefore = 1;
        $contextAfter = 1;
        $start = max(0, $startLine - 1 - $contextBefore);
        $end = min(count($this->sourceLines) - 1, $endLine - 1 + $contextAfter);

        for ($i = $start; $i <= $end; $i++) {
            $lineNum = $i + 1;
            $prefix = ($lineNum >= $startLine && $lineNum <= $endLine) ? '> ' : '  ';
            $lines[] = $prefix . $lineNum . ': ' . ($this->sourceLines[$i] ?? '');
        }

        return implode("\n", $lines);
    }
}

// ============================================================================
// SCANNER ENGINE
// ============================================================================

class PhpSastScanner
{
    private \PhpParser\Parser $parser;

    public function __construct()
    {
        $this->parser = (new ParserFactory())->createForNewestSupportedVersion();
    }

    /**
     * Scan a set of files and return results.
     *
     * @param array<string, string> $files  Map of filePath => fileContent
     * @param string $scanId
     * @return array  ScanResult structure
     */
    public function scan(array $files, string $scanId): array
    {
        $startTime = microtime(true);
        $allVulnerabilities = [];
        $errors = [];
        $filesScanned = 0;

        foreach ($files as $filePath => $content) {
            try {
                $vulns = $this->scanFile($filePath, $content);
                $allVulnerabilities = array_merge($allVulnerabilities, $vulns);
                $filesScanned++;
            } catch (\Throwable $e) {
                $errors[] = "Error scanning {$filePath}: {$e->getMessage()}";
                $filesScanned++;
            }
        }

        $duration = round((microtime(true) - $startTime) * 1000);

        return [
            'scanId' => $scanId,
            'language' => LANGUAGE,
            'totalFiles' => count($files),
            'filesScanned' => $filesScanned,
            'vulnerabilities' => $allVulnerabilities,
            'errors' => $errors,
            'duration' => $duration . 'ms',
        ];
    }

    /**
     * Scan a single PHP file.
     *
     * @return Vulnerability[]
     */
    private function scanFile(string $filePath, string $content): array
    {
        try {
            $ast = $this->parser->parse($content);
        } catch (Error $e) {
            throw new \RuntimeException("Parse error: {$e->getMessage()}");
        }

        if ($ast === null) {
            return [];
        }

        $visitor = new VulnerabilityVisitor($filePath, $content);
        $traverser = new NodeTraverser();
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        return $visitor->getVulnerabilities();
    }
}

// ============================================================================
// HTTP SERVER (Router for PHP built-in server)
// ============================================================================

/**
 * This script serves as both the scanner logic and the router for PHP's built-in server.
 * Run with: php -S 0.0.0.0:9006 scanner.php
 */

// Only handle HTTP requests when running as server
if (php_sapi_name() === 'cli-server' || php_sapi_name() === 'cli') {
    // When running as CLI server, $_SERVER vars are available
    if (php_sapi_name() === 'cli-server') {
        handleRequest();
    } elseif (php_sapi_name() === 'cli' && isset($argv[0]) && basename($argv[0]) === 'scanner.php') {
        // Direct CLI execution - start the built-in server
        $cmd = sprintf('php -S 0.0.0.0:%d %s', PORT, __FILE__);
        echo "Starting PHP SAST Scanner v" . VERSION . " on port " . PORT . "\n";
        echo "Endpoints: GET /health, POST /scan\n";
        echo "Running: {$cmd}\n";
        passthru($cmd);
    }
}

function handleRequest(): void
{
    $uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    $method = $_SERVER['REQUEST_METHOD'];

    // Set CORS and content type headers
    header('Content-Type: application/json');
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');

    if ($method === 'OPTIONS') {
        http_response_code(200);
        return;
    }

    try {
        switch ($uri) {
            case '/health':
                if ($method !== 'GET') {
                    sendError(405, 'Method Not Allowed');
                    return;
                }
                handleHealth();
                break;

            case '/scan':
                if ($method !== 'POST') {
                    sendError(405, 'Method Not Allowed');
                    return;
                }
                handleScan();
                break;

            default:
                sendError(404, "Not Found: {$uri}");
                break;
        }
    } catch (\Throwable $e) {
        error_log("Internal error: " . $e->getMessage() . "\n" . $e->getTraceAsString());
        sendError(500, 'Internal Server Error: ' . $e->getMessage());
    }
}

function handleHealth(): void
{
    echo json_encode([
        'status' => 'healthy',
        'language' => LANGUAGE,
        'version' => VERSION,
        'port' => PORT,
        'categories' => [
            'SQL Injection',
            'Command Injection',
            'Code Injection',
            'Cross-Site Scripting',
            'Path Traversal',
            'File Inclusion',
            'Insecure Deserialization',
            'XXE Injection',
            'SSRF',
            'LDAP Injection',
            'Hardcoded Secrets',
            'Weak Cryptography',
            'Insecure Randomness',
            'Laravel Security',
            'WordPress Security',
            'CodeIgniter Security',
            'Symfony Security',
            'Session Security',
            'Insecure File Upload',
            'Open Redirect',
            'Information Disclosure',
            'Cookie Security',
            'Type Juggling',
            'Object Injection',
            'CSRF',
            'Race Condition',
            'Missing Input Validation',
            'Timing Attack',
            'Email Injection',
            'Regex DoS',
            'Mass Assignment',
        ],
    ], JSON_PRETTY_PRINT);
}

function handleScan(): void
{
    $input = file_get_contents('php://input');
    if (empty($input)) {
        sendError(400, 'Empty request body');
        return;
    }

    $data = json_decode($input, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        sendError(400, 'Invalid JSON: ' . json_last_error_msg());
        return;
    }

    if (!isset($data['files']) || !is_array($data['files'])) {
        sendError(400, 'Missing or invalid "files" field. Expected object mapping file paths to content.');
        return;
    }

    $scanId = $data['scanId'] ?? uniqid('scan-');
    $files = $data['files'];

    error_log(sprintf("[%s] Scan %s: %d files", date('Y-m-d H:i:s'), $scanId, count($files)));

    $scanner = new PhpSastScanner();
    $result = $scanner->scan($files, $scanId);

    error_log(sprintf("[%s] Scan %s complete: %d vulnerabilities in %s",
        date('Y-m-d H:i:s'), $scanId, count($result['vulnerabilities']), $result['duration']));

    echo json_encode($result, JSON_PRETTY_PRINT);
}

function sendError(int $code, string $message): void
{
    http_response_code($code);
    echo json_encode(['error' => $message]);
}
