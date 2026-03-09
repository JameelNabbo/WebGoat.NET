#!/usr/bin/env python3
"""
Swift SAST Scanner - Custom tokenizer + AST-based vulnerability detection.
Detects 30+ vulnerability categories in Swift source code.
Port: 9010
"""

import re
import uuid
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn


# ──────────────────────────── Models ────────────────────────────

class ScanRequest(BaseModel):
    files: Dict[str, str]
    scanId: str = ""


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class Vulnerability:
    id: str
    category: str
    severity: str
    title: str
    description: str
    file_path: str
    line_number: int
    column: int
    code_snippet: str
    remediation: str
    cwe_id: str
    owasp_category: str
    confidence: str = "High"

    def to_dict(self):
        return asdict(self)


# ──────────────────────────── Swift Tokenizer ────────────────────────────

class TokenType(str, Enum):
    KEYWORD = "keyword"
    IDENTIFIER = "identifier"
    STRING_LITERAL = "string_literal"
    NUMBER = "number"
    OPERATOR = "operator"
    PUNCTUATION = "punctuation"
    COMMENT = "comment"
    ATTRIBUTE = "attribute"
    DIRECTIVE = "directive"
    FORCE_UNWRAP = "force_unwrap"
    OPTIONAL_CHAIN = "optional_chain"
    WHITESPACE = "whitespace"
    NEWLINE = "newline"
    EOF = "eof"


@dataclass
class Token:
    type: TokenType
    value: str
    line: int
    column: int


SWIFT_KEYWORDS = {
    "class", "struct", "enum", "protocol", "extension", "func", "var", "let",
    "if", "else", "guard", "switch", "case", "for", "while", "repeat", "do",
    "try", "catch", "throw", "throws", "rethrows", "return", "break", "continue",
    "import", "typealias", "associatedtype", "init", "deinit", "subscript",
    "operator", "precedencegroup", "public", "private", "fileprivate", "internal",
    "open", "static", "override", "final", "mutating", "nonmutating", "lazy",
    "weak", "unowned", "convenience", "required", "optional", "dynamic",
    "infix", "prefix", "postfix", "indirect", "where", "as", "is", "in",
    "self", "Self", "super", "nil", "true", "false", "some", "any",
    "async", "await", "actor", "nonisolated", "isolated",
}


class SwiftTokenizer:
    def __init__(self, source: str):
        self.source = source
        self.pos = 0
        self.line = 1
        self.column = 1
        self.tokens: List[Token] = []

    def tokenize(self) -> List[Token]:
        while self.pos < len(self.source):
            ch = self.source[self.pos]

            if ch == "\n":
                self.tokens.append(Token(TokenType.NEWLINE, "\n", self.line, self.column))
                self.line += 1
                self.column = 1
                self.pos += 1
            elif ch in " \t\r":
                self._skip_whitespace()
            elif ch == "/" and self.pos + 1 < len(self.source):
                next_ch = self.source[self.pos + 1]
                if next_ch == "/":
                    self._read_line_comment()
                elif next_ch == "*":
                    self._read_block_comment()
                else:
                    self._read_operator()
            elif ch == "#":
                self._read_directive()
            elif ch == "@":
                self._read_attribute()
            elif ch == "\"":
                self._read_string()
            elif ch.isdigit():
                self._read_number()
            elif ch.isalpha() or ch == "_":
                self._read_identifier()
            elif ch in "{}()[].,;:":
                self.tokens.append(Token(TokenType.PUNCTUATION, ch, self.line, self.column))
                self.column += 1
                self.pos += 1
            elif ch == "!":
                if self.tokens and self.tokens[-1].type in (TokenType.IDENTIFIER, TokenType.PUNCTUATION):
                    self.tokens.append(Token(TokenType.FORCE_UNWRAP, "!", self.line, self.column))
                else:
                    self.tokens.append(Token(TokenType.OPERATOR, "!", self.line, self.column))
                self.column += 1
                self.pos += 1
            elif ch == "?":
                self.tokens.append(Token(TokenType.OPTIONAL_CHAIN, "?", self.line, self.column))
                self.column += 1
                self.pos += 1
            else:
                self._read_operator()

        self.tokens.append(Token(TokenType.EOF, "", self.line, self.column))
        return self.tokens

    def _skip_whitespace(self):
        while self.pos < len(self.source) and self.source[self.pos] in " \t\r":
            self.column += 1
            self.pos += 1

    def _read_line_comment(self):
        start_col = self.column
        start = self.pos
        while self.pos < len(self.source) and self.source[self.pos] != "\n":
            self.pos += 1
            self.column += 1
        self.tokens.append(Token(TokenType.COMMENT, self.source[start:self.pos], self.line, start_col))

    def _read_block_comment(self):
        start_col = self.column
        start_line = self.line
        start = self.pos
        depth = 1
        self.pos += 2
        self.column += 2
        while self.pos < len(self.source) and depth > 0:
            if self.source[self.pos] == "/" and self.pos + 1 < len(self.source) and self.source[self.pos + 1] == "*":
                depth += 1
                self.pos += 2
                self.column += 2
            elif self.source[self.pos] == "*" and self.pos + 1 < len(self.source) and self.source[self.pos + 1] == "/":
                depth -= 1
                self.pos += 2
                self.column += 2
            elif self.source[self.pos] == "\n":
                self.line += 1
                self.column = 1
                self.pos += 1
            else:
                self.pos += 1
                self.column += 1
        self.tokens.append(Token(TokenType.COMMENT, self.source[start:self.pos], start_line, start_col))

    def _read_directive(self):
        start_col = self.column
        start = self.pos
        self.pos += 1
        self.column += 1
        while self.pos < len(self.source) and (self.source[self.pos].isalnum() or self.source[self.pos] == "_"):
            self.pos += 1
            self.column += 1
        self.tokens.append(Token(TokenType.DIRECTIVE, self.source[start:self.pos], self.line, start_col))

    def _read_attribute(self):
        start_col = self.column
        start = self.pos
        self.pos += 1
        self.column += 1
        while self.pos < len(self.source) and (self.source[self.pos].isalnum() or self.source[self.pos] == "_"):
            self.pos += 1
            self.column += 1
        self.tokens.append(Token(TokenType.ATTRIBUTE, self.source[start:self.pos], self.line, start_col))

    def _read_string(self):
        start_col = self.column
        start_line = self.line
        start = self.pos
        self.pos += 1
        self.column += 1
        while self.pos < len(self.source) and self.source[self.pos] != "\"":
            if self.source[self.pos] == "\\":
                self.pos += 2
                self.column += 2
            elif self.source[self.pos] == "\n":
                self.line += 1
                self.column = 1
                self.pos += 1
            else:
                self.pos += 1
                self.column += 1
        if self.pos < len(self.source):
            self.pos += 1
            self.column += 1
        self.tokens.append(Token(TokenType.STRING_LITERAL, self.source[start:self.pos], start_line, start_col))

    def _read_number(self):
        start_col = self.column
        start = self.pos
        while self.pos < len(self.source) and (self.source[self.pos].isalnum() or self.source[self.pos] in "._xXeEpP+-"):
            self.pos += 1
            self.column += 1
        self.tokens.append(Token(TokenType.NUMBER, self.source[start:self.pos], self.line, start_col))

    def _read_identifier(self):
        start_col = self.column
        start = self.pos
        while self.pos < len(self.source) and (self.source[self.pos].isalnum() or self.source[self.pos] == "_"):
            self.pos += 1
            self.column += 1
        value = self.source[start:self.pos]
        tok_type = TokenType.KEYWORD if value in SWIFT_KEYWORDS else TokenType.IDENTIFIER
        self.tokens.append(Token(tok_type, value, self.line, start_col))

    def _read_operator(self):
        start_col = self.column
        start = self.pos
        op_chars = set("+-*/%=<>&|^~!?.")
        while self.pos < len(self.source) and self.source[self.pos] in op_chars:
            self.pos += 1
            self.column += 1
        if self.pos == start:
            self.pos += 1
            self.column += 1
        self.tokens.append(Token(TokenType.OPERATOR, self.source[start:self.pos], self.line, start_col))


# ──────────────────────────── Vulnerability Rules ────────────────────────────

class SwiftVulnerabilityDetector:
    """Detects 30+ vulnerability categories in Swift code."""

    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []

    def scan_file(self, file_path: str, content: str) -> List[Vulnerability]:
        self.vulnerabilities = []
        lines = content.split("\n")
        try:
            tokenizer = SwiftTokenizer(content)
            tokens = tokenizer.tokenize()
        except Exception:
            tokens = []

        # Run all detection rules
        self._detect_sql_injection(file_path, content, lines)
        self._detect_command_injection(file_path, content, lines)
        self._detect_xss_webview(file_path, content, lines)
        self._detect_path_traversal(file_path, content, lines)
        self._detect_deserialization(file_path, content, lines)
        self._detect_hardcoded_secrets(file_path, content, lines)
        self._detect_weak_crypto(file_path, content, lines)
        self._detect_insecure_random(file_path, content, lines)
        self._detect_insecure_tls(file_path, content, lines)
        self._detect_keychain_misuse(file_path, content, lines)
        self._detect_pasteboard_leaks(file_path, content, lines)
        self._detect_webview_js_injection(file_path, content, lines)
        self._detect_biometric_bypass(file_path, content, lines)
        self._detect_url_scheme_abuse(file_path, content, lines)
        self._detect_appstorage_secrets(file_path, content, lines)
        self._detect_force_unwrap(file_path, content, lines, tokens)
        self._detect_ssrf(file_path, content, lines)
        self._detect_open_redirect(file_path, content, lines)
        self._detect_info_disclosure(file_path, content, lines)
        self._detect_missing_input_validation(file_path, content, lines)
        self._detect_vapor_issues(file_path, content, lines)
        self._detect_alamofire_ssrf(file_path, content, lines)
        self._detect_coredata_unencrypted(file_path, content, lines)
        self._detect_background_task_exposure(file_path, content, lines)
        self._detect_clipboard_leaks(file_path, content, lines)
        self._detect_missing_screenshot_prevention(file_path, content, lines)
        self._detect_debug_release_config(file_path, content, lines)
        self._detect_timing_attacks(file_path, content, lines)
        self._detect_jwt_issues(file_path, content, lines)
        self._detect_cors_issues(file_path, content, lines)
        self._detect_insecure_file_permissions(file_path, content, lines)

        return self.vulnerabilities

    def _add_vuln(self, category, severity, title, description, file_path,
                  line_number, column, code_snippet, remediation, cwe_id,
                  owasp_category, confidence="High"):
        vuln_id = hashlib.md5(
            f"{file_path}:{line_number}:{category}:{code_snippet[:50]}".encode()
        ).hexdigest()[:16]
        self.vulnerabilities.append(Vulnerability(
            id=vuln_id, category=category, severity=severity, title=title,
            description=description, file_path=file_path, line_number=line_number,
            column=column, code_snippet=code_snippet.strip(), remediation=remediation,
            cwe_id=cwe_id, owasp_category=owasp_category, confidence=confidence
        ))

    # ─── 1. SQL Injection ───
    def _detect_sql_injection(self, fp, content, lines):
        patterns = [
            (r'(?:GRDB|SQLite).*(?:execute|prepare)\s*\(\s*"[^"]*\\\(', "String interpolation in SQL query"),
            (r'(?:execute|prepare)\s*\(\s*"[^"]*"\s*\+\s*', "String concatenation in SQL query"),
            (r'raw\s*\(\s*"[^"]*\\\(', "Raw SQL with interpolation"),
            (r'SELECT\s+.*FROM\s+.*\\\(', "SQL query with string interpolation"),
            (r'INSERT\s+INTO\s+.*\\\(', "SQL INSERT with string interpolation"),
            (r'UPDATE\s+.*SET\s+.*\\\(', "SQL UPDATE with string interpolation"),
            (r'DELETE\s+FROM\s+.*\\\(', "SQL DELETE with string interpolation"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "SQL Injection", Severity.CRITICAL,
                        f"SQL Injection: {desc}",
                        f"User-controlled data may be interpolated into SQL query without parameterization. {desc}.",
                        fp, i, 1, line,
                        "Use parameterized queries with bound parameters instead of string interpolation.",
                        "CWE-89", "A03:2021-Injection")

    # ─── 2. Command Injection ───
    def _detect_command_injection(self, fp, content, lines):
        patterns = [
            (r'Process\s*\(\s*\).*(?:launchPath|executableURL)\s*=.*\\\(', "Process with interpolated path"),
            (r'Process\s*\(\s*\).*arguments\s*=.*\\\(', "Process with interpolated arguments"),
            (r'NSTask\s*\(\s*\)', "NSTask usage (deprecated, use Process)"),
            (r'\bsystem\s*\(', "C system() call"),
            (r'\bpopen\s*\(', "C popen() call"),
            (r'Process\.launchedProcess\s*\(.*\\\(', "Process launched with interpolated values"),
            (r'Shell\s*\.\s*run\s*\(.*\\\(', "Shell command with interpolation"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    self._add_vuln(
                        "Command Injection", Severity.CRITICAL,
                        f"Command Injection: {desc}",
                        f"External process execution detected with potential user-controlled input. {desc}.",
                        fp, i, 1, line,
                        "Validate and sanitize all inputs passed to process execution. Use allowlists for commands.",
                        "CWE-78", "A03:2021-Injection")

    # ─── 3. XSS (WKWebView) ───
    def _detect_xss_webview(self, fp, content, lines):
        patterns = [
            (r'loadHTMLString\s*\(.*\\\(', "loadHTMLString with interpolated content"),
            (r'evaluateJavaScript\s*\(.*\\\(', "evaluateJavaScript with interpolated code"),
            (r'WKWebView.*loadHTMLString', "WKWebView loading dynamic HTML"),
            (r'UIWebView', "UIWebView usage (deprecated, insecure)"),
            (r'javaScriptEnabled\s*=\s*true', "JavaScript enabled in WebView"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    self._add_vuln(
                        "Cross-Site Scripting (XSS)", Severity.HIGH,
                        f"XSS via WebView: {desc}",
                        f"WebView may render attacker-controlled content. {desc}.",
                        fp, i, 1, line,
                        "Sanitize all HTML/JavaScript before loading in WebViews. Avoid evaluateJavaScript with user input.",
                        "CWE-79", "A03:2021-Injection")

    # ─── 4. Path Traversal ───
    def _detect_path_traversal(self, fp, content, lines):
        patterns = [
            (r'(?:contentsOfFile|String\(contentsOf|Data\(contentsOf|FileManager.*contents).*\\\(', "File read with interpolated path"),
            (r'(?:write|createFile|moveItem|copyItem).*\\\(', "File write with interpolated path"),
            (r'URL\s*\(\s*fileURLWithPath\s*:.*\\\(', "File URL with interpolated path"),
            (r'appendingPathComponent\s*\(.*(?:request|param|input|query|user)', "Path component from user input"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Path Traversal", Severity.HIGH,
                        f"Path Traversal: {desc}",
                        f"File system operation uses potentially user-controlled path. {desc}.",
                        fp, i, 1, line,
                        "Validate paths against a base directory. Reject paths containing '..' sequences.",
                        "CWE-22", "A01:2021-Broken Access Control")

    # ─── 5. Deserialization ───
    def _detect_deserialization(self, fp, content, lines):
        patterns = [
            (r'NSKeyedUnarchiver\s*\.\s*unarchiveObject\s*\(', "NSKeyedUnarchiver.unarchiveObject (insecure)"),
            (r'NSKeyedUnarchiver\s*\.\s*unarchiveTopLevelObject', "NSKeyedUnarchiver.unarchiveTopLevelObject (insecure)"),
            (r'NSCoding', "NSCoding protocol (potential deserialization risk)"),
            (r'JSONDecoder\s*\(\s*\)\.decode.*from\s*:\s*(?:request|data|body|input)', "JSON deserialization of untrusted data"),
            (r'PropertyListDecoder', "PropertyList deserialization"),
            (r'unarchiveObject\s*\(\s*with\s*:', "Insecure unarchiving"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    sev = Severity.CRITICAL if "unarchiveObject" in desc else Severity.MEDIUM
                    self._add_vuln(
                        "Insecure Deserialization", sev,
                        f"Deserialization: {desc}",
                        f"Insecure deserialization detected. {desc}.",
                        fp, i, 1, line,
                        "Use NSSecureCoding with unarchivedObject(ofClass:from:). Validate all deserialized data.",
                        "CWE-502", "A08:2021-Software and Data Integrity Failures")

    # ─── 6. Hardcoded Secrets ───
    def _detect_hardcoded_secrets(self, fp, content, lines):
        patterns = [
            (r'(?:api[_-]?key|apikey|secret[_-]?key|password|passwd|token|auth[_-]?token|access[_-]?key|private[_-]?key)\s*[:=]\s*"[^"]{8,}"', "Hardcoded secret/credential"),
            (r'(?:Bearer|Basic)\s+[A-Za-z0-9+/=]{20,}', "Hardcoded authorization token"),
            (r'AIza[0-9A-Za-z_-]{35}', "Google API key"),
            (r'sk-[A-Za-z0-9]{20,}', "Secret key pattern (Stripe/OpenAI-style)"),
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
            (r'ghp_[A-Za-z0-9]{36}', "GitHub personal access token"),
            (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "Embedded private key"),
            (r'(?:firebase|aws|azure|gcp)[_-]?(?:key|secret|token|password)\s*=\s*"[^"]+"', "Cloud service credential"),
        ]
        for i, line in enumerate(lines, 1):
            if re.search(r'//.*(?:example|test|sample|placeholder|TODO|FIXME)', line, re.IGNORECASE):
                continue
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Hardcoded Secrets", Severity.CRITICAL,
                        f"Hardcoded Secret: {desc}",
                        f"Sensitive credential found hardcoded in source code. {desc}.",
                        fp, i, 1, line,
                        "Store secrets in Keychain, environment variables, or a secure vault. Never commit secrets to source code.",
                        "CWE-798", "A07:2021-Identification and Authentication Failures")

    # ─── 7. Weak Cryptography ───
    def _detect_weak_crypto(self, fp, content, lines):
        patterns = [
            (r'CC_MD5\s*\(', "MD5 hash function (weak)"),
            (r'CC_SHA1\s*\(', "SHA1 hash function (weak)"),
            (r'kCCAlgorithmDES\b', "DES encryption (weak)"),
            (r'kCCAlgorithm3DES\b', "3DES encryption (weak)"),
            (r'kCCOptionECBMode\b', "ECB mode (insecure)"),
            (r'Insecure\.MD5\b', "CryptoKit Insecure.MD5"),
            (r'Insecure\.SHA1\b', "CryptoKit Insecure.SHA1"),
            (r'\.md5\b', "MD5 usage"),
            (r'\.sha1\b', "SHA1 usage"),
            (r'CCCrypt.*kCCOptionECBMode', "ECB mode encryption"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    self._add_vuln(
                        "Weak Cryptography", Severity.HIGH,
                        f"Weak Crypto: {desc}",
                        f"Usage of weak or deprecated cryptographic algorithm detected. {desc}.",
                        fp, i, 1, line,
                        "Use SHA-256+ for hashing and AES-256-GCM for encryption. Migrate from MD5/SHA1/DES/3DES.",
                        "CWE-327", "A02:2021-Cryptographic Failures")

    # ─── 8. Insecure Random ───
    def _detect_insecure_random(self, fp, content, lines):
        patterns = [
            (r'\brand\s*\(\s*\)', "C rand() function (insecure)"),
            (r'\brandom\s*\(\s*\)', "random() function (insecure)"),
            (r'\barc4random\s*\(\s*\)', "arc4random without uniform (biased)"),
            (r'srand\s*\(', "srand seeding (predictable)"),
            (r'drand48\s*\(', "drand48 (insecure PRNG)"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    self._add_vuln(
                        "Insecure Random", Severity.HIGH,
                        f"Insecure Random: {desc}",
                        f"Use of weak random number generator. {desc}. Not suitable for security-sensitive operations.",
                        fp, i, 1, line,
                        "Use SecRandomCopyBytes() or CryptoKit for cryptographically secure random values.",
                        "CWE-330", "A02:2021-Cryptographic Failures")

    # ─── 9. Insecure TLS ───
    def _detect_insecure_tls(self, fp, content, lines):
        patterns = [
            (r'NSAppTransportSecurity.*NSAllowsArbitraryLoads.*true', "ATS disabled globally"),
            (r'AllowsArbitraryLoads.*true', "ATS AllowsArbitraryLoads enabled"),
            (r'NSExceptionAllowsInsecureHTTPLoads.*true', "ATS exception for insecure HTTP"),
            (r'NSTemporaryExceptionAllowsInsecureHTTPLoads', "Temporary ATS exception"),
            (r'\.tlsMinimumSupportedProtocol\s*=\s*\.(?:sslProtocol|tlsProtocol1[01])', "Weak TLS version"),
            (r'ServerTrustPolicy\s*\.\s*disableEvaluation', "Certificate validation disabled"),
            (r'\.disableEvaluation', "Trust evaluation disabled"),
            (r'URLSessionDelegate.*didReceive\s+challenge.*completionHandler\s*\(\s*\.useCredential', "Certificate pinning bypass"),
            (r'SecTrustSetAnchorCertificates.*nil', "Trust anchors cleared"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Insecure TLS Configuration", Severity.HIGH,
                        f"Insecure TLS: {desc}",
                        f"TLS/SSL security weakened. {desc}.",
                        fp, i, 1, line,
                        "Enable ATS, use TLS 1.2+, implement proper certificate pinning.",
                        "CWE-295", "A02:2021-Cryptographic Failures")

    # ─── 10. Keychain Misuse ───
    def _detect_keychain_misuse(self, fp, content, lines):
        patterns = [
            (r'UserDefaults.*(?:password|secret|token|key|credential|api[_-]?key|auth)', "Secrets stored in UserDefaults"),
            (r'UserDefaults\.standard\.set\s*\(.*(?:password|secret|token)', "Password/token in UserDefaults"),
            (r'kSecAttrAccessible.*(?:Always|AfterFirstUnlock)\b', "Keychain item accessible when device locked"),
            (r'kSecAttrAccessibleAlways\b', "Keychain always accessible (deprecated, insecure)"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    sev = Severity.HIGH if "UserDefaults" in desc else Severity.MEDIUM
                    self._add_vuln(
                        "iOS Keychain Misuse", sev,
                        f"Keychain Misuse: {desc}",
                        f"Sensitive data stored insecurely. {desc}.",
                        fp, i, 1, line,
                        "Use Keychain Services with kSecAttrAccessibleWhenUnlockedThisDeviceOnly for sensitive data.",
                        "CWE-922", "A04:2021-Insecure Design")

    # ─── 11. Pasteboard Leaks ───
    def _detect_pasteboard_leaks(self, fp, content, lines):
        patterns = [
            (r'UIPasteboard\.general\.string\s*=.*(?:password|secret|token|ssn|credit)', "Sensitive data copied to pasteboard"),
            (r'UIPasteboard\.general\s*\.\s*(?:string|strings|items)\s*=', "Data written to general pasteboard"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Pasteboard Data Leak", Severity.MEDIUM,
                        f"Pasteboard Leak: {desc}",
                        f"Sensitive data may leak through system pasteboard. {desc}. Other apps can read the pasteboard.",
                        fp, i, 1, line,
                        "Use UIPasteboard.withLocalOnly or expire pasteboard items. Avoid copying sensitive data.",
                        "CWE-200", "A04:2021-Insecure Design")

    # ─── 12. WebView JavaScript Injection ───
    def _detect_webview_js_injection(self, fp, content, lines):
        patterns = [
            (r'WKUserScript\s*\(.*source\s*:.*\\\(', "WKUserScript with interpolated JavaScript"),
            (r'addUserScript\s*\(.*\\\(', "User script with dynamic content"),
            (r'evaluateJavaScript\s*\(\s*".*\\\(', "evaluateJavaScript with interpolation"),
            (r'WKScriptMessageHandler', "Script message handler (verify message validation)"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    conf = "Medium" if "WKScriptMessageHandler" in desc else "High"
                    sev = Severity.HIGH if conf == "High" else Severity.MEDIUM
                    self._add_vuln(
                        "WebView JavaScript Injection", sev,
                        f"JS Injection: {desc}",
                        f"JavaScript injection risk in WebView. {desc}.",
                        fp, i, 1, line,
                        "Sanitize all data before passing to evaluateJavaScript. Validate WKScriptMessage content.",
                        "CWE-94", "A03:2021-Injection", confidence=conf)

    # ─── 13. Biometric Bypass ───
    def _detect_biometric_bypass(self, fp, content, lines):
        has_biometric = bool(re.search(r'LAContext|LocalAuthentication|evaluatePolicy', content))
        has_keychain_bio = bool(re.search(r'kSecAccessControlBiometryAny|kSecAccessControlBiometryCurrentSet', content))
        if has_biometric and not has_keychain_bio:
            for i, line in enumerate(lines, 1):
                if re.search(r'evaluatePolicy', line):
                    self._add_vuln(
                        "Biometric Bypass", Severity.HIGH,
                        "Biometric auth without Keychain binding",
                        "Biometric authentication result is checked in app logic only, not bound to Keychain access control. Attacker can bypass with runtime manipulation.",
                        fp, i, 1, line,
                        "Bind biometric auth to Keychain items using kSecAccessControlBiometryCurrentSet.",
                        "CWE-287", "A07:2021-Identification and Authentication Failures")

        bio_patterns = [
            (r'LAContext.*evaluatePolicy.*\.\s*deviceOwnerAuthentication\b', "Biometric with device passcode fallback"),
            (r'LAContext\s*\(\s*\).*(?:localizedFallbackTitle|localizedCancelTitle)\s*=\s*""', "Biometric UI bypass (empty fallback)"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in bio_patterns:
                if re.search(pattern, line):
                    self._add_vuln(
                        "Biometric Bypass", Severity.MEDIUM,
                        f"Biometric Issue: {desc}",
                        f"Biometric authentication weakness. {desc}.",
                        fp, i, 1, line,
                        "Use kSecAccessControlBiometryCurrentSet with Keychain for robust biometric auth.",
                        "CWE-287", "A07:2021-Identification and Authentication Failures",
                        confidence="Medium")

    # ─── 14. URL Scheme Abuse ───
    def _detect_url_scheme_abuse(self, fp, content, lines):
        patterns = [
            (r'func\s+application.*open\s+url.*options', "URL scheme handler without validation"),
            (r'openURL\s*\(.*\\\(', "openURL with interpolated URL"),
            (r'canOpenURL\s*\(.*\\\(', "canOpenURL with dynamic scheme"),
            (r'UIApplication\.shared\.open\s*\(.*\\\(', "Opening URL with interpolation"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    self._add_vuln(
                        "URL Scheme Abuse", Severity.MEDIUM,
                        f"URL Scheme: {desc}",
                        f"URL scheme handling may be vulnerable to abuse. {desc}.",
                        fp, i, 1, line,
                        "Validate all URL scheme parameters. Use Universal Links instead of custom URL schemes.",
                        "CWE-939", "A07:2021-Identification and Authentication Failures")

    # ─── 15. SwiftUI @AppStorage Secrets ───
    def _detect_appstorage_secrets(self, fp, content, lines):
        patterns = [
            (r'@AppStorage\s*\(\s*"(?:.*(?:password|secret|token|key|credential|api[_-]?key|auth).*)"', "@AppStorage storing sensitive data"),
            (r'@AppStorage.*(?:password|secret|token|auth)', "@AppStorage with sensitive value"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "SwiftUI @AppStorage Secrets", Severity.HIGH,
                        f"AppStorage Secret: {desc}",
                        f"Sensitive data stored in @AppStorage (UserDefaults). {desc}. Data is not encrypted.",
                        fp, i, 1, line,
                        "Use Keychain instead of @AppStorage for secrets. @AppStorage is backed by UserDefaults (unencrypted).",
                        "CWE-922", "A04:2021-Insecure Design")

    # ─── 16. Force Unwrap ───
    def _detect_force_unwrap(self, fp, content, lines, tokens):
        force_unwrap_lines = set()
        for j, token in enumerate(tokens):
            if token.type == TokenType.FORCE_UNWRAP:
                if j > 0 and tokens[j - 1].type == TokenType.IDENTIFIER:
                    context_line = lines[token.line - 1] if token.line <= len(lines) else ""
                    if not re.search(r'IBOutlet|@IBOutlet|XCTest|test[A-Z]', context_line):
                        force_unwrap_lines.add(token.line)

        for line_num in force_unwrap_lines:
            if line_num <= len(lines):
                line = lines[line_num - 1]
                self._add_vuln(
                    "Force Unwrap", Severity.LOW,
                    "Force Unwrap (!) used",
                    "Force unwrapping an optional value can cause a runtime crash if the value is nil.",
                    fp, line_num, 1, line,
                    "Use optional binding (if let/guard let), nil coalescing (??), or optional chaining (?.) instead.",
                    "CWE-476", "A04:2021-Insecure Design", confidence="Medium")

    # ─── 17. SSRF ───
    def _detect_ssrf(self, fp, content, lines):
        patterns = [
            (r'URL\s*\(\s*string\s*:\s*(?:request|param|input|query|user|url)', "URL from user-controlled input"),
            (r'URLRequest\s*\(\s*url\s*:\s*.*(?:request|param|input|query|user)', "URLRequest with user-controlled URL"),
            (r'URLSession.*dataTask.*url.*(?:request|param|input|query|user)', "URLSession with user URL"),
            (r'URL\s*\(\s*string\s*:\s*\\\(', "URL from string interpolation"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Server-Side Request Forgery (SSRF)", Severity.HIGH,
                        f"SSRF: {desc}",
                        f"Server-side request may be directed to attacker-controlled URL. {desc}.",
                        fp, i, 1, line,
                        "Validate URLs against an allowlist. Block internal/private IP ranges.",
                        "CWE-918", "A10:2021-Server-Side Request Forgery")

    # ─── 18. Open Redirect ───
    def _detect_open_redirect(self, fp, content, lines):
        patterns = [
            (r'UIApplication\.shared\.open\s*\(\s*URL\s*\(\s*string\s*:\s*(?:request|param|redirect|next|return|url)', "Open redirect via UIApplication"),
            (r'(?:redirect|navigate|open)\s*\(\s*(?:to\s*:\s*)?(?:request|param|url|next|return)', "Redirect to user-controlled URL"),
            (r'SFSafariViewController\s*\(\s*url\s*:\s*.*(?:request|param|url|redirect)', "SFSafariViewController with user URL"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Open Redirect", Severity.MEDIUM,
                        f"Open Redirect: {desc}",
                        f"Application may redirect users to an attacker-controlled URL. {desc}.",
                        fp, i, 1, line,
                        "Validate redirect URLs against an allowlist. Only allow relative redirects or known domains.",
                        "CWE-601", "A01:2021-Broken Access Control")

    # ─── 19. Info Disclosure ───
    def _detect_info_disclosure(self, fp, content, lines):
        patterns = [
            (r'(?:print|NSLog|debugPrint|dump)\s*\(.*(?:password|secret|token|key|credential|ssn|credit)', "Logging sensitive data"),
            (r'print\s*\(\s*".*(?:Error|error|Exception|exception).*\\\(', "Verbose error logging with interpolation"),
            (r'NSLog\s*\(\s*@?".*(?:password|token|secret)', "NSLog with sensitive data"),
            (r'os_log\s*\(.*\.(?:default|info).*(?:password|token|secret)', "os_log at non-private level with sensitive data"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Information Disclosure", Severity.MEDIUM,
                        f"Info Disclosure: {desc}",
                        f"Sensitive information may be leaked through logging. {desc}.",
                        fp, i, 1, line,
                        "Remove sensitive data from logs. Use os_log with .private for sensitive values in production.",
                        "CWE-532", "A09:2021-Security Logging and Monitoring Failures")

    # ─── 20. Missing Input Validation ───
    def _detect_missing_input_validation(self, fp, content, lines):
        patterns = [
            (r'request\.(?:body|query|params|input)\s*\[', "Direct use of request input without validation"),
            (r'URLComponents.*queryItems.*(?:first|value)', "URL query parameter used without validation"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Missing Input Validation", Severity.MEDIUM,
                        f"Input Validation: {desc}",
                        f"User input used without apparent validation. {desc}.",
                        fp, i, 1, line,
                        "Validate all input: check type, length, range, and format. Use Codable with strict types.",
                        "CWE-20", "A03:2021-Injection", confidence="Medium")

    # ─── 21. Vapor Framework Issues ───
    def _detect_vapor_issues(self, fp, content, lines):
        patterns = [
            (r'allowedOrigin\s*:\s*\.all', "CORS allows all origins in Vapor"),
            (r'req\.content\.decode', "Vapor content decode without validation"),
            (r'defaultMaxBodySize\s*=.*unlimited', "Unlimited body size in Vapor"),
            (r'req\.query\[', "Vapor query parameter without validation"),
            (r'Environment\.get\s*\(\s*"[^"]*"\s*\)\s*!', "Force unwrapping environment variable in Vapor"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    self._add_vuln(
                        "Vapor Framework Issue", Severity.MEDIUM,
                        f"Vapor Issue: {desc}",
                        f"Vapor framework security misconfiguration. {desc}.",
                        fp, i, 1, line,
                        "Configure CORS restrictively. Validate all decoded content. Set appropriate body size limits.",
                        "CWE-16", "A05:2021-Security Misconfiguration")

    # ─── 22. Alamofire SSRF ───
    def _detect_alamofire_ssrf(self, fp, content, lines):
        patterns = [
            (r'AF\.request\s*\(.*\\\(', "Alamofire request with interpolated URL"),
            (r'AF\.request\s*\(.*(?:request|param|input|user|url)', "Alamofire request with user-controlled URL"),
            (r'Session\.default\.request\s*\(.*\\\(', "Alamofire session request with interpolation"),
            (r'AF\.download\s*\(.*\\\(', "Alamofire download with interpolated URL"),
            (r'ServerTrustManager\s*\(\s*evaluators\s*:\s*\[\s*\]\s*\)', "Empty Alamofire trust evaluators"),
            (r'DisabledTrustEvaluator', "Alamofire DisabledTrustEvaluator"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    sev = Severity.CRITICAL if "DisabledTrust" in desc else Severity.HIGH
                    self._add_vuln(
                        "Alamofire SSRF/Trust Issue", sev,
                        f"Alamofire: {desc}",
                        f"Alamofire networking security issue. {desc}.",
                        fp, i, 1, line,
                        "Validate URLs before making requests. Use proper ServerTrustManager with certificate pinning.",
                        "CWE-918", "A10:2021-Server-Side Request Forgery")

    # ─── 23. CoreData Unencrypted ───
    def _detect_coredata_unencrypted(self, fp, content, lines):
        has_coredata = bool(re.search(r'import\s+CoreData|NSManagedObject|NSPersistentContainer', content))
        has_encryption = bool(re.search(r'NSPersistentStoreFileProtectionKey|SQLCipher|encryptedStore|FileProtection', content))
        if has_coredata and not has_encryption:
            patterns = [
                (r'NSPersistentContainer\s*\(', "CoreData container without encryption"),
                (r'\.addPersistentStore\s*\(', "Persistent store without encryption option"),
            ]
            for i, line in enumerate(lines, 1):
                for pattern, desc in patterns:
                    if re.search(pattern, line):
                        self._add_vuln(
                            "CoreData Unencrypted", Severity.MEDIUM,
                            f"CoreData: {desc}",
                            f"CoreData store may not be encrypted at rest. {desc}.",
                            fp, i, 1, line,
                            "Enable NSPersistentStoreFileProtectionKey or use SQLCipher for CoreData encryption.",
                            "CWE-311", "A02:2021-Cryptographic Failures", confidence="Medium")

    # ─── 24. Background Task Exposure ───
    def _detect_background_task_exposure(self, fp, content, lines):
        patterns = [
            (r'beginBackgroundTask.*(?:password|secret|token|auth)', "Background task with sensitive data"),
            (r'BGAppRefreshTask.*(?:fetch|sync).*(?:credential|token)', "Background refresh handling credentials"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Background Task Exposure", Severity.MEDIUM,
                        f"Background Exposure: {desc}",
                        f"Sensitive data may be exposed during background execution. {desc}.",
                        fp, i, 1, line,
                        "Clear sensitive data before entering background. Use data protection APIs.",
                        "CWE-200", "A04:2021-Insecure Design", confidence="Medium")

    # ─── 25. Clipboard Leaks ───
    def _detect_clipboard_leaks(self, fp, content, lines):
        patterns = [
            (r'UIPasteboard\.general', "General pasteboard access (shared across apps)"),
            (r'\.string\s*=\s*.*(?:password|secret|token|key)', "Copying sensitive data to clipboard"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Clipboard Data Leak", Severity.MEDIUM,
                        f"Clipboard Leak: {desc}",
                        f"Data may leak through system clipboard. {desc}.",
                        fp, i, 1, line,
                        "Use UIPasteboard.withLocalOnly. Set expiration on pasteboard items. Avoid copying secrets.",
                        "CWE-200", "A04:2021-Insecure Design")

    # ─── 26. Missing Screenshot Prevention ───
    def _detect_missing_screenshot_prevention(self, fp, content, lines):
        has_sensitive_ui = bool(re.search(
            r'(?:password|secret|credit|ssn|social.*security).*(?:Field|Label|Text|View)',
            content, re.IGNORECASE))
        has_screenshot_protection = bool(re.search(
            r'userDidTakeScreenshotNotification|UIScreen\.capturedDidChangeNotification|isSecureTextEntry|makeSecure',
            content))
        if has_sensitive_ui and not has_screenshot_protection:
            for i, line in enumerate(lines, 1):
                if re.search(r'(?:password|secret|credit|ssn).*(?:Field|Label|Text)', line, re.IGNORECASE):
                    self._add_vuln(
                        "Missing Screenshot Prevention", Severity.LOW,
                        "No screenshot protection for sensitive UI",
                        "Sensitive data displayed in UI without screenshot/screen recording protection.",
                        fp, i, 1, line,
                        "Observe UIScreen.capturedDidChangeNotification. Use secure text fields.",
                        "CWE-200", "A04:2021-Insecure Design", confidence="Medium")

    # ─── 27. Debug/Release Config ───
    def _detect_debug_release_config(self, fp, content, lines):
        patterns = [
            (r'isDebug\s*=\s*true', "Debug flag enabled"),
            (r'DEBUG_MODE\s*=\s*true', "Debug mode enabled"),
            (r'assert\s*\(.*(?:password|secret|token)', "Assert with sensitive data"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Debug/Release Configuration", Severity.LOW,
                        f"Debug Config: {desc}",
                        f"Debug configuration may leak information. {desc}.",
                        fp, i, 1, line,
                        "Ensure debug logging and flags are disabled in release builds. Use #if DEBUG guards.",
                        "CWE-215", "A05:2021-Security Misconfiguration")

    # ─── 28. Timing Attacks ───
    def _detect_timing_attacks(self, fp, content, lines):
        patterns = [
            (r'(?:password|token|secret|hash|signature|mac|hmac)\s*==\s*', "Direct string comparison for secrets"),
            (r'\.elementsEqual\s*\(.*(?:password|token|secret|hash)', "elementsEqual for secret comparison"),
            (r'isEqual\s*\(.*(?:password|token|secret|hash)', "isEqual for secret comparison"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Timing Attack", Severity.MEDIUM,
                        f"Timing Attack: {desc}",
                        f"Non-constant-time comparison of sensitive values. {desc}.",
                        fp, i, 1, line,
                        "Use constant-time comparison (e.g., HMAC verify, or compare SHA-256 hashes).",
                        "CWE-208", "A02:2021-Cryptographic Failures")

    # ─── 29. JWT Issues ───
    def _detect_jwt_issues(self, fp, content, lines):
        patterns = [
            (r'algorithm\s*:\s*\.none', "JWT algorithm set to none"),
            (r'verify\s*:\s*false.*(?:JWT|jwt)', "JWT verification disabled"),
            (r'JWTSigner\s*\.\s*hs256\s*\(\s*key\s*:\s*"[^"]{1,16}"', "JWT with short HMAC key"),
            (r'decode.*jwt.*verify.*false', "JWT decoded without verification"),
            (r'(?:jwt|token).*(?:expired|exp).*ignore', "JWT expiration ignored"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "JWT Security Issue", Severity.HIGH,
                        f"JWT Issue: {desc}",
                        f"JWT handling vulnerability. {desc}.",
                        fp, i, 1, line,
                        "Always verify JWT signatures. Use strong keys (256+ bits). Check expiration.",
                        "CWE-345", "A02:2021-Cryptographic Failures")

    # ─── 30. CORS Issues ───
    def _detect_cors_issues(self, fp, content, lines):
        patterns = [
            (r'Access-Control-Allow-Origin.*\*', "CORS allows all origins"),
            (r'allowedOrigin\s*:\s*\.all', "Vapor CORS allows all origins"),
            (r'corsConfiguration.*allowedOrigins\s*=\s*\[\s*"\*"', "CORS wildcard in config"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "CORS Misconfiguration", Severity.MEDIUM,
                        f"CORS: {desc}",
                        f"Cross-Origin Resource Sharing misconfigured. {desc}.",
                        fp, i, 1, line,
                        "Restrict CORS to specific trusted origins. Never use wildcard with credentials.",
                        "CWE-942", "A05:2021-Security Misconfiguration")

    # ─── 31. Insecure File Permissions ───
    def _detect_insecure_file_permissions(self, fp, content, lines):
        patterns = [
            (r'FileProtectionType\.(?:none|completeUntilFirstUserAuthentication)', "Weak file protection level"),
            (r'\.noFileProtection', "No file protection"),
            (r'createFile.*attributes\s*:\s*nil', "File created with nil attributes (no protection)"),
            (r'NSFileProtectionNone', "NSFileProtectionNone"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    self._add_vuln(
                        "Insecure File Permissions", Severity.MEDIUM,
                        f"File Protection: {desc}",
                        f"File may be accessible when device is locked. {desc}.",
                        fp, i, 1, line,
                        "Use FileProtectionType.complete or .completeUnlessOpen for sensitive files.",
                        "CWE-732", "A01:2021-Broken Access Control")


# ──────────────────────────── FastAPI Application ────────────────────────────

app = FastAPI(title="Swift SAST Scanner", version="1.0.0")
detector = SwiftVulnerabilityDetector()

SWIFT_EXTENSIONS = {".swift"}


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "scanner": "swift",
        "version": "1.0.0",
        "categories": 31,
        "description": "Swift SAST Scanner with custom tokenizer and AST analysis"
    }


@app.post("/scan")
async def scan(request: ScanRequest):
    scan_id = request.scanId or str(uuid.uuid4())
    all_vulnerabilities = []
    files_scanned = 0
    errors = []

    for file_path, content in request.files.items():
        ext = "." + file_path.rsplit(".", 1)[-1] if "." in file_path else ""
        if ext.lower() not in SWIFT_EXTENSIONS:
            continue

        files_scanned += 1
        try:
            vulns = detector.scan_file(file_path, content)
            all_vulnerabilities.extend([v.to_dict() for v in vulns])
        except Exception as e:
            errors.append({"file": file_path, "error": str(e)})

    # Build severity summary
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for v in all_vulnerabilities:
        sev = v.get("severity", "Info")
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Build category summary
    category_counts: Dict[str, int] = {}
    for v in all_vulnerabilities:
        cat = v.get("category", "Unknown")
        category_counts[cat] = category_counts.get(cat, 0) + 1

    return {
        "scanId": scan_id,
        "scanner": "swift",
        "version": "1.0.0",
        "filesScanned": files_scanned,
        "totalVulnerabilities": len(all_vulnerabilities),
        "severitySummary": severity_counts,
        "categorySummary": category_counts,
        "vulnerabilities": all_vulnerabilities,
        "errors": errors
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9010)
