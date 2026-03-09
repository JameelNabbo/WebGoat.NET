#!/usr/bin/env python3
"""
Objective-C SAST Scanner - Custom tokenizer + pattern-based vulnerability detection.
Detects 25+ vulnerability categories in Objective-C source code.
Port: 9011
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


# ──────────────────────────── Obj-C Tokenizer ────────────────────────────

class TokenType(str, Enum):
    KEYWORD = "keyword"
    OBJC_KEYWORD = "objc_keyword"
    IDENTIFIER = "identifier"
    STRING_LITERAL = "string_literal"
    OBJC_STRING = "objc_string"
    NUMBER = "number"
    OPERATOR = "operator"
    PUNCTUATION = "punctuation"
    COMMENT = "comment"
    PREPROCESSOR = "preprocessor"
    MESSAGE_SEND = "message_send"
    PROPERTY_ATTR = "property_attr"
    WHITESPACE = "whitespace"
    NEWLINE = "newline"
    EOF = "eof"


@dataclass
class Token:
    type: TokenType
    value: str
    line: int
    column: int


C_KEYWORDS = {
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if",
    "inline", "int", "long", "register", "restrict", "return", "short",
    "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
    "unsigned", "void", "volatile", "while", "_Bool", "_Complex", "_Imaginary",
}

OBJC_KEYWORDS = {
    "@interface", "@implementation", "@end", "@protocol", "@optional", "@required",
    "@property", "@synthesize", "@dynamic", "@class", "@selector", "@encode",
    "@synchronized", "@try", "@catch", "@finally", "@throw", "@autoreleasepool",
    "@compatibility_alias", "@available", "@import",
    "self", "super", "nil", "Nil", "YES", "NO", "NULL",
    "id", "instancetype", "SEL", "IMP", "Class", "BOOL",
    "NSInteger", "NSUInteger", "CGFloat",
}


class ObjCTokenizer:
    """Tokenizer for Objective-C that handles @keywords, [obj method:arg], NSString @"", etc."""

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
                self._read_preprocessor()
            elif ch == "@":
                self._read_at_token()
            elif ch == "\"":
                self._read_string()
            elif ch == "'":
                self._read_char_literal()
            elif ch.isdigit():
                self._read_number()
            elif ch.isalpha() or ch == "_":
                self._read_identifier()
            elif ch in "{}()[].,;:?~":
                self.tokens.append(Token(TokenType.PUNCTUATION, ch, self.line, self.column))
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
        self.pos += 2
        self.column += 2
        while self.pos < len(self.source) - 1:
            if self.source[self.pos] == "*" and self.source[self.pos + 1] == "/":
                self.pos += 2
                self.column += 2
                break
            elif self.source[self.pos] == "\n":
                self.line += 1
                self.column = 1
                self.pos += 1
            else:
                self.pos += 1
                self.column += 1
        self.tokens.append(Token(TokenType.COMMENT, self.source[start:self.pos], start_line, start_col))

    def _read_preprocessor(self):
        start_col = self.column
        start = self.pos
        while self.pos < len(self.source) and self.source[self.pos] != "\n":
            if self.source[self.pos] == "\\" and self.pos + 1 < len(self.source) and self.source[self.pos + 1] == "\n":
                self.pos += 2
                self.line += 1
                self.column = 1
            else:
                self.pos += 1
                self.column += 1
        self.tokens.append(Token(TokenType.PREPROCESSOR, self.source[start:self.pos], self.line, start_col))

    def _read_at_token(self):
        start_col = self.column
        start = self.pos

        # Check for @"string"
        if self.pos + 1 < len(self.source) and self.source[self.pos + 1] == "\"":
            self.pos += 1
            self.column += 1
            self._read_string(is_objc=True)
            return

        # Read @keyword
        self.pos += 1
        self.column += 1
        while self.pos < len(self.source) and (self.source[self.pos].isalnum() or self.source[self.pos] == "_"):
            self.pos += 1
            self.column += 1
        value = self.source[start:self.pos]
        tok_type = TokenType.OBJC_KEYWORD if value in OBJC_KEYWORDS else TokenType.IDENTIFIER
        self.tokens.append(Token(tok_type, value, self.line, start_col))

    def _read_string(self, is_objc=False):
        start_col = self.column
        start_line = self.line
        start = self.pos
        if is_objc:
            start -= 1  # Include the @
        self.pos += 1  # skip opening "
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
        tok_type = TokenType.OBJC_STRING if is_objc else TokenType.STRING_LITERAL
        self.tokens.append(Token(tok_type, self.source[start:self.pos], start_line, start_col))

    def _read_char_literal(self):
        start_col = self.column
        start = self.pos
        self.pos += 1
        self.column += 1
        if self.pos < len(self.source) and self.source[self.pos] == "\\":
            self.pos += 2
            self.column += 2
        elif self.pos < len(self.source):
            self.pos += 1
            self.column += 1
        if self.pos < len(self.source) and self.source[self.pos] == "'":
            self.pos += 1
            self.column += 1
        self.tokens.append(Token(TokenType.STRING_LITERAL, self.source[start:self.pos], self.line, start_col))

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
        if value in C_KEYWORDS or value in OBJC_KEYWORDS:
            tok_type = TokenType.KEYWORD
        else:
            tok_type = TokenType.IDENTIFIER
        self.tokens.append(Token(tok_type, value, self.line, start_col))

    def _read_operator(self):
        start_col = self.column
        start = self.pos
        op_chars = set("+-*/%=<>&|^~!")
        while self.pos < len(self.source) and self.source[self.pos] in op_chars:
            self.pos += 1
            self.column += 1
        if self.pos == start:
            self.pos += 1
            self.column += 1
        self.tokens.append(Token(TokenType.OPERATOR, self.source[start:self.pos], self.line, start_col))


# ──────────────────────────── Vulnerability Rules ────────────────────────────

class ObjCVulnerabilityDetector:
    """Detects 25+ vulnerability categories in Objective-C code."""

    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []

    def scan_file(self, file_path: str, content: str) -> List[Vulnerability]:
        self.vulnerabilities = []
        lines = content.split("\n")
        try:
            tokenizer = ObjCTokenizer(content)
            tokens = tokenizer.tokenize()
        except Exception:
            tokens = []

        self._detect_sql_injection(file_path, content, lines)
        self._detect_command_injection(file_path, content, lines)
        self._detect_xss_webview(file_path, content, lines)
        self._detect_format_string(file_path, content, lines)
        self._detect_path_traversal(file_path, content, lines)
        self._detect_deserialization(file_path, content, lines)
        self._detect_hardcoded_secrets(file_path, content, lines)
        self._detect_weak_crypto(file_path, content, lines)
        self._detect_insecure_random(file_path, content, lines)
        self._detect_insecure_tls(file_path, content, lines)
        self._detect_memory_management(file_path, content, lines, tokens)
        self._detect_keychain_misuse(file_path, content, lines)
        self._detect_pasteboard_leaks(file_path, content, lines)
        self._detect_url_scheme_injection(file_path, content, lines)
        self._detect_info_disclosure(file_path, content, lines)
        self._detect_webview_unsafe(file_path, content, lines)
        self._detect_deprecated_apis(file_path, content, lines)
        self._detect_nslog_sensitive(file_path, content, lines)
        self._detect_missing_cert_pinning(file_path, content, lines)
        self._detect_jailbreak_detection_missing(file_path, content, lines)
        self._detect_file_protection_missing(file_path, content, lines)
        self._detect_background_fetch_leaks(file_path, content, lines)
        self._detect_nsuserdefaults_secrets(file_path, content, lines)
        self._detect_buffer_overflow(file_path, content, lines)
        self._detect_missing_input_validation(file_path, content, lines)
        self._detect_retain_cycle(file_path, content, lines)
        self._detect_insecure_ipc(file_path, content, lines)

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

    # ─── 1. SQL Injection (sqlite3_exec) ───
    def _detect_sql_injection(self, fp, content, lines):
        patterns = [
            (r'sqlite3_exec\s*\(.*(?:stringWithFormat|appendFormat|appendString)', "sqlite3_exec with dynamic string"),
            (r'sqlite3_exec\s*\(\s*\w+\s*,\s*\[.*(?:stringWithFormat|UTF8String)', "sqlite3_exec with format string"),
            (r'sqlite3_prepare.*(?:stringWithFormat|appendString)', "sqlite3_prepare with dynamic SQL"),
            (r'executeQuery\s*:\s*\[NSString\s+stringWithFormat', "FMDB executeQuery with format string"),
            (r'executeUpdate\s*:\s*\[NSString\s+stringWithFormat', "FMDB executeUpdate with format string"),
            (r'SELECT\s+.*FROM\s+.*%@', "SQL query with format specifier"),
            (r'INSERT\s+INTO\s+.*%@', "SQL INSERT with format specifier"),
            (r'UPDATE\s+.*SET\s+.*%@', "SQL UPDATE with format specifier"),
            (r'DELETE\s+FROM\s+.*%@', "SQL DELETE with format specifier"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "SQL Injection", Severity.CRITICAL,
                        f"SQL Injection: {desc}",
                        f"SQL query constructed with user-controlled data without parameterization. {desc}.",
                        fp, i, 1, line,
                        "Use sqlite3_bind_text/sqlite3_bind_int with prepared statements. Use FMDB argument substitution with ?.",
                        "CWE-89", "A03:2021-Injection")

    # ─── 2. Command Injection (NSTask, system()) ───
    def _detect_command_injection(self, fp, content, lines):
        patterns = [
            (r'NSTask\s*\*.*=\s*\[\[NSTask\s+alloc\]\s+init\]', "NSTask instantiation"),
            (r'\[.*setLaunchPath\s*:\s*.*(?:stringWithFormat|%@)', "NSTask launchPath with dynamic string"),
            (r'\[.*setArguments\s*:\s*.*(?:stringWithFormat|%@)', "NSTask arguments with dynamic string"),
            (r'\bsystem\s*\(', "C system() call"),
            (r'\bpopen\s*\(', "C popen() call"),
            (r'\bexecv[pe]?\s*\(', "exec family function call"),
            (r'NSTask.*launchPath.*stringWithFormat', "NSTask with format string path"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    sev = Severity.CRITICAL if any(x in desc for x in ["system()", "popen()", "exec", "dynamic"]) else Severity.HIGH
                    self._add_vuln(
                        "Command Injection", sev,
                        f"Command Injection: {desc}",
                        f"External command execution with potential user input. {desc}.",
                        fp, i, 1, line,
                        "Validate and sanitize all inputs to command execution. Avoid system()/popen(). Use NSTask with static paths.",
                        "CWE-78", "A03:2021-Injection")

    # ─── 3. XSS (UIWebView/WKWebView) ───
    def _detect_xss_webview(self, fp, content, lines):
        patterns = [
            (r'UIWebView', "UIWebView usage (deprecated, insecure)"),
            (r'loadHTMLString\s*:.*(?:stringWithFormat|%@)', "loadHTMLString with dynamic content"),
            (r'stringByEvaluatingJavaScriptFromString\s*:.*(?:stringWithFormat|%@)', "JavaScript execution with format string"),
            (r'evaluateJavaScript\s*:.*(?:stringWithFormat|%@)', "WKWebView JS execution with format string"),
            (r'\[.*loadRequest\s*:.*(?:stringWithFormat|%@)', "WebView loading dynamic request"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    sev = Severity.HIGH if "UIWebView" in desc or "dynamic" in desc.lower() else Severity.MEDIUM
                    self._add_vuln(
                        "Cross-Site Scripting (XSS)", sev,
                        f"XSS via WebView: {desc}",
                        f"WebView may render attacker-controlled content. {desc}.",
                        fp, i, 1, line,
                        "Migrate from UIWebView to WKWebView. Sanitize all content before loading. Avoid dynamic JS evaluation.",
                        "CWE-79", "A03:2021-Injection")

    # ─── 4. Format String Vulnerability ───
    def _detect_format_string(self, fp, content, lines):
        patterns = [
            (r'NSLog\s*\(\s*(?!@?")(\w+)', "NSLog with variable as format string"),
            (r'NSLog\s*\(\s*\[.*(?:stringWithFormat|description)\]', "NSLog with dynamic format"),
            (r'\[\s*NSString\s+stringWithFormat\s*:\s*(?!@?")(\w+)', "stringWithFormat with variable format"),
            (r'printf\s*\(\s*(?!")[a-zA-Z_]\w*', "printf with variable format string"),
            (r'fprintf\s*\(\s*\w+\s*,\s*(?!")[a-zA-Z_]\w*', "fprintf with variable format string"),
            (r'sprintf\s*\(\s*\w+\s*,\s*(?!")[a-zA-Z_]\w*', "sprintf with variable format string"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    self._add_vuln(
                        "Format String Vulnerability", Severity.HIGH,
                        f"Format String: {desc}",
                        f"User-controlled data used as format string. {desc}. Attacker can read/write memory.",
                        fp, i, 1, line,
                        "Always use literal format strings: NSLog(@\"%@\", variable). Never pass variables directly as format strings.",
                        "CWE-134", "A03:2021-Injection")

    # ─── 5. Path Traversal ───
    def _detect_path_traversal(self, fp, content, lines):
        patterns = [
            (r'(?:contentsOfFile|contentsAtPath|fileExistsAtPath|dataWithContentsOfFile)\s*:.*(?:stringWithFormat|%@)', "File access with dynamic path"),
            (r'stringByAppendingPathComponent\s*:.*(?:param|input|request|user|query)', "Path component from user input"),
            (r'NSFileManager.*(?:contentsOfDirectory|removeItem|moveItem|copyItem).*(?:stringWithFormat|%@)', "File operation with dynamic path"),
            (r'initWithContentsOfFile\s*:.*(?:stringWithFormat|%@)', "File init with dynamic path"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Path Traversal", Severity.HIGH,
                        f"Path Traversal: {desc}",
                        f"File system operation with potentially user-controlled path. {desc}.",
                        fp, i, 1, line,
                        "Validate paths against a known base directory. Reject paths with '..' components.",
                        "CWE-22", "A01:2021-Broken Access Control")

    # ─── 6. Deserialization (NSKeyedUnarchiver, NSCoding) ───
    def _detect_deserialization(self, fp, content, lines):
        patterns = [
            (r'NSKeyedUnarchiver\s+unarchiveObjectWithData', "NSKeyedUnarchiver.unarchiveObjectWithData (insecure)"),
            (r'NSKeyedUnarchiver\s+unarchiveObjectWithFile', "NSKeyedUnarchiver.unarchiveObjectWithFile (insecure)"),
            (r'unarchiveTopLevelObjectWithData', "unarchiveTopLevelObjectWithData (insecure)"),
            (r'initForReadingWithData\s*:', "NSKeyedUnarchiver initForReadingWithData (insecure)"),
            (r'NSUnarchiver', "NSUnarchiver (deprecated, insecure)"),
            (r'<NSCoding>', "NSCoding conformance (potential deserialization risk)"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    sev = Severity.CRITICAL if "insecure" in desc.lower() else Severity.MEDIUM
                    self._add_vuln(
                        "Insecure Deserialization", sev,
                        f"Deserialization: {desc}",
                        f"Insecure deserialization may allow code execution. {desc}.",
                        fp, i, 1, line,
                        "Use NSSecureCoding with unarchivedObjectOfClass:fromData:error:. Set requiresSecureCoding = YES.",
                        "CWE-502", "A08:2021-Software and Data Integrity Failures")

    # ─── 7. Hardcoded Secrets ───
    def _detect_hardcoded_secrets(self, fp, content, lines):
        patterns = [
            (r'(?:api[_-]?key|apikey|secret[_-]?key|password|passwd|token|auth[_-]?token|access[_-]?key)\s*=\s*@?"[^"]{8,}"', "Hardcoded secret"),
            (r'(?:Bearer|Basic)\s+[A-Za-z0-9+/=]{20,}', "Hardcoded authorization token"),
            (r'AIza[0-9A-Za-z_-]{35}', "Google API key"),
            (r'sk-[A-Za-z0-9]{20,}', "Secret key pattern"),
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
            (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "Embedded private key"),
            (r'#define\s+\w*(?:KEY|SECRET|PASSWORD|TOKEN)\w*\s+@?"[^"]{8,}"', "Hardcoded credential in macro"),
        ]
        for i, line in enumerate(lines, 1):
            if re.search(r'//.*(?:example|test|sample|placeholder|TODO)', line, re.IGNORECASE):
                continue
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Hardcoded Secrets", Severity.CRITICAL,
                        f"Hardcoded Secret: {desc}",
                        f"Sensitive credential hardcoded in source code. {desc}.",
                        fp, i, 1, line,
                        "Store secrets in Keychain. Use environment variables or configuration files excluded from source control.",
                        "CWE-798", "A07:2021-Identification and Authentication Failures")

    # ─── 8. Weak Cryptography (CommonCrypto MD5/SHA1) ───
    def _detect_weak_crypto(self, fp, content, lines):
        patterns = [
            (r'CC_MD5\s*\(', "CC_MD5 hash (weak)"),
            (r'CC_SHA1\s*\(', "CC_SHA1 hash (weak)"),
            (r'CC_MD5_Init', "MD5 context initialization"),
            (r'CC_SHA1_Init', "SHA1 context initialization"),
            (r'kCCAlgorithmDES\b', "DES encryption (weak)"),
            (r'kCCAlgorithm3DES\b', "3DES encryption (weak)"),
            (r'kCCOptionECBMode\b', "ECB mode (insecure)"),
            (r'kCCModeCBC.*kCCOptionPKCS7Padding', "CBC with PKCS7 (consider GCM)"),
            (r'CCCrypt.*kCCOptionECBMode', "ECB mode encryption"),
            (r'MD5\s*\(', "MD5 function call"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    sev = Severity.HIGH if "ECB" in desc or "DES" in desc else Severity.MEDIUM
                    self._add_vuln(
                        "Weak Cryptography", sev,
                        f"Weak Crypto: {desc}",
                        f"Weak or deprecated cryptographic algorithm. {desc}.",
                        fp, i, 1, line,
                        "Use SHA-256+ for hashing, AES-256 in GCM/CTR mode for encryption. Migrate from MD5/SHA1/DES.",
                        "CWE-327", "A02:2021-Cryptographic Failures")

    # ─── 9. Insecure Random (arc4random pre-seed) ───
    def _detect_insecure_random(self, fp, content, lines):
        patterns = [
            (r'\brand\s*\(\s*\)', "C rand() function"),
            (r'\brandom\s*\(\s*\)', "random() function"),
            (r'srand\s*\(', "srand() seeding"),
            (r'srandom\s*\(', "srandom() seeding"),
            (r'drand48\s*\(', "drand48() function"),
            (r'arc4random\s*\(\s*\)', "arc4random() without uniform"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    sev = Severity.HIGH if "rand()" in desc or "srand" in desc else Severity.MEDIUM
                    self._add_vuln(
                        "Insecure Random", sev,
                        f"Insecure Random: {desc}",
                        f"Weak random number generator. {desc}. Not suitable for security operations.",
                        fp, i, 1, line,
                        "Use SecRandomCopyBytes() for cryptographic randomness. Use arc4random_uniform() for non-crypto needs.",
                        "CWE-330", "A02:2021-Cryptographic Failures")

    # ─── 10. Insecure TLS ───
    def _detect_insecure_tls(self, fp, content, lines):
        patterns = [
            (r'NSAllowsArbitraryLoads.*YES', "ATS disabled (AllowsArbitraryLoads)"),
            (r'setAllowsAnyHTTPSCertificate.*YES', "All HTTPS certificates allowed"),
            (r'continueWithoutCredentialForAuthenticationChallenge', "SSL challenge bypassed"),
            (r'NSURLSessionAuthChallenge.*UseCredential', "Certificate validation bypassed in challenge"),
            (r'allowInvalidCertificates\s*=\s*YES', "Invalid certificates allowed"),
            (r'SSLSetProtocolVersionMin.*kSSLProtocol[23]', "Weak SSL/TLS protocol"),
            (r'kSSLProtocol2\b', "SSLv2 (insecure)"),
            (r'kSSLProtocol3\b', "SSLv3 (insecure)"),
            (r'kTLSProtocol1\b', "TLS 1.0 (weak)"),
            (r'validatesDomainName\s*=\s*NO', "Domain name validation disabled"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Insecure TLS Configuration", Severity.HIGH,
                        f"Insecure TLS: {desc}",
                        f"TLS/SSL configuration weakened. {desc}.",
                        fp, i, 1, line,
                        "Enable ATS. Use TLS 1.2+. Implement certificate pinning. Validate domain names.",
                        "CWE-295", "A02:2021-Cryptographic Failures")

    # ─── 11. Memory Management Issues ───
    def _detect_memory_management(self, fp, content, lines, tokens):
        patterns = [
            (r'\[\s*\w+\s+release\s*\]', "Manual release (verify ARC usage)"),
            (r'\[\s*\w+\s+autorelease\s*\]', "Manual autorelease (verify ARC usage)"),
            (r'\[\s*\w+\s+retain\s*\]', "Manual retain (verify ARC usage)"),
            (r'\[\s*\w+\s+dealloc\s*\]', "Manual dealloc call"),
            (r'retainCount\b', "retainCount usage (unreliable)"),
            (r'CFRelease\s*\(\s*NULL', "CFRelease with NULL (crash)"),
            (r'free\s*\(\s*\w+\s*\)(?!.*\w+\s*=\s*NULL)', "free() without NULL assignment"),
        ]
        is_arc = not bool(re.search(r'-fno-objc-arc|__unsafe_unretained.*=', content))
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    if is_arc and ("release" in desc or "retain" in desc or "autorelease" in desc):
                        self._add_vuln(
                            "Memory Management", Severity.MEDIUM,
                            f"Memory Management: {desc}",
                            f"Manual memory management in ARC context. {desc}.",
                            fp, i, 1, line,
                            "Remove manual retain/release/autorelease calls when using ARC. Use __bridge for CF objects.",
                            "CWE-401", "A04:2021-Insecure Design", confidence="Medium")
                    elif "retainCount" in desc or "dealloc" in desc or "CFRelease" in desc or "free" in desc:
                        self._add_vuln(
                            "Memory Management", Severity.HIGH,
                            f"Memory Issue: {desc}",
                            f"Dangerous memory management pattern. {desc}.",
                            fp, i, 1, line,
                            "Avoid retainCount. Never call dealloc directly. Check for NULL before CFRelease. Set pointers to NULL after free.",
                            "CWE-416", "A04:2021-Insecure Design")

    # ─── 12. Keychain Misuse ───
    def _detect_keychain_misuse(self, fp, content, lines):
        patterns = [
            (r'NSUserDefaults.*(?:password|secret|token|key|credential)', "Secrets in NSUserDefaults"),
            (r'standardUserDefaults.*set.*(?:password|secret|token)', "Password/token in NSUserDefaults"),
            (r'kSecAttrAccessibleAlways\b', "Keychain always accessible (deprecated)"),
            (r'kSecAttrAccessibleAlwaysThisDeviceOnly', "Keychain always accessible (deprecated)"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    sev = Severity.HIGH if "NSUserDefaults" in desc else Severity.MEDIUM
                    self._add_vuln(
                        "Keychain Misuse", sev,
                        f"Keychain Misuse: {desc}",
                        f"Sensitive data stored insecurely. {desc}.",
                        fp, i, 1, line,
                        "Use Keychain with kSecAttrAccessibleWhenUnlockedThisDeviceOnly. Never use NSUserDefaults for secrets.",
                        "CWE-922", "A04:2021-Insecure Design")

    # ─── 13. Pasteboard Leaks ───
    def _detect_pasteboard_leaks(self, fp, content, lines):
        patterns = [
            (r'\[UIPasteboard\s+generalPasteboard\].*(?:setString|setValue).*(?:password|secret|token)', "Sensitive data on pasteboard"),
            (r'\[UIPasteboard\s+generalPasteboard\]', "General pasteboard access"),
            (r'UIPasteboardNameGeneral', "General pasteboard name reference"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    sev = Severity.HIGH if "password" in line.lower() or "secret" in line.lower() else Severity.MEDIUM
                    self._add_vuln(
                        "Pasteboard Data Leak", sev,
                        f"Pasteboard Leak: {desc}",
                        f"Data may leak via system pasteboard. {desc}. Other apps can read it.",
                        fp, i, 1, line,
                        "Use local pasteboards with expiration. Avoid placing sensitive data on the general pasteboard.",
                        "CWE-200", "A04:2021-Insecure Design")

    # ─── 14. URL Scheme Injection ───
    def _detect_url_scheme_injection(self, fp, content, lines):
        patterns = [
            (r'handleOpenURL\s*:', "URL scheme handler"),
            (r'openURL\s*:\s*.*(?:stringWithFormat|%@)', "openURL with dynamic URL"),
            (r'application.*openURL.*sourceApplication', "URL scheme without source validation"),
            (r'\[NSURL\s+URLWithString\s*:\s*.*(?:stringWithFormat|%@)', "NSURL from dynamic string"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    self._add_vuln(
                        "URL Scheme Injection", Severity.MEDIUM,
                        f"URL Scheme: {desc}",
                        f"URL scheme handling may be abused. {desc}.",
                        fp, i, 1, line,
                        "Validate URL scheme parameters. Verify sourceApplication. Use Universal Links instead.",
                        "CWE-939", "A07:2021-Identification and Authentication Failures")

    # ─── 15. Information Disclosure ───
    def _detect_info_disclosure(self, fp, content, lines):
        patterns = [
            (r'NSLog\s*\(\s*@?".*(?:password|secret|token|credit|ssn)', "NSLog with sensitive data"),
            (r'NSLog\s*\(\s*@?".*(?:Error|error|Exception).*%@', "Verbose error in NSLog"),
            (r'NSException.*reason\s*:', "Exception reason may leak info"),
            (r'description\].*(?:password|secret|token)', "Object description with secrets"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Information Disclosure", Severity.MEDIUM,
                        f"Info Disclosure: {desc}",
                        f"Sensitive information may be leaked. {desc}.",
                        fp, i, 1, line,
                        "Remove sensitive data from NSLog in production. Use os_log with privacy annotations.",
                        "CWE-532", "A09:2021-Security Logging and Monitoring Failures")

    # ─── 16. WebView Unsafe Settings ───
    def _detect_webview_unsafe(self, fp, content, lines):
        patterns = [
            (r'UIWebView', "UIWebView (deprecated, use WKWebView)"),
            (r'scalesPageToFit\s*=\s*YES', "WebView scalesPageToFit"),
            (r'allowsInlineMediaPlayback\s*=\s*YES', "Inline media playback (verify need)"),
            (r'mediaPlaybackRequiresUserAction\s*=\s*NO', "Auto media playback enabled"),
            (r'javaScriptEnabled\s*=\s*YES', "JavaScript explicitly enabled"),
            (r'allowFileAccessFromFileURLs.*YES', "File URL access enabled"),
            (r'allowUniversalAccessFromFileURLs.*YES', "Universal file URL access enabled"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    sev = Severity.HIGH if "Universal" in desc or "UIWebView" in desc else Severity.MEDIUM
                    self._add_vuln(
                        "WebView Unsafe Configuration", sev,
                        f"WebView Unsafe: {desc}",
                        f"WebView security misconfiguration. {desc}.",
                        fp, i, 1, line,
                        "Migrate to WKWebView. Disable unnecessary features. Restrict file URL access.",
                        "CWE-16", "A05:2021-Security Misconfiguration")

    # ─── 17. Deprecated APIs ───
    def _detect_deprecated_apis(self, fp, content, lines):
        patterns = [
            (r'UIWebView', "UIWebView (deprecated since iOS 12)"),
            (r'UIAlertView\b', "UIAlertView (deprecated since iOS 9)"),
            (r'UIActionSheet\b', "UIActionSheet (deprecated since iOS 8)"),
            (r'ABAddressBook\b', "ABAddressBook (deprecated, use Contacts)"),
            (r'ALAssetsLibrary\b', "ALAssetsLibrary (deprecated, use Photos)"),
            (r'UIPopoverController\b', "UIPopoverController (deprecated since iOS 9)"),
            (r'addressBook\s*=\s*ABAddressBookCreate', "ABAddressBookCreate (deprecated)"),
            (r'MPMoviePlayerController\b', "MPMoviePlayerController (deprecated)"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    self._add_vuln(
                        "Deprecated API Usage", Severity.LOW,
                        f"Deprecated API: {desc}",
                        f"Usage of deprecated API. {desc}. May be removed in future iOS versions.",
                        fp, i, 1, line,
                        "Migrate to recommended replacement APIs. Check Apple deprecation documentation.",
                        "CWE-477", "A06:2021-Vulnerable and Outdated Components")

    # ─── 18. NSLog Sensitive Data ───
    def _detect_nslog_sensitive(self, fp, content, lines):
        patterns = [
            (r'NSLog\s*\(.*(?:password|passwd|pwd|secret|token|api.?key|credential|auth)', "NSLog leaking sensitive data"),
            (r'NSLog\s*\(.*(?:credit.?card|cvv|ssn|social.?security)', "NSLog leaking PII"),
            (r'NSLog\s*\(.*(?:session|cookie|nonce|salt|hash)', "NSLog leaking security tokens"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "NSLog Sensitive Data", Severity.MEDIUM,
                        f"NSLog: {desc}",
                        f"Sensitive data logged via NSLog. {desc}. NSLog output is readable by other apps on non-jailbroken devices via Console.",
                        fp, i, 1, line,
                        "Remove NSLog with sensitive data in release builds. Use os_log with privacy annotations.",
                        "CWE-532", "A09:2021-Security Logging and Monitoring Failures")

    # ─── 19. Missing Certificate Pinning ───
    def _detect_missing_cert_pinning(self, fp, content, lines):
        has_networking = bool(re.search(r'NSURLSession|NSURLConnection|AFHTTPSessionManager|AFNetworking', content))
        has_pinning = bool(re.search(r'SecTrustEvaluate|evaluateServerTrust|pinnedCertificates|SSLPinningMode|TrustKit', content))
        if has_networking and not has_pinning:
            for i, line in enumerate(lines, 1):
                if re.search(r'NSURLSession|NSURLConnection|AFHTTPSessionManager', line):
                    self._add_vuln(
                        "Missing Certificate Pinning", Severity.MEDIUM,
                        "No certificate pinning for network requests",
                        "Network requests made without certificate pinning. Vulnerable to MITM attacks with rogue CAs.",
                        fp, i, 1, line,
                        "Implement certificate pinning using TrustKit, AFSecurityPolicy, or URLSessionDelegate.",
                        "CWE-295", "A02:2021-Cryptographic Failures", confidence="Medium")

    # ─── 20. Jailbreak Detection Missing ───
    def _detect_jailbreak_detection_missing(self, fp, content, lines):
        has_sensitive_ops = bool(re.search(r'Keychain|SecItem|kSecClass|LAContext|evaluatePolicy', content))
        has_jb_check = bool(re.search(r'jailbreak|jailbroken|cydia|substrate|checkJailbreak|isJailbroken|/Applications/Cydia', content, re.IGNORECASE))
        if has_sensitive_ops and not has_jb_check:
            for i, line in enumerate(lines, 1):
                if re.search(r'Keychain|SecItem|LAContext', line):
                    self._add_vuln(
                        "Missing Jailbreak Detection", Severity.LOW,
                        "No jailbreak detection for sensitive operations",
                        "Sensitive operations performed without jailbreak detection. Keychain and biometrics are less secure on jailbroken devices.",
                        fp, i, 1, line,
                        "Implement jailbreak detection checks before sensitive operations.",
                        "CWE-693", "A07:2021-Identification and Authentication Failures",
                        confidence="Medium")

    # ─── 21. File Protection Missing ───
    def _detect_file_protection_missing(self, fp, content, lines):
        patterns = [
            (r'NSFileProtectionNone', "NSFileProtectionNone"),
            (r'NSDataWritingFileProtectionNone', "Data writing without protection"),
            (r'createFileAtPath.*attributes\s*:\s*nil', "File created with nil attributes"),
            (r'NSFileProtectionCompleteUntilFirstUserAuthentication', "File accessible after first unlock"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    sev = Severity.MEDIUM if "None" in desc else Severity.LOW
                    self._add_vuln(
                        "Missing File Protection", sev,
                        f"File Protection: {desc}",
                        f"File may be accessible when device is locked. {desc}.",
                        fp, i, 1, line,
                        "Use NSFileProtectionComplete for sensitive files. Set file attributes explicitly.",
                        "CWE-732", "A01:2021-Broken Access Control")

    # ─── 22. Background Fetch Leaks ───
    def _detect_background_fetch_leaks(self, fp, content, lines):
        patterns = [
            (r'application.*performFetchWithCompletionHandler.*(?:password|secret|token|credential)', "Background fetch with credentials"),
            (r'beginBackgroundTaskWithExpirationHandler.*(?:password|secret|token)', "Background task handling secrets"),
            (r'UIBackgroundFetchInterval', "Background fetch enabled (verify data handling)"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    conf = "Medium" if "UIBackgroundFetchInterval" in desc else "High"
                    self._add_vuln(
                        "Background Fetch Data Leak", Severity.MEDIUM,
                        f"Background Fetch: {desc}",
                        f"Sensitive data may be exposed during background fetch. {desc}.",
                        fp, i, 1, line,
                        "Clear sensitive data before backgrounding. Use data protection APIs.",
                        "CWE-200", "A04:2021-Insecure Design", confidence=conf)

    # ─── 23. NSUserDefaults for Secrets ───
    def _detect_nsuserdefaults_secrets(self, fp, content, lines):
        patterns = [
            (r'\[NSUserDefaults\s+standardUserDefaults\].*(?:password|secret|token|api.?key|credential)', "NSUserDefaults storing secrets"),
            (r'setObject.*forKey.*(?:password|secret|token|apiKey)', "NSUserDefaults secret storage"),
            (r'NSUserDefaults.*setBool.*(?:isLoggedIn|authenticated)', "Auth state in NSUserDefaults"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "NSUserDefaults Secrets", Severity.HIGH,
                        f"NSUserDefaults: {desc}",
                        f"Sensitive data in NSUserDefaults (unencrypted plist). {desc}.",
                        fp, i, 1, line,
                        "Use Keychain for secrets. NSUserDefaults is stored as an unencrypted plist file.",
                        "CWE-922", "A04:2021-Insecure Design")

    # ─── 24. Buffer Overflow (C-style strings) ───
    def _detect_buffer_overflow(self, fp, content, lines):
        patterns = [
            (r'\bstrcpy\s*\(', "strcpy (no bounds checking)"),
            (r'\bstrcat\s*\(', "strcat (no bounds checking)"),
            (r'\bsprintf\s*\(', "sprintf (no bounds checking)"),
            (r'\bgets\s*\(', "gets() (never safe)"),
            (r'\bscanf\s*\(\s*"[^"]*%s', "scanf %s without width limit"),
            (r'\bmemcpy\s*\(.*(?:strlen|sizeof)', "memcpy with potential overflow"),
            (r'char\s+\w+\s*\[\s*\d+\s*\].*(?:strcpy|strcat|sprintf)', "Fixed buffer with unsafe string ops"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    sev = Severity.CRITICAL if "gets" in desc else Severity.HIGH
                    self._add_vuln(
                        "Buffer Overflow", sev,
                        f"Buffer Overflow: {desc}",
                        f"Potential buffer overflow. {desc}. May allow arbitrary code execution.",
                        fp, i, 1, line,
                        "Use strlcpy/strlcat/snprintf instead. Use NSString/NSData for string handling in Obj-C.",
                        "CWE-120", "A03:2021-Injection")

    # ─── 25. Missing Input Validation ───
    def _detect_missing_input_validation(self, fp, content, lines):
        patterns = [
            (r'objectForKey\s*:.*(?:param|input|user|query|request)', "Dictionary value from user input without validation"),
            (r'valueForKey\s*:.*(?:param|input|user|query)', "KVC valueForKey with user input"),
            (r'performSelector\s*:.*(?:NSSelectorFromString)', "Dynamic selector from string"),
            (r'setValue\s*:.*forKeyPath\s*:.*(?:param|input|user)', "KVC setValueForKeyPath with user data"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    sev = Severity.HIGH if "performSelector" in desc else Severity.MEDIUM
                    self._add_vuln(
                        "Missing Input Validation", sev,
                        f"Input Validation: {desc}",
                        f"User input used without validation. {desc}.",
                        fp, i, 1, line,
                        "Validate all input types, ranges, and formats. Avoid dynamic selectors from user input.",
                        "CWE-20", "A03:2021-Injection")

    # ─── 26. Retain Cycles ───
    def _detect_retain_cycle(self, fp, content, lines):
        patterns = [
            (r'\^\s*\{[^}]*\bself\b', "Block capturing self strongly (potential retain cycle)"),
            (r'(?:completion|callback|handler)\s*=\s*\^.*self', "Callback block capturing self"),
        ]
        has_weak_self = bool(re.search(r'__weak\s+typeof\s*\(\s*self\s*\)|weakSelf|__weak.*self', content))
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    if not has_weak_self:
                        self._add_vuln(
                            "Retain Cycle", Severity.MEDIUM,
                            f"Retain Cycle: {desc}",
                            f"Block captures self strongly without __weak reference. {desc}. May cause memory leaks.",
                            fp, i, 1, line,
                            "Use __weak typeof(self) weakSelf = self; before the block. Use weakSelf inside the block.",
                            "CWE-401", "A04:2021-Insecure Design", confidence="Medium")

    # ─── 27. Insecure IPC ───
    def _detect_insecure_ipc(self, fp, content, lines):
        patterns = [
            (r'NSDistributedNotificationCenter', "NSDistributedNotificationCenter (cross-process, unprotected)"),
            (r'CFMessagePort', "CFMessagePort IPC"),
            (r'NSXPCConnection.*(?:without|no).*(?:auth|valid)', "NSXPC without authentication"),
            (r'NSMachPort', "NSMachPort IPC"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Insecure IPC", Severity.MEDIUM,
                        f"Insecure IPC: {desc}",
                        f"Inter-process communication may be intercepted. {desc}.",
                        fp, i, 1, line,
                        "Use authenticated NSXPC connections. Validate messages. Restrict IPC endpoints.",
                        "CWE-927", "A04:2021-Insecure Design")


# ──────────────────────────── FastAPI Application ────────────────────────────

app = FastAPI(title="Objective-C SAST Scanner", version="1.0.0")
detector = ObjCVulnerabilityDetector()

OBJC_EXTENSIONS = {".m", ".mm", ".h"}


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "scanner": "objc",
        "version": "1.0.0",
        "categories": 27,
        "description": "Objective-C SAST Scanner with custom tokenizer and pattern analysis"
    }


@app.post("/scan")
async def scan(request: ScanRequest):
    scan_id = request.scanId or str(uuid.uuid4())
    all_vulnerabilities = []
    files_scanned = 0
    errors = []

    for file_path, content in request.files.items():
        ext = "." + file_path.rsplit(".", 1)[-1] if "." in file_path else ""
        if ext.lower() not in OBJC_EXTENSIONS:
            continue

        files_scanned += 1
        try:
            vulns = detector.scan_file(file_path, content)
            all_vulnerabilities.extend([v.to_dict() for v in vulns])
        except Exception as e:
            errors.append({"file": file_path, "error": str(e)})

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for v in all_vulnerabilities:
        sev = v.get("severity", "Info")
        if sev in severity_counts:
            severity_counts[sev] += 1

    category_counts: Dict[str, int] = {}
    for v in all_vulnerabilities:
        cat = v.get("category", "Unknown")
        category_counts[cat] = category_counts.get(cat, 0) + 1

    return {
        "scanId": scan_id,
        "scanner": "objc",
        "version": "1.0.0",
        "filesScanned": files_scanned,
        "totalVulnerabilities": len(all_vulnerabilities),
        "severitySummary": severity_counts,
        "categorySummary": category_counts,
        "vulnerabilities": all_vulnerabilities,
        "errors": errors
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9011)
