#!/usr/bin/env python3
"""
Dart SAST Scanner - Custom tokenizer + pattern-based vulnerability detection.
Detects 25+ vulnerability categories in Dart/Flutter source code.
Port: 9013
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


# ──────────────────────────── Dart Tokenizer ────────────────────────────

class TokenType(str, Enum):
    KEYWORD = "keyword"
    IDENTIFIER = "identifier"
    STRING_LITERAL = "string_literal"
    RAW_STRING = "raw_string"
    MULTILINE_STRING = "multiline_string"
    NUMBER = "number"
    OPERATOR = "operator"
    PUNCTUATION = "punctuation"
    COMMENT = "comment"
    ANNOTATION = "annotation"
    NULL_AWARE = "null_aware"
    CASCADE = "cascade"
    BANG = "bang"
    WHITESPACE = "whitespace"
    NEWLINE = "newline"
    EOF = "eof"


@dataclass
class Token:
    type: TokenType
    value: str
    line: int
    column: int


DART_KEYWORDS = {
    "abstract", "as", "assert", "async", "await", "break", "case", "catch",
    "class", "const", "continue", "covariant", "default", "deferred", "do",
    "dynamic", "else", "enum", "export", "extends", "extension", "external",
    "factory", "false", "final", "finally", "for", "Function", "get", "hide",
    "if", "implements", "import", "in", "interface", "is", "late", "library",
    "mixin", "new", "null", "on", "operator", "part", "required", "rethrow",
    "return", "sealed", "set", "show", "static", "super", "switch", "sync",
    "this", "throw", "true", "try", "typedef", "var", "void", "when",
    "while", "with", "yield",
}


class DartTokenizer:
    """Tokenizer for Dart that handles string interpolation, raw strings, cascade, null-aware, etc."""

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
            elif ch == "@":
                self._read_annotation()
            elif ch == "r" and self.pos + 1 < len(self.source) and self.source[self.pos + 1] in "\"'":
                self._read_raw_string()
            elif ch in "\"'":
                self._read_string()
            elif ch.isdigit():
                self._read_number()
            elif ch.isalpha() or ch == "_" or ch == "$":
                self._read_identifier()
            elif ch == "." and self.pos + 1 < len(self.source) and self.source[self.pos + 1] == ".":
                if self.pos + 2 < len(self.source) and self.source[self.pos + 2] == ".":
                    self.tokens.append(Token(TokenType.OPERATOR, "...", self.line, self.column))
                    self.pos += 3
                    self.column += 3
                else:
                    self.tokens.append(Token(TokenType.CASCADE, "..", self.line, self.column))
                    self.pos += 2
                    self.column += 2
            elif ch == "?" and self.pos + 1 < len(self.source) and self.source[self.pos + 1] in ".?":
                if self.source[self.pos + 1] == ".":
                    self.tokens.append(Token(TokenType.NULL_AWARE, "?.", self.line, self.column))
                    self.pos += 2
                    self.column += 2
                elif self.source[self.pos + 1] == "?":
                    self.tokens.append(Token(TokenType.NULL_AWARE, "??", self.line, self.column))
                    self.pos += 2
                    self.column += 2
                else:
                    self.tokens.append(Token(TokenType.PUNCTUATION, "?", self.line, self.column))
                    self.pos += 1
                    self.column += 1
            elif ch == "!":
                self.tokens.append(Token(TokenType.BANG, "!", self.line, self.column))
                self.pos += 1
                self.column += 1
            elif ch in "{}()[].,;:?":
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

    def _read_annotation(self):
        start_col = self.column
        start = self.pos
        self.pos += 1
        self.column += 1
        while self.pos < len(self.source) and (self.source[self.pos].isalnum() or self.source[self.pos] == "_"):
            self.pos += 1
            self.column += 1
        self.tokens.append(Token(TokenType.ANNOTATION, self.source[start:self.pos], self.line, start_col))

    def _read_raw_string(self):
        start_col = self.column
        start = self.pos
        self.pos += 1  # skip r
        self.column += 1
        quote = self.source[self.pos]
        # Check for triple quote
        if self.pos + 2 < len(self.source) and self.source[self.pos:self.pos + 3] == quote * 3:
            self.pos += 3
            self.column += 3
            end_quote = quote * 3
            while self.pos < len(self.source) - 2:
                if self.source[self.pos:self.pos + 3] == end_quote:
                    self.pos += 3
                    self.column += 3
                    break
                elif self.source[self.pos] == "\n":
                    self.line += 1
                    self.column = 1
                    self.pos += 1
                else:
                    self.pos += 1
                    self.column += 1
        else:
            self.pos += 1
            self.column += 1
            while self.pos < len(self.source) and self.source[self.pos] != quote:
                self.pos += 1
                self.column += 1
            if self.pos < len(self.source):
                self.pos += 1
                self.column += 1
        self.tokens.append(Token(TokenType.RAW_STRING, self.source[start:self.pos], self.line, start_col))

    def _read_string(self):
        start_col = self.column
        start_line = self.line
        start = self.pos
        quote = self.source[self.pos]
        # Triple quote
        if self.pos + 2 < len(self.source) and self.source[self.pos:self.pos + 3] == quote * 3:
            self.pos += 3
            self.column += 3
            end_quote = quote * 3
            while self.pos < len(self.source) - 2:
                if self.source[self.pos:self.pos + 3] == end_quote:
                    self.pos += 3
                    self.column += 3
                    break
                elif self.source[self.pos] == "\\":
                    self.pos += 2
                    self.column += 2
                elif self.source[self.pos] == "\n":
                    self.line += 1
                    self.column = 1
                    self.pos += 1
                else:
                    self.pos += 1
                    self.column += 1
            self.tokens.append(Token(TokenType.MULTILINE_STRING, self.source[start:self.pos], start_line, start_col))
        else:
            self.pos += 1
            self.column += 1
            while self.pos < len(self.source) and self.source[self.pos] != quote:
                if self.source[self.pos] == "\\":
                    self.pos += 2
                    self.column += 2
                elif self.source[self.pos] == "\n":
                    break
                else:
                    self.pos += 1
                    self.column += 1
            if self.pos < len(self.source) and self.source[self.pos] == quote:
                self.pos += 1
                self.column += 1
            self.tokens.append(Token(TokenType.STRING_LITERAL, self.source[start:self.pos], start_line, start_col))

    def _read_number(self):
        start_col = self.column
        start = self.pos
        while self.pos < len(self.source) and (self.source[self.pos].isalnum() or self.source[self.pos] in "._xXeE+-"):
            self.pos += 1
            self.column += 1
        self.tokens.append(Token(TokenType.NUMBER, self.source[start:self.pos], self.line, start_col))

    def _read_identifier(self):
        start_col = self.column
        start = self.pos
        while self.pos < len(self.source) and (self.source[self.pos].isalnum() or self.source[self.pos] in "_$"):
            self.pos += 1
            self.column += 1
        value = self.source[start:self.pos]
        tok_type = TokenType.KEYWORD if value in DART_KEYWORDS else TokenType.IDENTIFIER
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

class DartVulnerabilityDetector:
    """Detects 25+ vulnerability categories in Dart/Flutter code."""

    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []

    def scan_file(self, file_path: str, content: str) -> List[Vulnerability]:
        self.vulnerabilities = []
        lines = content.split("\n")
        try:
            tokenizer = DartTokenizer(content)
            tokens = tokenizer.tokenize()
        except Exception:
            tokens = []

        self._detect_sql_injection(file_path, content, lines)
        self._detect_command_injection(file_path, content, lines)
        self._detect_xss_webview(file_path, content, lines)
        self._detect_path_traversal(file_path, content, lines)
        self._detect_deserialization(file_path, content, lines)
        self._detect_hardcoded_secrets(file_path, content, lines)
        self._detect_weak_crypto(file_path, content, lines)
        self._detect_insecure_random(file_path, content, lines)
        self._detect_insecure_http(file_path, content, lines)
        self._detect_shared_preferences(file_path, content, lines)
        self._detect_webview_javascript(file_path, content, lines)
        self._detect_deep_link_abuse(file_path, content, lines)
        self._detect_firebase_misconfig(file_path, content, lines)
        self._detect_null_safety_bypass(file_path, content, lines, tokens)
        self._detect_missing_input_validation(file_path, content, lines)
        self._detect_ssrf(file_path, content, lines)
        self._detect_open_redirect(file_path, content, lines)
        self._detect_platform_channel_misuse(file_path, content, lines)
        self._detect_cert_pinning_bypass(file_path, content, lines)
        self._detect_debug_mode(file_path, content, lines)
        self._detect_logging_sensitive(file_path, content, lines)
        self._detect_file_upload(file_path, content, lines)
        self._detect_timing_attacks(file_path, content, lines)
        self._detect_jwt_issues(file_path, content, lines)
        self._detect_provider_state_leaks(file_path, content, lines)
        self._detect_isolate_issues(file_path, content, lines)
        self._detect_insecure_storage(file_path, content, lines)

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

    # ─── 1. SQL Injection (sqflite rawQuery) ───
    def _detect_sql_injection(self, fp, content, lines):
        patterns = [
            (r'rawQuery\s*\(\s*["\x27].*\$', "sqflite rawQuery with interpolation"),
            (r'rawQuery\s*\(\s*.*\+\s*', "sqflite rawQuery with concatenation"),
            (r'rawInsert\s*\(\s*["\x27].*\$', "sqflite rawInsert with interpolation"),
            (r'rawUpdate\s*\(\s*["\x27].*\$', "sqflite rawUpdate with interpolation"),
            (r'rawDelete\s*\(\s*["\x27].*\$', "sqflite rawDelete with interpolation"),
            (r'execute\s*\(\s*["\x27].*(?:SELECT|INSERT|UPDATE|DELETE).*\$', "SQL execute with interpolation"),
            (r'SELECT\s+.*FROM\s+.*\$\{', "SQL query with Dart interpolation"),
            (r'INSERT\s+INTO\s+.*\$\{', "SQL INSERT with Dart interpolation"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "SQL Injection", Severity.CRITICAL,
                        f"SQL Injection: {desc}",
                        f"SQL query uses string interpolation/concatenation. {desc}.",
                        fp, i, 1, line,
                        "Use parameterized queries: rawQuery('SELECT * FROM t WHERE id = ?', [userId]). Never interpolate user input into SQL.",
                        "CWE-89", "A03:2021-Injection")

    # ─── 2. Command Injection (Process.run) ───
    def _detect_command_injection(self, fp, content, lines):
        patterns = [
            (r'Process\.run\s*\(.*\$', "Process.run with interpolated command"),
            (r'Process\.start\s*\(.*\$', "Process.start with interpolated command"),
            (r'Process\.runSync\s*\(.*\$', "Process.runSync with interpolated command"),
            (r'Process\.run\s*\(.*(?:request|param|input|user|query)', "Process.run with user input"),
            (r'Process\.start\s*\(.*(?:request|param|input|user)', "Process.start with user input"),
            (r'Shell\.run\s*\(', "Shell.run command execution"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Command Injection", Severity.CRITICAL,
                        f"Command Injection: {desc}",
                        f"External process execution with potential user input. {desc}.",
                        fp, i, 1, line,
                        "Validate and sanitize all inputs. Use allowlists for commands. Avoid shell interpretation.",
                        "CWE-78", "A03:2021-Injection")

    # ─── 3. XSS (Flutter WebView) ───
    def _detect_xss_webview(self, fp, content, lines):
        patterns = [
            (r'WebView\s*\(.*initialUrl.*\$', "WebView with interpolated URL"),
            (r'loadHtmlString\s*\(.*\$', "WebView loadHtmlString with interpolation"),
            (r'evaluateJavascript\s*\(.*\$', "WebView evaluateJavascript with interpolation"),
            (r'runJavascript\s*\(.*\$', "WebView runJavascript with interpolation"),
            (r'InAppWebView.*initialData.*\$', "InAppWebView with interpolated data"),
            (r'HtmlElementView', "HtmlElementView (verify content sanitization)"),
            (r'Html\s*\(\s*data\s*:.*\$', "flutter_html with interpolated data"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    self._add_vuln(
                        "Cross-Site Scripting (XSS)", Severity.HIGH,
                        f"XSS via WebView: {desc}",
                        f"WebView may render attacker-controlled content. {desc}.",
                        fp, i, 1, line,
                        "Sanitize all HTML/JavaScript before loading in WebViews. Use content security policies.",
                        "CWE-79", "A03:2021-Injection")

    # ─── 4. Path Traversal ───
    def _detect_path_traversal(self, fp, content, lines):
        patterns = [
            (r'File\s*\(\s*.*\$.*(?:request|param|input|user|query)', "File with user-controlled path"),
            (r'File\s*\(\s*["\x27].*\$\{', "File with interpolated path"),
            (r'Directory\s*\(\s*.*\$', "Directory with interpolated path"),
            (r'readAsString\s*\(.*\$', "File read with dynamic path"),
            (r'writeAsString\s*\(.*\$', "File write with dynamic path"),
            (r'path\.join\s*\(.*(?:request|param|input|user)', "Path join with user input"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Path Traversal", Severity.HIGH,
                        f"Path Traversal: {desc}",
                        f"File system operation with user-controlled path. {desc}.",
                        fp, i, 1, line,
                        "Validate paths against base directory. Reject '..' components. Use path canonicalization.",
                        "CWE-22", "A01:2021-Broken Access Control")

    # ─── 5. Deserialization ───
    def _detect_deserialization(self, fp, content, lines):
        patterns = [
            (r'jsonDecode\s*\(.*(?:request|body|input|response)', "JSON deserialization of external data"),
            (r'json\.decode\s*\(.*(?:request|body|input)', "JSON decode of untrusted data"),
            (r'fromJson\s*\(.*(?:request|body|input|response)', "fromJson with external data"),
            (r'dart:mirrors', "dart:mirrors (reflection, deserialization risk)"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Insecure Deserialization", Severity.MEDIUM,
                        f"Deserialization: {desc}",
                        f"Deserialization of potentially untrusted data. {desc}.",
                        fp, i, 1, line,
                        "Validate and sanitize all deserialized data. Use type-safe models with fromJson factories.",
                        "CWE-502", "A08:2021-Software and Data Integrity Failures")

    # ─── 6. Hardcoded Secrets ───
    def _detect_hardcoded_secrets(self, fp, content, lines):
        patterns = [
            (r'(?:api[_-]?key|apiKey|secret[_-]?key|password|passwd|token|auth[_-]?token|access[_-]?key|privateKey)\s*[:=]\s*["\x27][^"\x27]{8,}["\x27]', "Hardcoded secret"),
            (r'(?:Bearer|Basic)\s+[A-Za-z0-9+/=]{20,}', "Hardcoded authorization token"),
            (r'AIza[0-9A-Za-z_-]{35}', "Google API key"),
            (r'sk-[A-Za-z0-9]{20,}', "Secret key pattern"),
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
            (r'ghp_[A-Za-z0-9]{36}', "GitHub personal access token"),
            (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "Embedded private key"),
            (r'const\s+\w*(?:key|secret|password|token)\w*\s*=\s*["\x27][^"\x27]{8,}', "Const credential"),
            (r'firebase.*(?:apiKey|messagingSenderId|appId)\s*[:=]\s*["\x27][^"\x27]+', "Firebase config in code"),
        ]
        for i, line in enumerate(lines, 1):
            if re.search(r'//.*(?:example|test|sample|placeholder|TODO|FIXME)', line, re.IGNORECASE):
                continue
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Hardcoded Secrets", Severity.CRITICAL,
                        f"Hardcoded Secret: {desc}",
                        f"Sensitive credential hardcoded in source. {desc}.",
                        fp, i, 1, line,
                        "Use flutter_secure_storage, environment variables, or --dart-define for secrets. Never commit secrets.",
                        "CWE-798", "A07:2021-Identification and Authentication Failures")

    # ─── 7. Weak Cryptography ───
    def _detect_weak_crypto(self, fp, content, lines):
        patterns = [
            (r'md5\.convert', "MD5 hash (weak)"),
            (r'sha1\.convert', "SHA1 hash (weak)"),
            (r'Md5\s*\(', "MD5 usage"),
            (r'Sha1\s*\(', "SHA1 usage"),
            (r'DES\b', "DES encryption (weak)"),
            (r'ECBBlockCipher', "ECB mode (insecure)"),
            (r'RC4\b', "RC4 cipher (weak)"),
            (r'Hmac\s*\(\s*md5', "HMAC-MD5 (weak hash)"),
            (r'Hmac\s*\(\s*sha1', "HMAC-SHA1 (weak hash)"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Weak Cryptography", Severity.HIGH,
                        f"Weak Crypto: {desc}",
                        f"Weak cryptographic algorithm. {desc}.",
                        fp, i, 1, line,
                        "Use SHA-256+ for hashing, AES-256-GCM for encryption. Use the pointycastle or cryptography package.",
                        "CWE-327", "A02:2021-Cryptographic Failures")

    # ─── 8. Insecure Random (math.Random) ───
    def _detect_insecure_random(self, fp, content, lines):
        patterns = [
            (r'Random\s*\(\s*\)', "math.Random() without secure (predictable)"),
            (r'Random\s*\(\s*\d+\s*\)', "math.Random with seed (predictable)"),
            (r'math\.Random\s*\(', "Dart math.Random (not cryptographic)"),
        ]
        has_secure = bool(re.search(r'Random\.secure\s*\(\s*\)', content))
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    if "secure" not in line.lower():
                        self._add_vuln(
                            "Insecure Random", Severity.HIGH,
                            f"Insecure Random: {desc}",
                            f"Predictable random number generator. {desc}. Not suitable for security.",
                            fp, i, 1, line,
                            "Use Random.secure() for cryptographically secure random values.",
                            "CWE-330", "A02:2021-Cryptographic Failures")

    # ─── 9. Insecure HTTP (no HTTPS) ───
    def _detect_insecure_http(self, fp, content, lines):
        patterns = [
            (r'http://(?!localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01]))', "HTTP URL (not HTTPS)"),
            (r'Uri\.parse\s*\(\s*["\x27]http://', "Uri.parse with HTTP scheme"),
            (r'HttpClient\s*\(\s*\).*badCertificateCallback', "HttpClient with bad certificate callback"),
            (r'badCertificateCallback\s*=.*true', "Bad certificate always accepted"),
            (r'allowBadCertificates\s*[:=]\s*true', "Bad certificates allowed"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    sev = Severity.HIGH if "badCertificate" in desc or "allowBad" in desc else Severity.MEDIUM
                    self._add_vuln(
                        "Insecure HTTP", sev,
                        f"Insecure HTTP: {desc}",
                        f"Insecure network communication. {desc}.",
                        fp, i, 1, line,
                        "Always use HTTPS. Enable certificate validation. Use http_certificate_pinning package.",
                        "CWE-319", "A02:2021-Cryptographic Failures")

    # ─── 10. Insecure SharedPreferences ───
    def _detect_shared_preferences(self, fp, content, lines):
        patterns = [
            (r'SharedPreferences.*(?:password|secret|token|api.?key|credential|auth)', "SharedPreferences storing secrets"),
            (r'setString\s*\(\s*["\x27](?:password|secret|token|apiKey|auth)', "SharedPreferences secret key"),
            (r'prefs\.set.*(?:password|secret|token)', "SharedPreferences secret storage"),
            (r'GetStorage\s*\(\s*\).*(?:write|put).*(?:password|secret|token)', "GetStorage secret storage"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Insecure SharedPreferences", Severity.HIGH,
                        f"SharedPreferences: {desc}",
                        f"Sensitive data in SharedPreferences (unencrypted). {desc}.",
                        fp, i, 1, line,
                        "Use flutter_secure_storage for secrets. SharedPreferences stores data as plain text XML/plist.",
                        "CWE-922", "A04:2021-Insecure Design")

    # ─── 11. WebView JavaScript ───
    def _detect_webview_javascript(self, fp, content, lines):
        patterns = [
            (r'javascriptMode\s*:\s*JavascriptMode\.unrestricted', "WebView JavaScript unrestricted"),
            (r'javaScriptEnabled\s*:\s*true', "JavaScript enabled in WebView"),
            (r'addJavaScriptChannel', "JavaScript channel (verify message validation)"),
            (r'JavaScriptMessage', "JavaScript message handler"),
            (r'onWebViewCreated.*controller.*runJavascript', "WebView controller executing JS"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    conf = "Medium" if "channel" in desc.lower() or "handler" in desc.lower() else "High"
                    sev = Severity.MEDIUM
                    self._add_vuln(
                        "WebView JavaScript", sev,
                        f"WebView JS: {desc}",
                        f"WebView JavaScript configuration may be insecure. {desc}.",
                        fp, i, 1, line,
                        "Restrict JavaScript to necessary pages. Validate all messages from JavaScript channels.",
                        "CWE-94", "A03:2021-Injection", confidence=conf)

    # ─── 12. Deep Link Abuse ───
    def _detect_deep_link_abuse(self, fp, content, lines):
        patterns = [
            (r'uni_links|app_links|go_router.*redirect', "Deep link handling"),
            (r'getInitialLink\s*\(', "Initial deep link without validation"),
            (r'linkStream.*listen', "Deep link stream listener"),
            (r'onGenerateRoute.*(?:param|query|arg)', "Route generation with parameters"),
            (r'Uri\.parse.*(?:queryParameters|pathSegments)', "URI parameter extraction"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    self._add_vuln(
                        "Deep Link Abuse", Severity.MEDIUM,
                        f"Deep Link: {desc}",
                        f"Deep link handling may be vulnerable to abuse. {desc}.",
                        fp, i, 1, line,
                        "Validate all deep link parameters. Use App Links/Universal Links for verified ownership.",
                        "CWE-939", "A07:2021-Identification and Authentication Failures",
                        confidence="Medium")

    # ─── 13. Firebase Misconfiguration ───
    def _detect_firebase_misconfig(self, fp, content, lines):
        patterns = [
            (r'FirebaseFirestore\.instance.*\.collection.*\.doc.*\.set\s*\(', "Firestore write (check security rules)"),
            (r'\.orderByChild\s*\(.*(?:password|secret|token)', "Firebase query on sensitive field"),
            (r'DatabaseReference.*\.set\s*\(.*(?:password|secret)', "Realtime DB storing secrets"),
            (r'FirebaseStorage.*\.putFile', "Firebase Storage upload (check rules)"),
            (r'googleapis\.com.*\.json', "Firebase config file reference"),
            (r'firebase_options\.dart', "Firebase options file"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    conf = "Medium" if "check" in desc.lower() else "High"
                    self._add_vuln(
                        "Firebase Misconfiguration", Severity.MEDIUM,
                        f"Firebase: {desc}",
                        f"Firebase configuration may be insecure. {desc}.",
                        fp, i, 1, line,
                        "Review Firebase security rules. Never store secrets in Firebase. Use server-side validation.",
                        "CWE-16", "A05:2021-Security Misconfiguration", confidence=conf)

    # ─── 14. Null Safety Bypass (!) ───
    def _detect_null_safety_bypass(self, fp, content, lines, tokens):
        bang_lines = set()
        for j, token in enumerate(tokens):
            if token.type == TokenType.BANG:
                if j > 0 and tokens[j - 1].type == TokenType.IDENTIFIER:
                    context_line = lines[token.line - 1] if token.line <= len(lines) else ""
                    # Skip test files, assert, and known safe patterns
                    if not re.search(r'test|_test\.dart|assert|expect|!=|==', context_line, re.IGNORECASE):
                        bang_lines.add(token.line)

        for line_num in bang_lines:
            if line_num <= len(lines):
                line = lines[line_num - 1]
                self._add_vuln(
                    "Null Safety Bypass", Severity.LOW,
                    "Null assertion operator (!) used",
                    "Force-unwrapping nullable value with ! operator can cause runtime exceptions.",
                    fp, line_num, 1, line,
                    "Use null-aware operators (?., ??, ??=) or null checks instead of ! operator.",
                    "CWE-476", "A04:2021-Insecure Design", confidence="Medium")

    # ─── 15. Missing Input Validation ───
    def _detect_missing_input_validation(self, fp, content, lines):
        patterns = [
            (r'request\.(?:body|query|params|input)\s*\[', "Direct request input access"),
            (r'TextEditingController.*\.text(?!\s*\.\s*(?:isEmpty|isNotEmpty|length|trim|validate))', "TextEditingController text without validation"),
            (r'Uri\.parse.*queryParameters\s*\[', "URI query parameter without validation"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Missing Input Validation", Severity.MEDIUM,
                        f"Input Validation: {desc}",
                        f"User input used without apparent validation. {desc}.",
                        fp, i, 1, line,
                        "Validate all input using TextFormField validators, RegExp, or custom validation logic.",
                        "CWE-20", "A03:2021-Injection", confidence="Medium")

    # ─── 16. SSRF (http.get user URL) ───
    def _detect_ssrf(self, fp, content, lines):
        patterns = [
            (r'http\.get\s*\(\s*Uri\.parse\s*\(.*(?:request|param|input|user|url)', "HTTP GET with user-controlled URL"),
            (r'http\.post\s*\(\s*Uri\.parse\s*\(.*(?:request|param|input|user)', "HTTP POST with user-controlled URL"),
            (r'Dio\s*\(\s*\).*get\s*\(.*(?:request|param|input|user|url)', "Dio GET with user URL"),
            (r'HttpClient.*openUrl\s*\(.*(?:request|param|input|user)', "HttpClient with user-controlled URL"),
            (r'Uri\.parse\s*\(\s*\$', "URI from string interpolation"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Server-Side Request Forgery (SSRF)", Severity.HIGH,
                        f"SSRF: {desc}",
                        f"HTTP request to user-controlled URL. {desc}.",
                        fp, i, 1, line,
                        "Validate URLs against allowlist. Block internal/private IPs. Parse and verify host before requests.",
                        "CWE-918", "A10:2021-Server-Side Request Forgery")

    # ─── 17. Open Redirect ───
    def _detect_open_redirect(self, fp, content, lines):
        patterns = [
            (r'launchUrl\s*\(.*(?:request|param|redirect|next|return|url)', "launchUrl with user-controlled URL"),
            (r'launch\s*\(.*(?:request|param|redirect|next|return)', "url_launcher with user-controlled URL"),
            (r'Navigator\.(?:push|pushNamed).*(?:request|param|url|redirect)', "Navigation to user-controlled route"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Open Redirect", Severity.MEDIUM,
                        f"Open Redirect: {desc}",
                        f"User may be redirected to attacker-controlled URL. {desc}.",
                        fp, i, 1, line,
                        "Validate URLs against allowlist. Only allow known routes or domains.",
                        "CWE-601", "A01:2021-Broken Access Control")

    # ─── 18. Platform Channel Misuse ───
    def _detect_platform_channel_misuse(self, fp, content, lines):
        patterns = [
            (r'MethodChannel\s*\(.*\).*invokeMethod.*(?:password|secret|token|key)', "Platform channel sending secrets"),
            (r'EventChannel\s*\(.*\).*(?:password|secret|token)', "Event channel with sensitive data"),
            (r'BasicMessageChannel.*(?:password|secret|token)', "Message channel with secrets"),
            (r'MethodChannel.*(?:execute|run|system|command)', "Platform channel executing commands"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    sev = Severity.HIGH if "command" in desc.lower() or "execute" in desc.lower() else Severity.MEDIUM
                    self._add_vuln(
                        "Platform Channel Misuse", sev,
                        f"Platform Channel: {desc}",
                        f"Platform channel may expose sensitive operations. {desc}.",
                        fp, i, 1, line,
                        "Validate all platform channel messages. Avoid passing secrets through channels. Use secure storage on native side.",
                        "CWE-927", "A04:2021-Insecure Design")

    # ─── 19. Certificate Pinning Bypass ───
    def _detect_cert_pinning_bypass(self, fp, content, lines):
        patterns = [
            (r'badCertificateCallback.*=.*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*\)\s*=>\s*true', "Certificate validation always returns true"),
            (r'badCertificateCallback.*return\s+true', "Certificate validation bypassed"),
            (r'SecurityContext.*setTrustedCertificates.*false', "Trusted certificates disabled"),
            (r'onBadCertificate.*true', "Bad certificate accepted"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    self._add_vuln(
                        "Certificate Pinning Bypass", Severity.CRITICAL,
                        f"Cert Bypass: {desc}",
                        f"TLS certificate validation disabled. {desc}. Enables MITM attacks.",
                        fp, i, 1, line,
                        "Implement proper certificate pinning. Never return true for bad certificate callbacks in production.",
                        "CWE-295", "A02:2021-Cryptographic Failures")

    # ─── 20. Debug Mode in Release ───
    def _detect_debug_mode(self, fp, content, lines):
        patterns = [
            (r'kDebugMode\s*(?:==\s*true|\?\?)', "kDebugMode check (verify release behavior)"),
            (r'assert\s*\(.*(?:password|secret|token)', "Assert with sensitive data"),
            (r'debugPrint\s*\(.*(?:password|secret|token|key|credential)', "debugPrint with sensitive data"),
            (r'kReleaseMode\s*==\s*false', "Release mode check (may enable debug features)"),
            (r'debugShowCheckedModeBanner\s*:\s*true', "Debug banner enabled"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Debug Mode in Release", Severity.LOW,
                        f"Debug Config: {desc}",
                        f"Debug configuration may leak info in release. {desc}.",
                        fp, i, 1, line,
                        "Use kReleaseMode checks. Remove debugPrint with secrets. Set debugShowCheckedModeBanner: false.",
                        "CWE-215", "A05:2021-Security Misconfiguration")

    # ─── 21. Logging Sensitive Data ───
    def _detect_logging_sensitive(self, fp, content, lines):
        patterns = [
            (r'(?:print|debugPrint|log|logger\.)\s*\(.*(?:password|secret|token|key|credential|ssn|credit)', "Logging sensitive data"),
            (r'print\s*\(\s*["\x27].*(?:Error|Exception).*\$', "Verbose error logging"),
            (r'Logger\s*\(.*\)\.(?:info|debug|warning)\s*\(.*(?:password|token|secret)', "Logger with sensitive data"),
            (r'developer\.log\s*\(.*(?:password|token|secret)', "Developer log with sensitive data"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Logging Sensitive Data", Severity.MEDIUM,
                        f"Sensitive Logging: {desc}",
                        f"Sensitive data may appear in logs. {desc}.",
                        fp, i, 1, line,
                        "Remove sensitive data from logs. Use conditional logging with kReleaseMode.",
                        "CWE-532", "A09:2021-Security Logging and Monitoring Failures")

    # ─── 22. Unvalidated File Upload ───
    def _detect_file_upload(self, fp, content, lines):
        patterns = [
            (r'MultipartFile\.fromPath\s*\(', "File upload (verify type validation)"),
            (r'MultipartRequest.*addFile', "Multipart file upload"),
            (r'ImagePicker.*pickImage.*(?!.*(?:maxWidth|maxHeight|imageQuality))', "Image picker without size limits"),
            (r'FilePicker\.platform\.pickFiles.*(?!.*(?:allowedExtensions|type))', "File picker without type restriction"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    self._add_vuln(
                        "Unvalidated File Upload", Severity.MEDIUM,
                        f"File Upload: {desc}",
                        f"File upload without apparent validation. {desc}.",
                        fp, i, 1, line,
                        "Validate file types, sizes, and content. Use allowedExtensions in FilePicker. Set size limits.",
                        "CWE-434", "A04:2021-Insecure Design", confidence="Medium")

    # ─── 23. Timing Attacks ───
    def _detect_timing_attacks(self, fp, content, lines):
        patterns = [
            (r'(?:password|token|secret|hash|signature)\s*==\s*', "Direct equality for secrets"),
            (r'\.compareTo\s*\(.*(?:password|token|secret|hash)', "compareTo for secret comparison"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Timing Attack", Severity.MEDIUM,
                        f"Timing Attack: {desc}",
                        f"Non-constant-time comparison of secrets. {desc}.",
                        fp, i, 1, line,
                        "Use constant-time comparison for secrets. Compare HMAC digests instead of raw values.",
                        "CWE-208", "A02:2021-Cryptographic Failures")

    # ─── 24. JWT Issues ───
    def _detect_jwt_issues(self, fp, content, lines):
        patterns = [
            (r'algorithm\s*:\s*["\x27]none', "JWT none algorithm"),
            (r'verify\s*:\s*false.*(?:jwt|token)', "JWT verification disabled"),
            (r'JwtDecoder\.decode.*(?!.*verify)', "JWT decoded without verification"),
            (r'(?:jwt|token).*(?:expired|exp).*ignore', "JWT expiration ignored"),
            (r'dart_jsonwebtoken.*SecretKey\s*\(\s*["\x27][^"\x27]{1,16}["\x27]', "JWT with short secret key"),
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

    # ─── 25. Provider/Riverpod State Leaks ───
    def _detect_provider_state_leaks(self, fp, content, lines):
        patterns = [
            (r'StateProvider.*(?:password|secret|token|credential)', "StateProvider with sensitive data"),
            (r'ChangeNotifier.*(?:password|secret|token)', "ChangeNotifier exposing secrets"),
            (r'StateNotifier.*(?:password|secret|token)', "StateNotifier with sensitive state"),
            (r'GetxController.*(?:password|secret|token).*\.obs', "GetX observable with secrets"),
            (r'BlocProvider.*(?:password|secret|token)', "Bloc with sensitive state"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "State Management Data Leak", Severity.MEDIUM,
                        f"State Leak: {desc}",
                        f"Sensitive data exposed in state management. {desc}. May persist in memory or be accessible via dev tools.",
                        fp, i, 1, line,
                        "Minimize sensitive data in state. Clear auth tokens on logout. Use secure storage.",
                        "CWE-200", "A04:2021-Insecure Design")

    # ─── 26. Isolate Issues ───
    def _detect_isolate_issues(self, fp, content, lines):
        patterns = [
            (r'Isolate\.spawn.*(?:password|secret|token|key)', "Isolate spawned with sensitive data"),
            (r'compute\s*\(.*(?:password|secret|token|key)', "compute() with sensitive data"),
            (r'SendPort.*send\s*\(.*(?:password|secret|token)', "SendPort sending sensitive data"),
            (r'ReceivePort.*listen.*(?:password|secret|token)', "ReceivePort receiving sensitive data"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Isolate Security Issue", Severity.MEDIUM,
                        f"Isolate: {desc}",
                        f"Sensitive data passed through Dart isolates. {desc}. Data is copied, not shared.",
                        fp, i, 1, line,
                        "Minimize sensitive data in isolate messages. Clear sensitive data after use.",
                        "CWE-200", "A04:2021-Insecure Design")

    # ─── 27. Insecure Local Storage ───
    def _detect_insecure_storage(self, fp, content, lines):
        patterns = [
            (r'Hive\.box.*(?:password|secret|token|key|credential)', "Hive box with sensitive data (unencrypted)"),
            (r'ObjectBox.*(?:password|secret|token)', "ObjectBox with sensitive data"),
            (r'sqflite.*(?:password|secret|token)(?!.*encrypt)', "sqflite with sensitive data (no encryption)"),
            (r'path_provider.*(?:getTemporaryDirectory|getApplicationDocumentsDirectory).*(?:password|secret|token)', "Temp/docs directory for secrets"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_vuln(
                        "Insecure Local Storage", Severity.HIGH,
                        f"Insecure Storage: {desc}",
                        f"Sensitive data in unencrypted local storage. {desc}.",
                        fp, i, 1, line,
                        "Use flutter_secure_storage or Hive with encryption for sensitive data.",
                        "CWE-922", "A04:2021-Insecure Design")


# ──────────────────────────── FastAPI Application ────────────────────────────

app = FastAPI(title="Dart SAST Scanner", version="1.0.0")
detector = DartVulnerabilityDetector()

DART_EXTENSIONS = {".dart"}


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "scanner": "dart",
        "version": "1.0.0",
        "categories": 27,
        "description": "Dart/Flutter SAST Scanner with custom tokenizer and pattern analysis"
    }


@app.post("/scan")
async def scan(request: ScanRequest):
    scan_id = request.scanId or str(uuid.uuid4())
    all_vulnerabilities = []
    files_scanned = 0
    errors = []

    for file_path, content in request.files.items():
        ext = "." + file_path.rsplit(".", 1)[-1] if "." in file_path else ""
        if ext.lower() not in DART_EXTENSIONS:
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
        "scanner": "dart",
        "version": "1.0.0",
        "filesScanned": files_scanned,
        "totalVulnerabilities": len(all_vulnerabilities),
        "severitySummary": severity_counts,
        "categorySummary": category_counts,
        "vulnerabilities": all_vulnerabilities,
        "errors": errors
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9013)
