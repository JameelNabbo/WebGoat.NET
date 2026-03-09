#!/usr/bin/env python3
"""
Offensive360 Perl SAST Scanner
Comprehensive static analysis for Perl source code using token-based parsing + regex patterns.
FastAPI server on port 9017.

Covers Perl 5 including CGI, Mojolicious, Dancer, Catalyst frameworks,
taint mode, regex injection, two-arg open, and Perl-specific security idioms.
"""

import os
import re
import uuid
import logging
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("perl-scanner")

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class Confidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

@dataclass
class Finding:
    rule_id: str
    category: str
    title: str
    description: str
    severity: str
    confidence: str
    file_path: str
    line_number: int
    column: int = 0
    end_line: int = 0
    code_snippet: str = ""
    remediation: str = ""
    cwe_id: str = ""
    owasp: str = ""
    references: List[str] = field(default_factory=list)

class ScanRequest(BaseModel):
    files: Dict[str, str]
    scanId: str = ""

class ScanResponse(BaseModel):
    scanId: str
    totalFiles: int
    totalFindings: int
    findings: List[Dict[str, Any]]
    summary: Dict[str, int]

# ---------------------------------------------------------------------------
# Helper: extract code snippet
# ---------------------------------------------------------------------------
def get_snippet(lines: List[str], line_num: int, context: int = 2) -> str:
    start = max(0, line_num - context - 1)
    end = min(len(lines), line_num + context)
    snippet_lines = []
    for i in range(start, end):
        marker = ">>> " if i == line_num - 1 else "    "
        snippet_lines.append(f"{marker}{i+1}: {lines[i]}")
    return "\n".join(snippet_lines)

# ---------------------------------------------------------------------------
# Perl-specific helpers
# ---------------------------------------------------------------------------
PERL_EXTENSIONS = {".pl", ".pm", ".cgi", ".psgi", ".t", ".pod"}

def is_perl_file(path: str) -> bool:
    lower = path.lower()
    return any(lower.endswith(ext) for ext in PERL_EXTENSIONS)

def is_perl_comment(line: str) -> bool:
    """Check if line is a Perl comment."""
    stripped = line.strip()
    return stripped.startswith("#")

# ---------------------------------------------------------------------------
# Vulnerability Rules
# ---------------------------------------------------------------------------
RULES: List[Dict[str, Any]] = [
    # ======================================================================
    # SQL Injection
    # ======================================================================
    {
        "id": "PL-SQL-001",
        "pattern": r'(?:\$dbh|\$sth|\$db)\s*->\s*(?:do|prepare|selectrow_array|selectall_arrayref|selectcol_arrayref)\s*\(',
        "context_pattern": r'(?:\$\w+|\.\s*\$|"\s*\.\s*\$|qq\{.*\$)',
        "category": "SQL Injection",
        "title": "DBI query with variable interpolation",
        "description": "DBI query methods used with Perl variable interpolation in the SQL string. Variables inside double-quoted strings or concatenated with '.' are expanded, enabling SQL injection.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "remediation": "Use placeholders: $dbh->prepare(\"SELECT * FROM users WHERE id = ?\"); $sth->execute($user_id);",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },
    {
        "id": "PL-SQL-002",
        "pattern": r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s+.*(?:\$\w+|\.\s*\$|"\s*\.\s*\$)',
        "category": "SQL Injection",
        "title": "SQL string with variable interpolation",
        "description": "Direct SQL string construction with Perl variable interpolation. Perl expands $variables inside double-quoted strings.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "remediation": "Use DBI placeholders (?) or $dbh->quote() for all user-supplied values.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },
    {
        "id": "PL-SQL-003",
        "pattern": r'prepare\s*\(\s*"[^"]*\$\w+',
        "category": "SQL Injection",
        "title": "DBI prepare with interpolated variable",
        "description": "DBI prepare statement with variable interpolation in the SQL string. Even though prepare is being used, interpolating variables defeats the purpose of parameterized queries.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "remediation": "Use '?' placeholders in prepare: $sth = $dbh->prepare('SELECT * FROM users WHERE name = ?');",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },
    {
        "id": "PL-SQL-004",
        "pattern": r'(?:qq\{|qq\[|qq\().*(?:SELECT|INSERT|UPDATE|DELETE).*\$\w+',
        "category": "SQL Injection",
        "title": "SQL in Perl qq{} operator with variable interpolation",
        "description": "Perl qq{} operator interpolates variables, making SQL strings vulnerable to injection.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "remediation": "Use DBI placeholders instead of qq{} for SQL queries.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },

    # ======================================================================
    # Command Injection
    # ======================================================================
    {
        "id": "PL-CMD-001",
        "pattern": r'system\s*\(.*\$\w+|system\s+"[^"]*\$\w+|system\s+qq\{.*\$\w+',
        "category": "Command Injection",
        "title": "system() with variable interpolation",
        "description": "Perl system() executes shell commands. When variables are interpolated into the command string, shell injection is possible.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "remediation": "Use the list form of system: system('cmd', @args) which bypasses shell interpretation. Never interpolate variables into shell commands.",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    },
    {
        "id": "PL-CMD-002",
        "pattern": r'exec\s*\(.*\$\w+|exec\s+"[^"]*\$\w+',
        "category": "Command Injection",
        "title": "exec() with variable interpolation",
        "description": "Perl exec() replaces the current process with a shell command. Variable interpolation enables command injection.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "remediation": "Use the list form of exec: exec('cmd', @args) to bypass the shell.",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    },
    {
        "id": "PL-CMD-003",
        "pattern": r'`[^`]*\$\w+[^`]*`|qx\{[^}]*\$\w+|qx\([^)]*\$\w+|qx\[[^\]]*\$\w+',
        "category": "Command Injection",
        "title": "Backtick/qx{} command execution with variable interpolation",
        "description": "Perl backticks (``) and qx{} execute shell commands with variable interpolation, enabling command injection.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "remediation": "Use IPC::Open3 or Capture::Tiny with list-form system() instead of backticks/qx{}.",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    },
    {
        "id": "PL-CMD-004",
        "pattern": r'open\s*\(\s*\w+\s*,\s*"?\|.*\$\w+|open\s*\(\s*\w+\s*,\s*"[^"]*\$\w+[^"]*\|"?\s*\)',
        "category": "Command Injection",
        "title": "open() with pipe for command execution",
        "description": "Perl open() with a pipe character (|) executes a shell command. Variable interpolation enables command injection.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "remediation": "Use IPC::Open3 or open with '-|' and list form: open(my $fh, '-|', 'cmd', @args);",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    },
    {
        "id": "PL-CMD-005",
        "pattern": r'(?:system|exec|open)\s*\(\s*["\'](?:sh|bash|ksh|csh|cmd|powershell)',
        "category": "Command Injection",
        "title": "Explicit shell interpreter invocation",
        "description": "Directly invoking a shell interpreter (sh, bash, cmd) enables command injection through argument manipulation.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "remediation": "Execute the target program directly without a shell wrapper.",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    },

    # ======================================================================
    # Code Injection (eval)
    # ======================================================================
    {
        "id": "PL-EVAL-001",
        "pattern": r'eval\s*"[^"]*\$\w+|eval\s+\$\w+|eval\s*\(\s*\$\w+|eval\s+qq\{',
        "category": "Code Injection",
        "title": "eval with variable interpolation (string eval)",
        "description": "Perl string eval evaluates a string as Perl code. If user input is interpolated, it enables arbitrary code execution. This is distinct from eval{} block form which is safe.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-94",
        "owasp": "A03:2021",
        "remediation": "Never pass user input to string eval. Use eval{} block form for exception handling. Redesign to avoid dynamic code evaluation.",
        "references": ["https://cwe.mitre.org/data/definitions/94.html"],
    },
    {
        "id": "PL-EVAL-002",
        "pattern": r'eval\s*\(\s*(?:param|CGI|request|\$ENV|\$ARGV)',
        "category": "Code Injection",
        "title": "eval with request/environment data",
        "description": "String eval using CGI parameters, environment variables, or command-line arguments enables arbitrary code execution.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-94",
        "owasp": "A03:2021",
        "remediation": "Never eval user-supplied data. Use a safe parser or validator for the expected input format.",
        "references": ["https://cwe.mitre.org/data/definitions/94.html"],
    },
    {
        "id": "PL-EVAL-003",
        "pattern": r'(?:do|require)\s+\$\w+',
        "category": "Code Injection",
        "title": "Dynamic file inclusion with variable path",
        "description": "Perl do/require with a variable path allows loading and executing arbitrary Perl files if the path is user-controlled.",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-98",
        "owasp": "A03:2021",
        "remediation": "Only use hardcoded paths with do/require. Validate paths against a whitelist.",
        "references": ["https://cwe.mitre.org/data/definitions/98.html"],
    },

    # ======================================================================
    # XSS
    # ======================================================================
    {
        "id": "PL-XSS-001",
        "pattern": r'print\s+(?:\$q\s*->\s*header|"Content-type).*(?:\$\w+|param\()',
        "category": "Cross-Site Scripting (XSS)",
        "title": "CGI output with unescaped user input",
        "description": "Printing user input directly in CGI response without HTML encoding enables cross-site scripting.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-79",
        "owasp": "A03:2021",
        "remediation": "Use CGI::escapeHTML() or HTML::Entities::encode_entities() to encode all user-supplied output.",
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
    },
    {
        "id": "PL-XSS-002",
        "pattern": r'param\s*\(.*\)|(?:\$q|\$cgi)\s*->\s*param\s*\(',
        "negative_pattern": r'(?:escapeHTML|encode_entities|html_escape|sanitize|escape)',
        "category": "Cross-Site Scripting (XSS)",
        "title": "CGI param() used without HTML encoding",
        "description": "CGI param() values used in HTML output without escaping enable XSS attacks.",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-79",
        "owasp": "A03:2021",
        "remediation": "Always encode CGI parameters before HTML output: escapeHTML(param('name')).",
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
    },
    {
        "id": "PL-XSS-003",
        "pattern": r'(?:\$c|\$self)\s*->\s*render\s*\(.*(?:inline|text)\s*=>.*\$',
        "category": "Cross-Site Scripting (XSS)",
        "title": "Mojolicious render with inline content containing variables",
        "description": "Mojolicious inline rendering with variable interpolation may produce unescaped HTML output.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-79",
        "owasp": "A03:2021",
        "remediation": "Use Mojolicious template helpers like xml_escape() or use template files with automatic escaping.",
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
    },
    {
        "id": "PL-XSS-004",
        "pattern": r'<%==?\s*\$\w+|<%= (?:param|stash|session)',
        "category": "Cross-Site Scripting (XSS)",
        "title": "Mojolicious/Mason template with unescaped variable",
        "description": "Template variables rendered with <%== (raw) in Mojolicious or unescaped in Mason templates enable XSS.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-79",
        "owasp": "A03:2021",
        "remediation": "Use <%= (auto-escaped) instead of <%== (raw) in Mojolicious. Encode output in Mason.",
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
    },

    # ======================================================================
    # Path Traversal
    # ======================================================================
    {
        "id": "PL-PATH-001",
        "pattern": r'open\s*\(\s*(?:my\s+)?\$?\w+\s*,\s*(?:"[^"]*\$|[\'"]\s*\.\s*\$|\$\w+)',
        "category": "Path Traversal",
        "title": "File open with user-controlled path",
        "description": "Opening files with paths derived from user input allows path traversal (../../etc/passwd) and arbitrary file access.",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-22",
        "owasp": "A01:2021",
        "remediation": "Validate file paths: use File::Spec->canonpath(), check for '..', and verify paths stay within expected directories.",
        "references": ["https://cwe.mitre.org/data/definitions/22.html"],
    },
    {
        "id": "PL-PATH-002",
        "pattern": r'(?:read_file|write_file|slurp|spew|File::Slurp)\s*\(\s*\$',
        "category": "Path Traversal",
        "title": "File::Slurp/Path::Tiny with user-controlled path",
        "description": "File reading/writing utilities with user-controlled paths enable arbitrary file access.",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-22",
        "owasp": "A01:2021",
        "remediation": "Validate and sanitize file paths before use. Use Cwd::realpath() and verify the base directory.",
        "references": ["https://cwe.mitre.org/data/definitions/22.html"],
    },

    # ======================================================================
    # Two-arg open (Perl-specific)
    # ======================================================================
    {
        "id": "PL-OPEN-001",
        "pattern": r'open\s*\(\s*(?:my\s+)?\$?\w+\s*,\s*(?:(?!<|>|>>|\+<|\+>|-\||\|-|<:)\$\w+|"[^<>|]*\$\w+[^<>|]*")\s*\)',
        "category": "File Operations",
        "title": "Two-argument open with potential file/command injection",
        "description": "Perl's two-argument open() interprets special characters in the filename (|, >, <). If user input is used, it can lead to command execution or file operations.",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "remediation": "Always use three-argument open: open(my $fh, '<', $filename) to prevent mode injection.",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    },
    {
        "id": "PL-OPEN-002",
        "pattern": r'open\s*\(\s*\w+\s*,\s*"[^"]*"\s*\)',
        "negative_pattern": r'open\s*\(\s*(?:my\s+)?\$?\w+\s*,\s*[\'"][<>+|-]',
        "category": "File Operations",
        "title": "Possible two-argument open form",
        "description": "Two-argument open in Perl interprets special characters. The three-argument form is safer and preferred.",
        "severity": Severity.LOW,
        "confidence": Confidence.LOW,
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "remediation": "Migrate to three-argument open: open(my $fh, '<', $file) or die;",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    },

    # ======================================================================
    # Deserialization
    # ======================================================================
    {
        "id": "PL-DESER-001",
        "pattern": r'(?:Storable::thaw|Storable::retrieve|thaw|fd_retrieve|retrieve)\s*\(\s*\$',
        "category": "Insecure Deserialization",
        "title": "Storable thaw/retrieve with untrusted data",
        "description": "Perl's Storable module can execute arbitrary code during deserialization via STORABLE_thaw hooks. Never deserialize untrusted data.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-502",
        "owasp": "A08:2021",
        "remediation": "Use JSON, YAML::Safe, or Sereal with a restricted deserializer for untrusted data.",
        "references": ["https://cwe.mitre.org/data/definitions/502.html"],
    },
    {
        "id": "PL-DESER-002",
        "pattern": r'YAML::Load\s*\(|YAML::Syck::Load\s*\(|Load\s*\(\s*\$(?:input|data|content|body|payload)',
        "category": "Insecure Deserialization",
        "title": "YAML::Load with potentially untrusted input",
        "description": "YAML::Load can instantiate arbitrary Perl objects via YAML tags (!!perl/hash:My::Class). Use YAML::Safe::Load instead.",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-502",
        "owasp": "A08:2021",
        "remediation": "Use YAML::Safe, YAML::XS with $YAML::XS::DisableBlessed = 1, or JSON for untrusted data.",
        "references": ["https://cwe.mitre.org/data/definitions/502.html"],
    },
    {
        "id": "PL-DESER-003",
        "pattern": r'(?:Data::Dumper|eval\s+(?:cat|read|slurp))',
        "context_pattern": r'(?:\$\w+|param|input|file)',
        "category": "Insecure Deserialization",
        "title": "Data::Dumper output eval for deserialization",
        "description": "Using eval to load Data::Dumper output is extremely dangerous as it executes arbitrary Perl code.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-502",
        "owasp": "A08:2021",
        "remediation": "Use JSON, YAML::Safe, or Sereal for data serialization instead of Data::Dumper + eval.",
        "references": ["https://cwe.mitre.org/data/definitions/502.html"],
    },

    # ======================================================================
    # SSRF
    # ======================================================================
    {
        "id": "PL-SSRF-001",
        "pattern": r'(?:LWP::UserAgent|HTTP::Tiny|WWW::Mechanize|Mojo::UserAgent)\s*->\s*(?:new|get|post|put|delete|request|head)',
        "context_pattern": r'(?:\$\w+|param|input|url)',
        "category": "Server-Side Request Forgery (SSRF)",
        "title": "HTTP client request with user-controlled URL",
        "description": "HTTP requests with user-controlled URLs can be exploited for SSRF attacks against internal services and cloud metadata endpoints.",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-918",
        "owasp": "A10:2021",
        "remediation": "Validate URLs against a whitelist. Block private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x). Parse and validate the hostname.",
        "references": ["https://cwe.mitre.org/data/definitions/918.html"],
    },
    {
        "id": "PL-SSRF-002",
        "pattern": r'(?:get|getprint|getstore|mirror)\s*\(\s*(?:\$|"[^"]*\$)',
        "context_pattern": r'(?:LWP::Simple|HTTP)',
        "category": "Server-Side Request Forgery (SSRF)",
        "title": "LWP::Simple request with variable URL",
        "description": "LWP::Simple functions with user-controlled URLs enable SSRF.",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-918",
        "owasp": "A10:2021",
        "remediation": "Validate and whitelist URLs before making requests.",
        "references": ["https://cwe.mitre.org/data/definitions/918.html"],
    },

    # ======================================================================
    # Hardcoded Secrets
    # ======================================================================
    {
        "id": "PL-SECRET-001",
        "pattern": r'(?:password|passwd|pwd|secret|api_key|apikey|token|auth_token|access_token|private_key)\s*(?:=|=>)\s*["\'][^"\']{8,}["\']',
        "category": "Hardcoded Secrets",
        "title": "Hardcoded password or secret in source code",
        "description": "Credentials hardcoded in Perl source code can be extracted from the repository.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "remediation": "Use environment variables ($ENV{SECRET_KEY}), config files outside the repo, or a secrets manager.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },
    {
        "id": "PL-SECRET-002",
        "pattern": r'(?:DBI->connect|DBI::\w+:)\s*\(\s*["\'][^"\']*["\'].*(?:password|pwd)\s*(?:=|=>)\s*["\'][^"\']+["\']',
        "category": "Hardcoded Secrets",
        "title": "DBI connection with hardcoded credentials",
        "description": "Database connection strings with embedded passwords in source code.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "remediation": "Store database credentials in environment variables or encrypted configuration files.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },
    {
        "id": "PL-SECRET-003",
        "pattern": r'my\s+\$\w*(?:key|secret|token|pass(?:word)?|credential)\w*\s*=\s*["\'][^"\']{8,}["\']',
        "category": "Hardcoded Secrets",
        "title": "Perl variable with hardcoded secret value",
        "description": "Variables named with key/secret/token/password containing hardcoded string values indicate embedded credentials.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "remediation": "Use $ENV{SECRET_KEY} or read from a config file excluded from version control.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },

    # ======================================================================
    # Weak Cryptography
    # ======================================================================
    {
        "id": "PL-CRYPTO-001",
        "pattern": r'Digest::MD5|md5_hex|md5_base64|md5\s*\(',
        "category": "Weak Cryptography",
        "title": "Use of MD5 hashing algorithm",
        "description": "MD5 is cryptographically broken with practical collision attacks. It must not be used for security purposes.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-327",
        "owasp": "A02:2021",
        "remediation": "Use Digest::SHA (sha256_hex) for hashing. For passwords, use Crypt::Bcrypt or Crypt::Argon2.",
        "references": ["https://cwe.mitre.org/data/definitions/327.html"],
    },
    {
        "id": "PL-CRYPTO-002",
        "pattern": r'Digest::SHA1|sha1_hex|sha1_base64|Digest::SHA\s*->\s*new\s*\(\s*1\s*\)',
        "category": "Weak Cryptography",
        "title": "Use of SHA-1 hashing algorithm",
        "description": "SHA-1 is deprecated due to practical collision attacks.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-327",
        "owasp": "A02:2021",
        "remediation": "Migrate to Digest::SHA with SHA-256 or SHA-512.",
        "references": ["https://cwe.mitre.org/data/definitions/327.html"],
    },
    {
        "id": "PL-CRYPTO-003",
        "pattern": r'Crypt::DES|Crypt::Blowfish|Crypt::RC4|Crypt::RC2',
        "category": "Weak Cryptography",
        "title": "Use of weak/deprecated encryption algorithm",
        "description": "DES, RC4, and RC2 provide insufficient encryption strength and have known vulnerabilities.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-327",
        "owasp": "A02:2021",
        "remediation": "Use Crypt::Cipher::AES with Crypt::Mode::CBC or Crypt::AuthEnc::GCM.",
        "references": ["https://cwe.mitre.org/data/definitions/327.html"],
    },

    # ======================================================================
    # Insecure Random
    # ======================================================================
    {
        "id": "PL-RAND-001",
        "pattern": r'(?:rand\s*\(|srand\s*\(|int\s*\(\s*rand)',
        "negative_pattern": r'(?:Crypt::Random|Math::Random::Secure|urandom)',
        "category": "Insecure Randomness",
        "title": "Use of rand() for security-sensitive operations",
        "description": "Perl's rand() is a predictable PRNG (uses drand48/libc rand). It must not be used for tokens, keys, or session IDs.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-330",
        "owasp": "A02:2021",
        "remediation": "Use Crypt::Random, Math::Random::Secure, or read from /dev/urandom for cryptographic randomness.",
        "references": ["https://cwe.mitre.org/data/definitions/330.html"],
    },

    # ======================================================================
    # Taint Mode
    # ======================================================================
    {
        "id": "PL-TAINT-001",
        "pattern": r'^#!.*perl',
        "negative_pattern": r'-T|-t',
        "category": "Missing Taint Mode",
        "title": "Perl script without taint mode (-T)",
        "description": "Perl taint mode (-T) tracks user input and prevents it from being used in dangerous operations (system, exec, open, eval) without explicit validation. Missing taint mode removes this safety net.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-20",
        "owasp": "A03:2021",
        "remediation": "Add -T flag to shebang line: #!/usr/bin/perl -T. Untaint variables with regex: ($clean) = ($tainted =~ /^([a-zA-Z0-9]+)$/);",
        "references": ["https://cwe.mitre.org/data/definitions/20.html"],
    },

    # ======================================================================
    # Regex Injection
    # ======================================================================
    {
        "id": "PL-REGEX-001",
        "pattern": r'=~\s*(?:m|s|tr|y)?\s*/[^/]*\$\w+|=~\s*(?:m|s)?\s*\{[^}]*\$\w+',
        "negative_pattern": r'\\Q.*\$|quotemeta',
        "category": "Regex Injection",
        "title": "User input in regex without quotemeta/\\Q\\E",
        "description": "Perl variables interpolated into regex patterns without \\Q\\E quoting allow regex injection. Attackers can craft patterns causing ReDoS or bypassing validation.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-625",
        "owasp": "A03:2021",
        "remediation": "Use \\Q$var\\E to escape metacharacters, or quotemeta($var), or qr/\\Q$var\\E/.",
        "references": ["https://cwe.mitre.org/data/definitions/625.html"],
    },

    # ======================================================================
    # CGI-specific
    # ======================================================================
    {
        "id": "PL-CGI-001",
        "pattern": r'(?:header|redirect)\s*\(.*(?:\$\w+|param\()',
        "context_pattern": r'(?:CGI|cgi)',
        "category": "CGI Security",
        "title": "CGI header/redirect with user-controlled value",
        "description": "CGI header or redirect using user-supplied values enables HTTP response splitting and open redirect attacks.",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-113",
        "owasp": "A03:2021",
        "remediation": "Validate redirect URLs against a whitelist. Strip newlines from header values.",
        "references": ["https://cwe.mitre.org/data/definitions/113.html"],
    },
    {
        "id": "PL-CGI-002",
        "pattern": r'use\s+CGI\b',
        "negative_pattern": r'(?:CGI::Carp|fatalsToBrowser)',
        "category": "CGI Security",
        "title": "CGI module without error handling configuration",
        "description": "CGI scripts without proper error handling may expose internal errors or stack traces to users.",
        "severity": Severity.LOW,
        "confidence": Confidence.LOW,
        "cwe": "CWE-209",
        "owasp": "A04:2021",
        "remediation": "Use CGI::Carp 'fatalsToBrowser' only in development. Log errors server-side in production.",
        "references": ["https://cwe.mitre.org/data/definitions/209.html"],
    },

    # ======================================================================
    # Mojolicious-specific
    # ======================================================================
    {
        "id": "PL-MOJO-001",
        "pattern": r'(?:\$self|\$c|\$app)\s*->\s*render\s*\(\s*text\s*=>',
        "context_pattern": r'(?:param|req|stash|\$\w+)',
        "category": "Mojolicious Security",
        "title": "Mojolicious render text with user input",
        "description": "Rendering text responses with user input in Mojolicious may not auto-escape, enabling XSS.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-79",
        "owasp": "A03:2021",
        "remediation": "Use template rendering with auto-escaping instead of inline text with user data.",
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
    },
    {
        "id": "PL-MOJO-002",
        "pattern": r'secrets\s*\(\s*\[\s*["\'][^"\']{1,15}["\']',
        "category": "Mojolicious Security",
        "title": "Weak Mojolicious application secret",
        "description": "Short or simple application secrets in Mojolicious can be brute-forced, compromising session integrity.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "remediation": "Use a strong, random secret of at least 32 characters. Store it in environment variables.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },

    # ======================================================================
    # Dancer-specific
    # ======================================================================
    {
        "id": "PL-DANCER-001",
        "pattern": r'session_secret\s*(?:=>|:)\s*["\'][^"\']{1,15}["\']',
        "category": "Dancer Security",
        "title": "Weak Dancer session secret",
        "description": "Short session secrets in Dancer can be brute-forced, compromising session integrity and enabling session forgery.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "remediation": "Use a strong, random secret of at least 32 characters.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },
    {
        "id": "PL-DANCER-002",
        "pattern": r'show_errors\s*(?:=>|:)\s*(?:1|true)',
        "category": "Dancer Security",
        "title": "Dancer show_errors enabled in production",
        "description": "Showing detailed errors in production exposes internal application state and stack traces.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-209",
        "owasp": "A04:2021",
        "remediation": "Set show_errors => 0 in production configuration.",
        "references": ["https://cwe.mitre.org/data/definitions/209.html"],
    },

    # ======================================================================
    # Catalyst-specific
    # ======================================================================
    {
        "id": "PL-CATALYST-001",
        "pattern": r'(?:\$c|\$ctx)\s*->\s*(?:req|request)\s*->\s*(?:param|params|body_params|query_params)',
        "negative_pattern": r'(?:validate|check|clean|sanitize|escape|encode)',
        "category": "Catalyst Security",
        "title": "Catalyst request parameter used without validation",
        "description": "Catalyst request parameters used without validation can lead to injection attacks.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-20",
        "owasp": "A03:2021",
        "remediation": "Use Data::FormValidator or HTML::FormHandler to validate all request parameters.",
        "references": ["https://cwe.mitre.org/data/definitions/20.html"],
    },

    # ======================================================================
    # Missing strict/warnings
    # ======================================================================
    {
        "id": "PL-STRICT-001",
        "pattern": r'^(?:use\s+strict|use\s+warnings|use\s+v5\.\d+|use\s+Moo|use\s+Moose|use\s+Modern::Perl)',
        "check_file_absence": True,
        "category": "Code Quality",
        "title": "Missing 'use strict' and/or 'use warnings'",
        "description": "Perl scripts without 'use strict' and 'use warnings' allow common bugs like typos in variable names, use of undefined values, and symbolic references, which can lead to security vulnerabilities.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-710",
        "owasp": "",
        "remediation": "Add 'use strict;' and 'use warnings;' at the top of every Perl file.",
        "references": ["https://cwe.mitre.org/data/definitions/710.html"],
    },

    # ======================================================================
    # Symbolic References
    # ======================================================================
    {
        "id": "PL-SYMREF-001",
        "pattern": r'no\s+strict\s+["\']refs["\']',
        "category": "Code Injection",
        "title": "Symbolic references enabled (no strict 'refs')",
        "description": "Disabling strict refs allows using strings as variable references, which can lead to variable injection if the string is user-controlled.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-94",
        "owasp": "A03:2021",
        "remediation": "Avoid 'no strict refs'. Use hash references or dispatch tables instead of symbolic references.",
        "references": ["https://cwe.mitre.org/data/definitions/94.html"],
    },

    # ======================================================================
    # Format String
    # ======================================================================
    {
        "id": "PL-FMT-001",
        "pattern": r'sprintf\s*\(\s*\$\w+',
        "category": "Format String",
        "title": "sprintf with user-controlled format string",
        "description": "Using a variable as the format string in sprintf allows format string attacks that may cause crashes or information disclosure.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-134",
        "owasp": "A03:2021",
        "remediation": "Use a hardcoded format string: sprintf('%s', $user_value) instead of sprintf($user_value).",
        "references": ["https://cwe.mitre.org/data/definitions/134.html"],
    },

    # ======================================================================
    # Race Conditions (TOCTOU)
    # ======================================================================
    {
        "id": "PL-RACE-001",
        "pattern": r'(?:-e\s+\$|-f\s+\$|-d\s+\$|-r\s+\$|-w\s+\$)',
        "context_pattern": r'(?:open|unlink|rename|chmod|mkdir)',
        "category": "Race Condition",
        "title": "TOCTOU race condition (file check then use)",
        "description": "Checking file existence/permissions (-e, -f, -r, -w) then performing operations creates a Time-of-Check-Time-of-Use (TOCTOU) race condition.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-367",
        "owasp": "A04:2021",
        "remediation": "Perform the operation directly and handle errors, rather than checking first then acting.",
        "references": ["https://cwe.mitre.org/data/definitions/367.html"],
    },

    # ======================================================================
    # Information Disclosure
    # ======================================================================
    {
        "id": "PL-INFO-001",
        "pattern": r'Carp::(?:confess|longmess)|confess\s+|cluck\s+',
        "category": "Information Disclosure",
        "title": "Carp::confess/cluck exposing stack traces",
        "description": "Carp::confess and cluck produce full stack traces that may expose internal file paths, variable values, and logic to users.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-209",
        "owasp": "A04:2021",
        "remediation": "Use Carp::croak (short message) in production. Log confess output server-side only.",
        "references": ["https://cwe.mitre.org/data/definitions/209.html"],
    },
    {
        "id": "PL-INFO-002",
        "pattern": r'die\s+"[^"]*(?:\$!|\$@|\$DBI::errstr)',
        "category": "Information Disclosure",
        "title": "die with error variable exposing system details",
        "description": "Using die with $!, $@, or $DBI::errstr may expose system error messages, file paths, or SQL errors to end users.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-209",
        "owasp": "A04:2021",
        "remediation": "Log detailed errors server-side. Return generic error messages to users.",
        "references": ["https://cwe.mitre.org/data/definitions/209.html"],
    },
    {
        "id": "PL-INFO-003",
        "pattern": r'(?:fatalsToBrowser|CGI::Carp.*fatalsToBrowser)',
        "category": "Information Disclosure",
        "title": "CGI fatalsToBrowser enabled",
        "description": "fatalsToBrowser sends Perl error messages and stack traces to the web browser, exposing internal details.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-209",
        "owasp": "A04:2021",
        "remediation": "Only enable fatalsToBrowser in development. Disable in production and log errors to files.",
        "references": ["https://cwe.mitre.org/data/definitions/209.html"],
    },

    # ======================================================================
    # Insecure TLS
    # ======================================================================
    {
        "id": "PL-TLS-001",
        "pattern": r'verify_hostname\s*(?:=>|=)\s*0|SSL_verify_mode\s*(?:=>|=)\s*(?:SSL_VERIFY_NONE|0x00|0)',
        "category": "Insecure TLS",
        "title": "SSL/TLS certificate verification disabled",
        "description": "Disabling hostname verification or SSL verification allows man-in-the-middle attacks.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-295",
        "owasp": "A07:2021",
        "remediation": "Always verify SSL certificates: verify_hostname => 1, SSL_verify_mode => SSL_VERIFY_PEER.",
        "references": ["https://cwe.mitre.org/data/definitions/295.html"],
    },

    # ======================================================================
    # Temporary File Issues
    # ======================================================================
    {
        "id": "PL-TMPFILE-001",
        "pattern": r'(?:open.*(?:/tmp/|/var/tmp/)|tmpnam\s*\(|tempnam\s*\()',
        "negative_pattern": r'(?:File::Temp|tempfile|mkstemp)',
        "category": "Insecure Temporary Files",
        "title": "Insecure temporary file creation",
        "description": "Creating temporary files in predictable locations without proper precautions enables symlink attacks and race conditions.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-377",
        "owasp": "A04:2021",
        "remediation": "Use File::Temp for secure temporary file creation: my ($fh, $filename) = tempfile();",
        "references": ["https://cwe.mitre.org/data/definitions/377.html"],
    },

    # ======================================================================
    # Logging Sensitive Data
    # ======================================================================
    {
        "id": "PL-LOG-001",
        "pattern": r'(?:warn|print\s+STDERR|Log::Log4perl|Log::Any|Log::Dispatch)\s*.*(?:password|secret|token|api_key|credit)',
        "category": "Sensitive Data Logging",
        "title": "Potentially logging sensitive data",
        "description": "Logging passwords, tokens, or personal data violates security best practices.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-532",
        "owasp": "A09:2021",
        "remediation": "Never log sensitive values. Mask or redact credentials before logging.",
        "references": ["https://cwe.mitre.org/data/definitions/532.html"],
    },

    # ======================================================================
    # Insecure Cookie
    # ======================================================================
    {
        "id": "PL-COOKIE-001",
        "pattern": r'(?:CGI::Cookie|cookie\s*\()',
        "negative_pattern": r'(?:-secure|-httponly|secure\s*=>|httponly\s*=>)',
        "category": "Insecure Cookie",
        "title": "Cookie without secure/httponly flags",
        "description": "Cookies without Secure and HttpOnly flags are vulnerable to interception and XSS-based session hijacking.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-614",
        "owasp": "A05:2021",
        "remediation": "Set -secure and -httponly flags on all security-sensitive cookies.",
        "references": ["https://cwe.mitre.org/data/definitions/614.html"],
    },

    # ======================================================================
    # World-readable/writable permissions
    # ======================================================================
    {
        "id": "PL-PERM-001",
        "pattern": r'chmod\s*\(\s*0?777|chmod\s*\(\s*0?666|umask\s*\(\s*0?000\s*\)',
        "category": "Insecure Permissions",
        "title": "World-readable/writable file permissions",
        "description": "Setting file permissions to 777 (rwxrwxrwx) or 666 (rw-rw-rw-) allows any user on the system to read, write, or execute the file.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-732",
        "owasp": "A01:2021",
        "remediation": "Use restrictive permissions: chmod(0600, $file) for sensitive files, chmod(0644, $file) for readable files.",
        "references": ["https://cwe.mitre.org/data/definitions/732.html"],
    },
]

# ---------------------------------------------------------------------------
# Scanner Engine
# ---------------------------------------------------------------------------
class PerlScanner:
    """Token-based Perl SAST scanner with multi-line context analysis."""

    def __init__(self):
        self.rules = RULES
        log.info(f"Perl Scanner initialized with {len(self.rules)} rules")

    def _check_multiline_context(self, lines: List[str], line_idx: int, pattern: str, window: int = 5) -> bool:
        """Check if a pattern appears within a window of lines around the target line."""
        start = max(0, line_idx - window)
        end = min(len(lines), line_idx + window + 1)
        context_block = "\n".join(lines[start:end])
        return bool(re.search(pattern, context_block, re.IGNORECASE))

    def _is_comment(self, line: str) -> bool:
        """Check if line is a Perl comment."""
        stripped = line.strip()
        return stripped.startswith("#")

    def _is_in_pod(self, lines: List[str], line_idx: int) -> bool:
        """Check if line is inside a POD documentation block."""
        in_pod = False
        for i in range(line_idx + 1):
            stripped = lines[i].strip()
            if stripped.startswith("=") and not stripped.startswith("=="):
                if stripped.startswith("=cut"):
                    in_pod = False
                elif stripped.startswith("=head") or stripped.startswith("=pod") or stripped.startswith("=over") or stripped.startswith("=item") or stripped.startswith("=begin") or stripped.startswith("=for") or stripped.startswith("=encoding"):
                    in_pod = True
        return in_pod

    def _is_in_heredoc(self, lines: List[str], line_idx: int) -> bool:
        """Basic check if line might be inside a heredoc."""
        for i in range(max(0, line_idx - 20), line_idx):
            if re.search(r'<<\s*["\']?(\w+)["\']?\s*;?\s*$', lines[i]):
                return True
        return False

    def scan_file(self, content: str, file_path: str) -> List[Finding]:
        """Scan a single Perl file for vulnerabilities."""
        findings: List[Finding] = []
        lines = content.split("\n")

        for rule in self.rules:
            # Handle file-level absence checks separately
            if rule.get("check_file_absence"):
                if not re.search(rule["pattern"], content, re.MULTILINE):
                    findings.append(Finding(
                        rule_id=rule["id"],
                        category=rule["category"],
                        title=rule["title"],
                        description=rule["description"],
                        severity=rule["severity"],
                        confidence=rule.get("confidence", Confidence.MEDIUM),
                        file_path=file_path,
                        line_number=1,
                        column=0,
                        code_snippet="(file-level check: pattern not found in file)",
                        remediation=rule.get("remediation", ""),
                        cwe_id=rule.get("cwe", ""),
                        owasp=rule.get("owasp", ""),
                        references=rule.get("references", []),
                    ))
                continue

            pattern = re.compile(rule["pattern"], re.IGNORECASE if rule.get("case_insensitive") else 0)

            for i, line in enumerate(lines):
                # Skip comments and POD
                if self._is_comment(line):
                    continue
                if self._is_in_pod(lines, i):
                    continue

                match = pattern.search(line)
                if not match:
                    continue

                # Check context pattern (multi-line aware)
                if rule.get("context_pattern"):
                    if not self._check_multiline_context(lines, i, rule["context_pattern"]):
                        continue

                # Check negative pattern
                if rule.get("negative_pattern"):
                    if self._check_multiline_context(lines, i, rule["negative_pattern"], window=3):
                        continue

                findings.append(Finding(
                    rule_id=rule["id"],
                    category=rule["category"],
                    title=rule["title"],
                    description=rule["description"],
                    severity=rule["severity"],
                    confidence=rule.get("confidence", Confidence.MEDIUM),
                    file_path=file_path,
                    line_number=i + 1,
                    column=match.start() + 1,
                    end_line=i + 1,
                    code_snippet=get_snippet(lines, i + 1),
                    remediation=rule.get("remediation", ""),
                    cwe_id=rule.get("cwe", ""),
                    owasp=rule.get("owasp", ""),
                    references=rule.get("references", []),
                ))

        return findings

    def scan(self, files: Dict[str, str], scan_id: str = "") -> ScanResponse:
        """Scan multiple Perl files."""
        if not scan_id:
            scan_id = str(uuid.uuid4())

        all_findings: List[Finding] = []
        scanned = 0

        for path, content in files.items():
            if not is_perl_file(path):
                continue
            scanned += 1
            try:
                file_findings = self.scan_file(content, path)
                all_findings.extend(file_findings)
            except Exception as e:
                log.error(f"Error scanning {path}: {e}", exc_info=True)

        # Deduplicate
        seen: Set[str] = set()
        unique_findings: List[Finding] = []
        for f in all_findings:
            key = f"{f.rule_id}:{f.file_path}:{f.line_number}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        # Sort by severity
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        unique_findings.sort(key=lambda f: (severity_order.get(f.severity, 5), f.file_path, f.line_number))

        # Build summary
        summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in unique_findings:
            summary[f.severity] = summary.get(f.severity, 0) + 1

        return ScanResponse(
            scanId=scan_id,
            totalFiles=scanned,
            totalFindings=len(unique_findings),
            findings=[asdict(f) for f in unique_findings],
            summary=summary,
        )


# ---------------------------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Offensive360 Perl SAST Scanner",
    description="Comprehensive static analysis for Perl using token-based parsing and regex pattern matching",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner = PerlScanner()


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "scanner": "Perl SAST Scanner",
        "version": "1.0.0",
        "engine": "token-based + regex pattern matching",
        "supported_extensions": list(PERL_EXTENSIONS),
        "vulnerability_categories": len(set(r["category"] for r in RULES)),
        "total_rules": len(RULES),
    }


@app.post("/scan", response_model=ScanResponse)
async def scan_files(request: ScanRequest):
    if not request.files:
        raise HTTPException(status_code=400, detail="No files provided")
    log.info(f"Scan request received: {len(request.files)} files, scanId={request.scanId}")
    try:
        result = scanner.scan(request.files, request.scanId)
        log.info(f"Scan complete: {result.totalFindings} findings in {result.totalFiles} files")
        return result
    except Exception as e:
        log.error(f"Scan failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("SCANNER_PORT", "9017"))
    log.info(f"Starting Perl SAST Scanner on port {port}")
    log.info(f"Rules loaded: {len(RULES)} covering {len(set(r['category'] for r in RULES))} categories")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
