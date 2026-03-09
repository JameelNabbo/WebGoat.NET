#!/usr/bin/env python3
"""
Offensive360 F# SAST Scanner
Comprehensive static analysis for F# source code using token-based parsing + regex patterns.
FastAPI server on port 9015.

F# uses significant whitespace, pipe operators (|>), pattern matching, computation expressions,
and functional-first paradigm with .NET interop.
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
log = logging.getLogger("fsharp-scanner")

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
# F# specific helpers
# ---------------------------------------------------------------------------
FSHARP_EXTENSIONS = {".fs", ".fsx", ".fsi"}

def is_fsharp_file(path: str) -> bool:
    return any(path.lower().endswith(ext) for ext in FSHARP_EXTENSIONS)

def is_comment_or_string(line: str, col: int) -> bool:
    """Basic check if position is inside a comment or string."""
    stripped = line.lstrip()
    if stripped.startswith("//"):
        return True
    if stripped.startswith("(*"):
        return True
    # Rough string check
    in_string = False
    i = 0
    while i < min(col, len(line)):
        if line[i] == '"' and (i == 0 or line[i-1] != '\\'):
            in_string = not in_string
        i += 1
    return in_string

# ---------------------------------------------------------------------------
# Vulnerability Rules
# ---------------------------------------------------------------------------
RULES: List[Dict[str, Any]] = [
    # ======================================================================
    # SQL Injection
    # ======================================================================
    {
        "id": "FS-SQL-001",
        "pattern": r'(?:SqlCommand|SqlConnection|OleDbCommand|NpgsqlCommand)\s*\(',
        "context_pattern": r'(?:sprintf|String\.Format|string\.Format|\+\s*["\w]|\$")',
        "category": "SQL Injection",
        "title": "SQL query constructed with string concatenation or interpolation",
        "description": "SQL command created using string concatenation or formatting, enabling SQL injection attacks. F# string interpolation ($\"\") with user input in SQL queries is particularly dangerous.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "remediation": "Use parameterized queries with SqlParameter. In F# use: cmd.Parameters.AddWithValue(\"@param\", value) |> ignore",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },
    {
        "id": "FS-SQL-002",
        "pattern": r'(?:ExecuteSqlRaw|FromSqlRaw|ExecuteSqlInterpolated)\s*[\(\$]',
        "context_pattern": r'(?:\+|\$"|sprintf|String\.Format)',
        "category": "SQL Injection",
        "title": "Entity Framework raw SQL with dynamic content",
        "description": "Entity Framework raw SQL methods used with string formatting or concatenation. Use FromSqlInterpolated which auto-parameterizes.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "remediation": "Use FromSqlInterpolated or parameterized queries instead of raw string operations.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },
    {
        "id": "FS-SQL-003",
        "pattern": r'(?:Dapper|connection)\s*\.(?:Query|Execute|QueryAsync|ExecuteAsync)\s*[\(<]',
        "context_pattern": r'(?:\+|\$"|sprintf|String\.Format)',
        "category": "SQL Injection",
        "title": "Dapper query with dynamic SQL construction",
        "description": "Dapper ORM query using string concatenation or interpolation for SQL construction.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "remediation": "Use Dapper's parameterized query syntax: connection.Query<T>(\"SELECT * FROM t WHERE id = @Id\", {| Id = value |})",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },
    {
        "id": "FS-SQL-004",
        "pattern": r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s+.*(?:\+|\$"|sprintf)',
        "context_pattern": None,
        "category": "SQL Injection",
        "title": "SQL string built with concatenation or interpolation",
        "description": "Direct SQL string construction detected. Even in F# functional code, SQL strings built dynamically are vulnerable to injection.",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "remediation": "Use parameterized queries or an ORM with proper parameter binding.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },

    # ======================================================================
    # Command Injection
    # ======================================================================
    {
        "id": "FS-CMD-001",
        "pattern": r'Process(?:StartInfo)?\.(?:Start|FileName|Arguments)',
        "context_pattern": r'(?:\+|\$"|sprintf|String\.Format|variable|input|param|arg|request)',
        "category": "Command Injection",
        "title": "Process execution with potential user-controlled input",
        "description": "System.Diagnostics.Process used with dynamically constructed arguments. Attackers can inject shell commands if input is not validated.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "remediation": "Validate and sanitize all inputs. Use ProcessStartInfo with ArgumentList instead of a single Arguments string. Never pass user input directly to shell commands.",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    },
    {
        "id": "FS-CMD-002",
        "pattern": r'ProcessStartInfo\s*\(\s*(?:"(?:cmd|bash|sh|powershell|pwsh)|.*(?:\+|\$"))',
        "category": "Command Injection",
        "title": "Shell process started with command interpreter",
        "description": "Starting cmd.exe, bash, or PowerShell directly allows command injection via argument manipulation.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "remediation": "Avoid invoking shell interpreters. Execute the target binary directly with explicit arguments.",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    },
    {
        "id": "FS-CMD-003",
        "pattern": r'Shell\s*\(|Interaction\.Shell\s*\(',
        "category": "Command Injection",
        "title": "VB-style Shell function used in F#",
        "description": "The Shell function (from Microsoft.VisualBasic) passes commands to the system shell, enabling command injection.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "remediation": "Use System.Diagnostics.Process with explicit arguments instead of Shell.",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    },

    # ======================================================================
    # Code Injection
    # ======================================================================
    {
        "id": "FS-CODE-001",
        "pattern": r'(?:FSharp\.Compiler\.Interactive|FsiEvaluationSession|Evaluate|EvalExpression|EvalInteraction)',
        "category": "Code Injection",
        "title": "F# Interactive (FSI) compiler used at runtime",
        "description": "Using F# Interactive compiler for dynamic code evaluation allows arbitrary code execution if input is user-controlled.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-94",
        "owasp": "A03:2021",
        "remediation": "Never evaluate user-controlled strings as F# code. Use a sandboxed interpreter or restrict inputs to a safe DSL.",
        "references": ["https://cwe.mitre.org/data/definitions/94.html"],
    },
    {
        "id": "FS-CODE-002",
        "pattern": r'(?:Assembly\.Load|Assembly\.LoadFile|Assembly\.LoadFrom|Activator\.CreateInstance)',
        "context_pattern": r'(?:\+|\$"|sprintf|String\.Format|variable|input|param)',
        "category": "Code Injection",
        "title": "Dynamic assembly loading with user-controlled path",
        "description": "Loading assemblies from paths that may be user-controlled enables arbitrary code execution.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-94",
        "owasp": "A03:2021",
        "remediation": "Only load assemblies from trusted, hardcoded paths. Validate assembly identity before loading.",
        "references": ["https://cwe.mitre.org/data/definitions/94.html"],
    },
    {
        "id": "FS-CODE-003",
        "pattern": r'(?:MethodInfo|PropertyInfo|FieldInfo)\.(?:Invoke|SetValue|GetValue)',
        "context_pattern": r'(?:\+|\$"|sprintf|String\.Format|variable|input|param)',
        "category": "Code Injection",
        "title": "Reflection invocation with potential user input",
        "description": "Using .NET reflection to dynamically invoke methods or access fields based on user input enables arbitrary code execution.",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-94",
        "owasp": "A03:2021",
        "remediation": "Avoid using reflection with user-controlled method/type names. Use a whitelist of allowed operations.",
        "references": ["https://cwe.mitre.org/data/definitions/94.html"],
    },
    {
        "id": "FS-CODE-004",
        "pattern": r'Type\.GetType\s*\(.*(?:\+|\$"|sprintf)',
        "category": "Code Injection",
        "title": "Dynamic type resolution with user input",
        "description": "Type.GetType with dynamically constructed type names can load arbitrary types, potentially executing static constructors or enabling deserialization attacks.",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-470",
        "owasp": "A03:2021",
        "remediation": "Use a whitelist of allowed type names. Never construct type names from user input.",
        "references": ["https://cwe.mitre.org/data/definitions/470.html"],
    },

    # ======================================================================
    # XSS (Giraffe/Saturn/Suave views)
    # ======================================================================
    {
        "id": "FS-XSS-001",
        "pattern": r'rawText\s+(?:\w+|(?:\$"))',
        "category": "Cross-Site Scripting (XSS)",
        "title": "Giraffe rawText with potentially unsafe content",
        "description": "Giraffe's rawText function renders HTML without encoding. If user input is passed, it enables XSS attacks.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-79",
        "owasp": "A03:2021",
        "remediation": "Use 'encodedText' or 'str' instead of 'rawText' for user-supplied content in Giraffe views.",
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
    },
    {
        "id": "FS-XSS-002",
        "pattern": r'Response\.Write\s*\(.*(?:\+|\$"|sprintf)',
        "category": "Cross-Site Scripting (XSS)",
        "title": "Direct response write without encoding",
        "description": "Writing user input directly to the HTTP response without HTML encoding enables XSS.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-79",
        "owasp": "A03:2021",
        "remediation": "Use HttpUtility.HtmlEncode or Giraffe's built-in encoding before writing to response.",
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
    },
    {
        "id": "FS-XSS-003",
        "pattern": r'(?:Content|ContentResult)\s*\(\s*(?:\$"|.*\+)',
        "category": "Cross-Site Scripting (XSS)",
        "title": "Content response with dynamic HTML content",
        "description": "Returning dynamic content as HTML without encoding user inputs allows XSS attacks.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-79",
        "owasp": "A03:2021",
        "remediation": "Encode all user-supplied data in HTML responses. Use Giraffe's view engine which auto-encodes.",
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
    },
    {
        "id": "FS-XSS-004",
        "pattern": r'Successful\.ok\s*\(.*(?:rawText|sprintf|String\.Format)',
        "category": "Cross-Site Scripting (XSS)",
        "title": "Suave response with unencoded content",
        "description": "Suave response handler returning unencoded user content enables XSS.",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-79",
        "owasp": "A03:2021",
        "remediation": "Encode user content before including it in Suave responses.",
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
    },

    # ======================================================================
    # Path Traversal
    # ======================================================================
    {
        "id": "FS-PATH-001",
        "pattern": r'(?:File|Directory|StreamReader|StreamWriter|FileStream)\.(?:Open|Read|Write|Create|Delete|Copy|Move|Exists|ReadAllText|ReadAllLines|WriteAllText|AppendAllText)',
        "context_pattern": r'(?:\+|\$"|sprintf|String\.Format|param|input|request|query)',
        "category": "Path Traversal",
        "title": "File system operation with user-controlled path",
        "description": "File system operations using user-controlled paths allow path traversal attacks (e.g., ../../etc/passwd).",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-22",
        "owasp": "A01:2021",
        "remediation": "Use Path.GetFullPath and verify the resolved path starts with the expected base directory. Never use user input directly in file paths.",
        "references": ["https://cwe.mitre.org/data/definitions/22.html"],
    },
    {
        "id": "FS-PATH-002",
        "pattern": r'Path\.Combine\s*\(.*(?:request|param|input|query|arg)',
        "category": "Path Traversal",
        "title": "Path.Combine with user-supplied path component",
        "description": "Path.Combine with user input can be bypassed if the user provides an absolute path (e.g., /etc/passwd on Linux).",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-22",
        "owasp": "A01:2021",
        "remediation": "After Path.Combine, verify the result starts with the expected base directory using Path.GetFullPath.",
        "references": ["https://cwe.mitre.org/data/definitions/22.html"],
    },

    # ======================================================================
    # Deserialization
    # ======================================================================
    {
        "id": "FS-DESER-001",
        "pattern": r'BinaryFormatter\s*\(\s*\)|BinaryFormatter\.Deserialize',
        "category": "Insecure Deserialization",
        "title": "BinaryFormatter deserialization (RCE risk)",
        "description": "BinaryFormatter is inherently unsafe and can execute arbitrary code during deserialization. Microsoft considers this class dangerous and has deprecated it.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-502",
        "owasp": "A08:2021",
        "remediation": "Replace BinaryFormatter with System.Text.Json or safe JSON serializers. Never deserialize untrusted data with BinaryFormatter.",
        "references": ["https://cwe.mitre.org/data/definitions/502.html", "https://aka.ms/binaryformatter"],
    },
    {
        "id": "FS-DESER-002",
        "pattern": r'JsonConvert\.DeserializeObject.*TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)',
        "category": "Insecure Deserialization",
        "title": "Newtonsoft JSON with dangerous TypeNameHandling",
        "description": "TypeNameHandling.All/Auto/Objects/Arrays allows type injection during JSON deserialization, enabling remote code execution.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-502",
        "owasp": "A08:2021",
        "remediation": "Use TypeNameHandling.None (default) or implement a custom SerializationBinder that whitelists allowed types.",
        "references": ["https://cwe.mitre.org/data/definitions/502.html"],
    },
    {
        "id": "FS-DESER-003",
        "pattern": r'(?:SoapFormatter|ObjectStateFormatter|LosFormatter|NetDataContractSerializer)\.(?:Deserialize|ReadObject)',
        "category": "Insecure Deserialization",
        "title": "Unsafe .NET deserialization formatter",
        "description": "These .NET formatters are known to be unsafe for deserializing untrusted data and can lead to remote code execution.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-502",
        "owasp": "A08:2021",
        "remediation": "Use System.Text.Json or Newtonsoft.Json with TypeNameHandling.None.",
        "references": ["https://cwe.mitre.org/data/definitions/502.html"],
    },
    {
        "id": "FS-DESER-004",
        "pattern": r'XmlSerializer\s*\(\s*(?:typeof|typedefof).*(?:\+|\$"|sprintf|String\.Format|input|param)',
        "category": "Insecure Deserialization",
        "title": "XmlSerializer with user-controlled type",
        "description": "XmlSerializer instantiated with a user-controlled type parameter can be used to exploit type confusion vulnerabilities.",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-502",
        "owasp": "A08:2021",
        "remediation": "Only use XmlSerializer with known, hardcoded types.",
        "references": ["https://cwe.mitre.org/data/definitions/502.html"],
    },

    # ======================================================================
    # XXE (XML External Entity)
    # ======================================================================
    {
        "id": "FS-XXE-001",
        "pattern": r'XmlDocument\s*\(\s*\)',
        "context_pattern": r'(?:XmlResolver|DtdProcessing\.Parse|ProhibitDtd\s*=\s*false)',
        "negative_pattern": r'XmlResolver\s*=\s*null',
        "category": "XML External Entity (XXE)",
        "title": "XmlDocument without safe XML resolver settings",
        "description": "XmlDocument without disabling external entity resolution is vulnerable to XXE attacks allowing file disclosure, SSRF, and DoS.",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-611",
        "owasp": "A05:2021",
        "remediation": "Set XmlResolver = null and DtdProcessing = DtdProcessing.Prohibit on XmlReaderSettings.",
        "references": ["https://cwe.mitre.org/data/definitions/611.html"],
    },
    {
        "id": "FS-XXE-002",
        "pattern": r'XmlReader\.Create\s*\(',
        "context_pattern": r'DtdProcessing\s*=\s*DtdProcessing\.Parse',
        "category": "XML External Entity (XXE)",
        "title": "XmlReader with DTD processing enabled",
        "description": "XmlReader with DtdProcessing.Parse allows processing of external DTDs, enabling XXE attacks.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-611",
        "owasp": "A05:2021",
        "remediation": "Use DtdProcessing = DtdProcessing.Prohibit in XmlReaderSettings.",
        "references": ["https://cwe.mitre.org/data/definitions/611.html"],
    },
    {
        "id": "FS-XXE-003",
        "pattern": r'XDocument\.(?:Load|Parse)\s*\(',
        "context_pattern": r'(?:DtdProcessing\.Parse|LoadOptions\.SetLineInfo)',
        "category": "XML External Entity (XXE)",
        "title": "XDocument loading with potential XXE",
        "description": "XDocument loading without safe reader settings may be vulnerable to XXE if DTD processing is not explicitly disabled.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-611",
        "owasp": "A05:2021",
        "remediation": "Pass an XmlReader with DtdProcessing.Prohibit to XDocument.Load.",
        "references": ["https://cwe.mitre.org/data/definitions/611.html"],
    },

    # ======================================================================
    # SSRF
    # ======================================================================
    {
        "id": "FS-SSRF-001",
        "pattern": r'(?:HttpClient|WebClient|WebRequest|HttpWebRequest)\.(?:GetAsync|PostAsync|SendAsync|GetStringAsync|DownloadString|GetResponse|Create)',
        "context_pattern": r'(?:\+|\$"|sprintf|String\.Format|param|input|request|query|url)',
        "category": "Server-Side Request Forgery (SSRF)",
        "title": "HTTP request with user-controlled URL",
        "description": "HTTP requests constructed with user-controlled URLs can be exploited for SSRF, allowing attackers to access internal services.",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-918",
        "owasp": "A10:2021",
        "remediation": "Validate and whitelist allowed URLs/domains. Block access to internal/private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, metadata endpoints).",
        "references": ["https://cwe.mitre.org/data/definitions/918.html"],
    },
    {
        "id": "FS-SSRF-002",
        "pattern": r'Uri\s*\(.*(?:\+|\$"|sprintf|String\.Format|param|input)',
        "category": "Server-Side Request Forgery (SSRF)",
        "title": "URI constructed from user input",
        "description": "URIs built with user input may enable SSRF attacks through URL manipulation.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-918",
        "owasp": "A10:2021",
        "remediation": "Validate URI scheme (only http/https), hostname against whitelist, and block private IP ranges.",
        "references": ["https://cwe.mitre.org/data/definitions/918.html"],
    },

    # ======================================================================
    # Hardcoded Secrets
    # ======================================================================
    {
        "id": "FS-SECRET-001",
        "pattern": r'(?:password|passwd|pwd|secret|apikey|api_key|token|auth_token|access_token|private_key)\s*=\s*"[^"]{8,}"',
        "category": "Hardcoded Secrets",
        "title": "Hardcoded password or secret in source code",
        "description": "Credentials or secrets hardcoded in source code can be extracted by anyone with access to the code repository.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "remediation": "Store secrets in environment variables, Azure Key Vault, AWS Secrets Manager, or secure configuration providers.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },
    {
        "id": "FS-SECRET-002",
        "pattern": r'[Cc]onnection[Ss]tring\s*=\s*"[^"]*(?:Password|PWD|Pwd)\s*=\s*[^"]*"',
        "category": "Hardcoded Secrets",
        "title": "Database connection string with embedded credentials",
        "description": "Connection strings with hardcoded passwords should use integrated authentication or secure credential storage.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "remediation": "Use integrated authentication, managed identities, or store connection strings in secure configuration.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },
    {
        "id": "FS-SECRET-003",
        "pattern": r'(?:let|let\s+mutable)\s+\w*(?:[Kk]ey|[Ss]ecret|[Tt]oken|[Pp]ass)\w*\s*=\s*"[^"]{8,}"',
        "category": "Hardcoded Secrets",
        "title": "F# let binding with hardcoded secret value",
        "description": "Variables named with key/secret/token/password containing hardcoded string values indicate embedded credentials.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "remediation": "Use configuration providers or environment variables. In F#: Environment.GetEnvironmentVariable(\"SECRET_KEY\")",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },

    # ======================================================================
    # Weak Cryptography
    # ======================================================================
    {
        "id": "FS-CRYPTO-001",
        "pattern": r'(?:MD5|MD5CryptoServiceProvider|MD5\.Create)',
        "category": "Weak Cryptography",
        "title": "Use of MD5 hashing algorithm",
        "description": "MD5 is cryptographically broken. Collision attacks are practical and it should never be used for security purposes.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-327",
        "owasp": "A02:2021",
        "remediation": "Use SHA-256, SHA-384, SHA-512, or HMAC-SHA256 for hashing. For passwords, use bcrypt, scrypt, or PBKDF2.",
        "references": ["https://cwe.mitre.org/data/definitions/327.html"],
    },
    {
        "id": "FS-CRYPTO-002",
        "pattern": r'(?:SHA1|SHA1CryptoServiceProvider|SHA1\.Create|SHA1Managed)',
        "category": "Weak Cryptography",
        "title": "Use of SHA-1 hashing algorithm",
        "description": "SHA-1 is deprecated due to practical collision attacks. It should not be used for security-sensitive operations.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-327",
        "owasp": "A02:2021",
        "remediation": "Migrate to SHA-256 or SHA-512.",
        "references": ["https://cwe.mitre.org/data/definitions/327.html"],
    },
    {
        "id": "FS-CRYPTO-003",
        "pattern": r'(?:DESCryptoServiceProvider|DES\.Create|TripleDESCryptoServiceProvider|TripleDES\.Create|RC2CryptoServiceProvider)',
        "category": "Weak Cryptography",
        "title": "Use of weak/deprecated encryption algorithm (DES/3DES/RC2)",
        "description": "DES (56-bit key), 3DES (being deprecated), and RC2 provide insufficient encryption strength.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-327",
        "owasp": "A02:2021",
        "remediation": "Use AES (AesCryptoServiceProvider or Aes.Create()) with 256-bit keys.",
        "references": ["https://cwe.mitre.org/data/definitions/327.html"],
    },
    {
        "id": "FS-CRYPTO-004",
        "pattern": r'(?:RijndaelManaged|AesManaged)\s*\(',
        "context_pattern": r'Mode\s*=\s*CipherMode\.ECB',
        "category": "Weak Cryptography",
        "title": "AES with ECB mode (insecure)",
        "description": "ECB mode encrypts identical plaintext blocks to identical ciphertext, leaking patterns. It should not be used.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-327",
        "owasp": "A02:2021",
        "remediation": "Use CBC mode with a random IV, or preferably use AES-GCM for authenticated encryption.",
        "references": ["https://cwe.mitre.org/data/definitions/327.html"],
    },

    # ======================================================================
    # Insecure Random
    # ======================================================================
    {
        "id": "FS-RAND-001",
        "pattern": r'(?:System\.Random|Random\s*\(\s*\)|Random\.Next|Random\.NextDouble)',
        "category": "Insecure Randomness",
        "title": "Use of System.Random for security-sensitive operations",
        "description": "System.Random is a predictable PRNG. It must not be used for generating tokens, keys, nonces, or other security-sensitive values.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-330",
        "owasp": "A02:2021",
        "remediation": "Use RNGCryptoServiceProvider, RandomNumberGenerator.Create(), or RandomNumberGenerator.GetBytes() for cryptographic randomness.",
        "references": ["https://cwe.mitre.org/data/definitions/330.html"],
    },

    # ======================================================================
    # Giraffe / Saturn Framework Security
    # ======================================================================
    {
        "id": "FS-GIRAFFE-001",
        "pattern": r'(?:AllowAnyOrigin|AllowAnyHeader|AllowAnyMethod|WithOrigins\s*\(\s*"\*"\s*\))',
        "category": "CORS Misconfiguration",
        "title": "Overly permissive CORS policy",
        "description": "Allowing any origin, header, or method in CORS policy exposes the API to cross-origin attacks.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-942",
        "owasp": "A05:2021",
        "remediation": "Restrict CORS to specific trusted origins. Never use AllowAnyOrigin with AllowCredentials.",
        "references": ["https://cwe.mitre.org/data/definitions/942.html"],
    },
    {
        "id": "FS-GIRAFFE-002",
        "pattern": r'requiresAuthentication|authorize|authorizeByPolicyName|authorizeByRole',
        "negative_pattern": r'(?:requiresAuthentication|authorize)',
        "check_absence": True,
        "category": "Missing Authorization",
        "title": "Giraffe/Saturn route handler without authentication",
        "description": "Route handlers in Giraffe/Saturn should use requiresAuthentication or authorize for protected endpoints.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.LOW,
        "cwe": "CWE-862",
        "owasp": "A01:2021",
        "remediation": "Add requiresAuthentication or authorizeByRole to sensitive route handlers.",
        "references": ["https://cwe.mitre.org/data/definitions/862.html"],
    },
    {
        "id": "FS-GIRAFFE-003",
        "pattern": r'AntiforgeryToken|ValidateAntiforgeryToken|xsrfToken',
        "check_absence": True,
        "check_file_absence": True,
        "category": "Missing CSRF Protection",
        "title": "Missing CSRF token validation in web application",
        "description": "Web applications handling form submissions should validate anti-forgery tokens to prevent CSRF attacks.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.LOW,
        "cwe": "CWE-352",
        "owasp": "A01:2021",
        "remediation": "Implement anti-forgery tokens in all state-changing form submissions using Giraffe's AntiForgery module.",
        "references": ["https://cwe.mitre.org/data/definitions/352.html"],
    },

    # ======================================================================
    # Suave Framework Security
    # ======================================================================
    {
        "id": "FS-SUAVE-001",
        "pattern": r'Suave\.Http\.ServerErrors\.INTERNAL_ERROR|Suave\.RequestErrors',
        "context_pattern": r'(?:sprintf|string\.Format|\$"|Exception\.Message|ex\.ToString)',
        "category": "Information Disclosure",
        "title": "Suave error response exposing internal details",
        "description": "Suave error responses containing exception details or internal state information can aid attackers.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-209",
        "owasp": "A04:2021",
        "remediation": "Return generic error messages to clients. Log detailed errors server-side only.",
        "references": ["https://cwe.mitre.org/data/definitions/209.html"],
    },
    {
        "id": "FS-SUAVE-002",
        "pattern": r'defaultConfig\s*(?:\{|\|)',
        "context_pattern": r'bindings\s*=.*IPAddress\.Any|0\.0\.0\.0',
        "category": "Suave Framework Security",
        "title": "Suave listening on all interfaces",
        "description": "Binding to 0.0.0.0 or IPAddress.Any exposes the service on all network interfaces, including public ones.",
        "severity": Severity.LOW,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-668",
        "owasp": "A05:2021",
        "remediation": "Bind to specific interfaces (127.0.0.1 for local only) or use a reverse proxy.",
        "references": ["https://cwe.mitre.org/data/definitions/668.html"],
    },

    # ======================================================================
    # Missing Input Validation
    # ======================================================================
    {
        "id": "FS-VALID-001",
        "pattern": r'(?:bindJson|bindQueryString|bindForm|BindModelAsync|TryBindQueryString)\s*<',
        "negative_pattern": r'(?:validation|validate|Validation|isValid|check)',
        "category": "Missing Input Validation",
        "title": "Model binding without validation in web handler",
        "description": "Data bound from HTTP requests without validation can contain malicious or malformed values.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-20",
        "owasp": "A03:2021",
        "remediation": "Validate all bound models using data annotations, FluentValidation, or manual validation before processing.",
        "references": ["https://cwe.mitre.org/data/definitions/20.html"],
    },

    # ======================================================================
    # Mutable State in Functional Code
    # ======================================================================
    {
        "id": "FS-MUTABLE-001",
        "pattern": r'let\s+mutable\s+\w+',
        "category": "Mutable State",
        "title": "Mutable variable binding in F# code",
        "description": "F# favors immutability. Mutable variables can lead to race conditions in concurrent code and make reasoning about state harder.",
        "severity": Severity.LOW,
        "confidence": Confidence.LOW,
        "cwe": "CWE-362",
        "owasp": "",
        "remediation": "Prefer immutable let bindings. Use ref cells or mutable only when absolutely necessary and protect with synchronization.",
        "references": ["https://cwe.mitre.org/data/definitions/362.html"],
    },
    {
        "id": "FS-MUTABLE-002",
        "pattern": r'ref\s+\w+|:=\s*|!\s*\w+',
        "context_pattern": r'(?:async|Async|task|Task|Thread|lock|parallel|concurrent)',
        "category": "Mutable State",
        "title": "Ref cell used in concurrent context",
        "description": "F# ref cells used in async/parallel contexts without synchronization can cause race conditions and data corruption.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-362",
        "owasp": "",
        "remediation": "Use thread-safe collections, Interlocked operations, or MailboxProcessor for concurrent state management.",
        "references": ["https://cwe.mitre.org/data/definitions/362.html"],
    },

    # ======================================================================
    # Unsafe Interop
    # ======================================================================
    {
        "id": "FS-INTEROP-001",
        "pattern": r'\[<DllImport\s*\(',
        "category": "Unsafe Interop",
        "title": "P/Invoke DllImport for native code interop",
        "description": "DllImport calls native code which can introduce memory safety vulnerabilities, buffer overflows, and bypass .NET security.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-111",
        "owasp": "A06:2021",
        "remediation": "Minimize P/Invoke usage. Validate all parameters, use SafeHandle for unmanaged resources, and apply SuppressUnmanagedCodeSecurityAttribute only when absolutely necessary.",
        "references": ["https://cwe.mitre.org/data/definitions/111.html"],
    },
    {
        "id": "FS-INTEROP-002",
        "pattern": r'(?:extern\s+|NativePtr|nativeptr|NativeInterop|Marshal\.(?:Copy|PtrToStructure|StructureToPtr|AllocHGlobal|ReadByte|WriteByte))',
        "category": "Unsafe Interop",
        "title": "Native pointer or Marshal operations",
        "description": "Native pointer operations and Marshal calls bypass .NET memory safety, risking buffer overflows and use-after-free bugs.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-787",
        "owasp": "A06:2021",
        "remediation": "Use managed alternatives where possible. Ensure proper bounds checking and memory management for native operations.",
        "references": ["https://cwe.mitre.org/data/definitions/787.html"],
    },
    {
        "id": "FS-INTEROP-003",
        "pattern": r'\[<SuppressUnmanagedCodeSecurity',
        "category": "Unsafe Interop",
        "title": "SuppressUnmanagedCodeSecurity attribute disables security checks",
        "description": "SuppressUnmanagedCodeSecurity disables runtime security checks on P/Invoke calls, potentially allowing malicious native code execution.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-250",
        "owasp": "A06:2021",
        "remediation": "Remove this attribute unless absolutely required for performance. Apply it only to methods that have been security-audited.",
        "references": ["https://cwe.mitre.org/data/definitions/250.html"],
    },

    # ======================================================================
    # Type Provider Security
    # ======================================================================
    {
        "id": "FS-TYPEPROV-001",
        "pattern": r'\[<TypeProvider|type\s+\w+\s*=\s*(?:CsvProvider|JsonProvider|XmlProvider|SqlDataProvider|SqlEntityProvider|WsdlService)',
        "context_pattern": r'(?:http://|https://|ftp://)',
        "category": "Type Provider Security",
        "title": "Type provider fetching data from remote URL",
        "description": "F# type providers that fetch schema or data from remote URLs can be exploited via MITM attacks or compromised servers, leading to code injection at compile time.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-829",
        "owasp": "A08:2021",
        "remediation": "Use HTTPS for all type provider URLs. Pin schemas locally when possible. Verify the integrity of remote schemas.",
        "references": ["https://cwe.mitre.org/data/definitions/829.html"],
    },

    # ======================================================================
    # Missing Error Handling
    # ======================================================================
    {
        "id": "FS-ERR-001",
        "pattern": r'failwith\s+"',
        "negative_pattern": r'(?:try|with\s*\|)',
        "category": "Error Handling",
        "title": "failwith without exception handling",
        "description": "Using failwith without a surrounding try/with block causes unhandled exceptions that may crash the application or expose error details.",
        "severity": Severity.LOW,
        "confidence": Confidence.LOW,
        "cwe": "CWE-755",
        "owasp": "A04:2021",
        "remediation": "Wrap failwith calls in try/with blocks, or use Option/Result types for error handling in F# idiomatic style.",
        "references": ["https://cwe.mitre.org/data/definitions/755.html"],
    },
    {
        "id": "FS-ERR-002",
        "pattern": r'with\s*\|\s*_\s*->\s*(?:\(\)|ignore|())',
        "category": "Error Handling",
        "title": "Exception swallowed silently",
        "description": "Catching all exceptions and ignoring them (| _ -> ()) hides errors, making debugging difficult and potentially masking security issues.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-390",
        "owasp": "A04:2021",
        "remediation": "At minimum, log caught exceptions. Use specific exception types and handle each appropriately.",
        "references": ["https://cwe.mitre.org/data/definitions/390.html"],
    },
    {
        "id": "FS-ERR-003",
        "pattern": r'(?:raise|reraise)\s+.*(?:Exception\.Message|ex\.Message)',
        "category": "Information Disclosure",
        "title": "Exception message propagation may leak internal details",
        "description": "Raising exceptions that include internal error messages can disclose system internals to end users.",
        "severity": Severity.LOW,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-209",
        "owasp": "A04:2021",
        "remediation": "Use generic error messages in exceptions visible to users. Log detailed messages server-side.",
        "references": ["https://cwe.mitre.org/data/definitions/209.html"],
    },

    # ======================================================================
    # Information Disclosure
    # ======================================================================
    {
        "id": "FS-INFO-001",
        "pattern": r'(?:printfn|printf|eprintfn|Console\.Write)\s+.*(?:password|secret|token|key|connectionString)',
        "category": "Information Disclosure",
        "title": "Sensitive data printed to console/logs",
        "description": "Logging or printing sensitive information (passwords, tokens, keys) may expose credentials in log files.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-532",
        "owasp": "A09:2021",
        "remediation": "Never log sensitive values. Mask or redact credentials before logging.",
        "references": ["https://cwe.mitre.org/data/definitions/532.html"],
    },
    {
        "id": "FS-INFO-002",
        "pattern": r'(?:DeveloperExceptionPage|UseDeveloperExceptionPage|ShowDetailedErrors\s*=\s*true)',
        "category": "Information Disclosure",
        "title": "Developer exception page enabled (production risk)",
        "description": "Developer exception pages show detailed stack traces, SQL queries, and internal state that aid attackers.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-209",
        "owasp": "A04:2021",
        "remediation": "Only enable developer exception pages in Development environment. Use UseExceptionHandler in production.",
        "references": ["https://cwe.mitre.org/data/definitions/209.html"],
    },

    # ======================================================================
    # Missing Authorization
    # ======================================================================
    {
        "id": "FS-AUTH-001",
        "pattern": r'(?:route|routef|subRoute|GET|POST|PUT|DELETE|PATCH)\s+(?:>=>|>>)',
        "negative_pattern": r'(?:requiresAuthentication|authorize|Authorize|authenticated)',
        "category": "Missing Authorization",
        "title": "HTTP route handler potentially missing authentication",
        "description": "Giraffe/Saturn route handlers should include authentication/authorization checks for protected resources.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.LOW,
        "cwe": "CWE-862",
        "owasp": "A01:2021",
        "remediation": "Add requiresAuthentication or appropriate authorization middleware to protected routes.",
        "references": ["https://cwe.mitre.org/data/definitions/862.html"],
    },

    # ======================================================================
    # LDAP Injection
    # ======================================================================
    {
        "id": "FS-LDAP-001",
        "pattern": r'(?:DirectoryEntry|DirectorySearcher|LdapConnection)\s*\(',
        "context_pattern": r'(?:\+|\$"|sprintf|String\.Format|param|input)',
        "category": "LDAP Injection",
        "title": "LDAP query with user-controlled input",
        "description": "LDAP queries built with user input without proper escaping can be exploited for LDAP injection attacks.",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-90",
        "owasp": "A03:2021",
        "remediation": "Escape special LDAP characters in user input or use parameterized LDAP queries.",
        "references": ["https://cwe.mitre.org/data/definitions/90.html"],
    },

    # ======================================================================
    # Insecure TLS/SSL
    # ======================================================================
    {
        "id": "FS-TLS-001",
        "pattern": r'ServicePointManager\.ServerCertificateValidationCallback\s*=|ServerCertificateCustomValidationCallback\s*=',
        "context_pattern": r'(?:true|_\s*->\s*true)',
        "category": "Insecure TLS",
        "title": "SSL certificate validation disabled",
        "description": "Disabling SSL certificate validation allows man-in-the-middle attacks by accepting any certificate.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-295",
        "owasp": "A07:2021",
        "remediation": "Never disable certificate validation in production. Use proper CA certificates and certificate pinning if needed.",
        "references": ["https://cwe.mitre.org/data/definitions/295.html"],
    },
    {
        "id": "FS-TLS-002",
        "pattern": r'SecurityProtocolType\.(?:Ssl3|Tls(?:\s|$)|Tls11)',
        "category": "Insecure TLS",
        "title": "Use of deprecated SSL/TLS protocol version",
        "description": "SSL 3.0, TLS 1.0, and TLS 1.1 have known vulnerabilities and are deprecated.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-326",
        "owasp": "A02:2021",
        "remediation": "Use SecurityProtocolType.Tls12 or SecurityProtocolType.Tls13.",
        "references": ["https://cwe.mitre.org/data/definitions/326.html"],
    },

    # ======================================================================
    # Open Redirect
    # ======================================================================
    {
        "id": "FS-REDIR-001",
        "pattern": r'(?:redirectTo|Redirect|RedirectResult|redirect)\s*(?:\(|\$"|.*\+)',
        "context_pattern": r'(?:param|input|request|query|url|returnUrl)',
        "category": "Open Redirect",
        "title": "Redirect with user-controlled URL",
        "description": "Redirecting to user-controlled URLs enables phishing attacks by redirecting victims to malicious sites.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-601",
        "owasp": "A01:2021",
        "remediation": "Validate redirect URLs against a whitelist of allowed domains. Use relative URLs when possible.",
        "references": ["https://cwe.mitre.org/data/definitions/601.html"],
    },

    # ======================================================================
    # Insecure Cookie
    # ======================================================================
    {
        "id": "FS-COOKIE-001",
        "pattern": r'CookieOptions|SetCookie|Cookies\.Append',
        "context_pattern": r'(?:Secure\s*=\s*false|HttpOnly\s*=\s*false|SameSite\s*=\s*SameSiteMode\.None)',
        "category": "Insecure Cookie",
        "title": "Cookie with insecure flags",
        "description": "Cookies without Secure, HttpOnly, or SameSite flags are vulnerable to session hijacking, XSS, and CSRF.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-614",
        "owasp": "A05:2021",
        "remediation": "Set Secure = true, HttpOnly = true, and SameSite = Strict/Lax on all security-sensitive cookies.",
        "references": ["https://cwe.mitre.org/data/definitions/614.html"],
    },

    # ======================================================================
    # Logging Sensitive Data
    # ======================================================================
    {
        "id": "FS-LOG-001",
        "pattern": r'(?:ILogger|Logger|log|Log)\.\w+\s*\(.*(?:password|secret|token|apiKey|connectionString|credit.?card|ssn)',
        "category": "Sensitive Data Logging",
        "title": "Potentially logging sensitive data",
        "description": "Logging sensitive information such as passwords, tokens, or personal data may violate privacy regulations and aid attackers.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-532",
        "owasp": "A09:2021",
        "remediation": "Never log sensitive values. Use structured logging with data masking.",
        "references": ["https://cwe.mitre.org/data/definitions/532.html"],
    },
]

# ---------------------------------------------------------------------------
# Scanner Engine
# ---------------------------------------------------------------------------
class FSharpScanner:
    """Token-based F# SAST scanner with multi-line context analysis."""

    def __init__(self):
        self.rules = RULES
        log.info(f"F# Scanner initialized with {len(self.rules)} rules")

    def _check_multiline_context(self, lines: List[str], line_idx: int, pattern: str, window: int = 5) -> bool:
        """Check if a pattern appears within a window of lines around the target line."""
        start = max(0, line_idx - window)
        end = min(len(lines), line_idx + window + 1)
        context_block = "\n".join(lines[start:end])
        return bool(re.search(pattern, context_block, re.IGNORECASE))

    def _is_in_comment(self, lines: List[str], line_idx: int, col: int = 0) -> bool:
        """Check if a line is inside a comment (single-line or multi-line block comment)."""
        line = lines[line_idx]
        stripped = line.strip()
        # Single-line comment
        if stripped.startswith("//"):
            return True
        # Check for multi-line block comments (* ... *)
        in_block = False
        for i in range(line_idx + 1):
            l = lines[i]
            j = 0
            while j < len(l):
                if not in_block and j + 1 < len(l) and l[j] == '(' and l[j+1] == '*':
                    in_block = True
                    j += 2
                    continue
                if in_block and j + 1 < len(l) and l[j] == '*' and l[j+1] == ')':
                    in_block = False
                    j += 2
                    continue
                j += 1
        return in_block

    def scan_file(self, content: str, file_path: str) -> List[Finding]:
        """Scan a single F# file for vulnerabilities."""
        findings: List[Finding] = []
        lines = content.split("\n")

        for rule in self.rules:
            # Skip absence-check rules (handled separately)
            if rule.get("check_file_absence"):
                continue

            pattern = re.compile(rule["pattern"], re.IGNORECASE)

            for i, line in enumerate(lines):
                # Skip comments
                if self._is_in_comment(lines, i):
                    continue

                match = pattern.search(line)
                if not match:
                    continue

                # Check context pattern (multi-line aware)
                if rule.get("context_pattern"):
                    if not self._check_multiline_context(lines, i, rule["context_pattern"]):
                        continue

                # Check negative pattern (should NOT match)
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

        # File-level absence checks
        full_content = content
        for rule in self.rules:
            if rule.get("check_file_absence") and not re.search(rule["pattern"], full_content, re.IGNORECASE):
                # Check if this file has web framework code
                has_web = bool(re.search(r'(?:Giraffe|Saturn|Suave|route|webApp|choose)', full_content))
                if has_web:
                    findings.append(Finding(
                        rule_id=rule["id"],
                        category=rule["category"],
                        title=rule["title"],
                        description=rule["description"],
                        severity=rule["severity"],
                        confidence=rule.get("confidence", Confidence.LOW),
                        file_path=file_path,
                        line_number=1,
                        column=0,
                        code_snippet="(file-level check: pattern not found in file)",
                        remediation=rule.get("remediation", ""),
                        cwe_id=rule.get("cwe", ""),
                        owasp=rule.get("owasp", ""),
                        references=rule.get("references", []),
                    ))

        return findings

    def scan(self, files: Dict[str, str], scan_id: str = "") -> ScanResponse:
        """Scan multiple F# files."""
        if not scan_id:
            scan_id = str(uuid.uuid4())

        all_findings: List[Finding] = []
        scanned = 0

        for path, content in files.items():
            if not is_fsharp_file(path):
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

        # Sort by severity then file/line
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
    title="Offensive360 F# SAST Scanner",
    description="Comprehensive static analysis for F# using token-based parsing and regex pattern matching",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner = FSharpScanner()


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "scanner": "F# SAST Scanner",
        "version": "1.0.0",
        "engine": "token-based + regex pattern matching",
        "supported_extensions": list(FSHARP_EXTENSIONS),
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
    port = int(os.environ.get("SCANNER_PORT", "9015"))
    log.info(f"Starting F# SAST Scanner on port {port}")
    log.info(f"Rules loaded: {len(RULES)} covering {len(set(r['category'] for r in RULES))} categories")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
