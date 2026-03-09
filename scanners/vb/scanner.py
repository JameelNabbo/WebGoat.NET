#!/usr/bin/env python3
"""
Offensive360 VB/VB.NET SAST Scanner
Comprehensive static analysis for VB.NET, VB6, VBA, and VBScript source code
using token-based parsing + regex patterns.
FastAPI server on port 9016.

Covers ASP.NET WebForms, VB6/VBA COM, VBScript (WSH), and modern VB.NET.
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
log = logging.getLogger("vb-scanner")

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
# VB-specific helpers
# ---------------------------------------------------------------------------
VB_EXTENSIONS = {".vb", ".vbs", ".bas", ".cls", ".frm", ".ctl", ".dsr", ".asp", ".aspx.vb", ".vbhtml"}

def is_vb_file(path: str) -> bool:
    lower = path.lower()
    return any(lower.endswith(ext) for ext in VB_EXTENSIONS)

def is_vb_comment(line: str) -> bool:
    """Check if line is a VB comment (starts with ' or Rem)."""
    stripped = line.strip()
    return stripped.startswith("'") or stripped.upper().startswith("REM ")

# ---------------------------------------------------------------------------
# Vulnerability Rules
# ---------------------------------------------------------------------------
RULES: List[Dict[str, Any]] = [
    # ======================================================================
    # SQL Injection
    # ======================================================================
    {
        "id": "VB-SQL-001",
        "pattern": r'(?:SqlCommand|OleDbCommand|OdbcCommand|SqlDataAdapter)\s*\(',
        "context_pattern": r'(?:\&\s*"|"\s*\&|\+\s*"|"\s*\+|String\.Format|String\.Concat)',
        "category": "SQL Injection",
        "title": "SQL command with string concatenation",
        "description": "SQL command constructed using VB string concatenation (&) or (+) operator. This allows SQL injection when user input is included.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "remediation": "Use parameterized queries: cmd.Parameters.AddWithValue(\"@param\", value). Never concatenate user input into SQL strings.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },
    {
        "id": "VB-SQL-002",
        "pattern": r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC)\s+.*(?:\&\s*"|"\s*\&|\+\s*"|"\s*\+)',
        "category": "SQL Injection",
        "title": "SQL string built with concatenation",
        "description": "Direct SQL string construction using VB concatenation operator (&). This is the most common VB SQL injection pattern.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "remediation": "Use SqlCommand with Parameters.AddWithValue or stored procedures with parameters.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },
    {
        "id": "VB-SQL-003",
        "pattern": r'(?:ADODB\.(?:Connection|Command|Recordset))',
        "context_pattern": r'(?:\.Execute|\.Open|CommandText\s*=).*(?:\&|" \+)',
        "category": "SQL Injection",
        "title": "VB6/VBA ADODB with dynamic SQL",
        "description": "ADODB objects (COM ADO) used with string concatenation for SQL queries. Common in legacy VB6/VBA applications.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "remediation": "Use ADODB.Command with Parameters collection for parameterized queries.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },
    {
        "id": "VB-SQL-004",
        "pattern": r'ExecuteSqlRaw|FromSqlRaw',
        "context_pattern": r'(?:\&|String\.Format|String\.Concat|\$")',
        "category": "SQL Injection",
        "title": "Entity Framework raw SQL with dynamic content",
        "description": "EF Core raw SQL methods used with string formatting in VB.NET code.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "remediation": "Use FromSqlInterpolated or parameterized queries with EF Core.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },
    {
        "id": "VB-SQL-005",
        "pattern": r'(?:Dim|Dim\s+\w+\s+As\s+String)\s*=\s*"(?:SELECT|INSERT|UPDATE|DELETE)\s+',
        "context_pattern": r'(?:\&\s*\w|\&\s*Request|\&\s*TextBox|\&\s*txt)',
        "category": "SQL Injection",
        "title": "SQL string variable concatenated with user input controls",
        "description": "SQL query string concatenated with TextBox or Request values, typical WebForms SQL injection pattern.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "remediation": "Never concatenate control values into SQL. Use parameterized queries.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },

    # ======================================================================
    # Command Injection
    # ======================================================================
    {
        "id": "VB-CMD-001",
        "pattern": r'(?:Process\.Start|ProcessStartInfo)\s*\(',
        "context_pattern": r'(?:\&|\+|String\.Format|variable|input|param|Request)',
        "category": "Command Injection",
        "title": "Process execution with potential user-controlled input",
        "description": "Process.Start used with dynamically constructed arguments enables command injection.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "remediation": "Validate and sanitize all inputs. Use ProcessStartInfo with ArgumentList. Never pass user input to shell commands.",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    },
    {
        "id": "VB-CMD-002",
        "pattern": r'Shell\s*\(|Shell\s+"|Microsoft\.VisualBasic\.Interaction\.Shell',
        "category": "Command Injection",
        "title": "VB Shell function for command execution",
        "description": "The VB Shell function executes commands through the system shell, enabling command injection if input is user-controlled.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "remediation": "Use Process.Start with explicit arguments instead of Shell. Validate all inputs.",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    },
    {
        "id": "VB-CMD-003",
        "pattern": r'CreateObject\s*\(\s*"(?:WScript\.Shell|Shell\.Application|Scripting\.FileSystemObject)"',
        "category": "Command Injection",
        "title": "WScript.Shell or Shell.Application COM object creation",
        "description": "Creating WScript.Shell or Shell.Application COM objects allows arbitrary command execution. Common in VBScript malware.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "remediation": "Avoid WScript.Shell for command execution. Use managed alternatives with proper input validation.",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    },
    {
        "id": "VB-CMD-004",
        "pattern": r'\.Run\s*\(|\.Exec\s*\(',
        "context_pattern": r'(?:WScript\.Shell|Shell\.Application|objShell|wshShell)',
        "category": "Command Injection",
        "title": "Shell object .Run or .Exec method invocation",
        "description": "Invoking Run or Exec on a Shell object executes arbitrary system commands.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "remediation": "Use managed Process class with sanitized arguments instead of COM Shell objects.",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    },

    # ======================================================================
    # Code Injection
    # ======================================================================
    {
        "id": "VB-CODE-001",
        "pattern": r'CallByName\s*\(',
        "context_pattern": r'(?:\&|\+|Request|input|param|variable)',
        "category": "Code Injection",
        "title": "CallByName with potentially user-controlled method name",
        "description": "CallByName dynamically invokes methods by name. If the method name comes from user input, it enables arbitrary method invocation.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-94",
        "owasp": "A03:2021",
        "remediation": "Never use user input as method names in CallByName. Use a whitelist of allowed method names.",
        "references": ["https://cwe.mitre.org/data/definitions/94.html"],
    },
    {
        "id": "VB-CODE-002",
        "pattern": r'CreateObject\s*\((?:\s*\w+|\s*Request|\s*.*\&)',
        "category": "Code Injection",
        "title": "CreateObject with dynamic ProgID",
        "description": "CreateObject with a dynamically constructed ProgID allows instantiation of arbitrary COM objects, enabling code execution.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-94",
        "owasp": "A03:2021",
        "remediation": "Only use CreateObject with hardcoded, trusted ProgIDs. Never use user input as ProgID.",
        "references": ["https://cwe.mitre.org/data/definitions/94.html"],
    },
    {
        "id": "VB-CODE-003",
        "pattern": r'(?:Eval|Execute|ExecuteGlobal)\s*\(',
        "category": "Code Injection",
        "title": "VBScript Eval/Execute for dynamic code execution",
        "description": "Eval, Execute, and ExecuteGlobal interpret strings as VBScript code at runtime. If user input reaches these functions, arbitrary code execution occurs.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-94",
        "owasp": "A03:2021",
        "remediation": "Never pass user input to Eval/Execute/ExecuteGlobal. Redesign to avoid dynamic code evaluation.",
        "references": ["https://cwe.mitre.org/data/definitions/94.html"],
    },
    {
        "id": "VB-CODE-004",
        "pattern": r'(?:Assembly\.Load|Assembly\.LoadFile|Assembly\.LoadFrom|Activator\.CreateInstance)',
        "context_pattern": r'(?:\&|\+|String\.Format|Request|input|param)',
        "category": "Code Injection",
        "title": "Dynamic assembly loading with user-controlled path",
        "description": "Loading assemblies from paths that may be user-controlled enables arbitrary code execution.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-94",
        "owasp": "A03:2021",
        "remediation": "Only load assemblies from trusted, hardcoded paths.",
        "references": ["https://cwe.mitre.org/data/definitions/94.html"],
    },

    # ======================================================================
    # XSS (ASP.NET WebForms)
    # ======================================================================
    {
        "id": "VB-XSS-001",
        "pattern": r'Response\.Write\s*\(.*(?:\&|\+|Request|TextBox|txt\w+|variable)',
        "category": "Cross-Site Scripting (XSS)",
        "title": "Response.Write with user input (XSS)",
        "description": "Writing user input directly to the HTTP response without HTML encoding enables cross-site scripting attacks. This is the most common WebForms XSS pattern.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-79",
        "owasp": "A03:2021",
        "remediation": "Use HttpUtility.HtmlEncode() or Server.HtmlEncode() before writing user input to the response.",
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
    },
    {
        "id": "VB-XSS-002",
        "pattern": r'\.InnerHtml\s*=|\.Text\s*=.*Request(?:\.|\.Item|\()',
        "category": "Cross-Site Scripting (XSS)",
        "title": "Setting control InnerHtml/Text from request data",
        "description": "Setting InnerHtml or control Text directly from Request data without encoding enables XSS.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-79",
        "owasp": "A03:2021",
        "remediation": "Use InnerText instead of InnerHtml, or HtmlEncode the value before assignment.",
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
    },
    {
        "id": "VB-XSS-003",
        "pattern": r'<%\s*=\s*(?:Request|Session|ViewState)',
        "category": "Cross-Site Scripting (XSS)",
        "title": "ASP inline expression with request/session data",
        "description": "ASP.NET inline expressions (<%=) rendering request or session data without encoding are vulnerable to XSS.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-79",
        "owasp": "A03:2021",
        "remediation": "Use <%: (encoded expression) or HttpUtility.HtmlEncode in ASP.NET 4+.",
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
    },
    {
        "id": "VB-XSS-004",
        "pattern": r'(?:Literal|Label)\d*\.Text\s*=\s*(?:Request|.*\&\s*Request)',
        "category": "Cross-Site Scripting (XSS)",
        "title": "ASP.NET Literal/Label with unencoded user input",
        "description": "Setting Literal or Label Text to unencoded user input enables XSS, especially with Literal controls which render raw HTML.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-79",
        "owasp": "A03:2021",
        "remediation": "Use Literal.Mode = LiteralMode.Encode, or encode the value manually.",
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
    },

    # ======================================================================
    # Path Traversal
    # ======================================================================
    {
        "id": "VB-PATH-001",
        "pattern": r'(?:File|Directory|StreamReader|StreamWriter|FileStream|My\.Computer\.FileSystem)\.(?:Open|Read|Write|Create|Delete|Copy|Move|Exists|ReadAllText|ReadAllLines|WriteAllText|OpenText)',
        "context_pattern": r'(?:\&|\+|Request|input|param|TextBox|txt)',
        "category": "Path Traversal",
        "title": "File system operation with user-controlled path",
        "description": "File operations using paths derived from user input allow path traversal attacks (../../etc/passwd).",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-22",
        "owasp": "A01:2021",
        "remediation": "Use Path.GetFullPath and verify the resolved path starts with the expected base directory. Reject paths containing '..'.",
        "references": ["https://cwe.mitre.org/data/definitions/22.html"],
    },
    {
        "id": "VB-PATH-002",
        "pattern": r'(?:FileSystemObject|fso)\.\w+(?:File|Folder|Text)',
        "context_pattern": r'(?:\&|\+|Request|input|WScript\.Arguments)',
        "category": "Path Traversal",
        "title": "VBScript FileSystemObject with user-controlled path",
        "description": "Scripting.FileSystemObject operations with user-controlled paths allow path traversal and arbitrary file access.",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-22",
        "owasp": "A01:2021",
        "remediation": "Validate and sanitize file paths. Use whitelisted directories and reject paths containing '..'.",
        "references": ["https://cwe.mitre.org/data/definitions/22.html"],
    },
    {
        "id": "VB-PATH-003",
        "pattern": r'Server\.MapPath\s*\(.*(?:\&|\+|Request)',
        "category": "Path Traversal",
        "title": "Server.MapPath with user input",
        "description": "Server.MapPath with user input can be used to traverse outside the web root.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-22",
        "owasp": "A01:2021",
        "remediation": "Validate the mapped path remains within the intended directory. Do not include user input in paths.",
        "references": ["https://cwe.mitre.org/data/definitions/22.html"],
    },

    # ======================================================================
    # Deserialization
    # ======================================================================
    {
        "id": "VB-DESER-001",
        "pattern": r'BinaryFormatter\s*(?:\(|\.Deserialize)',
        "category": "Insecure Deserialization",
        "title": "BinaryFormatter deserialization (RCE risk)",
        "description": "BinaryFormatter is inherently unsafe and enables remote code execution during deserialization. Microsoft has deprecated it.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-502",
        "owasp": "A08:2021",
        "remediation": "Replace BinaryFormatter with System.Text.Json or safe JSON serializers. Never deserialize untrusted data with BinaryFormatter.",
        "references": ["https://cwe.mitre.org/data/definitions/502.html", "https://aka.ms/binaryformatter"],
    },
    {
        "id": "VB-DESER-002",
        "pattern": r'JsonConvert\.DeserializeObject.*TypeNameHandling\s*:?=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)',
        "category": "Insecure Deserialization",
        "title": "Newtonsoft JSON with dangerous TypeNameHandling",
        "description": "TypeNameHandling.All/Auto/Objects/Arrays enables type injection during JSON deserialization, leading to RCE.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-502",
        "owasp": "A08:2021",
        "remediation": "Use TypeNameHandling.None (default). Implement a custom SerializationBinder with type whitelist if type information is needed.",
        "references": ["https://cwe.mitre.org/data/definitions/502.html"],
    },
    {
        "id": "VB-DESER-003",
        "pattern": r'(?:SoapFormatter|ObjectStateFormatter|LosFormatter|NetDataContractSerializer)\.\w*(?:Deserialize|ReadObject)',
        "category": "Insecure Deserialization",
        "title": "Unsafe .NET deserialization formatter",
        "description": "These .NET formatters are known to be unsafe for deserializing untrusted data and can lead to RCE.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-502",
        "owasp": "A08:2021",
        "remediation": "Use System.Text.Json or Newtonsoft.Json with TypeNameHandling.None.",
        "references": ["https://cwe.mitre.org/data/definitions/502.html"],
    },

    # ======================================================================
    # XXE (XML External Entity)
    # ======================================================================
    {
        "id": "VB-XXE-001",
        "pattern": r'(?:New\s+)?XmlDocument\s*(?:\(|\{)',
        "negative_pattern": r'XmlResolver\s*=\s*Nothing',
        "category": "XML External Entity (XXE)",
        "title": "XmlDocument without safe resolver settings",
        "description": "XmlDocument without setting XmlResolver = Nothing is vulnerable to XXE attacks (file disclosure, SSRF, DoS).",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-611",
        "owasp": "A05:2021",
        "remediation": "Set XmlResolver = Nothing on XmlDocument. Use XmlReaderSettings with DtdProcessing = DtdProcessing.Prohibit.",
        "references": ["https://cwe.mitre.org/data/definitions/611.html"],
    },
    {
        "id": "VB-XXE-002",
        "pattern": r'(?:MSXML2\.DOMDocument|MSXML\.DOMDocument|DOMDocument)',
        "context_pattern": r'(?:loadXML|Load|async)',
        "category": "XML External Entity (XXE)",
        "title": "MSXML DOM with potential XXE vulnerability",
        "description": "MSXML DOM objects in VB6/VBScript may process external entities by default, enabling XXE attacks.",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-611",
        "owasp": "A05:2021",
        "remediation": "Set .setProperty(\"ProhibitDTD\", True) or use MSXML2.DOMDocument60 with resolveExternals = False.",
        "references": ["https://cwe.mitre.org/data/definitions/611.html"],
    },
    {
        "id": "VB-XXE-003",
        "pattern": r'DtdProcessing\s*:?=\s*DtdProcessing\.Parse',
        "category": "XML External Entity (XXE)",
        "title": "DTD processing explicitly enabled",
        "description": "Enabling DTD processing allows XML external entity attacks.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-611",
        "owasp": "A05:2021",
        "remediation": "Use DtdProcessing = DtdProcessing.Prohibit.",
        "references": ["https://cwe.mitre.org/data/definitions/611.html"],
    },

    # ======================================================================
    # SSRF
    # ======================================================================
    {
        "id": "VB-SSRF-001",
        "pattern": r'(?:HttpClient|WebClient|HttpWebRequest|WebRequest)\.(?:GetAsync|PostAsync|SendAsync|DownloadString|DownloadData|GetResponse|Create)',
        "context_pattern": r'(?:\&|\+|String\.Format|Request|input|param|url|TextBox)',
        "category": "Server-Side Request Forgery (SSRF)",
        "title": "HTTP request with user-controlled URL",
        "description": "HTTP requests with user-controlled URLs enable SSRF attacks against internal services and cloud metadata endpoints.",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-918",
        "owasp": "A10:2021",
        "remediation": "Validate URLs against a whitelist. Block private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x).",
        "references": ["https://cwe.mitre.org/data/definitions/918.html"],
    },
    {
        "id": "VB-SSRF-002",
        "pattern": r'(?:MSXML2\.(?:XMLHTTP|ServerXMLHTTP)|WinHttp\.WinHttpRequest)',
        "context_pattern": r'\.(?:Open|open)\s*.*(?:\&|\+|Request|variable)',
        "category": "Server-Side Request Forgery (SSRF)",
        "title": "COM HTTP object with user-controlled URL",
        "description": "MSXML2.XMLHTTP or WinHttp objects with user-controlled URLs enable SSRF in VB6/VBScript applications.",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-918",
        "owasp": "A10:2021",
        "remediation": "Validate and whitelist allowed URLs/domains before making HTTP requests.",
        "references": ["https://cwe.mitre.org/data/definitions/918.html"],
    },

    # ======================================================================
    # Hardcoded Secrets
    # ======================================================================
    {
        "id": "VB-SECRET-001",
        "pattern": r'(?:password|passwd|pwd|secret|apikey|api_key|token|auth_token|access_token|private_key)\s*(?:=|:=)\s*"[^"]{8,}"',
        "category": "Hardcoded Secrets",
        "title": "Hardcoded password or secret in source code",
        "description": "Credentials hardcoded in source code can be extracted by anyone with repository access.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "remediation": "Store secrets in environment variables, configuration files outside source control, or a secrets manager.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },
    {
        "id": "VB-SECRET-002",
        "pattern": r'(?:connectionString|connStr|strConn)\s*(?:=|:=)\s*"[^"]*(?:Password|PWD|Pwd)\s*=\s*[^"]*"',
        "category": "Hardcoded Secrets",
        "title": "Connection string with embedded credentials",
        "description": "Database connection strings with hardcoded passwords should use integrated authentication or secure credential storage.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "remediation": "Use integrated Windows authentication, or store connection strings in encrypted configuration sections.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },
    {
        "id": "VB-SECRET-003",
        "pattern": r'Dim\s+\w*(?:[Kk]ey|[Ss]ecret|[Tt]oken|[Pp]ass(?:word)?)\w*\s+As\s+String\s*=\s*"[^"]{8,}"',
        "category": "Hardcoded Secrets",
        "title": "Variable with hardcoded secret value",
        "description": "Variables named with key/secret/token/password containing hardcoded string values indicate embedded credentials.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "remediation": "Use ConfigurationManager.AppSettings or environment variables for sensitive values.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },

    # ======================================================================
    # Weak Cryptography
    # ======================================================================
    {
        "id": "VB-CRYPTO-001",
        "pattern": r'(?:MD5CryptoServiceProvider|MD5\.Create|New\s+MD5Managed)',
        "category": "Weak Cryptography",
        "title": "Use of MD5 hashing algorithm",
        "description": "MD5 is cryptographically broken with practical collision attacks. It must not be used for security.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-327",
        "owasp": "A02:2021",
        "remediation": "Use SHA256CryptoServiceProvider, SHA384, or SHA512 for hashing. For passwords, use bcrypt, scrypt, or PBKDF2.",
        "references": ["https://cwe.mitre.org/data/definitions/327.html"],
    },
    {
        "id": "VB-CRYPTO-002",
        "pattern": r'(?:SHA1CryptoServiceProvider|SHA1\.Create|SHA1Managed|New\s+SHA1)',
        "category": "Weak Cryptography",
        "title": "Use of SHA-1 hashing algorithm",
        "description": "SHA-1 is deprecated due to practical collision attacks.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-327",
        "owasp": "A02:2021",
        "remediation": "Migrate to SHA256 or SHA512.",
        "references": ["https://cwe.mitre.org/data/definitions/327.html"],
    },
    {
        "id": "VB-CRYPTO-003",
        "pattern": r'(?:DESCryptoServiceProvider|DES\.Create|TripleDESCryptoServiceProvider|TripleDES\.Create|RC2CryptoServiceProvider)',
        "category": "Weak Cryptography",
        "title": "Use of weak/deprecated encryption (DES/3DES/RC2)",
        "description": "DES (56-bit), 3DES (deprecated), and RC2 provide insufficient encryption strength.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-327",
        "owasp": "A02:2021",
        "remediation": "Use AesCryptoServiceProvider or Aes.Create() with 256-bit keys.",
        "references": ["https://cwe.mitre.org/data/definitions/327.html"],
    },

    # ======================================================================
    # Insecure Random
    # ======================================================================
    {
        "id": "VB-RAND-001",
        "pattern": r'(?:Rnd\s*\(|Randomize|New\s+Random(?:\s*\(|$))',
        "category": "Insecure Randomness",
        "title": "Use of Rnd/Randomize or System.Random for security",
        "description": "VB's Rnd function and System.Random are predictable PRNGs that must not be used for security tokens, keys, or nonces.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-330",
        "owasp": "A02:2021",
        "remediation": "Use RNGCryptoServiceProvider or RandomNumberGenerator for cryptographic randomness.",
        "references": ["https://cwe.mitre.org/data/definitions/330.html"],
    },

    # ======================================================================
    # ASP.NET WebForms-specific
    # ======================================================================
    {
        "id": "VB-WEBFORMS-001",
        "pattern": r'EnableViewStateMac\s*=\s*(?:False|"False"|"false")',
        "category": "ASP.NET WebForms Security",
        "title": "ViewState MAC validation disabled",
        "description": "Disabling ViewState MAC validation allows tampering with ViewState data, potentially enabling code execution or data manipulation.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-642",
        "owasp": "A04:2021",
        "remediation": "Always keep EnableViewStateMac = True (default). This is required for ViewState integrity.",
        "references": ["https://cwe.mitre.org/data/definitions/642.html"],
    },
    {
        "id": "VB-WEBFORMS-002",
        "pattern": r'EnableEventValidation\s*=\s*(?:False|"False"|"false")',
        "category": "ASP.NET WebForms Security",
        "title": "Event validation disabled",
        "description": "Disabling event validation allows attackers to submit unauthorized postback events, enabling parameter tampering.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-602",
        "owasp": "A04:2021",
        "remediation": "Keep EnableEventValidation = True. If custom controls require it, validate events manually.",
        "references": ["https://cwe.mitre.org/data/definitions/602.html"],
    },
    {
        "id": "VB-WEBFORMS-003",
        "pattern": r'ValidateRequest\s*=\s*(?:False|"False"|"false")',
        "category": "ASP.NET WebForms Security",
        "title": "Request validation disabled",
        "description": "Disabling ASP.NET request validation removes built-in XSS protection, allowing script injection through form inputs.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-79",
        "owasp": "A03:2021",
        "remediation": "Keep ValidateRequest = True. Encode output instead of disabling input validation.",
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
    },
    {
        "id": "VB-WEBFORMS-004",
        "pattern": r'ViewStateEncryptionMode\s*=\s*(?:Never|"Never")',
        "category": "ASP.NET WebForms Security",
        "title": "ViewState encryption disabled",
        "description": "Disabling ViewState encryption exposes application state to the client, potentially leaking sensitive data.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-311",
        "owasp": "A04:2021",
        "remediation": "Use ViewStateEncryptionMode = Always for sensitive applications.",
        "references": ["https://cwe.mitre.org/data/definitions/311.html"],
    },

    # ======================================================================
    # VB6/VBA-specific
    # ======================================================================
    {
        "id": "VB-VB6-001",
        "pattern": r'(?:Open\s+.*For\s+(?:Input|Output|Append|Binary)\s+As)',
        "context_pattern": r'(?:\&|\+|variable|input|param|Environ)',
        "category": "File Operations (VB6)",
        "title": "VB6 Open statement with user-controlled path",
        "description": "VB6 Open statement with dynamically constructed file paths allows path traversal and arbitrary file access.",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-22",
        "owasp": "A01:2021",
        "remediation": "Validate file paths against a whitelist of allowed directories. Reject paths containing '..'.",
        "references": ["https://cwe.mitre.org/data/definitions/22.html"],
    },
    {
        "id": "VB-VB6-002",
        "pattern": r'Environ\s*\(\s*"',
        "category": "Information Disclosure (VB6)",
        "title": "Environment variable access",
        "description": "Reading environment variables may expose sensitive configuration data. Ensure environment values are validated before use.",
        "severity": Severity.LOW,
        "confidence": Confidence.LOW,
        "cwe": "CWE-200",
        "owasp": "A04:2021",
        "remediation": "Treat environment variable values as untrusted input. Validate before use in security-sensitive operations.",
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
    },

    # ======================================================================
    # VBScript-specific
    # ======================================================================
    {
        "id": "VB-VBSCRIPT-001",
        "pattern": r'WScript\.Shell|Wscript\.CreateObject\s*\(\s*"WScript\.Shell"',
        "category": "VBScript Security",
        "title": "WScript.Shell object usage",
        "description": "WScript.Shell allows arbitrary command execution in VBScript/WSH environments. This is commonly used in malware and attack scripts.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "remediation": "Restrict WScript.Shell usage. Use Group Policy to disable WSH for non-administrative users.",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    },
    {
        "id": "VB-VBSCRIPT-002",
        "pattern": r'GetObject\s*\(\s*"(?:winmgmts|LDAP|WinNT)(?::|//)',
        "category": "VBScript Security",
        "title": "GetObject for WMI/LDAP/WinNT provider access",
        "description": "GetObject with WMI, LDAP, or WinNT providers can be used for system reconnaissance, lateral movement, or privilege escalation.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-284",
        "owasp": "A01:2021",
        "remediation": "Restrict access to these providers. Validate user permissions before WMI/LDAP operations.",
        "references": ["https://cwe.mitre.org/data/definitions/284.html"],
    },

    # ======================================================================
    # Missing Input Validation
    # ======================================================================
    {
        "id": "VB-VALID-001",
        "pattern": r'Request(?:\.QueryString|\.Form|\.Item|\()',
        "negative_pattern": r'(?:Validate|IsNumeric|IsDate|Regex\.IsMatch|HtmlEncode|UrlEncode|Int32\.TryParse)',
        "category": "Missing Input Validation",
        "title": "Request parameter used without validation",
        "description": "Request parameters used directly without validation or sanitization can lead to injection attacks.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-20",
        "owasp": "A03:2021",
        "remediation": "Validate all request parameters. Use type checking (IsNumeric, TryParse), length limits, and whitelist validation.",
        "references": ["https://cwe.mitre.org/data/definitions/20.html"],
    },

    # ======================================================================
    # On Error Resume Next (Error Swallowing)
    # ======================================================================
    {
        "id": "VB-ERR-001",
        "pattern": r'On\s+Error\s+Resume\s+Next',
        "category": "Error Handling",
        "title": "On Error Resume Next suppresses all errors",
        "description": "On Error Resume Next silently ignores all errors, hiding bugs and security issues. Errors in security-critical code may be silently bypassed.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-390",
        "owasp": "A04:2021",
        "remediation": "Use structured error handling (Try/Catch in VB.NET). If On Error Resume Next is needed, check Err.Number immediately after each risky operation.",
        "references": ["https://cwe.mitre.org/data/definitions/390.html"],
    },
    {
        "id": "VB-ERR-002",
        "pattern": r'Catch\s+(?:ex\s+As\s+)?Exception\s*\n\s*(?:End\s+Try|\')',
        "category": "Error Handling",
        "title": "Empty Catch block swallows exception",
        "description": "Catching exceptions without handling them hides errors and may mask security vulnerabilities.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-390",
        "owasp": "A04:2021",
        "remediation": "At minimum, log caught exceptions. Handle specific exception types appropriately.",
        "references": ["https://cwe.mitre.org/data/definitions/390.html"],
    },

    # ======================================================================
    # Late Binding Security
    # ======================================================================
    {
        "id": "VB-LATE-001",
        "pattern": r'(?:Dim\s+\w+)\s*$|(?:Dim\s+\w+\s+As\s+Object)',
        "context_pattern": r'(?:CreateObject|GetObject|CallByName)',
        "category": "Late Binding Security",
        "title": "Late-bound object with dynamic method invocation",
        "description": "Late-bound objects (As Object / untyped Dim) combined with CreateObject or CallByName allow arbitrary COM object instantiation and method invocation.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-470",
        "owasp": "A03:2021",
        "remediation": "Use early binding (As SpecificType) and avoid dynamic object creation from user input.",
        "references": ["https://cwe.mitre.org/data/definitions/470.html"],
    },

    # ======================================================================
    # COM Interop Issues
    # ======================================================================
    {
        "id": "VB-COM-001",
        "pattern": r'(?:CreateObject|GetObject)\s*\(.*(?:\&|\+|Request|input|variable)',
        "category": "COM Interop Security",
        "title": "COM object creation with user-controlled ProgID",
        "description": "Creating COM objects with user-supplied ProgIDs allows instantiation of arbitrary COM objects, potentially enabling code execution.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-94",
        "owasp": "A03:2021",
        "remediation": "Only use hardcoded ProgIDs with CreateObject. Validate ProgIDs against a whitelist.",
        "references": ["https://cwe.mitre.org/data/definitions/94.html"],
    },
    {
        "id": "VB-COM-002",
        "pattern": r'Marshal\.ReleaseComObject|Marshal\.FinalReleaseComObject',
        "negative_pattern": r'(?:Try|Finally)',
        "category": "COM Interop Security",
        "title": "COM object release without proper error handling",
        "description": "Releasing COM objects without proper error handling can cause resource leaks or access violations.",
        "severity": Severity.LOW,
        "confidence": Confidence.LOW,
        "cwe": "CWE-404",
        "owasp": "",
        "remediation": "Always release COM objects in a Finally block. Use Marshal.FinalReleaseComObject to fully release.",
        "references": ["https://cwe.mitre.org/data/definitions/404.html"],
    },

    # ======================================================================
    # Information Disclosure
    # ======================================================================
    {
        "id": "VB-INFO-001",
        "pattern": r'customErrors\s+mode\s*=\s*"Off"|CustomErrors\s*=\s*CustomErrorsMode\.Off',
        "category": "Information Disclosure",
        "title": "Custom errors disabled (detailed errors exposed)",
        "description": "Disabling custom errors shows detailed stack traces and exception details to end users, aiding attackers.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-209",
        "owasp": "A04:2021",
        "remediation": "Set customErrors mode=\"RemoteOnly\" or \"On\" in web.config. Use a custom error page.",
        "references": ["https://cwe.mitre.org/data/definitions/209.html"],
    },
    {
        "id": "VB-INFO-002",
        "pattern": r'(?:Debug\.Print|Debug\.Write|Console\.Write|MsgBox|MessageBox\.Show)\s*\(.*(?:password|secret|token|key|connectionString|credit)',
        "category": "Information Disclosure",
        "title": "Sensitive data written to debug output or message box",
        "description": "Debug output or message boxes displaying sensitive information may expose credentials.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-532",
        "owasp": "A09:2021",
        "remediation": "Never display sensitive values in debug output or message boxes. Mask or redact credentials.",
        "references": ["https://cwe.mitre.org/data/definitions/532.html"],
    },
    {
        "id": "VB-INFO-003",
        "pattern": r'Trace\s*=\s*(?:True|"True"|"true")|trace\s+enabled\s*=\s*"true"',
        "category": "Information Disclosure",
        "title": "ASP.NET page tracing enabled",
        "description": "Page tracing exposes detailed request/response data, session variables, and server information to end users.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-200",
        "owasp": "A04:2021",
        "remediation": "Disable tracing in production: set Trace = False in page directive and trace enabled=\"false\" in web.config.",
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
    },

    # ======================================================================
    # Missing Authorization
    # ======================================================================
    {
        "id": "VB-AUTH-001",
        "pattern": r'(?:Sub|Function)\s+(?:Page_Load|btnSubmit_Click|btn\w+_Click)',
        "negative_pattern": r'(?:IsAuthenticated|IsInRole|User\.Identity|Authorize|PrincipalPermission|Session\(".*[Ll]ogin|Session\(".*[Uu]ser)',
        "category": "Missing Authorization",
        "title": "Page/event handler without authentication check",
        "description": "WebForms event handlers should verify user authentication and authorization before processing requests.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.LOW,
        "cwe": "CWE-862",
        "owasp": "A01:2021",
        "remediation": "Check User.Identity.IsAuthenticated and roles before processing sensitive operations.",
        "references": ["https://cwe.mitre.org/data/definitions/862.html"],
    },

    # ======================================================================
    # Insecure TLS/SSL
    # ======================================================================
    {
        "id": "VB-TLS-001",
        "pattern": r'ServicePointManager\.ServerCertificateValidationCallback\s*=|ServerCertificateCustomValidationCallback\s*=',
        "context_pattern": r'(?:True|Return\s+True|true)',
        "category": "Insecure TLS",
        "title": "SSL certificate validation disabled",
        "description": "Disabling SSL certificate validation allows man-in-the-middle attacks.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-295",
        "owasp": "A07:2021",
        "remediation": "Never disable certificate validation in production. Use proper CA certificates.",
        "references": ["https://cwe.mitre.org/data/definitions/295.html"],
    },
    {
        "id": "VB-TLS-002",
        "pattern": r'SecurityProtocolType\.(?:Ssl3|Tls\b|Tls11)',
        "category": "Insecure TLS",
        "title": "Use of deprecated SSL/TLS protocol version",
        "description": "SSL 3.0, TLS 1.0, and TLS 1.1 have known vulnerabilities and are deprecated.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-326",
        "owasp": "A02:2021",
        "remediation": "Use SecurityProtocolType.Tls12 Or SecurityProtocolType.Tls13.",
        "references": ["https://cwe.mitre.org/data/definitions/326.html"],
    },

    # ======================================================================
    # LDAP Injection
    # ======================================================================
    {
        "id": "VB-LDAP-001",
        "pattern": r'(?:DirectoryEntry|DirectorySearcher|LdapConnection)\s*\(',
        "context_pattern": r'(?:\&|\+|String\.Format|Request|input|TextBox)',
        "category": "LDAP Injection",
        "title": "LDAP query with user-controlled input",
        "description": "LDAP queries built with user input without proper escaping can be exploited for LDAP injection.",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-90",
        "owasp": "A03:2021",
        "remediation": "Escape special LDAP characters (* ( ) \\ NUL) in user input. Use parameterized LDAP queries.",
        "references": ["https://cwe.mitre.org/data/definitions/90.html"],
    },

    # ======================================================================
    # Open Redirect
    # ======================================================================
    {
        "id": "VB-REDIR-001",
        "pattern": r'Response\.Redirect\s*\(.*(?:\&|\+|Request|TextBox|input)',
        "category": "Open Redirect",
        "title": "Response.Redirect with user-controlled URL",
        "description": "Redirecting to user-controlled URLs enables phishing attacks by redirecting victims to malicious sites.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-601",
        "owasp": "A01:2021",
        "remediation": "Validate redirect URLs against a whitelist. Use relative URLs when possible.",
        "references": ["https://cwe.mitre.org/data/definitions/601.html"],
    },

    # ======================================================================
    # Insecure Cookie
    # ======================================================================
    {
        "id": "VB-COOKIE-001",
        "pattern": r'(?:HttpCookie|Response\.Cookies)',
        "context_pattern": r'(?:Secure\s*=\s*False|HttpOnly\s*=\s*False)',
        "category": "Insecure Cookie",
        "title": "Cookie with insecure flags",
        "description": "Cookies without Secure or HttpOnly flags are vulnerable to session hijacking via network sniffing or XSS.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "cwe": "CWE-614",
        "owasp": "A05:2021",
        "remediation": "Set Secure = True and HttpOnly = True on all security-sensitive cookies.",
        "references": ["https://cwe.mitre.org/data/definitions/614.html"],
    },

    # ======================================================================
    # Logging Sensitive Data
    # ======================================================================
    {
        "id": "VB-LOG-001",
        "pattern": r'(?:EventLog\.WriteEntry|Trace\.Write|Debug\.Write|log\.\w+)\s*\(.*(?:password|secret|token|apiKey|connectionString|credit)',
        "category": "Sensitive Data Logging",
        "title": "Potentially logging sensitive data",
        "description": "Logging passwords, tokens, or personal data violates security best practices and privacy regulations.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-532",
        "owasp": "A09:2021",
        "remediation": "Never log sensitive values. Use structured logging with data masking.",
        "references": ["https://cwe.mitre.org/data/definitions/532.html"],
    },

    # ======================================================================
    # Hardcoded IP/URL
    # ======================================================================
    {
        "id": "VB-CONFIG-001",
        "pattern": r'"(?:http://|https://|ftp://)\d+\.\d+\.\d+\.\d+',
        "category": "Hardcoded Configuration",
        "title": "Hardcoded IP address in URL",
        "description": "Hardcoded IP addresses in URLs make the application environment-specific and may expose internal network topology.",
        "severity": Severity.LOW,
        "confidence": Confidence.MEDIUM,
        "cwe": "CWE-547",
        "owasp": "A05:2021",
        "remediation": "Use configuration files or DNS names instead of hardcoded IPs.",
        "references": ["https://cwe.mitre.org/data/definitions/547.html"],
    },
]

# ---------------------------------------------------------------------------
# Scanner Engine
# ---------------------------------------------------------------------------
class VBScanner:
    """Token-based VB/VB.NET SAST scanner with multi-line context analysis."""

    def __init__(self):
        self.rules = RULES
        log.info(f"VB Scanner initialized with {len(self.rules)} rules")

    def _check_multiline_context(self, lines: List[str], line_idx: int, pattern: str, window: int = 5) -> bool:
        """Check if a pattern appears within a window of lines around the target line."""
        start = max(0, line_idx - window)
        end = min(len(lines), line_idx + window + 1)
        context_block = "\n".join(lines[start:end])
        return bool(re.search(pattern, context_block, re.IGNORECASE))

    def _is_comment(self, line: str) -> bool:
        """Check if a line is a VB comment."""
        stripped = line.strip()
        return stripped.startswith("'") or stripped.upper().startswith("REM ")

    def _handle_line_continuation(self, lines: List[str]) -> List[Tuple[str, int]]:
        """Handle VB line continuation character (_) by joining continued lines.
        Returns list of (joined_line, original_line_number)."""
        result = []
        i = 0
        while i < len(lines):
            current = lines[i]
            orig_line = i
            # VB uses _ at end of line for continuation
            while current.rstrip().endswith(" _") and i + 1 < len(lines):
                current = current.rstrip()[:-1] + lines[i + 1].lstrip()
                i += 1
            result.append((current, orig_line))
            i += 1
        return result

    def scan_file(self, content: str, file_path: str) -> List[Finding]:
        """Scan a single VB file for vulnerabilities."""
        findings: List[Finding] = []
        lines = content.split("\n")

        for rule in self.rules:
            pattern = re.compile(rule["pattern"], re.IGNORECASE)

            for i, line in enumerate(lines):
                # Skip comments
                if self._is_comment(line):
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

        return findings

    def scan(self, files: Dict[str, str], scan_id: str = "") -> ScanResponse:
        """Scan multiple VB files."""
        if not scan_id:
            scan_id = str(uuid.uuid4())

        all_findings: List[Finding] = []
        scanned = 0

        for path, content in files.items():
            if not is_vb_file(path):
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
    title="Offensive360 VB/VB.NET SAST Scanner",
    description="Comprehensive static analysis for VB.NET, VB6, VBA, and VBScript using token-based parsing and regex",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner = VBScanner()


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "scanner": "VB/VB.NET SAST Scanner",
        "version": "1.0.0",
        "engine": "token-based + regex pattern matching",
        "supported_extensions": list(VB_EXTENSIONS),
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
    port = int(os.environ.get("SCANNER_PORT", "9016"))
    log.info(f"Starting VB/VB.NET SAST Scanner on port {port}")
    log.info(f"Rules loaded: {len(RULES)} covering {len(set(r['category'] for r in RULES))} categories")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
