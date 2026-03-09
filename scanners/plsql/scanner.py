#!/usr/bin/env python3
"""
Offensive360 PL/SQL SAST Scanner
Comprehensive static analysis for PL/SQL and Oracle SQL source code.
Token-based parser with pattern matching for security vulnerabilities.
FastAPI server on port 9018.
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
log = logging.getLogger("plsql-scanner")

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
# PL/SQL Tokenizer
# ---------------------------------------------------------------------------
class TokenType(str, Enum):
    KEYWORD = "KEYWORD"
    IDENTIFIER = "IDENTIFIER"
    STRING = "STRING"
    NUMBER = "NUMBER"
    OPERATOR = "OPERATOR"
    COMMENT = "COMMENT"
    WHITESPACE = "WHITESPACE"
    DELIMITER = "DELIMITER"
    UNKNOWN = "UNKNOWN"

@dataclass
class Token:
    type: TokenType
    value: str
    line: int
    col: int

# PL/SQL keywords
PLSQL_KEYWORDS = {
    'SELECT', 'FROM', 'WHERE', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP',
    'ALTER', 'TABLE', 'INDEX', 'VIEW', 'PROCEDURE', 'FUNCTION', 'PACKAGE',
    'TRIGGER', 'SEQUENCE', 'SYNONYM', 'BEGIN', 'END', 'DECLARE', 'EXCEPTION',
    'WHEN', 'THEN', 'ELSE', 'ELSIF', 'IF', 'LOOP', 'WHILE', 'FOR', 'CURSOR',
    'OPEN', 'FETCH', 'CLOSE', 'INTO', 'EXECUTE', 'IMMEDIATE', 'RETURN', 'IS',
    'AS', 'IN', 'OUT', 'NOCOPY', 'DEFAULT', 'NULL', 'NOT', 'AND', 'OR',
    'LIKE', 'BETWEEN', 'EXISTS', 'GRANT', 'REVOKE', 'ROLE', 'PRIVILEGE',
    'CONNECT', 'RESOURCE', 'DBA', 'AUTHID', 'CURRENT_USER', 'DEFINER',
    'PRAGMA', 'AUTONOMOUS_TRANSACTION', 'RESTRICT_REFERENCES', 'RAISE',
    'RAISE_APPLICATION_ERROR', 'DBMS_SQL', 'DBMS_OUTPUT', 'UTL_FILE',
    'UTL_HTTP', 'UTL_TCP', 'UTL_SMTP', 'DBMS_SCHEDULER', 'DBMS_CRYPTO',
    'DBMS_OBFUSCATION_TOOLKIT', 'DBMS_ASSERT', 'ACCESSIBLE', 'BY',
    'TYPE', 'RECORD', 'REF', 'SYS_REFCURSOR', 'BULK', 'COLLECT',
    'FORALL', 'COMMIT', 'ROLLBACK', 'SAVEPOINT', 'EXCEPTION_INIT',
    'NO_DATA_FOUND', 'TOO_MANY_ROWS', 'OTHERS', 'SQLCODE', 'SQLERRM',
    'REPLACE', 'BODY', 'FORCE', 'CASCADE', 'CONSTRAINTS', 'PURGE',
    'WITH', 'ADMIN', 'OPTION', 'ANY', 'SYSTEM', 'OBJECT', 'TABLESPACE',
    'AUDIT', 'NOAUDIT', 'ON', 'IDENTIFIED', 'PASSWORD', 'ACCOUNT',
    'LOCK', 'UNLOCK', 'PROFILE', 'QUOTA', 'UNLIMITED', 'TEMPORARY',
}


def tokenize_plsql(source: str) -> List[Token]:
    """Tokenize PL/SQL source code."""
    tokens: List[Token] = []
    i = 0
    line = 1
    col = 1
    n = len(source)

    while i < n:
        # Track newlines
        if source[i] == '\n':
            line += 1
            col = 1
            i += 1
            continue

        # Skip carriage returns
        if source[i] == '\r':
            i += 1
            continue

        # Whitespace
        if source[i] in ' \t':
            i += 1
            col += 1
            continue

        # Single-line comment --
        if i + 1 < n and source[i:i+2] == '--':
            start = i
            start_col = col
            while i < n and source[i] != '\n':
                i += 1
                col += 1
            tokens.append(Token(TokenType.COMMENT, source[start:i], line, start_col))
            continue

        # Multi-line comment /* ... */
        if i + 1 < n and source[i:i+2] == '/*':
            start = i
            start_line = line
            start_col = col
            i += 2
            col += 2
            while i + 1 < n and source[i:i+2] != '*/':
                if source[i] == '\n':
                    line += 1
                    col = 1
                else:
                    col += 1
                i += 1
            if i + 1 < n:
                i += 2
                col += 2
            tokens.append(Token(TokenType.COMMENT, source[start:i], start_line, start_col))
            continue

        # String literal (single-quoted)
        if source[i] == "'":
            start = i
            start_col = col
            i += 1
            col += 1
            while i < n:
                if source[i] == "'" and i + 1 < n and source[i+1] == "'":
                    i += 2
                    col += 2
                elif source[i] == "'":
                    i += 1
                    col += 1
                    break
                else:
                    if source[i] == '\n':
                        line += 1
                        col = 1
                    else:
                        col += 1
                    i += 1
            tokens.append(Token(TokenType.STRING, source[start:i], line, start_col))
            continue

        # Quoted identifier (double-quoted)
        if source[i] == '"':
            start = i
            start_col = col
            i += 1
            col += 1
            while i < n and source[i] != '"':
                if source[i] == '\n':
                    line += 1
                    col = 1
                else:
                    col += 1
                i += 1
            if i < n:
                i += 1
                col += 1
            tokens.append(Token(TokenType.IDENTIFIER, source[start:i], line, start_col))
            continue

        # Numbers
        if source[i].isdigit():
            start = i
            start_col = col
            while i < n and (source[i].isdigit() or source[i] == '.'):
                i += 1
                col += 1
            tokens.append(Token(TokenType.NUMBER, source[start:i], line, start_col))
            continue

        # Identifiers and keywords
        if source[i].isalpha() or source[i] == '_' or source[i] == '$':
            start = i
            start_col = col
            while i < n and (source[i].isalnum() or source[i] in '_$#'):
                i += 1
                col += 1
            word = source[start:i]
            if word.upper() in PLSQL_KEYWORDS:
                tokens.append(Token(TokenType.KEYWORD, word.upper(), line, start_col))
            else:
                tokens.append(Token(TokenType.IDENTIFIER, word, line, start_col))
            continue

        # Operators and delimiters
        if source[i] in '.:;,(){}[]@':
            tokens.append(Token(TokenType.DELIMITER, source[i], line, col))
            i += 1
            col += 1
            continue

        if source[i] in '+-*/<>=!|&~^%':
            start = i
            start_col = col
            # Two-char operators
            if i + 1 < n and source[i:i+2] in (':=', '!=', '<>', '<=', '>=', '||', '**', '..'):
                tokens.append(Token(TokenType.OPERATOR, source[i:i+2], line, col))
                i += 2
                col += 2
            else:
                tokens.append(Token(TokenType.OPERATOR, source[i], line, col))
                i += 1
                col += 1
            continue

        # Unknown character
        tokens.append(Token(TokenType.UNKNOWN, source[i], line, col))
        i += 1
        col += 1

    return tokens


# ---------------------------------------------------------------------------
# Vulnerability Rules
# ---------------------------------------------------------------------------

PLSQL_RULES = [
    # ---- SQL Injection ----
    {
        "id": "PLSQL-SQLI-001",
        "category": "SQL Injection",
        "title": "EXECUTE IMMEDIATE with String Concatenation",
        "description": "EXECUTE IMMEDIATE statement uses string concatenation which may allow SQL injection. User-supplied values should be passed via USING clause with bind variables.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"(?i)EXECUTE\s+IMMEDIATE\s+[^;]*\|\|",
        "cwe_id": "CWE-89",
        "owasp": "A03:2021-Injection",
        "remediation": "Use bind variables with the USING clause instead of concatenation. Example: EXECUTE IMMEDIATE 'SELECT * FROM t WHERE id = :1' USING p_id;",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },
    {
        "id": "PLSQL-SQLI-002",
        "category": "SQL Injection",
        "title": "DBMS_SQL with Dynamic SQL",
        "description": "DBMS_SQL.PARSE is used to execute dynamically constructed SQL. If user input is included without proper sanitization, this can lead to SQL injection.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"(?i)DBMS_SQL\s*\.\s*PARSE\s*\(",
        "cwe_id": "CWE-89",
        "owasp": "A03:2021-Injection",
        "remediation": "Use bind variables via DBMS_SQL.BIND_VARIABLE instead of concatenating user input into the SQL string.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },
    {
        "id": "PLSQL-SQLI-003",
        "category": "SQL Injection",
        "title": "Dynamic SQL via String Variable",
        "description": "A variable is used with EXECUTE IMMEDIATE, suggesting dynamically constructed SQL that may be vulnerable to injection.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"(?i)EXECUTE\s+IMMEDIATE\s+[a-z_]\w*\s*;",
        "cwe_id": "CWE-89",
        "owasp": "A03:2021-Injection",
        "remediation": "Ensure the variable content is constructed using bind variables, not concatenation of user input.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },
    {
        "id": "PLSQL-SQLI-004",
        "category": "SQL Injection",
        "title": "OPEN Cursor with Dynamic SQL Concatenation",
        "description": "A REF CURSOR is opened with dynamically constructed SQL using concatenation, which may allow SQL injection.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"(?i)OPEN\s+\w+\s+FOR\s+[^;]*\|\|",
        "cwe_id": "CWE-89",
        "owasp": "A03:2021-Injection",
        "remediation": "Use bind variables with the USING clause when opening REF CURSORs dynamically.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },

    # ---- Privilege Escalation ----
    {
        "id": "PLSQL-PRIV-001",
        "category": "Privilege Escalation",
        "title": "AUTHID CURRENT_USER with Dynamic SQL",
        "description": "A procedure using AUTHID CURRENT_USER combined with dynamic SQL can be exploited for privilege escalation if a higher-privileged user executes it.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"(?i)AUTHID\s+CURRENT_USER[\s\S]{0,500}EXECUTE\s+IMMEDIATE",
        "cwe_id": "CWE-269",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Use AUTHID DEFINER for procedures containing dynamic SQL, or validate all inputs with DBMS_ASSERT.",
        "references": ["https://cwe.mitre.org/data/definitions/269.html"],
    },
    {
        "id": "PLSQL-PRIV-002",
        "category": "Privilege Escalation",
        "title": "GRANT with ADMIN OPTION",
        "description": "GRANT statement includes WITH ADMIN OPTION, allowing the grantee to further grant the privilege to others. This can lead to privilege escalation.",
        "severity": "High",
        "confidence": "High",
        "pattern": r"(?i)GRANT\s+[^;]+WITH\s+ADMIN\s+OPTION",
        "cwe_id": "CWE-269",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Remove WITH ADMIN OPTION unless absolutely necessary. Use role-based access control instead.",
        "references": ["https://cwe.mitre.org/data/definitions/269.html"],
    },

    # ---- Code Injection ----
    {
        "id": "PLSQL-CINJ-001",
        "category": "Code Injection",
        "title": "DBMS_SCHEDULER.CREATE_JOB with User Input",
        "description": "DBMS_SCHEDULER.CREATE_JOB constructs job action using concatenation, potentially allowing code injection.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"(?i)DBMS_SCHEDULER\s*\.\s*CREATE_JOB\s*\([^)]*\|\|",
        "cwe_id": "CWE-94",
        "owasp": "A03:2021-Injection",
        "remediation": "Validate and sanitize all user input before using in DBMS_SCHEDULER.CREATE_JOB. Use parameterized job definitions.",
        "references": ["https://cwe.mitre.org/data/definitions/94.html"],
    },
    {
        "id": "PLSQL-CINJ-002",
        "category": "Code Injection",
        "title": "DBMS_SCHEDULER with Dynamic PL/SQL Block",
        "description": "DBMS_SCHEDULER is used with a dynamically constructed PL/SQL block, which could allow arbitrary code execution.",
        "severity": "Critical",
        "confidence": "Medium",
        "pattern": r"(?i)DBMS_SCHEDULER\s*\.\s*(CREATE_JOB|CREATE_PROGRAM)\s*\([^)]*job_action\s*=>",
        "cwe_id": "CWE-94",
        "owasp": "A03:2021-Injection",
        "remediation": "Use stored procedures as job actions instead of inline PL/SQL blocks. Validate all parameters.",
        "references": ["https://cwe.mitre.org/data/definitions/94.html"],
    },

    # ---- Directory Traversal ----
    {
        "id": "PLSQL-PATH-001",
        "category": "Directory Traversal",
        "title": "UTL_FILE with User-Controlled Path",
        "description": "UTL_FILE operations use user-controlled file paths or directory names, potentially allowing directory traversal attacks.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"(?i)UTL_FILE\s*\.\s*(FOPEN|FOPEN_NCHAR)\s*\([^)]*\|\|",
        "cwe_id": "CWE-22",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Use Oracle directory objects with restricted permissions. Validate file names against a whitelist. Never use user input directly in file paths.",
        "references": ["https://cwe.mitre.org/data/definitions/22.html"],
    },
    {
        "id": "PLSQL-PATH-002",
        "category": "Directory Traversal",
        "title": "UTL_FILE Operations without Path Validation",
        "description": "UTL_FILE is used for file operations. Ensure the directory and filename parameters are validated to prevent unauthorized file access.",
        "severity": "Medium",
        "confidence": "Medium",
        "pattern": r"(?i)UTL_FILE\s*\.\s*(FOPEN|PUT_LINE|GET_LINE|FCLOSE|FREMOVE|FRENAME|FCOPY)",
        "cwe_id": "CWE-22",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Restrict UTL_FILE usage to predefined Oracle directory objects. Implement input validation on filenames.",
        "references": ["https://cwe.mitre.org/data/definitions/22.html"],
    },

    # ---- Information Disclosure ----
    {
        "id": "PLSQL-INFO-001",
        "category": "Information Disclosure",
        "title": "DBMS_OUTPUT with Sensitive Data",
        "description": "DBMS_OUTPUT.PUT_LINE may expose sensitive information such as passwords, tokens, or internal data.",
        "severity": "Medium",
        "confidence": "Medium",
        "pattern": r"(?i)DBMS_OUTPUT\s*\.\s*PUT_LINE\s*\([^)]*(?:password|secret|token|key|credential|ssn|credit)",
        "cwe_id": "CWE-200",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Remove DBMS_OUTPUT.PUT_LINE statements that output sensitive data. Use proper logging mechanisms with data masking.",
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
    },
    {
        "id": "PLSQL-INFO-002",
        "category": "Information Disclosure",
        "title": "Error Message Reveals Schema Information",
        "description": "Exception handler exposes SQLERRM or SQLCODE directly to the user, potentially revealing internal schema or query details.",
        "severity": "Medium",
        "confidence": "High",
        "pattern": r"(?i)WHEN\s+OTHERS\s+THEN[\s\S]{0,200}(?:SQLERRM|SQLCODE)[\s\S]{0,100}(?:RAISE_APPLICATION_ERROR|DBMS_OUTPUT)",
        "cwe_id": "CWE-209",
        "owasp": "A04:2021-Insecure Design",
        "remediation": "Log detailed error information server-side and return generic error messages to users.",
        "references": ["https://cwe.mitre.org/data/definitions/209.html"],
    },
    {
        "id": "PLSQL-INFO-003",
        "category": "Information Disclosure",
        "title": "DBMS_OUTPUT Exposing Debug Information",
        "description": "DBMS_OUTPUT.PUT_LINE left in production code may leak internal variable values or processing details.",
        "severity": "Low",
        "confidence": "Low",
        "pattern": r"(?i)DBMS_OUTPUT\s*\.\s*PUT_LINE\s*\(",
        "cwe_id": "CWE-200",
        "owasp": "A04:2021-Insecure Design",
        "remediation": "Remove or conditionally compile DBMS_OUTPUT statements. Use proper logging frameworks in production.",
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
    },

    # ---- Hardcoded Credentials ----
    {
        "id": "PLSQL-CRED-001",
        "category": "Hardcoded Credentials",
        "title": "Hardcoded Password in Source Code",
        "description": "A password or credential value appears to be hardcoded in the PL/SQL source code.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"(?i)(?:password|passwd|pwd)\s*(?::=|=>|=)\s*'[^']{3,}'",
        "cwe_id": "CWE-798",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Store credentials in Oracle Wallet or a secure vault. Use Oracle Credential Store Framework.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },
    {
        "id": "PLSQL-CRED-002",
        "category": "Hardcoded Credentials",
        "title": "Database Connection String with Credentials",
        "description": "A database connection string containing embedded credentials was found in the source code.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"(?i)(?:jdbc|oci8?|thin)\s*[:@].*(?:password|pwd)\s*=\s*\S+",
        "cwe_id": "CWE-798",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Use Oracle Wallet or externalized configuration for connection strings. Never embed credentials in source.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },
    {
        "id": "PLSQL-CRED-003",
        "category": "Hardcoded Credentials",
        "title": "DEFAULT Password Not Changed",
        "description": "A user or role is created with the DEFAULT keyword or a well-known default password.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"(?i)IDENTIFIED\s+BY\s+(?:tiger|scott|manager|change_on_install|oracle|sys|system|admin|password|welcome|test)",
        "cwe_id": "CWE-798",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Use strong, unique passwords. Enforce password complexity policies via Oracle profiles.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },

    # ---- Weak Cryptography ----
    {
        "id": "PLSQL-CRYP-001",
        "category": "Weak Cryptography",
        "title": "DBMS_OBFUSCATION_TOOLKIT Usage (Deprecated)",
        "description": "DBMS_OBFUSCATION_TOOLKIT is deprecated and uses weak DES encryption. Use DBMS_CRYPTO instead.",
        "severity": "High",
        "confidence": "High",
        "pattern": r"(?i)DBMS_OBFUSCATION_TOOLKIT\s*\.",
        "cwe_id": "CWE-327",
        "owasp": "A02:2021-Cryptographic Failures",
        "remediation": "Replace DBMS_OBFUSCATION_TOOLKIT with DBMS_CRYPTO using AES-256 encryption.",
        "references": ["https://cwe.mitre.org/data/definitions/327.html"],
    },
    {
        "id": "PLSQL-CRYP-002",
        "category": "Weak Cryptography",
        "title": "DBMS_CRYPTO with Weak Algorithm",
        "description": "DBMS_CRYPTO is used with a weak encryption algorithm (DES, 3DES, or MD5).",
        "severity": "High",
        "confidence": "High",
        "pattern": r"(?i)DBMS_CRYPTO\s*\.\s*(ENCRYPT_DES|DES_CBC_MODE|DES3_CBC_MODE|HASH_MD5)",
        "cwe_id": "CWE-327",
        "owasp": "A02:2021-Cryptographic Failures",
        "remediation": "Use DBMS_CRYPTO.ENCRYPT_AES256 with CBC or GCM mode. Use SHA-256 or SHA-512 for hashing.",
        "references": ["https://cwe.mitre.org/data/definitions/327.html"],
    },
    {
        "id": "PLSQL-CRYP-003",
        "category": "Weak Cryptography",
        "title": "Missing Encryption for Sensitive Data",
        "description": "Sensitive data (password, SSN, credit card) is stored or transmitted without encryption. No DBMS_CRYPTO usage detected.",
        "severity": "Medium",
        "confidence": "Low",
        "pattern": r"(?i)(?:INSERT|UPDATE)\s+(?:INTO\s+)?\w+\s*\([^)]*(?:password|ssn|credit_card|card_number|account_number)[^)]*\)\s*VALUES",
        "cwe_id": "CWE-311",
        "owasp": "A02:2021-Cryptographic Failures",
        "remediation": "Encrypt sensitive data before storing it using DBMS_CRYPTO.ENCRYPT with AES-256.",
        "references": ["https://cwe.mitre.org/data/definitions/311.html"],
    },

    # ---- Missing Input Validation ----
    {
        "id": "PLSQL-VALID-001",
        "category": "Missing Input Validation",
        "title": "No DBMS_ASSERT Usage for Input Validation",
        "description": "Dynamic SQL is constructed without using DBMS_ASSERT to validate identifiers or sanitize input.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"(?i)EXECUTE\s+IMMEDIATE\s+[^;]*\|\|(?![\s\S]*DBMS_ASSERT)",
        "cwe_id": "CWE-20",
        "owasp": "A03:2021-Injection",
        "remediation": "Use DBMS_ASSERT.SIMPLE_SQL_NAME, DBMS_ASSERT.ENQUOTE_NAME, or DBMS_ASSERT.ENQUOTE_LITERAL to validate dynamic SQL components.",
        "references": ["https://cwe.mitre.org/data/definitions/20.html"],
    },
    {
        "id": "PLSQL-VALID-002",
        "category": "Missing Input Validation",
        "title": "Procedure Parameter Used Directly in SQL",
        "description": "A procedure parameter appears to be concatenated directly into SQL without validation.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"(?i)(?:PROCEDURE|FUNCTION)\s+\w+\s*\([^)]*(?:p_|in_|v_)\w+[^)]*\)[\s\S]{0,500}(?:EXECUTE\s+IMMEDIATE|OPEN\s+\w+\s+FOR)\s+[^;]*\|\|\s*(?:p_|in_|v_)",
        "cwe_id": "CWE-20",
        "owasp": "A03:2021-Injection",
        "remediation": "Validate parameters using DBMS_ASSERT before using them in dynamic SQL. Use bind variables where possible.",
        "references": ["https://cwe.mitre.org/data/definitions/20.html"],
    },

    # ---- Excessive Privileges ----
    {
        "id": "PLSQL-PRIV-003",
        "category": "Excessive Privileges",
        "title": "DBA Role Grant",
        "description": "The DBA role grants unlimited privileges on the database. This should be restricted to a minimal set of administrators.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"(?i)GRANT\s+DBA\s+TO\s+",
        "cwe_id": "CWE-250",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Grant only the specific privileges needed. Create custom roles with minimal permissions.",
        "references": ["https://cwe.mitre.org/data/definitions/250.html"],
    },
    {
        "id": "PLSQL-PRIV-004",
        "category": "Excessive Privileges",
        "title": "ANY Privilege Grant",
        "description": "Granting ANY privileges (SELECT ANY TABLE, EXECUTE ANY PROCEDURE, etc.) provides excessive access across all schemas.",
        "severity": "High",
        "confidence": "High",
        "pattern": r"(?i)GRANT\s+\w+\s+ANY\s+\w+\s+TO\s+",
        "cwe_id": "CWE-250",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Grant privileges on specific objects rather than using ANY. Use schema-level grants.",
        "references": ["https://cwe.mitre.org/data/definitions/250.html"],
    },
    {
        "id": "PLSQL-PRIV-005",
        "category": "Excessive Privileges",
        "title": "PUBLIC Grant on Sensitive Package",
        "description": "A sensitive database package is granted to PUBLIC, making it accessible to all database users.",
        "severity": "High",
        "confidence": "High",
        "pattern": r"(?i)GRANT\s+EXECUTE\s+ON\s+(?:UTL_FILE|UTL_HTTP|UTL_TCP|UTL_SMTP|DBMS_SQL|DBMS_SCHEDULER|DBMS_CRYPTO|DBMS_SYS_SQL|DBMS_JAVA)\s+TO\s+PUBLIC",
        "cwe_id": "CWE-250",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Revoke PUBLIC grants on sensitive packages. Grant EXECUTE only to specific roles that require it.",
        "references": ["https://cwe.mitre.org/data/definitions/250.html"],
    },

    # ---- Network Access (SSRF) ----
    {
        "id": "PLSQL-SSRF-001",
        "category": "Server-Side Request Forgery",
        "title": "UTL_HTTP Request without URL Validation",
        "description": "UTL_HTTP.REQUEST or UTL_HTTP.BEGIN_REQUEST is used without apparent URL validation, potentially allowing SSRF attacks.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"(?i)UTL_HTTP\s*\.\s*(REQUEST|BEGIN_REQUEST)\s*\(",
        "cwe_id": "CWE-918",
        "owasp": "A10:2021-Server-Side Request Forgery",
        "remediation": "Validate and whitelist URLs before making HTTP requests. Use Access Control Lists (ACLs) to restrict outbound connections.",
        "references": ["https://cwe.mitre.org/data/definitions/918.html"],
    },
    {
        "id": "PLSQL-SSRF-002",
        "category": "Server-Side Request Forgery",
        "title": "UTL_TCP Connection without Validation",
        "description": "UTL_TCP.OPEN_CONNECTION is used, allowing outbound TCP connections from the database server.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"(?i)UTL_TCP\s*\.\s*OPEN_CONNECTION\s*\(",
        "cwe_id": "CWE-918",
        "owasp": "A10:2021-Server-Side Request Forgery",
        "remediation": "Validate target hosts against a whitelist. Use Oracle Network ACLs to restrict outbound connections.",
        "references": ["https://cwe.mitre.org/data/definitions/918.html"],
    },
    {
        "id": "PLSQL-SSRF-003",
        "category": "Server-Side Request Forgery",
        "title": "UTL_SMTP Email without Validation",
        "description": "UTL_SMTP is used for sending emails. Ensure recipient addresses and content are validated.",
        "severity": "Medium",
        "confidence": "Medium",
        "pattern": r"(?i)UTL_SMTP\s*\.\s*(OPEN_CONNECTION|MAIL|RCPT|DATA)\s*\(",
        "cwe_id": "CWE-918",
        "owasp": "A10:2021-Server-Side Request Forgery",
        "remediation": "Validate email addresses and content. Use Network ACLs to restrict SMTP connections to authorized mail servers.",
        "references": ["https://cwe.mitre.org/data/definitions/918.html"],
    },

    # ---- Unprotected Procedures ----
    {
        "id": "PLSQL-AUTH-001",
        "category": "Unprotected Procedure",
        "title": "Missing ACCESSIBLE BY Clause",
        "description": "A procedure or function does not use ACCESSIBLE BY to restrict which program units can invoke it.",
        "severity": "Medium",
        "confidence": "Low",
        "pattern": r"(?i)CREATE\s+(?:OR\s+REPLACE\s+)?(?:PROCEDURE|FUNCTION)\s+\w+(?!\s*ACCESSIBLE\s+BY)",
        "cwe_id": "CWE-284",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Add ACCESSIBLE BY clause to restrict which program units can invoke this procedure/function.",
        "references": ["https://cwe.mitre.org/data/definitions/284.html"],
    },

    # ---- Cursor Injection ----
    {
        "id": "PLSQL-CINJ-003",
        "category": "Cursor Injection",
        "title": "REF CURSOR with Dynamic SQL",
        "description": "A REF CURSOR is opened with dynamically constructed SQL, which may be vulnerable to cursor injection.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"(?i)(?:SYS_REFCURSOR|REF\s+CURSOR)[\s\S]{0,300}OPEN\s+\w+\s+FOR\s+\w+",
        "cwe_id": "CWE-89",
        "owasp": "A03:2021-Injection",
        "remediation": "Use bind variables with the USING clause when opening REF CURSORs. Validate all input with DBMS_ASSERT.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },

    # ---- XML Injection ----
    {
        "id": "PLSQL-XML-001",
        "category": "XML Injection",
        "title": "XMLTYPE with User Input",
        "description": "XMLTYPE constructor uses concatenated or user-supplied input, potentially allowing XML injection or XXE attacks.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"(?i)XMLTYPE\s*\(\s*[^')][^)]*\|\|",
        "cwe_id": "CWE-91",
        "owasp": "A03:2021-Injection",
        "remediation": "Validate and sanitize XML input. Disable external entity processing. Use parameterized XML construction.",
        "references": ["https://cwe.mitre.org/data/definitions/91.html"],
    },
    {
        "id": "PLSQL-XML-002",
        "category": "XML Injection",
        "title": "XMLTYPE from User-Provided String",
        "description": "XMLTYPE is constructed from a variable that may contain user input, risking XML injection.",
        "severity": "Medium",
        "confidence": "Low",
        "pattern": r"(?i)XMLTYPE\s*\(\s*(?:p_|v_|l_)\w+\s*\)",
        "cwe_id": "CWE-91",
        "owasp": "A03:2021-Injection",
        "remediation": "Validate XML structure and content before creating XMLTYPE objects. Sanitize user input.",
        "references": ["https://cwe.mitre.org/data/definitions/91.html"],
    },

    # ---- Data Exposure ----
    {
        "id": "PLSQL-DATA-001",
        "category": "Data Exposure",
        "title": "SELECT * without Column Restriction",
        "description": "SELECT * retrieves all columns, which may include sensitive data not needed by the query consumer.",
        "severity": "Low",
        "confidence": "Medium",
        "pattern": r"(?i)SELECT\s+\*\s+FROM\s+",
        "cwe_id": "CWE-200",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Explicitly list only the required columns in SELECT statements to minimize data exposure.",
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
    },

    # ---- Missing Audit ----
    {
        "id": "PLSQL-AUDIT-001",
        "category": "Missing Audit",
        "title": "Sensitive Operation without Audit Trail",
        "description": "A DML operation on a sensitive table (users, accounts, credentials, payments) lacks audit logging.",
        "severity": "Medium",
        "confidence": "Low",
        "pattern": r"(?i)(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+(?:users|accounts|credentials|payments|orders|customers|employees|salaries|audit_log)\b",
        "cwe_id": "CWE-778",
        "owasp": "A09:2021-Security Logging and Monitoring Failures",
        "remediation": "Implement audit triggers on sensitive tables. Use Oracle Unified Auditing for comprehensive tracking.",
        "references": ["https://cwe.mitre.org/data/definitions/778.html"],
    },

    # ---- Autonomous Transaction ----
    {
        "id": "PLSQL-AUTO-001",
        "category": "Autonomous Transaction Abuse",
        "title": "PRAGMA AUTONOMOUS_TRANSACTION in Trigger",
        "description": "AUTONOMOUS_TRANSACTION in a trigger can bypass transaction isolation, potentially causing data inconsistency or security issues.",
        "severity": "Medium",
        "confidence": "High",
        "pattern": r"(?i)CREATE\s+(?:OR\s+REPLACE\s+)?TRIGGER[\s\S]{0,300}PRAGMA\s+AUTONOMOUS_TRANSACTION",
        "cwe_id": "CWE-362",
        "owasp": "A04:2021-Insecure Design",
        "remediation": "Avoid AUTONOMOUS_TRANSACTION in triggers unless for audit logging. Ensure it does not bypass security checks.",
        "references": ["https://cwe.mitre.org/data/definitions/362.html"],
    },
    {
        "id": "PLSQL-AUTO-002",
        "category": "Autonomous Transaction Abuse",
        "title": "PRAGMA AUTONOMOUS_TRANSACTION Used",
        "description": "AUTONOMOUS_TRANSACTION commits independently of the main transaction. If misused, it can lead to data inconsistency.",
        "severity": "Low",
        "confidence": "Low",
        "pattern": r"(?i)PRAGMA\s+AUTONOMOUS_TRANSACTION",
        "cwe_id": "CWE-362",
        "owasp": "A04:2021-Insecure Design",
        "remediation": "Use AUTONOMOUS_TRANSACTION only for logging/auditing. Ensure it does not modify business data independently.",
        "references": ["https://cwe.mitre.org/data/definitions/362.html"],
    },

    # ---- PRAGMA RESTRICT_REFERENCES ----
    {
        "id": "PLSQL-PRAGMA-001",
        "category": "Missing PRAGMA RESTRICT_REFERENCES",
        "title": "Package Function without RESTRICT_REFERENCES",
        "description": "A package function lacks PRAGMA RESTRICT_REFERENCES, allowing unintended side effects (writes to DB, package state).",
        "severity": "Low",
        "confidence": "Low",
        "pattern": r"(?i)(?:CREATE\s+(?:OR\s+REPLACE\s+)?PACKAGE\s+)[\s\S]*?FUNCTION\s+\w+(?![\s\S]*PRAGMA\s+RESTRICT_REFERENCES)",
        "cwe_id": "CWE-710",
        "owasp": "A04:2021-Insecure Design",
        "remediation": "Add PRAGMA RESTRICT_REFERENCES (WNDS, WNPS, RNDS, RNPS) where appropriate to declare function purity.",
        "references": ["https://cwe.mitre.org/data/definitions/710.html"],
    },

    # ---- TNS Poisoning ----
    {
        "id": "PLSQL-TNS-001",
        "category": "TNS Poisoning",
        "title": "Listener Configuration in Source Code",
        "description": "TNS listener configuration (tnsnames, listener.ora) details found in source code, which could facilitate TNS poisoning attacks.",
        "severity": "Medium",
        "confidence": "Medium",
        "pattern": r"(?i)(?:DESCRIPTION\s*=\s*\(\s*ADDRESS\s*=|SERVICE_NAME\s*=|SID\s*=|HOST\s*=)",
        "cwe_id": "CWE-319",
        "owasp": "A02:2021-Cryptographic Failures",
        "remediation": "Externalize TNS configuration. Enable listener password protection. Use encryption for database connections.",
        "references": ["https://cwe.mitre.org/data/definitions/319.html"],
    },

    # ---- Tablespace Issues ----
    {
        "id": "PLSQL-TBS-001",
        "category": "Default Tablespace Issue",
        "title": "Objects Created in SYSTEM/SYSAUX Tablespace",
        "description": "Database objects are being created in SYSTEM or SYSAUX tablespace, which is a security and performance risk.",
        "severity": "Medium",
        "confidence": "Medium",
        "pattern": r"(?i)TABLESPACE\s+(?:SYSTEM|SYSAUX)",
        "cwe_id": "CWE-276",
        "owasp": "A05:2021-Security Misconfiguration",
        "remediation": "Create dedicated tablespaces for application data. Never use SYSTEM or SYSAUX for user objects.",
        "references": ["https://cwe.mitre.org/data/definitions/276.html"],
    },

    # ---- Exception Handling ----
    {
        "id": "PLSQL-EXCP-001",
        "category": "Insecure Exception Handling",
        "title": "WHEN OTHERS without Re-raise",
        "description": "A WHEN OTHERS exception handler catches all exceptions without re-raising, which can hide security-relevant errors.",
        "severity": "Medium",
        "confidence": "Medium",
        "pattern": r"(?i)WHEN\s+OTHERS\s+THEN\s+(?:NULL|DBMS_OUTPUT)",
        "cwe_id": "CWE-390",
        "owasp": "A09:2021-Security Logging and Monitoring Failures",
        "remediation": "Always log exceptions in WHEN OTHERS handlers and re-raise using RAISE or RAISE_APPLICATION_ERROR.",
        "references": ["https://cwe.mitre.org/data/definitions/390.html"],
    },

    # ---- Additional patterns ----
    {
        "id": "PLSQL-CRED-004",
        "category": "Hardcoded Credentials",
        "title": "Hardcoded Encryption Key",
        "description": "An encryption key appears to be hardcoded in the source code.",
        "severity": "Critical",
        "confidence": "Medium",
        "pattern": r"(?i)(?:encryption_key|encrypt_key|aes_key|des_key|key_string)\s*(?::=|=>|=)\s*'[^']{3,}'",
        "cwe_id": "CWE-321",
        "owasp": "A02:2021-Cryptographic Failures",
        "remediation": "Store encryption keys in Oracle Wallet or a Hardware Security Module (HSM). Never hardcode keys.",
        "references": ["https://cwe.mitre.org/data/definitions/321.html"],
    },
    {
        "id": "PLSQL-SQLI-005",
        "category": "SQL Injection",
        "title": "Dynamic Table Name Concatenation",
        "description": "A table name is dynamically constructed using concatenation, which could allow SQL injection if the table name comes from user input.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"(?i)(?:FROM|INTO|UPDATE|JOIN)\s+['\"]?\s*\|\|\s*\w+\s*\|\|",
        "cwe_id": "CWE-89",
        "owasp": "A03:2021-Injection",
        "remediation": "Use DBMS_ASSERT.SIMPLE_SQL_NAME to validate dynamic table names. Use a whitelist of allowed table names.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },
]


# ---------------------------------------------------------------------------
# Semantic Analyzers (beyond regex)
# ---------------------------------------------------------------------------

class PLSQLSemanticAnalyzer:
    """Performs deeper semantic analysis on PL/SQL code using tokenized input."""

    def analyze(self, source: str, filepath: str, tokens: List[Token]) -> List[Finding]:
        findings: List[Finding] = []
        lines = source.split('\n')

        self._check_execute_immediate_patterns(source, lines, filepath, findings)
        self._check_grant_patterns(source, lines, filepath, findings)
        self._check_missing_exception_handling(source, lines, filepath, findings)
        self._check_commit_in_loop(source, lines, filepath, findings)
        self._check_no_encryption_for_sensitive_columns(source, lines, filepath, findings)

        return findings

    def _check_execute_immediate_patterns(self, source: str, lines: List[str],
                                           filepath: str, findings: List[Finding]):
        """Check for EXECUTE IMMEDIATE that builds SQL from parameters without USING."""
        pattern = re.compile(
            r"(?i)EXECUTE\s+IMMEDIATE\s+(\w+)\s*;",
        )
        for i, line in enumerate(lines, 1):
            m = pattern.search(line)
            if m:
                var_name = m.group(1)
                # Look backwards for the variable assignment with concatenation
                start_search = max(0, i - 20)
                context = '\n'.join(lines[start_search:i])
                concat_pattern = re.compile(
                    rf"(?i){re.escape(var_name)}\s*:=\s*[^;]*\|\|",
                )
                if concat_pattern.search(context):
                    # Check if USING is present
                    using_pattern = re.compile(
                        r"(?i)EXECUTE\s+IMMEDIATE\s+\w+\s+USING\b",
                    )
                    if not using_pattern.search(line):
                        snippet = line.strip()
                        findings.append(Finding(
                            rule_id="PLSQL-SQLI-006",
                            category="SQL Injection",
                            title="Variable-Based Dynamic SQL without Bind Variables",
                            description=f"Variable '{var_name}' is built with concatenation and executed without USING clause for bind variables.",
                            severity="Critical",
                            confidence="High",
                            file_path=filepath,
                            line_number=i,
                            code_snippet=snippet,
                            remediation="Use bind variables with the USING clause: EXECUTE IMMEDIATE v_sql USING p_value;",
                            cwe_id="CWE-89",
                            owasp="A03:2021-Injection",
                        ))

    def _check_grant_patterns(self, source: str, lines: List[str],
                               filepath: str, findings: List[Finding]):
        """Check for overly permissive GRANT statements."""
        pattern = re.compile(r"(?i)GRANT\s+(ALL\s+PRIVILEGES?)\s+", re.IGNORECASE)
        for i, line in enumerate(lines, 1):
            m = pattern.search(line)
            if m:
                findings.append(Finding(
                    rule_id="PLSQL-PRIV-006",
                    category="Excessive Privileges",
                    title="GRANT ALL PRIVILEGES",
                    description="GRANT ALL PRIVILEGES provides complete access and violates the principle of least privilege.",
                    severity="Critical",
                    confidence="High",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip(),
                    remediation="Grant only the specific privileges needed for the use case.",
                    cwe_id="CWE-250",
                    owasp="A01:2021-Broken Access Control",
                ))

    def _check_missing_exception_handling(self, source: str, lines: List[str],
                                            filepath: str, findings: List[Finding]):
        """Detect procedures/functions without exception handlers."""
        proc_pattern = re.compile(
            r"(?i)(?:CREATE\s+(?:OR\s+REPLACE\s+)?)?(?:PROCEDURE|FUNCTION)\s+(\w+)",
        )
        begin_count = 0
        exception_found = False
        current_proc = None
        proc_line = 0

        for i, line in enumerate(lines, 1):
            m = proc_pattern.search(line)
            if m:
                if current_proc and begin_count > 0 and not exception_found:
                    findings.append(Finding(
                        rule_id="PLSQL-EXCP-002",
                        category="Missing Exception Handling",
                        title=f"No Exception Handler in {current_proc}",
                        description=f"Procedure/function '{current_proc}' has no EXCEPTION block, which may cause unhandled errors to propagate sensitive information.",
                        severity="Low",
                        confidence="Low",
                        file_path=filepath,
                        line_number=proc_line,
                        code_snippet=lines[proc_line-1].strip() if proc_line <= len(lines) else "",
                        remediation="Add an EXCEPTION block with appropriate handlers (WHEN NO_DATA_FOUND, WHEN OTHERS, etc.).",
                        cwe_id="CWE-754",
                        owasp="A04:2021-Insecure Design",
                    ))
                current_proc = m.group(1)
                proc_line = i
                begin_count = 0
                exception_found = False

            upper_line = line.strip().upper()
            if re.match(r'\bBEGIN\b', upper_line):
                begin_count += 1
            if re.match(r'\bEXCEPTION\b', upper_line):
                exception_found = True
            if re.match(r'\bEND\b', upper_line):
                begin_count -= 1

    def _check_commit_in_loop(self, source: str, lines: List[str],
                                filepath: str, findings: List[Finding]):
        """Detect COMMIT inside a loop, which can cause partial commits on failure."""
        in_loop = False
        loop_start = 0
        for i, line in enumerate(lines, 1):
            upper = line.strip().upper()
            if re.search(r'\bLOOP\b', upper) and not re.search(r'\bEND\s+LOOP\b', upper):
                in_loop = True
                loop_start = i
            if re.search(r'\bEND\s+LOOP\b', upper):
                in_loop = False
            if in_loop and re.search(r'\bCOMMIT\b', upper):
                findings.append(Finding(
                    rule_id="PLSQL-TXN-001",
                    category="Transaction Safety",
                    title="COMMIT Inside Loop",
                    description="COMMIT inside a loop can cause partial data commits on failure, leading to data inconsistency.",
                    severity="Medium",
                    confidence="Medium",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip(),
                    remediation="Move COMMIT outside the loop or use SAVEPOINT for partial rollback capability.",
                    cwe_id="CWE-362",
                    owasp="A04:2021-Insecure Design",
                ))

    def _check_no_encryption_for_sensitive_columns(self, source: str, lines: List[str],
                                                      filepath: str, findings: List[Finding]):
        """Detect sensitive column creation without encryption."""
        create_table_pattern = re.compile(
            r"(?i)CREATE\s+TABLE\s+\w+\s*\(([^;]+)\)",
            re.DOTALL,
        )
        sensitive_cols = re.compile(
            r"(?i)\b(password|credit_card|card_number|ssn|social_security|secret|api_key|token)\b\s+(?:VARCHAR2?|CHAR|CLOB|RAW|BLOB)",
        )
        for m in create_table_pattern.finditer(source):
            table_def = m.group(1)
            for col_match in sensitive_cols.finditer(table_def):
                # Find line number
                pos = m.start() + table_def.find(col_match.group(0))
                line_num = source[:pos].count('\n') + 1
                findings.append(Finding(
                    rule_id="PLSQL-CRYP-004",
                    category="Missing Encryption",
                    title=f"Sensitive Column '{col_match.group(1)}' Not Encrypted",
                    description=f"Column '{col_match.group(1)}' stores sensitive data but is not encrypted at the column level.",
                    severity="High",
                    confidence="Medium",
                    file_path=filepath,
                    line_number=line_num,
                    code_snippet=col_match.group(0).strip(),
                    remediation="Use Transparent Data Encryption (TDE) or DBMS_CRYPTO to encrypt sensitive columns.",
                    cwe_id="CWE-311",
                    owasp="A02:2021-Cryptographic Failures",
                ))


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------
def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Remove duplicate findings based on file, line, category, and rule_id."""
    seen: Set[str] = set()
    unique: List[Finding] = []
    for f in findings:
        key = f"{f.file_path}:{f.line_number}:{f.rule_id}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ---------------------------------------------------------------------------
# Main Scanner
# ---------------------------------------------------------------------------
class PLSQLScanner:
    """Orchestrates token-based + regex scanning for PL/SQL files."""

    PLSQL_EXTENSIONS = {
        ".sql", ".pls", ".plb", ".pks", ".pkb", ".pck", ".fnc", ".prc",
        ".trg", ".typ", ".tyb", ".spc", ".bdy", ".plsql", ".ora",
    }

    def __init__(self):
        self.semantic_analyzer = PLSQLSemanticAnalyzer()
        log.info("PL/SQL Scanner initialized")

    def _get_snippet(self, lines: List[str], line_num: int, context: int = 2) -> str:
        """Get code snippet around the given line."""
        start = max(0, line_num - 1 - context)
        end = min(len(lines), line_num + context)
        snippet_lines = []
        for i in range(start, end):
            marker = ">>>" if i == line_num - 1 else "   "
            snippet_lines.append(f"{marker} {i+1:4d} | {lines[i]}")
        return '\n'.join(snippet_lines)

    def _apply_regex_rules(self, content: str, filepath: str) -> List[Finding]:
        """Apply all regex-based vulnerability rules."""
        findings: List[Finding] = []
        lines = content.split('\n')

        for rule in PLSQL_RULES:
            pattern = re.compile(rule["pattern"], re.MULTILINE | re.DOTALL)
            for m in pattern.finditer(content):
                line_num = content[:m.start()].count('\n') + 1
                snippet = self._get_snippet(lines, line_num)

                findings.append(Finding(
                    rule_id=rule["id"],
                    category=rule["category"],
                    title=rule["title"],
                    description=rule["description"],
                    severity=rule["severity"],
                    confidence=rule["confidence"],
                    file_path=filepath,
                    line_number=line_num,
                    code_snippet=snippet,
                    remediation=rule["remediation"],
                    cwe_id=rule["cwe_id"],
                    owasp=rule["owasp"],
                    references=rule.get("references", []),
                ))

        return findings

    def scan(self, files: Dict[str, str], scan_id: str) -> ScanResponse:
        """Scan all provided files and return findings."""
        all_findings: List[Finding] = []
        scanned = 0

        for path, content in files.items():
            ext = os.path.splitext(path)[1].lower()
            if ext not in self.PLSQL_EXTENSIONS:
                continue

            scanned += 1

            # Phase 1: Regex-based rules
            regex_findings = self._apply_regex_rules(content, path)
            all_findings.extend(regex_findings)

            # Phase 2: Tokenize for semantic analysis
            try:
                tokens = tokenize_plsql(content)
                semantic_findings = self.semantic_analyzer.analyze(content, path, tokens)
                all_findings.extend(semantic_findings)
            except Exception as e:
                log.warning(f"Semantic analysis failed for {path}: {e}")

        # Deduplicate
        all_findings = deduplicate_findings(all_findings)

        # Sort by severity then file/line
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        all_findings.sort(key=lambda f: (severity_order.get(f.severity, 5), f.file_path, f.line_number))

        # Build summary
        summary: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in all_findings:
            summary[f.severity] = summary.get(f.severity, 0) + 1

        return ScanResponse(
            scanId=scan_id or str(uuid.uuid4()),
            totalFiles=scanned,
            totalFindings=len(all_findings),
            findings=[asdict(f) for f in all_findings],
            summary=summary,
        )


# ---------------------------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Offensive360 PL/SQL SAST Scanner",
    description="Comprehensive static analysis for PL/SQL and Oracle SQL source code",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner = PLSQLScanner()


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "scanner": "PL/SQL SAST Scanner",
        "version": "1.0.0",
        "engine": "token-based parser + regex pattern matching",
        "vulnerability_categories": 20,
        "total_rules": len(PLSQL_RULES) + 6,  # regex + semantic rules
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
    port = int(os.environ.get("SCANNER_PORT", "9018"))
    log.info(f"Starting PL/SQL SAST Scanner on port {port}")
    log.info(f"Rules: {len(PLSQL_RULES)} regex + 6 semantic = {len(PLSQL_RULES) + 6} total")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
