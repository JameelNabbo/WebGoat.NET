#!/usr/bin/env python3
"""
Offensive360 Oracle Forms SAST Scanner
Comprehensive static analysis for Oracle Forms files (.fmb XML exports, .fmx, .pll, .xml).
Detects security issues in form triggers, PL/SQL blocks, and form properties.
FastAPI server on port 9020.
"""

import os
import re
import uuid
import logging
import xml.etree.ElementTree as ET
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
log = logging.getLogger("oracle-forms-scanner")

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
# Oracle Forms Trigger Names (security-relevant)
# ---------------------------------------------------------------------------
SECURITY_TRIGGERS = {
    'POST-QUERY', 'PRE-QUERY', 'WHEN-BUTTON-PRESSED', 'WHEN-LIST-CHANGED',
    'WHEN-NEW-FORM-INSTANCE', 'WHEN-NEW-BLOCK-INSTANCE', 'WHEN-NEW-RECORD-INSTANCE',
    'WHEN-NEW-ITEM-INSTANCE', 'WHEN-VALIDATE-ITEM', 'WHEN-VALIDATE-RECORD',
    'PRE-INSERT', 'PRE-UPDATE', 'PRE-DELETE', 'POST-INSERT', 'POST-UPDATE',
    'POST-DELETE', 'ON-ERROR', 'ON-MESSAGE', 'POST-FORM', 'PRE-FORM',
    'ON-LOGON', 'ON-LOGOUT', 'POST-LOGON', 'PRE-LOGON',
    'WHEN-MOUSE-CLICK', 'WHEN-MOUSE-DOUBLECLICK', 'KEY-COMMIT',
    'KEY-EXECUTE-QUERY', 'KEY-EXIT', 'KEY-OTHERS',
}


# ---------------------------------------------------------------------------
# PL/SQL-in-Forms Regex Rules
# ---------------------------------------------------------------------------
PLSQL_IN_FORMS_RULES = [
    # ---- SQL Injection in Triggers ----
    {
        "id": "OFRM-SQLI-001",
        "category": "SQL Injection",
        "title": "Dynamic SQL in Form Trigger",
        "description": "EXECUTE IMMEDIATE with concatenation found in a form trigger. User input from form items may be injected into SQL.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"(?i)EXECUTE\s+IMMEDIATE\s+[^;]*\|\|",
        "cwe_id": "CWE-89",
        "owasp": "A03:2021-Injection",
        "remediation": "Use bind variables with USING clause. Never concatenate :BLOCK.ITEM values into dynamic SQL.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },
    {
        "id": "OFRM-SQLI-002",
        "category": "SQL Injection",
        "title": "Form Item Value in Dynamic SQL",
        "description": "A form item reference (:BLOCK.ITEM) is concatenated into a dynamic SQL string, creating a SQL injection vulnerability.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"(?i)(?:EXECUTE\s+IMMEDIATE|OPEN\s+\w+\s+FOR)\s+[^;]*\|\|\s*:[A-Za-z_]+\.[A-Za-z_]+",
        "cwe_id": "CWE-89",
        "owasp": "A03:2021-Injection",
        "remediation": "Use bind variables: EXECUTE IMMEDIATE v_sql USING :BLOCK.ITEM;",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },
    {
        "id": "OFRM-SQLI-003",
        "category": "SQL Injection",
        "title": "SET_BLOCK_PROPERTY DEFAULT_WHERE with Concatenation",
        "description": "SET_BLOCK_PROPERTY with DEFAULT_WHERE uses concatenation, allowing SQL injection through form item values.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"(?i)SET_BLOCK_PROPERTY\s*\([^)]*DEFAULT_WHERE[^)]*\|\|",
        "cwe_id": "CWE-89",
        "owasp": "A03:2021-Injection",
        "remediation": "Use bind variables or parameterized queries instead of concatenating form values into WHERE clauses.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },
    {
        "id": "OFRM-SQLI-004",
        "category": "SQL Injection",
        "title": "DBMS_SQL in Form PL/SQL Block",
        "description": "DBMS_SQL.PARSE is used within a form's PL/SQL block. Dynamic SQL in forms is particularly risky.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"(?i)DBMS_SQL\s*\.\s*PARSE\s*\(",
        "cwe_id": "CWE-89",
        "owasp": "A03:2021-Injection",
        "remediation": "Use bind variables via DBMS_SQL.BIND_VARIABLE. Validate all form inputs before SQL execution.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },

    # ---- Hardcoded Credentials ----
    {
        "id": "OFRM-CRED-001",
        "category": "Hardcoded Credentials",
        "title": "Database Connection String in Form",
        "description": "A database connection string with credentials is hardcoded in the form PL/SQL code.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"(?i)(?:password|passwd|pwd)\s*(?::=|=>|=)\s*'[^']{3,}'",
        "cwe_id": "CWE-798",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Use Oracle Wallet or externalized configuration for database credentials. Never hardcode in form code.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },
    {
        "id": "OFRM-CRED-002",
        "category": "Hardcoded Credentials",
        "title": "LOGON_SCREEN with Hardcoded Credentials",
        "description": "Form uses LOGON with hardcoded username/password instead of the standard Oracle Forms logon dialog.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"(?i)(?:LOGON|SET_APPLICATION_PROPERTY\s*\(\s*(?:USERNAME|PASSWORD))\s*[,)]\s*'[^']+'",
        "cwe_id": "CWE-798",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Use the standard Oracle Forms logon dialog or SSO. Never hardcode credentials in form code.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },
    {
        "id": "OFRM-CRED-003",
        "category": "Hardcoded Credentials",
        "title": "Connection String Pattern in Form",
        "description": "A connection string pattern (user/password@database) is found in the form code.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"(?i)\w+/\w+@\w+",
        "cwe_id": "CWE-798",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Externalize database connection configuration. Use Oracle Wallet for authentication.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },

    # ---- Client-Side Validation Only ----
    {
        "id": "OFRM-CLNT-001",
        "category": "Client-Side Validation Only",
        "title": "Validation Only in WHEN-VALIDATE-ITEM",
        "description": "Input validation is performed only in the client-side WHEN-VALIDATE-ITEM trigger without corresponding server-side checks.",
        "severity": "Medium",
        "confidence": "Medium",
        "pattern": r"(?i)WHEN-VALIDATE-ITEM[\s\S]{0,50}(?:IF|CASE)\s+:[\w.]+\s*(?:IS\s+NULL|=|<|>|!=|NOT\s+BETWEEN)",
        "cwe_id": "CWE-602",
        "owasp": "A04:2021-Insecure Design",
        "remediation": "Implement server-side validation using database constraints, triggers, or stored procedures in addition to form-level validation.",
        "references": ["https://cwe.mitre.org/data/definitions/602.html"],
    },

    # ---- Information Disclosure ----
    {
        "id": "OFRM-INFO-001",
        "category": "Information Disclosure",
        "title": "Sensitive Data in Form Alert",
        "description": "A form ALERT or MESSAGE displays potentially sensitive information (error details, SQL, passwords).",
        "severity": "Medium",
        "confidence": "Medium",
        "pattern": r"(?i)(?:SET_ALERT_PROPERTY|MESSAGE)\s*\([^)]*(?:SQLERRM|SQLCODE|password|error|exception|debug)",
        "cwe_id": "CWE-209",
        "owasp": "A04:2021-Insecure Design",
        "remediation": "Display generic error messages to users. Log detailed errors server-side.",
        "references": ["https://cwe.mitre.org/data/definitions/209.html"],
    },
    {
        "id": "OFRM-INFO-002",
        "category": "Information Disclosure",
        "title": "DBMS_OUTPUT in Form Code",
        "description": "DBMS_OUTPUT.PUT_LINE in form code may expose debug or sensitive information.",
        "severity": "Low",
        "confidence": "Low",
        "pattern": r"(?i)DBMS_OUTPUT\s*\.\s*PUT_LINE\s*\(",
        "cwe_id": "CWE-200",
        "owasp": "A04:2021-Insecure Design",
        "remediation": "Remove DBMS_OUTPUT calls from production form code.",
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
    },

    # ---- LOV Injection ----
    {
        "id": "OFRM-LOV-001",
        "category": "LOV Injection",
        "title": "Dynamic LOV Query with Concatenation",
        "description": "A List of Values (LOV) query is constructed dynamically using concatenation, allowing LOV injection.",
        "severity": "High",
        "confidence": "High",
        "pattern": r"(?i)SET_LOV_PROPERTY\s*\([^)]*(?:GROUP_NAME|QUERY_TEXT)[^)]*\|\|",
        "cwe_id": "CWE-89",
        "owasp": "A03:2021-Injection",
        "remediation": "Use parameterized LOV queries. Validate input before constructing LOV query text.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },
    {
        "id": "OFRM-LOV-002",
        "category": "LOV Injection",
        "title": "Record Group with Dynamic SQL",
        "description": "A record group query is set dynamically using SET_GROUP_SELECTION, potentially allowing injection.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"(?i)(?:SET_GROUP_SELECTION|POPULATE_GROUP_WITH_QUERY)\s*\([^)]*\|\|",
        "cwe_id": "CWE-89",
        "owasp": "A03:2021-Injection",
        "remediation": "Use static record group queries or validate all input used in dynamic queries.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },

    # ---- Excessive Database Privileges ----
    {
        "id": "OFRM-PRIV-001",
        "category": "Excessive Privileges",
        "title": "DML Operations without Role Check",
        "description": "INSERT/UPDATE/DELETE operations in form triggers without checking user roles or permissions.",
        "severity": "Medium",
        "confidence": "Low",
        "pattern": r"(?i)WHEN-BUTTON-PRESSED[\s\S]{0,200}(?:INSERT\s+INTO|UPDATE\s+|DELETE\s+FROM)",
        "cwe_id": "CWE-862",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Check user roles before executing DML operations. Use GET_APPLICATION_PROPERTY(USERNAME) for access control.",
        "references": ["https://cwe.mitre.org/data/definitions/862.html"],
    },

    # ---- Hidden Items with Sensitive Data ----
    {
        "id": "OFRM-HIDE-001",
        "category": "Hidden Item Exposure",
        "title": "Sensitive Data Assigned to Hidden Item",
        "description": "A hidden form item is assigned sensitive data. Hidden items are still accessible via the DOM in web forms.",
        "severity": "Medium",
        "confidence": "Medium",
        "pattern": r"(?i):[\w]+\.(?:password|secret|token|key|ssn|credit)\w*\s*:=",
        "cwe_id": "CWE-200",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Do not store sensitive data in form items (even hidden ones). Use server-side session variables instead.",
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
    },

    # ---- Unprotected Form Navigation ----
    {
        "id": "OFRM-NAV-001",
        "category": "Unprotected Navigation",
        "title": "CALL_FORM/OPEN_FORM without Authentication Check",
        "description": "Form navigation (CALL_FORM, OPEN_FORM, NEW_FORM) occurs without verifying user authentication or authorization.",
        "severity": "Medium",
        "confidence": "Low",
        "pattern": r"(?i)(?:CALL_FORM|OPEN_FORM|NEW_FORM)\s*\(\s*'[^']+'\s*(?:,|\))",
        "cwe_id": "CWE-862",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Verify user roles/permissions before navigating to other forms. Implement a centralized access control function.",
        "references": ["https://cwe.mitre.org/data/definitions/862.html"],
    },

    # ---- Missing WHEN-VALIDATE-ITEM ----
    {
        "id": "OFRM-VALID-001",
        "category": "Missing Input Validation",
        "title": "User Input Used without WHEN-VALIDATE-ITEM",
        "description": "Form item values are used in SQL or logic without a corresponding WHEN-VALIDATE-ITEM trigger for validation.",
        "severity": "Medium",
        "confidence": "Low",
        "pattern": r"(?i)(?:SELECT|INSERT|UPDATE|DELETE|EXECUTE\s+IMMEDIATE)\s+[^;]*:[\w]+\.\w+",
        "cwe_id": "CWE-20",
        "owasp": "A03:2021-Injection",
        "remediation": "Add WHEN-VALIDATE-ITEM triggers to validate all user inputs before they are used in SQL operations.",
        "references": ["https://cwe.mitre.org/data/definitions/20.html"],
    },

    # ---- Record Group Injection ----
    {
        "id": "OFRM-RG-001",
        "category": "Record Group Injection",
        "title": "Dynamic Record Group Query",
        "description": "A record group query is modified at runtime using form item values, potentially allowing injection.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"(?i)POPULATE_GROUP_WITH_QUERY\s*\(\s*\w+\s*,\s*[^)]*\|\|\s*:[A-Za-z_]+\.[A-Za-z_]+",
        "cwe_id": "CWE-89",
        "owasp": "A03:2021-Injection",
        "remediation": "Use parameterized record group queries. Validate all form inputs before using in queries.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },

    # ---- Missing Commit Handling ----
    {
        "id": "OFRM-CMT-001",
        "category": "Missing Commit Handling",
        "title": "DML without COMMIT_FORM or Exception Handler",
        "description": "DML operations in a form trigger without COMMIT_FORM and no error handling, risking data loss.",
        "severity": "Medium",
        "confidence": "Low",
        "pattern": r"(?i)(?:INSERT\s+INTO|UPDATE\s+|DELETE\s+FROM)\s+\w+[\s\S]{0,300}(?!COMMIT_FORM|EXCEPTION)(?:END\s*;)",
        "cwe_id": "CWE-755",
        "owasp": "A04:2021-Insecure Design",
        "remediation": "Always call COMMIT_FORM after DML operations and add proper exception handlers.",
        "references": ["https://cwe.mitre.org/data/definitions/755.html"],
    },

    # ---- File Upload ----
    {
        "id": "OFRM-FILE-001",
        "category": "File Upload Vulnerability",
        "title": "File Upload without Validation",
        "description": "Form uses READ_IMAGE_FILE, CLIENT_OLE2, or CLIENT_HOST for file operations without validating file type or content.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"(?i)(?:READ_IMAGE_FILE|WRITE_IMAGE_FILE|CLIENT_OLE2|CLIENT_HOST|HOST)\s*\(",
        "cwe_id": "CWE-434",
        "owasp": "A04:2021-Insecure Design",
        "remediation": "Validate file types, sizes, and content before processing. Implement server-side file validation.",
        "references": ["https://cwe.mitre.org/data/definitions/434.html"],
    },

    # ---- URL Parameter Handling ----
    {
        "id": "OFRM-URL-001",
        "category": "URL Parameter Injection",
        "title": "GET_PARAMETER or URL Value Used Unsafely",
        "description": "URL parameters from WEB.SHOW_DOCUMENT or GET_PARAMETER are used in SQL or logic without sanitization.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"(?i)(?:GET_PARAMETER|WEB\.SHOW_DOCUMENT)\s*\([^)]*\)",
        "cwe_id": "CWE-20",
        "owasp": "A03:2021-Injection",
        "remediation": "Validate and sanitize all URL parameters. Never use them directly in SQL or system commands.",
        "references": ["https://cwe.mitre.org/data/definitions/20.html"],
    },

    # ---- JavaScript Injection in Web Forms ----
    {
        "id": "OFRM-XSS-001",
        "category": "Cross-Site Scripting",
        "title": "JavaScript in Web.Show_Document",
        "description": "WEB.SHOW_DOCUMENT constructs URLs with user input, potentially allowing JavaScript injection.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"(?i)WEB\.SHOW_DOCUMENT\s*\(\s*[^)]*\|\|\s*:[A-Za-z_]+\.[A-Za-z_]+",
        "cwe_id": "CWE-79",
        "owasp": "A03:2021-Injection",
        "remediation": "Validate and encode all user input used in URLs. Use UTL_URL.ESCAPE for URL encoding.",
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
    },
    {
        "id": "OFRM-XSS-002",
        "category": "Cross-Site Scripting",
        "title": "HTML Content in Form Display",
        "description": "Form generates HTML content with user input that could be rendered in the browser.",
        "severity": "Medium",
        "confidence": "Low",
        "pattern": r"(?i)(?:<script|<iframe|javascript:)[^>]*:[A-Za-z_]+\.[A-Za-z_]+",
        "cwe_id": "CWE-79",
        "owasp": "A03:2021-Injection",
        "remediation": "Sanitize all user input before including in HTML. Use output encoding.",
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
    },

    # ---- Bean Area Security ----
    {
        "id": "OFRM-BEAN-001",
        "category": "Java Bean Security",
        "title": "Java Bean with Unrestricted Access",
        "description": "A Java bean is loaded in the form without access restrictions. Java beans can execute arbitrary code on the client.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"(?i)(?:FBEAN\.INVOKE|SET_CUSTOM_PROPERTY|IMPLEMENTATION_CLASS)\s*\(",
        "cwe_id": "CWE-94",
        "owasp": "A03:2021-Injection",
        "remediation": "Validate Java bean implementations. Use signed JARs. Restrict bean capabilities through security policies.",
        "references": ["https://cwe.mitre.org/data/definitions/94.html"],
    },

    # ---- Session Management ----
    {
        "id": "OFRM-SESS-001",
        "category": "Session Management",
        "title": "Missing Session Timeout Configuration",
        "description": "Form does not implement session timeout, allowing indefinite sessions.",
        "severity": "Medium",
        "confidence": "Low",
        "pattern": r"(?i)WHEN-NEW-FORM-INSTANCE(?![\s\S]*(?:SET_TIMER|CREATE_TIMER|SESSION_TIMEOUT))",
        "cwe_id": "CWE-613",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Implement session timeout using CREATE_TIMER and WHEN-TIMER-EXPIRED triggers.",
        "references": ["https://cwe.mitre.org/data/definitions/613.html"],
    },
    {
        "id": "OFRM-SESS-002",
        "category": "Session Management",
        "title": "Form Logon without Session Token Validation",
        "description": "ON-LOGON or WHEN-NEW-FORM-INSTANCE does not validate session tokens, risking session hijacking.",
        "severity": "Medium",
        "confidence": "Low",
        "pattern": r"(?i)(?:ON-LOGON|WHEN-NEW-FORM-INSTANCE)[\s\S]{0,300}(?:LOGON|SET_APPLICATION_PROPERTY)",
        "cwe_id": "CWE-384",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Implement session token validation on form initialization. Regenerate session IDs after authentication.",
        "references": ["https://cwe.mitre.org/data/definitions/384.html"],
    },

    # ---- Unencrypted Communication ----
    {
        "id": "OFRM-COMM-001",
        "category": "Unencrypted Communication",
        "title": "HTTP URL in Form (Not HTTPS)",
        "description": "Form uses HTTP URLs instead of HTTPS, transmitting data without encryption.",
        "severity": "Medium",
        "confidence": "High",
        "pattern": r"(?i)'http://[^']+'\s*(?:\)|,|;)",
        "cwe_id": "CWE-319",
        "owasp": "A02:2021-Cryptographic Failures",
        "remediation": "Use HTTPS for all URLs. Configure Oracle Forms to use SSL/TLS connections.",
        "references": ["https://cwe.mitre.org/data/definitions/319.html"],
    },

    # ---- Insecure Form Properties ----
    {
        "id": "OFRM-PROP-001",
        "category": "Insecure Form Properties",
        "title": "Form Access Control Not Set",
        "description": "Form does not implement role-based access control in WHEN-NEW-FORM-INSTANCE.",
        "severity": "Medium",
        "confidence": "Low",
        "pattern": r"(?i)WHEN-NEW-FORM-INSTANCE(?![\s\S]*(?:GET_APPLICATION_PROPERTY\s*\(\s*(?:USERNAME|USER)|FND_FUNCTION|CHECK_ROLE|IS_AUTHORIZED))",
        "cwe_id": "CWE-862",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Implement role-based access control in WHEN-NEW-FORM-INSTANCE. Check user roles before granting form access.",
        "references": ["https://cwe.mitre.org/data/definitions/862.html"],
    },

    # ---- HOST Command Injection ----
    {
        "id": "OFRM-CMD-001",
        "category": "Command Injection",
        "title": "HOST/CLIENT_HOST Command Execution",
        "description": "HOST or CLIENT_HOST is used to execute operating system commands from the form, potentially allowing command injection.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"(?i)(?:HOST|CLIENT_HOST)\s*\(\s*[^)]*\|\|",
        "cwe_id": "CWE-78",
        "owasp": "A03:2021-Injection",
        "remediation": "Avoid using HOST/CLIENT_HOST. If necessary, validate and whitelist all command parameters.",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    },
    {
        "id": "OFRM-CMD-002",
        "category": "Command Injection",
        "title": "HOST/CLIENT_HOST with User Input",
        "description": "HOST or CLIENT_HOST command includes form item values, allowing OS command injection.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"(?i)(?:HOST|CLIENT_HOST)\s*\(\s*[^)]*:[A-Za-z_]+\.[A-Za-z_]+",
        "cwe_id": "CWE-78",
        "owasp": "A03:2021-Injection",
        "remediation": "Never pass user input to HOST/CLIENT_HOST. Use stored procedures for server-side operations.",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    },
]


# ---------------------------------------------------------------------------
# XML-Specific Analyzers (for .fmb XML exports)
# ---------------------------------------------------------------------------
class FormsXMLAnalyzer:
    """Analyzes Oracle Forms XML exports for security issues."""

    def analyze_xml(self, content: str, filepath: str) -> List[Finding]:
        """Parse Oracle Forms XML and detect security issues."""
        findings: List[Finding] = []

        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            # Not valid XML, skip XML-specific analysis
            return findings

        # Check for trigger content
        self._check_triggers(root, filepath, findings)
        # Check for data block properties
        self._check_data_blocks(root, filepath, findings)
        # Check for item properties
        self._check_items(root, filepath, findings)
        # Check for module properties
        self._check_module_properties(root, filepath, findings)

        return findings

    def _check_triggers(self, root: ET.Element, filepath: str, findings: List[Finding]):
        """Check trigger PL/SQL code for vulnerabilities."""
        for trigger in root.iter():
            tag = trigger.tag.lower() if trigger.tag else ""
            if 'trigger' not in tag:
                continue

            trigger_name = trigger.get('Name', trigger.get('name', ''))
            trigger_text = trigger.get('TriggerText', '')
            if not trigger_text:
                # Check child elements
                for child in trigger:
                    if child.text:
                        trigger_text += child.text

            if not trigger_text:
                continue

            # Check for dynamic SQL in triggers
            if re.search(r"(?i)EXECUTE\s+IMMEDIATE\s+[^;]*\|\|", trigger_text):
                findings.append(Finding(
                    rule_id="OFRM-XML-SQLI-001",
                    category="SQL Injection",
                    title=f"Dynamic SQL in Trigger '{trigger_name}'",
                    description=f"Trigger '{trigger_name}' contains EXECUTE IMMEDIATE with concatenation.",
                    severity="Critical",
                    confidence="High",
                    file_path=filepath,
                    line_number=1,
                    code_snippet=trigger_text[:200],
                    remediation="Use bind variables in trigger code.",
                    cwe_id="CWE-89",
                    owasp="A03:2021-Injection",
                ))

            # Check for hardcoded passwords in trigger code
            if re.search(r"(?i)(?:password|passwd|pwd)\s*(?::=|=>|=)\s*'[^']{3,}'", trigger_text):
                findings.append(Finding(
                    rule_id="OFRM-XML-CRED-001",
                    category="Hardcoded Credentials",
                    title=f"Hardcoded Password in Trigger '{trigger_name}'",
                    description=f"Trigger '{trigger_name}' contains a hardcoded password.",
                    severity="Critical",
                    confidence="High",
                    file_path=filepath,
                    line_number=1,
                    code_snippet=trigger_text[:200],
                    remediation="Remove hardcoded credentials. Use Oracle Wallet or SSO.",
                    cwe_id="CWE-798",
                    owasp="A07:2021-Identification and Authentication Failures",
                ))

    def _check_data_blocks(self, root: ET.Element, filepath: str, findings: List[Finding]):
        """Check data block properties for security issues."""
        for block in root.iter():
            tag = block.tag.lower() if block.tag else ""
            if 'block' not in tag and 'datablock' not in tag:
                continue

            block_name = block.get('Name', block.get('name', ''))

            # Check for INSERT/UPDATE/DELETE allowed on blocks that should be read-only
            insert_allowed = block.get('InsertAllowed', block.get('insertAllowed', 'true'))
            update_allowed = block.get('UpdateAllowed', block.get('updateAllowed', 'true'))
            delete_allowed = block.get('DeleteAllowed', block.get('deleteAllowed', 'true'))

            # Check for overly permissive blocks
            query_source = block.get('QueryDataSourceName', block.get('queryDataSourceName', ''))
            if query_source and all(x.lower() == 'true' for x in [insert_allowed, update_allowed, delete_allowed]):
                findings.append(Finding(
                    rule_id="OFRM-XML-PERM-001",
                    category="Excessive Permissions",
                    title=f"All DML Allowed on Block '{block_name}'",
                    description=f"Block '{block_name}' allows INSERT, UPDATE, and DELETE. Review if all operations are needed.",
                    severity="Low",
                    confidence="Low",
                    file_path=filepath,
                    line_number=1,
                    code_snippet=f"Block: {block_name}, Source: {query_source}",
                    remediation="Restrict DML operations on blocks to only what is needed. Set InsertAllowed/UpdateAllowed/DeleteAllowed to FALSE where not required.",
                    cwe_id="CWE-276",
                    owasp="A01:2021-Broken Access Control",
                ))

    def _check_items(self, root: ET.Element, filepath: str, findings: List[Finding]):
        """Check item properties for security issues."""
        for item in root.iter():
            tag = item.tag.lower() if item.tag else ""
            if 'item' not in tag:
                continue

            item_name = item.get('Name', item.get('name', ''))
            item_type = item.get('ItemType', item.get('itemType', ''))
            visible = item.get('Visible', item.get('visible', 'true'))

            # Hidden items with sensitive names
            if visible.lower() == 'false':
                sensitive_names = ['password', 'secret', 'token', 'key', 'ssn', 'credit', 'card']
                for sens in sensitive_names:
                    if sens in item_name.lower():
                        findings.append(Finding(
                            rule_id="OFRM-XML-HIDE-001",
                            category="Hidden Item Exposure",
                            title=f"Hidden Item '{item_name}' Contains Sensitive Data",
                            description=f"Hidden item '{item_name}' may contain sensitive data. Hidden items are accessible via the DOM.",
                            severity="Medium",
                            confidence="Medium",
                            file_path=filepath,
                            line_number=1,
                            code_snippet=f"Item: {item_name}, Type: {item_type}, Visible: {visible}",
                            remediation="Do not store sensitive data in hidden form items. Use server-side session storage.",
                            cwe_id="CWE-200",
                            owasp="A01:2021-Broken Access Control",
                        ))
                        break

    def _check_module_properties(self, root: ET.Element, filepath: str, findings: List[Finding]):
        """Check module-level properties for security issues."""
        # Check root element for module properties
        module_name = root.get('Name', root.get('name', 'Unknown'))

        # Check for console window (debug) enabled
        console = root.get('ConsoleWindow', root.get('consoleWindow', ''))
        if console:
            findings.append(Finding(
                rule_id="OFRM-XML-DBG-001",
                category="Debug Configuration",
                title="Console Window Enabled in Form",
                description=f"Form '{module_name}' has ConsoleWindow set, which may expose debug output in production.",
                severity="Low",
                confidence="Medium",
                file_path=filepath,
                line_number=1,
                code_snippet=f"Module: {module_name}, ConsoleWindow: {console}",
                remediation="Disable ConsoleWindow in production forms.",
                cwe_id="CWE-489",
                owasp="A05:2021-Security Misconfiguration",
            ))


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------
def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Remove duplicate findings."""
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
class OracleFormsScanner:
    """Orchestrates scanning for Oracle Forms files."""

    FORMS_EXTENSIONS = {
        ".fmb", ".fmx", ".fmt", ".pll", ".pld", ".olb", ".mmb", ".mmx",
        ".rdf", ".xml", ".sql", ".pls", ".pkb", ".pks", ".plsql",
    }

    def __init__(self):
        self.xml_analyzer = FormsXMLAnalyzer()
        log.info("Oracle Forms Scanner initialized")

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

        for rule in PLSQL_IN_FORMS_RULES:
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

    def _is_xml_content(self, content: str) -> bool:
        """Check if the content is XML."""
        stripped = content.strip()
        return stripped.startswith('<?xml') or stripped.startswith('<Module') or stripped.startswith('<Form')

    def scan(self, files: Dict[str, str], scan_id: str) -> ScanResponse:
        """Scan all provided files and return findings."""
        all_findings: List[Finding] = []
        scanned = 0

        for path, content in files.items():
            ext = os.path.splitext(path)[1].lower()
            if ext not in self.FORMS_EXTENSIONS:
                continue

            scanned += 1

            # Phase 1: Regex-based PL/SQL analysis (works on both XML exports and raw PL/SQL)
            regex_findings = self._apply_regex_rules(content, path)
            all_findings.extend(regex_findings)

            # Phase 2: XML-specific analysis for .fmb XML exports
            if self._is_xml_content(content):
                try:
                    xml_findings = self.xml_analyzer.analyze_xml(content, path)
                    all_findings.extend(xml_findings)
                except Exception as e:
                    log.warning(f"XML analysis failed for {path}: {e}")

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
    title="Offensive360 Oracle Forms SAST Scanner",
    description="Comprehensive static analysis for Oracle Forms (.fmb XML exports, PL/SQL triggers, form properties)",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner = OracleFormsScanner()


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "scanner": "Oracle Forms SAST Scanner",
        "version": "1.0.0",
        "engine": "regex + XML parser",
        "vulnerability_categories": 20,
        "total_rules": len(PLSQL_IN_FORMS_RULES) + 5,  # regex + XML rules
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
    port = int(os.environ.get("SCANNER_PORT", "9020"))
    log.info(f"Starting Oracle Forms SAST Scanner on port {port}")
    log.info(f"Rules: {len(PLSQL_IN_FORMS_RULES)} regex + 5 XML = {len(PLSQL_IN_FORMS_RULES) + 5} total")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
