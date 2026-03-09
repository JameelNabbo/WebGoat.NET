#!/usr/bin/env python3
"""
Rust SAST Scanner - AST-based static analysis for Rust source code.
Uses tree-sitter-rust for parsing and pattern matching.
Runs as an HTTP server on port 9009 with POST /scan and GET /health endpoints.
"""

import json
import re
import sys
import time
import uuid
import logging
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict

from flask import Flask, request, jsonify
from tree_sitter import Language, Parser
import tree_sitter_rust as ts_rust

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("rust-sast")

# ---------------------------------------------------------------------------
# Tree-sitter setup
# ---------------------------------------------------------------------------
RUST_LANGUAGE = Language(ts_rust.language(), "rust")

def make_parser() -> Parser:
    p = Parser()
    p.set_language(RUST_LANGUAGE)
    return p

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
@dataclass
class Vulnerability:
    id: str
    title: str
    description: str
    severity: str          # Critical / High / Medium / Low / Info
    confidence: str        # High / Medium / Low
    category: str
    cwe: str
    filePath: str
    startLine: int
    endLine: int
    snippet: str
    remediation: str
    owasp: str = ""
    startColumn: int = 0
    endColumn: int = 0
    references: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def node_text(node, source_bytes: bytes) -> str:
    """Extract the text of a tree-sitter node."""
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

def get_line_snippet(source: str, line: int, context: int = 0) -> str:
    """Return line(s) of source around `line` (1-based)."""
    lines = source.split("\n")
    start = max(0, line - 1 - context)
    end = min(len(lines), line + context)
    return "\n".join(lines[start:end]).strip()

def walk(node):
    """Depth-first walk yielding every node."""
    yield node
    for child in node.children:
        yield from walk(child)

def find_nodes(root, node_type: str):
    """Find all nodes of a given type."""
    for n in walk(root):
        if n.type == node_type:
            yield n

def find_nodes_multi(root, node_types: set):
    """Find all nodes whose type is in the given set."""
    for n in walk(root):
        if n.type in node_types:
            yield n

def parent_chain(node):
    """Yield all ancestor nodes."""
    n = node.parent
    while n is not None:
        yield n
        n = n.parent

def is_inside(node, parent_type: str) -> bool:
    """Check if a node is inside a specific parent type."""
    for p in parent_chain(node):
        if p.type == parent_type:
            return True
    return False

def get_string_value(node, src: bytes) -> Optional[str]:
    """Extract string literal value (without quotes)."""
    text = node_text(node, src)
    if text.startswith('"') and text.endswith('"'):
        return text[1:-1]
    if text.startswith('r"') or text.startswith('r#"'):
        # Raw string
        idx = text.index('"')
        return text[idx+1:-1-text.count('#', 0, idx)]
    return None


# ---------------------------------------------------------------------------
# Vulnerability rule definitions
# ---------------------------------------------------------------------------

class RustAnalyzer:
    """Comprehensive Rust vulnerability analyzer using tree-sitter AST."""

    def __init__(self):
        self.parser = make_parser()
        self.vulns: List[Vulnerability] = []

    def analyze_file(self, filepath: str, source: str) -> List[Vulnerability]:
        self.vulns = []
        src_bytes = source.encode("utf-8")
        tree = self.parser.parse(src_bytes)
        root = tree.root_node

        if root.has_error:
            # Still try to analyze what we can
            pass

        # Run all checks
        self._check_unsafe_code(root, src_bytes, source, filepath)
        self._check_command_injection(root, src_bytes, source, filepath)
        self._check_sql_injection(root, src_bytes, source, filepath)
        self._check_path_traversal(root, src_bytes, source, filepath)
        self._check_deserialization(root, src_bytes, source, filepath)
        self._check_hardcoded_secrets(root, src_bytes, source, filepath)
        self._check_weak_crypto(root, src_bytes, source, filepath)
        self._check_insecure_random(root, src_bytes, source, filepath)
        self._check_race_conditions(root, src_bytes, source, filepath)
        self._check_memory_safety(root, src_bytes, source, filepath)
        self._check_integer_overflow(root, src_bytes, source, filepath)
        self._check_panic_in_production(root, src_bytes, source, filepath)
        self._check_error_handling(root, src_bytes, source, filepath)
        self._check_actix_web_issues(root, src_bytes, source, filepath)
        self._check_rocket_issues(root, src_bytes, source, filepath)
        self._check_tokio_async_issues(root, src_bytes, source, filepath)
        self._check_ffi_safety(root, src_bytes, source, filepath)
        self._check_info_disclosure(root, src_bytes, source, filepath)
        self._check_ssl_tls(root, src_bytes, source, filepath)
        self._check_file_permissions(root, src_bytes, source, filepath)
        self._check_regex_dos(root, src_bytes, source, filepath)
        self._check_type_confusion(root, src_bytes, source, filepath)
        self._check_input_validation(root, src_bytes, source, filepath)
        self._check_resource_leaks(root, src_bytes, source, filepath)
        self._check_timing_attacks(root, src_bytes, source, filepath)
        self._check_format_string(root, src_bytes, source, filepath)
        self._check_deprecated_unsafe_functions(root, src_bytes, source, filepath)

        # Deduplicate: same title + same line = same finding
        seen = set()
        deduped = []
        for v in self.vulns:
            key = (v.title, v.filePath, v.startLine)
            if key not in seen:
                seen.add(key)
                deduped.append(v)
        self.vulns = deduped

        return self.vulns

    def _add(self, title, desc, severity, confidence, category, cwe, filepath,
             node, source, remediation, owasp="", refs=None):
        self.vulns.append(Vulnerability(
            id=str(uuid.uuid4()),
            title=title,
            description=desc,
            severity=severity,
            confidence=confidence,
            category=category,
            cwe=cwe,
            filePath=filepath,
            startLine=node.start_point[0] + 1,
            endLine=node.end_point[0] + 1,
            startColumn=node.start_point[1] + 1,
            endColumn=node.end_point[1] + 1,
            snippet=get_line_snippet(source, node.start_point[0] + 1, context=1),
            remediation=remediation,
            owasp=owasp,
            references=refs or [],
        ))

    # -----------------------------------------------------------------------
    # 1. Unsafe Code
    # -----------------------------------------------------------------------
    def _check_unsafe_code(self, root, src, source, fp):
        for node in find_nodes(root, "unsafe_block"):
            text = node_text(node, src)
            # Check for raw pointer dereference
            if "*" in text and ("as *const" in text or "as *mut" in text or
                                ".offset(" in text or "*ptr" in text):
                self._add(
                    "Raw Pointer Dereference in Unsafe Block",
                    "Raw pointer dereference inside unsafe block. This bypasses Rust's borrow checker "
                    "and can lead to null pointer dereference, use-after-free, or buffer overflows.",
                    "Critical", "High", "Memory Safety", "CWE-119",
                    fp, node, source,
                    "Minimize unsafe code. Use safe abstractions like Box, Rc, Arc. "
                    "If raw pointers are necessary, validate they are non-null and properly aligned.",
                    "A9:2017", ["https://doc.rust-lang.org/book/ch19-01-unsafe-rust.html"]
                )
            elif "transmute" in text:
                self._add(
                    "Transmute in Unsafe Block",
                    "std::mem::transmute used in unsafe block. Transmute reinterprets bits of one type "
                    "as another with no safety checks, potentially causing undefined behavior.",
                    "Critical", "High", "Memory Safety", "CWE-843",
                    fp, node, source,
                    "Avoid transmute. Use safe alternatives like From/Into traits, "
                    "TryFrom/TryInto, or as casts when possible.",
                    refs=["https://doc.rust-lang.org/std/mem/fn.transmute.html"]
                )
            else:
                self._add(
                    "Unsafe Code Block",
                    "Unsafe block detected. Code inside unsafe blocks bypasses Rust's safety guarantees "
                    "and can introduce memory safety vulnerabilities.",
                    "High", "High", "Memory Safety", "CWE-676",
                    fp, node, source,
                    "Minimize the use of unsafe blocks. Encapsulate unsafe code in safe abstractions "
                    "with well-documented safety invariants.",
                    refs=["https://doc.rust-lang.org/nomicon/"]
                )

        # Check for unsafe function declarations
        for node in find_nodes(root, "function_item"):
            text = node_text(node, src)
            if text.strip().startswith("unsafe fn") or text.strip().startswith("pub unsafe fn"):
                self._add(
                    "Unsafe Function Declaration",
                    "Function declared as unsafe. Callers must use an unsafe block, and the compiler "
                    "cannot enforce safety invariants.",
                    "High", "High", "Memory Safety", "CWE-676",
                    fp, node, source,
                    "Consider whether the function can be made safe by encapsulating the unsafe "
                    "operations internally and documenting safety requirements.",
                    refs=["https://doc.rust-lang.org/book/ch19-01-unsafe-rust.html"]
                )

        # Check for unsafe impl
        for node in find_nodes(root, "impl_item"):
            text = node_text(node, src)
            if text.strip().startswith("unsafe impl"):
                self._add(
                    "Unsafe Trait Implementation",
                    "Unsafe trait implementation detected. The compiler cannot verify the safety "
                    "invariants of the trait.",
                    "Medium", "High", "Memory Safety", "CWE-676",
                    fp, node, source,
                    "Ensure all safety invariants documented by the trait are upheld. "
                    "Add thorough documentation explaining why the implementation is safe.",
                )

    # -----------------------------------------------------------------------
    # 2. Command Injection
    # -----------------------------------------------------------------------
    def _check_command_injection(self, root, src, source, fp):
        for node in find_nodes(root, "call_expression"):
            text = node_text(node, src)
            # std::process::Command::new with dynamic input
            if "Command::new" in text:
                # Check if the argument is a variable (not a string literal)
                func_node = node.child_by_field_name("function")
                args_node = node.child_by_field_name("arguments")
                if args_node:
                    args_text = node_text(args_node, src)
                    # If argument is not a string literal, it might be user input
                    if not re.match(r'^\(\s*"[^"]*"\s*\)$', args_text):
                        self._add(
                            "Potential Command Injection",
                            "Command::new called with a dynamic argument. If user input reaches "
                            "this call, it could lead to arbitrary command execution.",
                            "Critical", "Medium", "Injection", "CWE-78",
                            fp, node, source,
                            "Use a whitelist of allowed commands. Never pass unsanitized user input "
                            "to Command::new. Consider using a safe command builder pattern.",
                            "A1:2017",
                            ["https://cwe.mitre.org/data/definitions/78.html"]
                        )
                    else:
                        # Even with static command, check for .arg() with variables
                        pass

            # Check for .arg() with format! or variable
            if ".arg(" in text and ("format!" in text or "&" in text):
                # More detailed check for method chains
                if "Command" in text or is_inside(node, "call_expression"):
                    if not re.search(r'\.arg\(\s*"[^"]*"\s*\)', text):
                        self._add(
                            "Command Argument Injection",
                            "Dynamic value passed to Command .arg(). If the value originates from "
                            "user input, it could lead to argument injection.",
                            "High", "Medium", "Injection", "CWE-88",
                            fp, node, source,
                            "Validate and sanitize all arguments passed to Command. "
                            "Use allowlists for acceptable argument values.",
                            "A1:2017",
                        )

        # Check for shell execution via method chains
        for node in find_nodes(root, "macro_invocation"):
            text = node_text(node, src)
            macro_name = ""
            for child in node.children:
                if child.type == "identifier":
                    macro_name = node_text(child, src)
                    break
            # Check for shell commands in format strings
            if macro_name == "format" and ("sh -c" in text or "bash -c" in text or
                                            "/bin/sh" in text or "cmd /c" in text):
                self._add(
                    "Shell Command Construction",
                    "Shell command being constructed with format!. This is a high-risk pattern "
                    "that can lead to command injection if any variable contains user input.",
                    "Critical", "High", "Injection", "CWE-78",
                    fp, node, source,
                    "Never construct shell commands from strings. Use Command::new with separate .arg() "
                    "calls for each argument. Avoid shell interpreters entirely.",
                    "A1:2017",
                )

    # -----------------------------------------------------------------------
    # 3. SQL Injection
    # -----------------------------------------------------------------------
    def _check_sql_injection(self, root, src, source, fp):
        sql_keywords = re.compile(
            r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b',
            re.IGNORECASE
        )

        for node in find_nodes(root, "macro_invocation"):
            text = node_text(node, src)
            macro_name = ""
            for child in node.children:
                if child.type == "identifier":
                    macro_name = node_text(child, src)
                    break

            if macro_name == "format" and sql_keywords.search(text):
                self._add(
                    "SQL Injection via String Formatting",
                    "SQL query constructed using format! macro. String interpolation in SQL "
                    "queries is the primary cause of SQL injection vulnerabilities.",
                    "Critical", "High", "Injection", "CWE-89",
                    fp, node, source,
                    "Use parameterized queries or an ORM. With diesel, use .filter() and .eq(). "
                    "With sqlx, use query!() or query_as!() macros with bind parameters ($1, $2).",
                    "A1:2017",
                    ["https://cwe.mitre.org/data/definitions/89.html"]
                )

        # Check for raw SQL in diesel/sqlx
        for node in find_nodes(root, "call_expression"):
            text = node_text(node, src)
            if ("sql_query(" in text or "raw_sql(" in text or
                "execute_unprepared(" in text or "raw_execute(" in text):
                self._add(
                    "Raw SQL Query Usage",
                    "Raw SQL query function detected. Raw SQL bypasses the ORM's query builder "
                    "safety and may be vulnerable to SQL injection if variables are interpolated.",
                    "High", "Medium", "Injection", "CWE-89",
                    fp, node, source,
                    "Use the ORM's query builder with parameterized queries. "
                    "If raw SQL is necessary, always use bind parameters.",
                    "A1:2017",
                )

        # String concatenation with SQL
        for node in find_nodes(root, "binary_expression"):
            text = node_text(node, src)
            if "+" in text and sql_keywords.search(text):
                self._add(
                    "SQL String Concatenation",
                    "SQL query built via string concatenation. This is vulnerable to SQL injection.",
                    "Critical", "Medium", "Injection", "CWE-89",
                    fp, node, source,
                    "Never concatenate user input into SQL strings. Use parameterized queries.",
                    "A1:2017",
                )

    # -----------------------------------------------------------------------
    # 4. Path Traversal
    # -----------------------------------------------------------------------
    def _check_path_traversal(self, root, src, source, fp):
        fs_functions = [
            "read_to_string", "write", "create", "open", "read_dir",
            "remove_file", "remove_dir", "remove_dir_all", "rename",
            "copy", "canonicalize", "metadata", "read_link",
            "create_dir", "create_dir_all"
        ]

        for node in find_nodes(root, "call_expression"):
            text = node_text(node, src)

            for func in fs_functions:
                if f"fs::{func}" in text or f"File::{func}" in text or f"Path::new" in text:
                    # Check if argument is dynamic
                    args_node = node.child_by_field_name("arguments")
                    if args_node:
                        args_text = node_text(args_node, src)
                        if not re.match(r'^\(\s*"[^"]*"\s*\)$', args_text):
                            self._add(
                                "Potential Path Traversal",
                                f"Filesystem operation '{func}' called with dynamic path. If user input "
                                "reaches this path without validation, it could allow reading/writing "
                                "arbitrary files (e.g., ../../etc/passwd).",
                                "High", "Medium", "Path Traversal", "CWE-22",
                                fp, node, source,
                                "Validate and canonicalize paths before use. Check that the resolved path "
                                "is within the expected directory. Use Path::canonicalize() and verify the "
                                "prefix matches the allowed base directory.",
                                "A5:2017",
                                ["https://cwe.mitre.org/data/definitions/22.html"]
                            )
                            break

        # Check for format! used to construct paths
        for node in find_nodes(root, "macro_invocation"):
            text = node_text(node, src)
            macro_name = ""
            for child in node.children:
                if child.type == "identifier":
                    macro_name = node_text(child, src)
                    break
            if macro_name == "format" and (".." in text or "/" in text or "\\\\" in text):
                if any(kw in text for kw in ["path", "file", "dir", "folder", "upload"]):
                    self._add(
                        "Path Construction with User Input",
                        "File path constructed using format! macro. This pattern is susceptible "
                        "to path traversal attacks if any variable contains '..' sequences.",
                        "High", "Medium", "Path Traversal", "CWE-22",
                        fp, node, source,
                        "Use Path::join() and then canonicalize(). Verify the resulting path "
                        "starts with the expected base directory.",
                        "A5:2017",
                    )

    # -----------------------------------------------------------------------
    # 5. Deserialization
    # -----------------------------------------------------------------------
    def _check_deserialization(self, root, src, source, fp):
        for node in find_nodes(root, "call_expression"):
            text = node_text(node, src)

            # serde deserialization from untrusted input
            if "serde_json::from_str" in text or "serde_json::from_slice" in text:
                self._add(
                    "JSON Deserialization",
                    "Deserialization from JSON detected. If the input is from an untrusted source, "
                    "malformed or malicious data could cause panics or logic errors.",
                    "Medium", "Low", "Deserialization", "CWE-502",
                    fp, node, source,
                    "Validate deserialized data after parsing. Use serde's validation attributes "
                    "(#[serde(deny_unknown_fields)]) and implement custom Deserialize for strict validation.",
                    "A8:2017",
                )

            if "bincode::deserialize" in text:
                self._add(
                    "Binary Deserialization (bincode)",
                    "bincode deserialization detected. bincode is not self-describing and can "
                    "cause panics or memory issues with malformed input. Not safe for untrusted data.",
                    "High", "Medium", "Deserialization", "CWE-502",
                    fp, node, source,
                    "Do not use bincode for untrusted input. Use a format with built-in "
                    "validation like serde_json or MessagePack with size limits.",
                    "A8:2017",
                    ["https://cwe.mitre.org/data/definitions/502.html"]
                )

            if "serde_yaml::from_str" in text or "serde_yaml::from_reader" in text:
                self._add(
                    "YAML Deserialization",
                    "YAML deserialization detected. YAML parsers may support tags that could "
                    "lead to unexpected behavior or denial of service with deeply nested documents.",
                    "Medium", "Medium", "Deserialization", "CWE-502",
                    fp, node, source,
                    "Validate YAML input size and depth. Consider using a stricter format like JSON "
                    "for untrusted input. Set recursion limits if available.",
                    "A8:2017",
                )

            if "toml::from_str" in text or "serde_cbor" in text or "rmp_serde" in text:
                self._add(
                    "Deserialization of Untrusted Data",
                    "Deserialization from a binary/text format detected. Ensure the input source "
                    "is trusted and validated.",
                    "Medium", "Low", "Deserialization", "CWE-502",
                    fp, node, source,
                    "Validate input before deserialization. Implement size limits and schema validation.",
                    "A8:2017",
                )

    # -----------------------------------------------------------------------
    # 6. Hardcoded Secrets
    # -----------------------------------------------------------------------
    def _check_hardcoded_secrets(self, root, src, source, fp):
        secret_patterns = [
            (r'(?i)(password|passwd|pwd)\s*[:=]\s*"[^"]{4,}"', "Hardcoded Password"),
            (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*"[^"]{8,}"', "Hardcoded API Key"),
            (r'(?i)(secret[_-]?key|secret)\s*[:=]\s*"[^"]{8,}"', "Hardcoded Secret Key"),
            (r'(?i)(token|auth[_-]?token|access[_-]?token)\s*[:=]\s*"[^"]{8,}"', "Hardcoded Token"),
            (r'(?i)(private[_-]?key)\s*[:=]\s*"[^"]{8,}"', "Hardcoded Private Key"),
            (r'(?i)(aws[_-]?access|aws[_-]?secret)\s*[:=]\s*"[A-Za-z0-9/+=]{16,}"', "Hardcoded AWS Credential"),
            (r'(?i)(connection[_-]?string|conn[_-]?str)\s*[:=]\s*"[^"]{8,}"', "Hardcoded Connection String"),
            (r'(?i)(database[_-]?url|db[_-]?url)\s*[:=]\s*"[^"]{8,}"', "Hardcoded Database URL"),
        ]

        for node in find_nodes(root, "let_declaration"):
            text = node_text(node, src)
            for pattern, title in secret_patterns:
                if re.search(pattern, text):
                    self._add(
                        title,
                        f"Potential hardcoded credential found in variable declaration. "
                        "Hardcoded secrets in source code can be extracted by anyone with "
                        "access to the codebase.",
                        "Critical", "High", "Secrets", "CWE-798",
                        fp, node, source,
                        "Use environment variables (std::env::var) or a secrets manager. "
                        "Never commit credentials to source control.",
                        "A2:2017",
                        ["https://cwe.mitre.org/data/definitions/798.html"]
                    )
                    break

        # Check const and static declarations too
        for node in find_nodes_multi(root, {"const_item", "static_item"}):
            text = node_text(node, src)
            for pattern, title in secret_patterns:
                if re.search(pattern, text):
                    self._add(
                        f"{title} in Constant",
                        "Hardcoded credential in a constant/static variable. These are compiled "
                        "into the binary and can be extracted with simple string analysis.",
                        "Critical", "High", "Secrets", "CWE-798",
                        fp, node, source,
                        "Load secrets from environment variables at runtime, not compile-time constants.",
                        "A2:2017",
                    )
                    break

        # Check string literals for common secret patterns
        for node in find_nodes(root, "string_literal"):
            text = node_text(node, src)
            # AWS keys
            if re.search(r'AKIA[0-9A-Z]{16}', text):
                self._add(
                    "AWS Access Key ID Detected",
                    "String literal contains what appears to be an AWS Access Key ID.",
                    "Critical", "High", "Secrets", "CWE-798",
                    fp, node, source,
                    "Remove the key from source code immediately. Rotate the credential. "
                    "Use AWS IAM roles or environment variables.",
                    "A2:2017",
                )
            # Private keys
            if "BEGIN RSA PRIVATE KEY" in text or "BEGIN PRIVATE KEY" in text:
                self._add(
                    "Embedded Private Key",
                    "Private key material embedded in source code.",
                    "Critical", "High", "Secrets", "CWE-321",
                    fp, node, source,
                    "Store private keys in secure key management systems, not in source code.",
                    "A2:2017",
                )
            # JWT secrets
            if re.search(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}', text):
                self._add(
                    "Hardcoded JWT Token",
                    "JWT token embedded in source code. This token may grant unauthorized access.",
                    "High", "High", "Secrets", "CWE-798",
                    fp, node, source,
                    "Never hardcode JWT tokens. Generate them dynamically at runtime.",
                    "A2:2017",
                )

    # -----------------------------------------------------------------------
    # 7. Weak Cryptography
    # -----------------------------------------------------------------------
    def _check_weak_crypto(self, root, src, source, fp):
        weak_algos = {
            "md5": ("MD5", "CWE-328"),
            "Md5": ("MD5", "CWE-328"),
            "MD5": ("MD5", "CWE-328"),
            "sha1": ("SHA-1", "CWE-328"),
            "Sha1": ("SHA-1", "CWE-328"),
            "SHA1": ("SHA-1", "CWE-328"),
            "des": ("DES", "CWE-327"),
            "Des": ("DES", "CWE-327"),
            "rc4": ("RC4", "CWE-327"),
            "Rc4": ("RC4", "CWE-327"),
        }

        for node in find_nodes(root, "use_declaration"):
            text = node_text(node, src)
            for algo_name, (display_name, cwe) in weak_algos.items():
                if algo_name in text:
                    self._add(
                        f"Weak Cryptographic Algorithm ({display_name})",
                        f"{display_name} is cryptographically broken and should not be used "
                        "for security purposes such as password hashing, digital signatures, "
                        "or integrity verification.",
                        "High", "High", "Cryptography", cwe,
                        fp, node, source,
                        f"Replace {display_name} with SHA-256/SHA-3 for hashing, "
                        "AES-256-GCM for encryption, or Argon2/bcrypt for passwords.",
                        "A3:2017",
                        ["https://cwe.mitre.org/data/definitions/327.html"]
                    )

        # Check for weak key sizes
        for node in find_nodes(root, "call_expression"):
            text = node_text(node, src)
            if "Rsa::generate" in text or "rsa::generate" in text:
                # Check key size
                if "1024" in text or "512" in text:
                    self._add(
                        "Weak RSA Key Size",
                        "RSA key generated with insufficient key size. Keys smaller than 2048 bits "
                        "are considered insecure.",
                        "High", "High", "Cryptography", "CWE-326",
                        fp, node, source,
                        "Use RSA key size of at least 2048 bits, preferably 4096 bits. "
                        "Consider using elliptic curve cryptography (Ed25519) for better performance.",
                        "A3:2017",
                    )

        # ECB mode
        for node in walk(root):
            text = node_text(node, src)
            if "ecb" in text.lower() and ("encrypt" in text.lower() or "cipher" in text.lower() or
                                            "Ecb" in text or "ECB" in text):
                if node.type in ("call_expression", "use_declaration", "let_declaration"):
                    self._add(
                        "ECB Mode Encryption",
                        "ECB (Electronic Codebook) mode detected. ECB does not provide "
                        "semantic security as identical plaintext blocks produce identical ciphertext.",
                        "High", "Medium", "Cryptography", "CWE-327",
                        fp, node, source,
                        "Use AES-GCM or AES-CBC with HMAC (encrypt-then-MAC). Never use ECB mode.",
                        "A3:2017",
                    )

    # -----------------------------------------------------------------------
    # 8. Insecure Random
    # -----------------------------------------------------------------------
    def _check_insecure_random(self, root, src, source, fp):
        for node in find_nodes(root, "use_declaration"):
            text = node_text(node, src)
            if "rand::thread_rng" in text or "rand::random" in text:
                # thread_rng is actually OK for most purposes, but not for cryptographic use
                pass

        for node in find_nodes(root, "call_expression"):
            text = node_text(node, src)
            if ("thread_rng()" in text or "SmallRng" in text or
                "StdRng::from_seed" in text or "XorShiftRng" in text or
                "ChaCha8Rng" in text):

                # Check if used in security context
                parent_text = ""
                for p in parent_chain(node):
                    parent_text = node_text(p, src)
                    if len(parent_text) > 500:
                        break

                security_context = any(kw in parent_text.lower() for kw in [
                    "token", "secret", "key", "nonce", "salt", "password",
                    "session", "csrf", "auth", "crypto"
                ])

                if security_context or "SmallRng" in text or "XorShiftRng" in text:
                    self._add(
                        "Insecure Random Number Generator",
                        "Non-cryptographic RNG used in a potentially security-sensitive context. "
                        "SmallRng, XorShiftRng, and thread_rng are not suitable for security purposes.",
                        "High" if security_context else "Medium",
                        "Medium", "Cryptography", "CWE-338",
                        fp, node, source,
                        "Use OsRng or ChaCha20Rng (with 20 rounds) from the rand crate for "
                        "cryptographic purposes. For tokens and secrets, use the 'ring' crate.",
                        "A3:2017",
                        ["https://cwe.mitre.org/data/definitions/338.html"]
                    )

    # -----------------------------------------------------------------------
    # 9. Race Conditions
    # -----------------------------------------------------------------------
    def _check_race_conditions(self, root, src, source, fp):
        # Check for Arc<Mutex> patterns with potential deadlock
        for node in find_nodes(root, "let_declaration"):
            text = node_text(node, src)
            if "Arc::new(Mutex::new" in text or "Arc::new(RwLock::new" in text:
                # Look for multiple lock acquisitions
                parent_fn = None
                for p in parent_chain(node):
                    if p.type == "function_item":
                        parent_fn = p
                        break
                if parent_fn:
                    fn_text = node_text(parent_fn, src)
                    lock_count = fn_text.count(".lock()") + fn_text.count(".write()")
                    if lock_count >= 2:
                        self._add(
                            "Potential Deadlock Risk",
                            "Multiple lock acquisitions detected in the same function scope. "
                            "Acquiring multiple locks without consistent ordering can cause deadlocks.",
                            "High", "Medium", "Concurrency", "CWE-833",
                            fp, node, source,
                            "Always acquire locks in a consistent global order. Consider using "
                            "parking_lot for deadlock detection or restructuring to use fewer locks.",
                            refs=["https://cwe.mitre.org/data/definitions/833.html"]
                        )

        # Static mut
        for node in find_nodes(root, "static_item"):
            text = node_text(node, src)
            if "static mut " in text:
                self._add(
                    "Mutable Static Variable",
                    "Mutable static (static mut) detected. Access to mutable statics is always "
                    "unsafe and constitutes a data race in multithreaded code.",
                    "Critical", "High", "Concurrency", "CWE-362",
                    fp, node, source,
                    "Use std::sync::Mutex, RwLock, or atomics for shared mutable state. "
                    "Consider using once_cell::sync::Lazy for lazy initialization.",
                    refs=["https://doc.rust-lang.org/reference/items/static-items.html"]
                )

    # -----------------------------------------------------------------------
    # 10. Memory Safety
    # -----------------------------------------------------------------------
    def _check_memory_safety(self, root, src, source, fp):
        for node in find_nodes(root, "call_expression"):
            text = node_text(node, src)

            if "mem::forget" in text or "std::mem::forget" in text:
                self._add(
                    "mem::forget Usage",
                    "std::mem::forget prevents Drop from running, which can cause resource leaks "
                    "(file handles, network connections, locks). While safe, it's usually a code smell.",
                    "Medium", "High", "Memory Safety", "CWE-401",
                    fp, node, source,
                    "Use ManuallyDrop instead of mem::forget for more explicit resource management. "
                    "Ensure the resource will be properly cleaned up.",
                )

            if "ManuallyDrop::new" in text:
                self._add(
                    "ManuallyDrop Usage",
                    "ManuallyDrop prevents automatic drop. The value must be explicitly dropped "
                    "or it will leak. Double-drop of the inner value causes undefined behavior.",
                    "Medium", "Medium", "Memory Safety", "CWE-401",
                    fp, node, source,
                    "Ensure ManuallyDrop values are either properly dropped with ManuallyDrop::drop() "
                    "or intentionally leaked. Never call drop on the same ManuallyDrop twice.",
                )

            if "from_raw_parts" in text:
                self._add(
                    "Unsafe from_raw_parts",
                    "from_raw_parts constructs a slice/Vec from raw pointer and length. "
                    "Invalid arguments cause undefined behavior.",
                    "Critical", "High", "Memory Safety", "CWE-119",
                    fp, node, source,
                    "Ensure pointer is valid, properly aligned, and the length is correct. "
                    "The memory must have been allocated with the same allocator.",
                )

            if "Box::from_raw" in text:
                self._add(
                    "Box::from_raw Usage",
                    "Box::from_raw reconstructs a Box from a raw pointer. The pointer must have "
                    "been obtained from Box::into_raw or a compatible allocation.",
                    "High", "High", "Memory Safety", "CWE-416",
                    fp, node, source,
                    "Ensure the raw pointer was obtained from Box::into_raw and is used exactly once. "
                    "Double-free or use-after-free will result from misuse.",
                )

        # Check for raw pointer arithmetic
        for node in find_nodes(root, "call_expression"):
            text = node_text(node, src)
            if ".offset(" in text or ".add(" in text or ".sub(" in text:
                if is_inside(node, "unsafe_block"):
                    self._add(
                        "Raw Pointer Arithmetic",
                        "Pointer offset/add/sub operations in unsafe context. Out-of-bounds "
                        "pointer arithmetic is undefined behavior.",
                        "High", "High", "Memory Safety", "CWE-119",
                        fp, node, source,
                        "Validate bounds before pointer arithmetic. Consider using slices or "
                        "iterators instead of manual pointer manipulation.",
                    )

    # -----------------------------------------------------------------------
    # 11. Integer Overflow
    # -----------------------------------------------------------------------
    def _check_integer_overflow(self, root, src, source, fp):
        # Check for arithmetic operations in unsafe or critical contexts
        for node in find_nodes(root, "binary_expression"):
            text = node_text(node, src)
            # Look for arithmetic on user-facing types
            ops = ["+", "-", "*"]
            has_arith = any(f" {op} " in text for op in ops)

            if has_arith and is_inside(node, "unsafe_block"):
                self._add(
                    "Unchecked Arithmetic in Unsafe Block",
                    "Arithmetic operation inside unsafe block without overflow checking. "
                    "In release builds, Rust wraps on overflow silently.",
                    "High", "Medium", "Integer Safety", "CWE-190",
                    fp, node, source,
                    "Use checked_add/checked_sub/checked_mul or saturating variants. "
                    "Enable overflow-checks in Cargo.toml for release builds: "
                    "[profile.release] overflow-checks = true",
                    refs=["https://cwe.mitre.org/data/definitions/190.html"]
                )

        # Check for as casts that could truncate
        for node in find_nodes(root, "type_cast_expression"):
            text = node_text(node, src)
            truncating = [
                ("u64", "u32"), ("u64", "u16"), ("u64", "u8"),
                ("u32", "u16"), ("u32", "u8"), ("u16", "u8"),
                ("i64", "i32"), ("i64", "i16"), ("i64", "i8"),
                ("i32", "i16"), ("i32", "i8"), ("i16", "i8"),
                ("usize", "u32"), ("usize", "u16"), ("usize", "u8"),
                ("isize", "i32"), ("isize", "i16"), ("isize", "i8"),
                ("u64", "i32"), ("u32", "i16"), ("usize", "i32"),
            ]
            for from_t, to_t in truncating:
                if f"as {to_t}" in text:
                    self._add(
                        "Potentially Truncating Cast",
                        f"Type cast to {to_t} detected. If the source value exceeds the target "
                        f"type's range, it will be silently truncated, possibly causing logic errors.",
                        "Medium", "Low", "Integer Safety", "CWE-681",
                        fp, node, source,
                        f"Use TryFrom/TryInto to handle truncation: "
                        f"{to_t}::try_from(value).expect(\"value out of range\"). "
                        "Or use the 'as' cast only when the value is known to be in range.",
                    )
                    break

    # -----------------------------------------------------------------------
    # 12. Panic in Production
    # -----------------------------------------------------------------------
    def _check_panic_in_production(self, root, src, source, fp):
        for node in find_nodes(root, "call_expression"):
            text = node_text(node, src)

            # .unwrap() on Option/Result
            if text.endswith(".unwrap()") or ".unwrap()" in text:
                # Skip test functions
                in_test = False
                for p in parent_chain(node):
                    if p.type == "function_item":
                        fn_text = node_text(p, src)
                        if "#[test]" in fn_text or "#[cfg(test)]" in fn_text or "fn test_" in fn_text:
                            in_test = True
                            break
                    if p.type == "mod_item":
                        mod_text = node_text(p, src)
                        if "#[cfg(test)]" in mod_text:
                            in_test = True
                            break

                if not in_test:
                    self._add(
                        "Panic-Inducing unwrap()",
                        "unwrap() will panic and crash the program if the value is None/Err. "
                        "In production code, this can cause denial of service.",
                        "Medium", "High", "Error Handling", "CWE-248",
                        fp, node, source,
                        "Replace with match, if let, unwrap_or, unwrap_or_else, or the ? operator. "
                        "Example: value.unwrap_or_default() or value?",
                    )

            # .expect() on Option/Result
            if ".expect(" in text:
                in_test = False
                for p in parent_chain(node):
                    if p.type == "function_item":
                        fn_text = node_text(p, src)
                        if "#[test]" in fn_text or "#[cfg(test)]" in fn_text:
                            in_test = True
                            break
                if not in_test:
                    self._add(
                        "Panic-Inducing expect()",
                        "expect() will panic with a message if the value is None/Err. "
                        "While more descriptive than unwrap(), it still crashes in production.",
                        "Low", "High", "Error Handling", "CWE-248",
                        fp, node, source,
                        "Use proper error handling with match, if let, or the ? operator "
                        "to propagate errors gracefully.",
                    )

        # panic! macro
        for node in find_nodes(root, "macro_invocation"):
            macro_name = ""
            for child in node.children:
                if child.type == "identifier":
                    macro_name = node_text(child, src)
                    break
            if macro_name == "panic":
                in_test = False
                for p in parent_chain(node):
                    if p.type == "function_item":
                        fn_text = node_text(p, src)
                        if "#[test]" in fn_text or "#[cfg(test)]" in fn_text:
                            in_test = True
                            break
                if not in_test:
                    self._add(
                        "Explicit panic! in Production Code",
                        "panic! macro will immediately crash the thread/program. "
                        "This should only be used for truly unrecoverable situations.",
                        "Medium", "High", "Error Handling", "CWE-248",
                        fp, node, source,
                        "Return Result or Option instead of panicking. Use anyhow or thiserror "
                        "crates for ergonomic error handling.",
                    )

            # todo! and unimplemented!
            if macro_name in ("todo", "unimplemented"):
                self._add(
                    f"{macro_name}! Macro in Code",
                    f"The {macro_name}! macro will panic at runtime. This indicates "
                    "incomplete implementation that should not be in production code.",
                    "High", "High", "Error Handling", "CWE-248",
                    fp, node, source,
                    "Implement the missing functionality or return a proper error.",
                )

        # Array indexing without bounds check
        for node in find_nodes(root, "index_expression"):
            text = node_text(node, src)
            # Direct indexing (array[i]) can panic
            if not ".get(" in text:
                in_test = False
                for p in parent_chain(node):
                    if p.type == "function_item":
                        fn_text = node_text(p, src)
                        if "#[test]" in fn_text:
                            in_test = True
                            break
                if not in_test:
                    self._add(
                        "Unchecked Array/Slice Indexing",
                        "Direct indexing (collection[index]) panics on out-of-bounds access. "
                        "If the index could be out of range, this will crash the program.",
                        "Low", "Low", "Error Handling", "CWE-129",
                        fp, node, source,
                        "Use .get(index) which returns Option<&T> instead of panicking. "
                        "Or validate the index against .len() before accessing.",
                    )

    # -----------------------------------------------------------------------
    # 13. Error Handling
    # -----------------------------------------------------------------------
    def _check_error_handling(self, root, src, source, fp):
        # Check for ignored Results (let _ = ...)
        for node in find_nodes(root, "let_declaration"):
            text = node_text(node, src)
            pattern_node = node.child_by_field_name("pattern")
            if pattern_node and node_text(pattern_node, src).strip() == "_":
                # Check if the value is a function call (likely returns Result)
                value = node.child_by_field_name("value")
                if value and value.type == "call_expression":
                    val_text = node_text(value, src)
                    if not val_text.startswith("drop("):
                        self._add(
                            "Ignored Result Value",
                            "Function return value explicitly discarded with `let _ = ...`. "
                            "If the function returns a Result, errors will be silently swallowed.",
                            "Medium", "Medium", "Error Handling", "CWE-252",
                            fp, node, source,
                            "Handle the Result with match or ? operator. If intentionally ignoring, "
                            "add a comment explaining why the error is safe to ignore.",
                        )

        # Empty catch blocks (map_err with no-op)
        for node in find_nodes(root, "call_expression"):
            text = node_text(node, src)
            if ".map_err(|_|" in text or ".map_err(|_e|" in text:
                if "()" in text.split(".map_err")[1]:
                    self._add(
                        "Error Information Discarded",
                        "Error details are being discarded in map_err. This makes debugging "
                        "and error reporting difficult.",
                        "Low", "Medium", "Error Handling", "CWE-755",
                        fp, node, source,
                        "Preserve error information or log it before conversion. "
                        "Use .map_err(|e| { log::error!(\"{}\", e); new_error })",
                    )

    # -----------------------------------------------------------------------
    # 14. Actix-web Security Issues
    # -----------------------------------------------------------------------
    def _check_actix_web_issues(self, root, src, source, fp):
        full_text = source

        # Check for permissive CORS
        if "Cors::permissive()" in full_text or '.allowed_origin("*")' in full_text:
            for node in find_nodes(root, "call_expression"):
                text = node_text(node, src)
                if "Cors::permissive()" in text or 'allowed_origin("*")' in text:
                    self._add(
                        "Overly Permissive CORS Configuration",
                        "CORS configured to allow all origins. This allows any website to make "
                        "authenticated requests to your API, potentially enabling CSRF attacks.",
                        "High", "High", "Web Security", "CWE-942",
                        fp, node, source,
                        "Restrict allowed_origin to specific trusted domains. "
                        "Never use Cors::permissive() in production.",
                        "A5:2017",
                        ["https://cwe.mitre.org/data/definitions/942.html"]
                    )

        # Check for missing authentication extractors
        for node in find_nodes(root, "attribute_item"):
            text = node_text(node, src)
            if any(m in text for m in ["get(", "post(", "put(", "delete(", "patch("]):
                # Check the function signature for auth parameters
                parent = node.next_named_sibling
                if parent and parent.type == "function_item":
                    fn_text = node_text(parent, src)
                    params = fn_text.split("(", 1)[1].split(")")[0] if "(" in fn_text else ""
                    has_auth = any(kw in params for kw in [
                        "Identity", "Auth", "Claims", "Token", "Session",
                        "HttpAuthentication", "BearerAuth"
                    ])
                    if not has_auth and ("admin" in text.lower() or "user" in text.lower() or
                                         "api" in text.lower() or "private" in text.lower()):
                        self._add(
                            "Missing Authentication on Sensitive Endpoint",
                            f"Endpoint handler appears to handle sensitive data but has no "
                            "authentication extractor in its parameters.",
                            "High", "Low", "Web Security", "CWE-306",
                            fp, node, source,
                            "Add an authentication extractor (Identity, BearerAuth) to the "
                            "handler function parameters.",
                            "A2:2017",
                        )

        # HttpResponse with sensitive data in error
        for node in find_nodes(root, "call_expression"):
            text = node_text(node, src)
            if ("HttpResponse::InternalServerError" in text or
                "HttpResponse::BadRequest" in text):
                if "format!" in text and ("{:?}" in text or "{:#?}" in text or "err" in text.lower()):
                    self._add(
                        "Detailed Error Information in Response",
                        "Internal error details are being sent in HTTP response. This can "
                        "leak sensitive information about the application internals.",
                        "Medium", "Medium", "Information Disclosure", "CWE-209",
                        fp, node, source,
                        "Return generic error messages to clients. Log detailed errors server-side.",
                        "A3:2017",
                    )

    # -----------------------------------------------------------------------
    # 15. Rocket-specific Issues
    # -----------------------------------------------------------------------
    def _check_rocket_issues(self, root, src, source, fp):
        full_text = source

        # Rocket: missing security headers
        if "rocket" in full_text.lower() and "#[launch]" in full_text:
            if "X-Content-Type-Options" not in full_text and "Helmet" not in full_text:
                # Find the launch function
                for node in find_nodes(root, "function_item"):
                    fn_text = node_text(node, src)
                    if "#[launch]" in source[:node.start_byte].decode("utf-8", errors="replace") if isinstance(source, bytes) else source[:node.start_point[0]]:
                        self._add(
                            "Missing Security Headers (Rocket)",
                            "Rocket application does not appear to set security headers. "
                            "Missing headers like X-Content-Type-Options, X-Frame-Options, etc.",
                            "Medium", "Low", "Web Security", "CWE-693",
                            fp, node, source,
                            "Use rocket_contrib::helmet::SpaceHelmet or add a fairing "
                            "that sets security headers on all responses.",
                            "A6:2017",
                        )
                        break

        # Rocket: raw form data without validation
        for node in find_nodes(root, "attribute_item"):
            text = node_text(node, src)
            if "FromForm" in text:
                self._add(
                    "Form Input Requires Validation (Rocket)",
                    "Rocket FromForm struct detected. Ensure all fields have appropriate "
                    "validation constraints to prevent injection attacks.",
                    "Low", "Low", "Input Validation", "CWE-20",
                    fp, node, source,
                    "Add validation with #[field(validate = ...)] attributes or implement "
                    "custom FromForm to validate all input fields.",
                )

    # -----------------------------------------------------------------------
    # 16. Tokio/Async Issues
    # -----------------------------------------------------------------------
    def _check_tokio_async_issues(self, root, src, source, fp):
        for node in find_nodes(root, "call_expression"):
            text = node_text(node, src)

            # Blocking operations in async context
            blocking_calls = [
                "std::thread::sleep", "thread::sleep",
                "std::fs::read", "std::fs::write", "std::fs::read_to_string",
                "std::net::TcpStream", "std::io::stdin",
            ]
            for bc in blocking_calls:
                if bc in text:
                    if is_inside(node, "async_block") or self._in_async_fn(node, src):
                        self._add(
                            "Blocking Call in Async Context",
                            f"'{bc}' is a blocking operation used inside an async context. "
                            "This will block the entire tokio runtime thread, degrading performance "
                            "and potentially causing deadlocks.",
                            "High", "High", "Async Safety", "CWE-834",
                            fp, node, source,
                            f"Use the async equivalent: tokio::time::sleep, tokio::fs::read, "
                            "tokio::net::TcpStream, etc. For CPU-bound work, use "
                            "tokio::task::spawn_blocking().",
                            refs=["https://docs.rs/tokio/latest/tokio/"]
                        )
                        break

            # Unbounded channels
            if ("unbounded_channel" in text or "mpsc::unbounded" in text or
                "unbounded()" in text):
                self._add(
                    "Unbounded Channel",
                    "Unbounded channel detected. Without backpressure, a fast producer "
                    "can overwhelm a slow consumer, causing memory exhaustion.",
                    "Medium", "Medium", "Resource Management", "CWE-400",
                    fp, node, source,
                    "Use bounded channels (mpsc::channel(capacity)) to provide backpressure. "
                    "Choose a capacity based on expected throughput.",
                )

            # spawn without JoinHandle
            if "tokio::spawn" in text or "task::spawn" in text:
                parent = node.parent
                if parent and parent.type == "expression_statement":
                    # JoinHandle is not being stored
                    self._add(
                        "Detached Async Task",
                        "Spawned task's JoinHandle is not stored. If the task panics, the error "
                        "will be silently swallowed. Task cancellation is also not possible.",
                        "Low", "Medium", "Async Safety", "CWE-755",
                        fp, node, source,
                        "Store the JoinHandle and await it, or use a task tracker. "
                        "At minimum, unwrap the JoinHandle to propagate panics.",
                    )

    def _in_async_fn(self, node, src):
        """Check if a node is inside an async function."""
        for p in parent_chain(node):
            if p.type == "function_item":
                fn_text = node_text(p, src)
                return "async fn" in fn_text
        return False

    # -----------------------------------------------------------------------
    # 17. FFI Safety
    # -----------------------------------------------------------------------
    def _check_ffi_safety(self, root, src, source, fp):
        for node in find_nodes(root, "extern_block"):
            text = node_text(node, src)
            self._add(
                "Foreign Function Interface (FFI) Block",
                "extern block declares foreign functions. Calling foreign functions is inherently "
                "unsafe and the compiler cannot verify memory safety across the FFI boundary.",
                "High", "High", "FFI Safety", "CWE-676",
                fp, node, source,
                "Wrap FFI calls in safe Rust abstractions. Validate all pointers and sizes "
                "at the boundary. Use the 'bindgen' crate for auto-generated safe bindings.",
            )

        for node in find_nodes(root, "call_expression"):
            text = node_text(node, src)

            if "CString::new" in text:
                # Check if followed by .unwrap() — NUL byte not handled
                if ".unwrap()" in text:
                    self._add(
                        "CString NUL Byte Not Handled",
                        "CString::new(...).unwrap() will panic if the input contains a NUL byte. "
                        "User input may contain NUL bytes.",
                        "Medium", "Medium", "FFI Safety", "CWE-170",
                        fp, node, source,
                        "Handle the NulError: CString::new(s).map_err(|_| MyError::InvalidString)?",
                    )

            if "CStr::from_ptr" in text:
                self._add(
                    "CStr::from_ptr Usage",
                    "CStr::from_ptr is unsafe and requires the pointer to reference a valid "
                    "NUL-terminated C string with a lifetime at least as long as the CStr.",
                    "High", "High", "FFI Safety", "CWE-119",
                    fp, node, source,
                    "Validate the pointer is non-null before calling from_ptr. "
                    "Ensure the lifetime of the underlying data is correctly managed.",
                )

    # -----------------------------------------------------------------------
    # 18. Information Disclosure
    # -----------------------------------------------------------------------
    def _check_info_disclosure(self, root, src, source, fp):
        # Debug trait on sensitive structs
        for node in find_nodes(root, "attribute_item"):
            text = node_text(node, src)
            if "derive" in text and "Debug" in text:
                # Check if the struct has sensitive fields
                sibling = node.next_named_sibling
                if sibling and sibling.type == "struct_item":
                    struct_text = node_text(sibling, src)
                    sensitive_fields = ["password", "secret", "token", "key", "credential",
                                       "private", "ssn", "credit_card", "api_key"]
                    for field_name in sensitive_fields:
                        if field_name in struct_text.lower():
                            self._add(
                                "Debug Trait on Sensitive Struct",
                                f"Struct containing sensitive field ('{field_name}') derives Debug. "
                                "This means the sensitive data can be accidentally logged or displayed.",
                                "Medium", "Medium", "Information Disclosure", "CWE-532",
                                fp, node, source,
                                "Implement Debug manually, redacting sensitive fields: "
                                "impl fmt::Debug for MyStruct { fn fmt(&self, f: &mut fmt::Formatter) -> "
                                "fmt::Result { f.debug_struct(\"MyStruct\").field(\"password\", "
                                "&\"[REDACTED]\").finish() } }",
                            )
                            break

        # Printing sensitive data
        for node in find_nodes(root, "macro_invocation"):
            macro_name = ""
            for child in node.children:
                if child.type == "identifier":
                    macro_name = node_text(child, src)
                    break
            if macro_name in ("println", "print", "eprintln", "eprint", "dbg"):
                text = node_text(node, src)
                sensitive = ["password", "secret", "token", "key", "credential", "api_key"]
                for s in sensitive:
                    if s in text.lower():
                        self._add(
                            "Sensitive Data in Log/Print Output",
                            f"Potentially sensitive data ('{s}') printed to stdout/stderr. "
                            "This data may end up in log files or console output.",
                            "Medium", "Medium", "Information Disclosure", "CWE-532",
                            fp, node, source,
                            "Never log sensitive data. Redact or mask sensitive values before logging.",
                            "A3:2017",
                        )
                        break

    # -----------------------------------------------------------------------
    # 19. SSL/TLS Misconfiguration
    # -----------------------------------------------------------------------
    def _check_ssl_tls(self, root, src, source, fp):
        for node in find_nodes(root, "call_expression"):
            text = node_text(node, src)

            if "danger_accept_invalid_certs(true)" in text:
                self._add(
                    "TLS Certificate Validation Disabled",
                    "Certificate validation is disabled. This makes the connection vulnerable "
                    "to man-in-the-middle attacks.",
                    "Critical", "High", "TLS Security", "CWE-295",
                    fp, node, source,
                    "Never disable certificate validation in production. Use proper CA certificates. "
                    "If using self-signed certs, add them to the trust store.",
                    "A3:2017",
                    ["https://cwe.mitre.org/data/definitions/295.html"]
                )

            if "danger_accept_invalid_hostnames(true)" in text:
                self._add(
                    "TLS Hostname Verification Disabled",
                    "Hostname verification is disabled. This allows connections to servers "
                    "with certificates for different domains.",
                    "Critical", "High", "TLS Security", "CWE-297",
                    fp, node, source,
                    "Always verify hostnames. The certificate must match the server being connected to.",
                    "A3:2017",
                )

            if "min_protocol_version" in text and ("Tls10" in text or "Tls11" in text or
                                                     "Ssl" in text):
                self._add(
                    "Insecure TLS Protocol Version",
                    "Allowing TLS 1.0, TLS 1.1, or SSL. These protocol versions have known "
                    "vulnerabilities (POODLE, BEAST, etc.).",
                    "High", "High", "TLS Security", "CWE-327",
                    fp, node, source,
                    "Set minimum protocol version to TLS 1.2 or preferably TLS 1.3.",
                    "A3:2017",
                )

        # Check for HTTP (non-HTTPS) URLs
        for node in find_nodes(root, "string_literal"):
            text = node_text(node, src)
            if re.search(r'"http://[^"]*\.(com|org|net|io|dev)', text):
                if "localhost" not in text and "127.0.0.1" not in text:
                    self._add(
                        "HTTP URL (Non-Encrypted)",
                        "Plaintext HTTP URL detected. Data transmitted over HTTP is not encrypted "
                        "and can be intercepted.",
                        "Medium", "Medium", "TLS Security", "CWE-319",
                        fp, node, source,
                        "Use HTTPS URLs for all external communications.",
                        "A3:2017",
                    )

    # -----------------------------------------------------------------------
    # 20. File Permissions
    # -----------------------------------------------------------------------
    def _check_file_permissions(self, root, src, source, fp):
        for node in find_nodes(root, "call_expression"):
            text = node_text(node, src)

            if "set_permissions" in text or "Permissions::from_mode" in text:
                # Check for overly permissive modes
                if "0o777" in text or "0o666" in text or "0o755" in text:
                    mode = "0o777" if "0o777" in text else ("0o666" if "0o666" in text else "0o755")
                    self._add(
                        "Overly Permissive File Permissions",
                        f"File permissions set to {mode}. World-readable/writable files can be "
                        "accessed or modified by any user on the system.",
                        "High" if mode in ("0o777", "0o666") else "Medium",
                        "High", "File Security", "CWE-732",
                        fp, node, source,
                        "Use restrictive permissions: 0o600 (owner read/write) or 0o644 (owner write, "
                        "others read). For directories, use 0o700 or 0o755.",
                        refs=["https://cwe.mitre.org/data/definitions/732.html"]
                    )

            # Temp file creation without secure permissions
            if "tempfile" not in source.lower() and ("File::create" in text and "tmp" in text.lower()):
                self._add(
                    "Insecure Temporary File Creation",
                    "Temporary file created without using the tempfile crate. Manual temp file "
                    "creation is vulnerable to symlink attacks and race conditions.",
                    "Medium", "Low", "File Security", "CWE-377",
                    fp, node, source,
                    "Use the 'tempfile' crate for secure temporary file creation. "
                    "It handles atomic creation and proper permissions.",
                )

    # -----------------------------------------------------------------------
    # 21. Regex DoS
    # -----------------------------------------------------------------------
    def _check_regex_dos(self, root, src, source, fp):
        catastrophic_patterns = [
            (r'\([^)]*\+\)\+', "nested quantifiers"),
            (r'\([^)]*\*\)\*', "nested quantifiers"),
            (r'\([^)]*\+\)\*', "nested quantifiers"),
            (r'\([^)]*\*\)\+', "nested quantifiers"),
            (r'(\.\*){2,}', "multiple wildcards"),
            (r'\([^)]*\|[^)]*\)\+', "alternation with quantifier"),
        ]

        for node in find_nodes(root, "macro_invocation"):
            text = node_text(node, src)
            macro_name = ""
            for child in node.children:
                if child.type == "identifier":
                    macro_name = node_text(child, src)
                    break

        for node in find_nodes(root, "call_expression"):
            text = node_text(node, src)
            if "Regex::new" in text or "RegexSet::new" in text:
                # Extract the regex pattern
                for string_node in find_nodes(node, "string_literal"):
                    pattern = node_text(string_node, src)
                    for cat_pattern, issue in catastrophic_patterns:
                        if re.search(cat_pattern, pattern):
                            self._add(
                                "Potential ReDoS (Regular Expression DoS)",
                                f"Regex pattern contains {issue}, which can cause catastrophic "
                                "backtracking and denial of service with crafted input.",
                                "High", "Medium", "Denial of Service", "CWE-1333",
                                fp, node, source,
                                "Simplify the regex to avoid nested quantifiers. The Rust regex "
                                "crate uses a finite automaton and is generally safe, but complex "
                                "patterns can still cause high CPU usage. Consider using regex::bytes "
                                "with size limits on input.",
                                refs=["https://cwe.mitre.org/data/definitions/1333.html"]
                            )
                            break

    # -----------------------------------------------------------------------
    # 22. Type Confusion
    # -----------------------------------------------------------------------
    def _check_type_confusion(self, root, src, source, fp):
        for node in find_nodes(root, "call_expression"):
            text = node_text(node, src)

            if "transmute" in text:
                # Check for potentially unsafe transmute patterns
                dangerous_transmutes = [
                    ("&", "*", "reference to raw pointer"),
                    ("u8", "bool", "integer to bool"),
                    ("Vec", "String", "Vec to String without UTF-8 check"),
                    ("&[u8]", "&str", "bytes to str without UTF-8 check"),
                ]
                for from_t, to_t, desc in dangerous_transmutes:
                    if from_t in text and to_t in text:
                        self._add(
                            f"Dangerous Transmute ({desc})",
                            f"transmute used for {desc}. This can create values that violate "
                            "type invariants and cause undefined behavior.",
                            "Critical", "High", "Type Safety", "CWE-843",
                            fp, node, source,
                            "Use safe conversion functions: String::from_utf8, str::from_utf8, "
                            "as casts, or From/Into traits instead of transmute.",
                            refs=["https://doc.rust-lang.org/std/mem/fn.transmute.html"]
                        )
                        break

            # transmute_copy is even more dangerous
            if "transmute_copy" in text:
                self._add(
                    "transmute_copy Usage",
                    "transmute_copy reinterprets bits without size checks. Even more dangerous "
                    "than transmute as it can read uninitialized memory if sizes don't match.",
                    "Critical", "High", "Type Safety", "CWE-843",
                    fp, node, source,
                    "Avoid transmute_copy entirely. Use safe alternatives like byte-level serialization.",
                )

    # -----------------------------------------------------------------------
    # 23. Missing Input Validation
    # -----------------------------------------------------------------------
    def _check_input_validation(self, root, src, source, fp):
        # Check for web handler functions without input validation
        for node in find_nodes(root, "function_item"):
            text = node_text(node, src)

            # Check actix-web extractors
            if "web::Json<" in text or "web::Query<" in text or "web::Form<" in text:
                fn_body = text.split("{", 1)[1] if "{" in text else ""
                if ("validate" not in fn_body.lower() and
                    "is_empty" not in fn_body and
                    "len()" not in fn_body and
                    ".contains(" not in fn_body):
                    # Check if the struct has validation attributes
                    self._add(
                        "Missing Input Validation on Web Handler",
                        "Web handler accepts user input but does not appear to validate it. "
                        "Unvalidated input can lead to injection, overflow, and logic errors.",
                        "Medium", "Low", "Input Validation", "CWE-20",
                        fp, node, source,
                        "Use the 'validator' crate with #[derive(Validate)] on request types. "
                        "Call .validate()? at the start of each handler.",
                        "A1:2017",
                    )

        # Check for direct use of env vars without validation
        for node in find_nodes(root, "call_expression"):
            text = node_text(node, src)
            if "env::var(" in text and ".unwrap()" in text:
                self._add(
                    "Unvalidated Environment Variable",
                    "Environment variable read with unwrap(). If the variable is not set, "
                    "the program will panic. The value is also not validated.",
                    "Medium", "High", "Input Validation", "CWE-20",
                    fp, node, source,
                    "Use env::var().unwrap_or_else() with a default value, or validate "
                    "the value after reading. Use dotenv crate for .env file support.",
                )

    # -----------------------------------------------------------------------
    # 24. Resource Leaks
    # -----------------------------------------------------------------------
    def _check_resource_leaks(self, root, src, source, fp):
        for node in find_nodes(root, "call_expression"):
            text = node_text(node, src)

            # File opened but not used with RAII pattern
            if "File::open" in text or "File::create" in text:
                parent = node.parent
                if parent and parent.type == "expression_statement":
                    # File handle not stored
                    self._add(
                        "File Handle Not Stored (Potential Leak)",
                        "File opened but handle not stored in a variable. The file will be "
                        "immediately closed, which is likely unintentional.",
                        "Medium", "High", "Resource Management", "CWE-404",
                        fp, node, source,
                        "Store the file handle in a variable and use it within a scope "
                        "for automatic cleanup via Drop.",
                    )

            # into_raw without corresponding from_raw
            if "into_raw()" in text:
                parent_fn = None
                for p in parent_chain(node):
                    if p.type == "function_item":
                        parent_fn = p
                        break
                if parent_fn:
                    fn_text = node_text(parent_fn, src)
                    if "from_raw" not in fn_text:
                        self._add(
                            "Potential Memory Leak (into_raw without from_raw)",
                            "into_raw() transfers ownership to a raw pointer but no corresponding "
                            "from_raw() is visible in this function to reclaim ownership.",
                            "Medium", "Low", "Resource Management", "CWE-401",
                            fp, node, source,
                            "Ensure every into_raw() has a matching from_raw() to prevent memory leaks. "
                            "Document the ownership transfer clearly.",
                        )

        # Check for infinite loops without break conditions
        for node in find_nodes(root, "loop_expression"):
            text = node_text(node, src)
            if "loop {" in text or "loop{" in text:
                if "break" not in text and "return" not in text:
                    self._add(
                        "Infinite Loop Without Exit Condition",
                        "loop {} without a break or return statement. This will run forever "
                        "and consume CPU resources.",
                        "Medium", "Medium", "Resource Management", "CWE-835",
                        fp, node, source,
                        "Add a break condition or use while/for loops with termination conditions.",
                    )

    # -----------------------------------------------------------------------
    # 25. Timing Attacks
    # -----------------------------------------------------------------------
    def _check_timing_attacks(self, root, src, source, fp):
        for node in find_nodes(root, "binary_expression"):
            text = node_text(node, src)

            # Direct == comparison on potentially secret values
            if " == " in text:
                sensitive = ["password", "secret", "token", "key", "hash",
                            "signature", "mac", "hmac", "digest"]
                for s in sensitive:
                    if s in text.lower():
                        self._add(
                            "Potential Timing Attack (Non-Constant-Time Comparison)",
                            f"Direct equality comparison on potentially sensitive value ('{s}'). "
                            "Standard == comparison short-circuits, leaking information about "
                            "the secret through timing differences.",
                            "High", "Medium", "Cryptography", "CWE-208",
                            fp, node, source,
                            "Use constant_time_eq from the 'subtle' crate or "
                            "ring::constant_time::verify_slices_are_equal for comparing secrets.",
                            "A3:2017",
                            ["https://cwe.mitre.org/data/definitions/208.html"]
                        )
                        break

    # -----------------------------------------------------------------------
    # 26. Format String Issues
    # -----------------------------------------------------------------------
    def _check_format_string(self, root, src, source, fp):
        for node in find_nodes(root, "macro_invocation"):
            macro_name = ""
            for child in node.children:
                if child.type == "identifier":
                    macro_name = node_text(child, src)
                    break

            # format! with user-controlled values in the format string
            if macro_name in ("format", "println", "print", "write", "writeln"):
                text = node_text(node, src)
                # Check for format!("{}", user_input) used in SQL/commands
                # This is more about identifying risky composition patterns

        # Check for write! to response without escaping
        for node in find_nodes(root, "macro_invocation"):
            macro_name = ""
            for child in node.children:
                if child.type == "identifier":
                    macro_name = node_text(child, src)
                    break
            if macro_name in ("write", "writeln"):
                text = node_text(node, src)
                if "html" in text.lower() or "<" in text:
                    self._add(
                        "Unescaped HTML in Output",
                        "HTML content written without escaping. If user input is included, "
                        "this could lead to cross-site scripting (XSS).",
                        "High", "Medium", "XSS", "CWE-79",
                        fp, node, source,
                        "Use an HTML template engine with auto-escaping (Tera, Askama) "
                        "or html_escape crate. Never write raw user input as HTML.",
                        "A7:2017",
                        ["https://cwe.mitre.org/data/definitions/79.html"]
                    )

    # -----------------------------------------------------------------------
    # 27. Deprecated / Unsafe Function Usage
    # -----------------------------------------------------------------------
    def _check_deprecated_unsafe_functions(self, root, src, source, fp):
        for node in find_nodes(root, "call_expression"):
            text = node_text(node, src)

            if "std::env::set_var" in text or "env::set_var" in text:
                self._add(
                    "env::set_var is Unsafe in Multi-threaded Context",
                    "std::env::set_var is not thread-safe. In Rust 1.66+, calling it from "
                    "multiple threads is undefined behavior. It is being deprecated.",
                    "High", "High", "Thread Safety", "CWE-362",
                    fp, node, source,
                    "Set environment variables before spawning threads, or use a "
                    "thread-safe configuration mechanism instead.",
                )

            if "std::env::remove_var" in text or "env::remove_var" in text:
                self._add(
                    "env::remove_var is Unsafe in Multi-threaded Context",
                    "std::env::remove_var is not thread-safe, similar to set_var.",
                    "High", "High", "Thread Safety", "CWE-362",
                    fp, node, source,
                    "Avoid removing environment variables in multi-threaded code.",
                )

            # String::from_utf8_unchecked
            if "from_utf8_unchecked" in text:
                self._add(
                    "Unchecked UTF-8 Conversion",
                    "from_utf8_unchecked skips UTF-8 validation. If the input is not valid UTF-8, "
                    "it creates an invalid String, causing undefined behavior.",
                    "High", "High", "Memory Safety", "CWE-176",
                    fp, node, source,
                    "Use String::from_utf8() which validates the input and returns Result. "
                    "Only use unchecked if you have externally verified the data is valid UTF-8.",
                )

            # Uninitialized memory
            if "MaybeUninit::uninit().assume_init()" in text or "mem::uninitialized" in text:
                self._add(
                    "Use of Uninitialized Memory",
                    "Creating uninitialized memory and immediately assuming it's initialized. "
                    "Reading uninitialized memory is undefined behavior.",
                    "Critical", "High", "Memory Safety", "CWE-457",
                    fp, node, source,
                    "Use MaybeUninit properly: write to it first, then call assume_init(). "
                    "mem::uninitialized is deprecated; use MaybeUninit instead.",
                    refs=["https://doc.rust-lang.org/std/mem/union.MaybeUninit.html"]
                )


# ---------------------------------------------------------------------------
# Flask HTTP Server
# ---------------------------------------------------------------------------

app = Flask(__name__)
VERSION = "1.0.0"
PORT = 9009

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "language": "rust",
        "version": VERSION,
        "port": PORT,
        "engine": "tree-sitter-rust (AST-based)",
        "categories": 27,
    })

@app.route("/scan", methods=["POST"])
def scan():
    start = time.time()

    data = request.get_json(force=True)
    if not data:
        return jsonify({"error": "Invalid JSON body"}), 400

    files = data.get("files", {})
    scan_id = data.get("scanId", str(uuid.uuid4()))

    if not files:
        return jsonify({"error": "No files provided"}), 400

    log.info("[%s] Starting scan: %d files", scan_id, len(files))

    analyzer = RustAnalyzer()
    all_vulns: List[Dict] = []
    errors: List[str] = []
    rust_files = 0

    for filepath, content in files.items():
        if not filepath.endswith(".rs"):
            continue
        rust_files += 1
        try:
            vulns = analyzer.analyze_file(filepath, content)
            all_vulns.extend([asdict(v) for v in vulns])
        except Exception as e:
            errors.append(f"Error analyzing {filepath}: {str(e)}")
            log.error("Error analyzing %s: %s", filepath, e)

    duration = time.time() - start

    result = {
        "scanId": scan_id,
        "language": "rust",
        "totalFiles": len(files),
        "filesScanned": rust_files,
        "vulnerabilities": all_vulns,
        "errors": errors,
        "duration": f"{duration:.3f}s",
    }

    log.info("[%s] Scan complete: %d files, %d vulnerabilities in %s",
             scan_id, rust_files, len(all_vulns), result["duration"])

    return jsonify(result)


if __name__ == "__main__":
    log.info("Rust SAST Scanner v%s starting on port %d", VERSION, PORT)
    log.info("Engine: tree-sitter-rust (AST-based analysis)")
    log.info("Vulnerability categories: 27")
    log.info("Endpoints: GET /health, POST /scan")
    app.run(host="0.0.0.0", port=PORT, debug=False)
