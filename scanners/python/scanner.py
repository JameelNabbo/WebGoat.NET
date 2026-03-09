#!/usr/bin/env python3
"""
Offensive360 Python SAST Scanner
Comprehensive AST-based static analysis for Python code.
Runs as a FastAPI service on port 9001.
"""

import ast
import sys
import uuid
import time
import re as _re
import hashlib
import logging
import signal
import traceback
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from contextlib import contextmanager

# ---------------------------------------------------------------------------
# FastAPI imports
# ---------------------------------------------------------------------------
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("python-sast")

# ═══════════════════════════════════════════════════════════════════════════
# 1.  DATA MODELS
# ═══════════════════════════════════════════════════════════════════════════

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
class DataFlowNode:
    file: str
    line: int
    code: str

@dataclass
class Vulnerability:
    title: str
    severity: Severity
    confidence: Confidence
    cwe: str
    owasp: str
    file_path: str
    line_number: int
    column_offset: int
    end_line: int
    code_snippet: str
    remediation: str
    category: str
    data_flow: List[DataFlowNode] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": str(uuid.uuid4()),
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "filePath": self.file_path,
            "lineNumber": self.line_number,
            "columnOffset": self.column_offset,
            "endLine": self.end_line,
            "codeSnippet": self.code_snippet,
            "remediation": self.remediation,
            "category": self.category,
            "dataFlow": [{"file": n.file, "line": n.line, "code": n.code} for n in self.data_flow],
        }

# ═══════════════════════════════════════════════════════════════════════════
# 2.  TAINT TRACKING ENGINE
# ═══════════════════════════════════════════════════════════════════════════

# --- Sources: things that bring external / untrusted data in ---------------
TAINT_SOURCES: Dict[str, List[str]] = {
    # Flask
    "request.args": ["flask"],
    "request.form": ["flask"],
    "request.json": ["flask"],
    "request.data": ["flask"],
    "request.values": ["flask"],
    "request.files": ["flask"],
    "request.cookies": ["flask"],
    "request.headers": ["flask"],
    "request.get_json": ["flask"],
    # Django
    "request.GET": ["django"],
    "request.POST": ["django"],
    "request.META": ["django"],
    "request.COOKIES": ["django"],
    "request.body": ["django"],
    # FastAPI
    "request.query_params": ["fastapi"],
    "request.path_params": ["fastapi"],
    # stdlib
    "sys.argv": ["stdlib"],
    "os.environ": ["stdlib"],
    "input": ["stdlib"],
}

# --- Sinks: dangerous functions that should never receive tainted data -----
TAINT_SINKS: Dict[str, Dict[str, str]] = {
    # SQL
    "cursor.execute":       {"cat": "SQL Injection",       "cwe": "CWE-89",  "owasp": "A03:2021", "sev": "Critical"},
    "cursor.executemany":   {"cat": "SQL Injection",       "cwe": "CWE-89",  "owasp": "A03:2021", "sev": "Critical"},
    "connection.execute":   {"cat": "SQL Injection",       "cwe": "CWE-89",  "owasp": "A03:2021", "sev": "Critical"},
    "engine.execute":       {"cat": "SQL Injection",       "cwe": "CWE-89",  "owasp": "A03:2021", "sev": "Critical"},
    "session.execute":      {"cat": "SQL Injection",       "cwe": "CWE-89",  "owasp": "A03:2021", "sev": "Critical"},
    "text":                 {"cat": "SQL Injection",       "cwe": "CWE-89",  "owasp": "A03:2021", "sev": "Critical"},
    # Command
    "os.system":            {"cat": "Command Injection",   "cwe": "CWE-78",  "owasp": "A03:2021", "sev": "Critical"},
    "os.popen":             {"cat": "Command Injection",   "cwe": "CWE-78",  "owasp": "A03:2021", "sev": "Critical"},
    "subprocess.call":      {"cat": "Command Injection",   "cwe": "CWE-78",  "owasp": "A03:2021", "sev": "Critical"},
    "subprocess.run":       {"cat": "Command Injection",   "cwe": "CWE-78",  "owasp": "A03:2021", "sev": "Critical"},
    "subprocess.Popen":     {"cat": "Command Injection",   "cwe": "CWE-78",  "owasp": "A03:2021", "sev": "Critical"},
    "subprocess.check_output": {"cat": "Command Injection","cwe": "CWE-78",  "owasp": "A03:2021", "sev": "Critical"},
    "subprocess.check_call":{"cat": "Command Injection",   "cwe": "CWE-78",  "owasp": "A03:2021", "sev": "Critical"},
    # Code injection
    "eval":                 {"cat": "Code Injection",      "cwe": "CWE-94",  "owasp": "A03:2021", "sev": "Critical"},
    "exec":                 {"cat": "Code Injection",      "cwe": "CWE-94",  "owasp": "A03:2021", "sev": "Critical"},
    "compile":              {"cat": "Code Injection",      "cwe": "CWE-94",  "owasp": "A03:2021", "sev": "High"},
    # Deserialization
    "pickle.loads":         {"cat": "Deserialization",     "cwe": "CWE-502", "owasp": "A08:2021", "sev": "Critical"},
    "pickle.load":          {"cat": "Deserialization",     "cwe": "CWE-502", "owasp": "A08:2021", "sev": "Critical"},
    "yaml.load":            {"cat": "Deserialization",     "cwe": "CWE-502", "owasp": "A08:2021", "sev": "High"},
    "yaml.unsafe_load":     {"cat": "Deserialization",     "cwe": "CWE-502", "owasp": "A08:2021", "sev": "Critical"},
    "marshal.loads":        {"cat": "Deserialization",     "cwe": "CWE-502", "owasp": "A08:2021", "sev": "Critical"},
    "shelve.open":          {"cat": "Deserialization",     "cwe": "CWE-502", "owasp": "A08:2021", "sev": "High"},
    "jsonpickle.decode":    {"cat": "Deserialization",     "cwe": "CWE-502", "owasp": "A08:2021", "sev": "Critical"},
    # SSRF
    "requests.get":         {"cat": "SSRF",                "cwe": "CWE-918", "owasp": "A10:2021", "sev": "High"},
    "requests.post":        {"cat": "SSRF",                "cwe": "CWE-918", "owasp": "A10:2021", "sev": "High"},
    "requests.put":         {"cat": "SSRF",                "cwe": "CWE-918", "owasp": "A10:2021", "sev": "High"},
    "requests.delete":      {"cat": "SSRF",                "cwe": "CWE-918", "owasp": "A10:2021", "sev": "High"},
    "requests.head":        {"cat": "SSRF",                "cwe": "CWE-918", "owasp": "A10:2021", "sev": "High"},
    "requests.patch":       {"cat": "SSRF",                "cwe": "CWE-918", "owasp": "A10:2021", "sev": "High"},
    "urllib.request.urlopen":{"cat": "SSRF",               "cwe": "CWE-918", "owasp": "A10:2021", "sev": "High"},
    "httpx.get":            {"cat": "SSRF",                "cwe": "CWE-918", "owasp": "A10:2021", "sev": "High"},
    "httpx.post":           {"cat": "SSRF",                "cwe": "CWE-918", "owasp": "A10:2021", "sev": "High"},
    # Path traversal
    "open":                 {"cat": "Path Traversal",      "cwe": "CWE-22",  "owasp": "A01:2021", "sev": "High"},
    "os.path.join":         {"cat": "Path Traversal",      "cwe": "CWE-22",  "owasp": "A01:2021", "sev": "High"},
    "shutil.copy":          {"cat": "Path Traversal",      "cwe": "CWE-22",  "owasp": "A01:2021", "sev": "High"},
    "shutil.move":          {"cat": "Path Traversal",      "cwe": "CWE-22",  "owasp": "A01:2021", "sev": "High"},
    # XSS / Template injection
    "render_template_string":{"cat":"Template Injection",  "cwe": "CWE-79",  "owasp": "A03:2021", "sev": "High"},
    "Markup":               {"cat": "XSS",                 "cwe": "CWE-79",  "owasp": "A03:2021", "sev": "High"},
    "mark_safe":            {"cat": "XSS",                 "cwe": "CWE-79",  "owasp": "A03:2021", "sev": "High"},
    "Jinja2.Template":      {"cat": "Template Injection",  "cwe": "CWE-1336","owasp": "A03:2021", "sev": "High"},
    # LDAP
    "ldap.search_s":        {"cat": "LDAP Injection",      "cwe": "CWE-90",  "owasp": "A03:2021", "sev": "High"},
    "ldap.search":          {"cat": "LDAP Injection",      "cwe": "CWE-90",  "owasp": "A03:2021", "sev": "High"},
}

# --- Sanitizers: functions that cleanse tainted data ----------------------
SANITIZERS: Set[str] = {
    "int", "float", "bool", "str", "abs",
    "bleach.clean", "escape", "html.escape", "markupsafe.escape",
    "quote", "urllib.parse.quote", "shlex.quote",
    "sanitize", "clean", "strip_tags",
    "parameterize", "prepared",
    "validator",
}

# ═══════════════════════════════════════════════════════════════════════════
# 3.  AST HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _node_name(node: ast.AST) -> str:
    """Resolve a dotted name from an AST node (e.g. os.path.join)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        val = _node_name(node.value)
        if val:
            return f"{val}.{node.attr}"
        return node.attr
    if isinstance(node, ast.Subscript):
        return _node_name(node.value)
    return ""

def _node_line(node: ast.AST) -> int:
    return getattr(node, "lineno", 0)

def _node_col(node: ast.AST) -> int:
    return getattr(node, "col_offset", 0)

def _node_end_line(node: ast.AST) -> int:
    return getattr(node, "end_lineno", None) or _node_line(node)

def _get_source_line(lines: List[str], lineno: int) -> str:
    if 0 < lineno <= len(lines):
        return lines[lineno - 1].rstrip()
    return ""

def _get_snippet(lines: List[str], lineno: int, context: int = 2) -> str:
    start = max(0, lineno - 1 - context)
    end = min(len(lines), lineno + context)
    parts = []
    for i in range(start, end):
        prefix = ">>>" if i == lineno - 1 else "   "
        parts.append(f"{prefix} {i+1}: {lines[i].rstrip()}")
    return "\n".join(parts)

def _contains_taint_source(node: ast.AST) -> Optional[str]:
    """Return the taint-source name if the node references one, else None."""
    name = _node_name(node)
    if not name:
        return None
    for src in TAINT_SOURCES:
        if name == src or name.endswith("." + src) or src.endswith("." + name):
            return src
        # subscript access: request.args["key"] / request.GET["key"]
        if isinstance(node, ast.Subscript):
            base = _node_name(node.value)
            if base and (base == src or base.endswith("." + src)):
                return src
    # input() call
    if isinstance(node, ast.Call):
        fn = _node_name(node.func)
        if fn == "input":
            return "input"
    return None

def _is_tainted_expr(node: ast.AST, tainted_vars: Set[str]) -> Tuple[bool, Optional[str]]:
    """Check if an expression is tainted (references a tainted variable or source)."""
    # Direct source reference
    src = _contains_taint_source(node)
    if src:
        return True, src

    # Variable reference
    if isinstance(node, ast.Name) and node.id in tainted_vars:
        return True, node.id

    # Attribute on tainted var  (e.g.  user_input.strip())
    if isinstance(node, ast.Attribute):
        base = _node_name(node.value)
        if base in tainted_vars:
            return True, base

    # Subscript on tainted var
    if isinstance(node, ast.Subscript):
        base = _node_name(node.value)
        if base in tainted_vars:
            return True, base

    # String concat / formatting propagates taint
    if isinstance(node, ast.BinOp):
        l_taint = _is_tainted_expr(node.left, tainted_vars)
        r_taint = _is_tainted_expr(node.right, tainted_vars)
        if l_taint[0]:
            return l_taint
        if r_taint[0]:
            return r_taint

    # f-string
    if isinstance(node, ast.JoinedStr):
        for val in node.values:
            if isinstance(val, ast.FormattedValue):
                t = _is_tainted_expr(val.value, tainted_vars)
                if t[0]:
                    return t

    # .format() call
    if isinstance(node, ast.Call):
        fn = _node_name(node.func)
        # Check if the call itself is a taint source
        if fn == "input" or fn in TAINT_SOURCES:
            return True, fn
        # Propagate through .format()
        if fn and fn.endswith(".format"):
            for arg in node.args:
                t = _is_tainted_expr(arg, tainted_vars)
                if t[0]:
                    return t
            for kw in node.keywords:
                t = _is_tainted_expr(kw.value, tainted_vars)
                if t[0]:
                    return t
        # str() / int() etc. are sanitizers
        if fn in SANITIZERS:
            return False, None
        # If calling with a tainted argument
        for arg in node.args:
            t = _is_tainted_expr(arg, tainted_vars)
            if t[0]:
                # Check if the callee is a sanitizer
                if fn in SANITIZERS:
                    return False, None
                return t

    # % formatting
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        if isinstance(node.right, ast.Tuple):
            for elt in node.right.elts:
                t = _is_tainted_expr(elt, tainted_vars)
                if t[0]:
                    return t
        else:
            t = _is_tainted_expr(node.right, tainted_vars)
            if t[0]:
                return t

    # List / Tuple / Set / Dict may carry taint
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for elt in node.elts:
            t = _is_tainted_expr(elt, tainted_vars)
            if t[0]:
                return t

    return False, None


def _is_sanitizer_call(node: ast.AST) -> bool:
    """Check if a call node is a sanitizer."""
    if isinstance(node, ast.Call):
        fn = _node_name(node.func)
        return fn in SANITIZERS
    return False

def _call_name(node: ast.Call) -> str:
    return _node_name(node.func)


# ═══════════════════════════════════════════════════════════════════════════
# 4.  FILE ANALYZER  (heart of the scanner)
# ═══════════════════════════════════════════════════════════════════════════

class FileAnalyzer:
    """Analyze a single Python file's AST for security vulnerabilities."""

    def __init__(self, file_path: str, source: str):
        self.file_path = file_path
        self.source = source
        self.lines = source.splitlines()
        self.vulns: List[Vulnerability] = []
        self.tainted_vars: Set[str] = set()
        self.taint_origins: Dict[str, Tuple[int, str]] = {}  # var -> (line, source_desc)
        self.var_assignments: Dict[str, List[Tuple[int, ast.AST]]] = {}  # var -> [(line, node)]
        self.imports: Dict[str, str] = {}  # alias -> module
        self.function_params: Dict[str, Set[str]] = {}  # func_name -> param set
        self.class_bases: Dict[str, List[str]] = {}  # class_name -> [base classes]
        self.decorators: Dict[str, List[str]] = {}  # func_name -> [decorator names]
        self.tree: Optional[ast.AST] = None
        self.current_function: Optional[str] = None
        self.has_csrf_exempt: bool = False
        self.django_settings: Dict[str, Any] = {}
        self.string_constants: Dict[str, Tuple[str, int]] = {}  # var -> (value, line)

    # --- parse + full analysis ---
    def analyze(self) -> List[Vulnerability]:
        try:
            self.tree = ast.parse(self.source, filename=self.file_path)
        except SyntaxError:
            return self.vulns

        # Phase 1: Gather metadata (imports, assignments, classes, funcs)
        self._gather_metadata(self.tree)
        # Phase 2: Taint propagation
        self._propagate_taint(self.tree)
        # Phase 3: Rule-based checks
        self._check_all_rules(self.tree)

        return self.vulns

    # ─── Phase 1: metadata gathering ──────────────────────────────────────
    def _gather_metadata(self, tree: ast.AST):
        for node in ast.walk(tree):
            # Imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.imports[alias.asname or alias.name] = alias.name
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for alias in node.names:
                    full = f"{mod}.{alias.name}" if mod else alias.name
                    self.imports[alias.asname or alias.name] = full

            # Assignments
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    name = _node_name(target)
                    if name:
                        self.var_assignments.setdefault(name, []).append((_node_line(node), node.value))
                        # Track string constants
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            self.string_constants[name] = (node.value.value, _node_line(node))

            # Function definitions
            elif isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                params = set()
                for arg in node.args.args:
                    params.add(arg.arg)
                self.function_params[node.name] = params
                # Decorators
                decs = []
                for d in node.decorator_list:
                    decs.append(_node_name(d))
                self.decorators[node.name] = decs

            # Classes
            elif isinstance(node, ast.ClassDef):
                bases = [_node_name(b) for b in node.bases if _node_name(b)]
                self.class_bases[node.name] = bases

    # ─── Phase 2: taint propagation ───────────────────────────────────────
    def _propagate_taint(self, tree: ast.AST):
        """Walk the AST, marking variables as tainted when they receive user input."""
        for node in ast.walk(tree):
            # Track function context
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.current_function = node.name
                # Mark function params as tainted if they come from web frameworks
                # (heuristic: params named request, data, body, user_input, etc.)
                for arg in node.args.args:
                    if arg.arg in ("request",):
                        self.tainted_vars.add(arg.arg)
                        self.taint_origins[arg.arg] = (_node_line(node), "function parameter")
                    # FastAPI path/query params are user input
                    decs = self.decorators.get(node.name, [])
                    for dec in decs:
                        if dec and ("app.get" in dec or "app.post" in dec or "app.put" in dec
                                    or "app.delete" in dec or "router.get" in dec or "router.post" in dec
                                    or "api_view" in dec):
                            # All non-self/cls params in route handlers are user input
                            if arg.arg not in ("self", "cls", "request", "db", "session"):
                                self.tainted_vars.add(arg.arg)
                                self.taint_origins[arg.arg] = (_node_line(node), "route parameter")

            # Assignment: propagate taint
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    tgt_name = _node_name(target)
                    if not tgt_name:
                        continue
                    is_tainted, source = _is_tainted_expr(node.value, self.tainted_vars)
                    if is_tainted:
                        self.tainted_vars.add(tgt_name)
                        self.taint_origins[tgt_name] = (_node_line(node), source or "unknown")
                    elif _is_sanitizer_call(node.value):
                        # Sanitization removes taint
                        self.tainted_vars.discard(tgt_name)

    # ─── Phase 3: rule checks ─────────────────────────────────────────────
    def _check_all_rules(self, tree: ast.AST):
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.current_function = node.name

            if isinstance(node, ast.Call):
                self._check_taint_sinks(node)
                self._check_sql_injection(node)
                self._check_command_injection(node)
                self._check_code_injection(node)
                self._check_deserialization(node)
                self._check_ssrf(node)
                self._check_path_traversal(node)
                self._check_xss(node)
                self._check_ldap_injection(node)
                self._check_weak_crypto(node)
                self._check_insecure_random(node)
                self._check_xxe(node)
                self._check_ssl_verify_disabled(node)
                self._check_temp_file_issues(node)
                self._check_subprocess_shell(node)
                self._check_unsafe_yaml(node)
                self._check_jwt_issues(node)
                self._check_open_redirect(node)
                self._check_template_injection(node)
                self._check_logging_sensitive(node)
                self._check_unsafe_xml(node)

            if isinstance(node, ast.Assign):
                self._check_hardcoded_secrets(node)
                self._check_debug_mode(node)
                self._check_django_settings(node)
                self._check_flask_settings(node)
                self._check_mass_assignment(node)
                self._check_cors_star(node)
                self._check_timing_attack(node)

            if isinstance(node, ast.Compare):
                self._check_timing_attack_compare(node)

            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._check_missing_auth(node)
                self._check_fastapi_no_auth(node)
                self._check_race_conditions(node)
                self._check_input_validation(node)
                self._check_insecure_file_upload(node)

            if isinstance(node, ast.ClassDef):
                self._check_django_model_form(node)
                self._check_prototype_pollution(node)

            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                self._check_redos(node)

        # File-level checks
        self._check_hardcoded_secrets_strings()
        self._check_django_csrf(tree)
        self._check_insufficient_logging(tree)
        self._check_information_disclosure(tree)
        self._check_security_misconfiguration(tree)
        self._check_integer_overflow(tree)
        self._check_buffer_issues(tree)

    # ─── Helpers to add vulnerabilities ─────────────────────────────────
    def _add(self, node: ast.AST, title: str, severity: Severity, confidence: Confidence,
             cwe: str, owasp: str, category: str, remediation: str,
             data_flow: Optional[List[DataFlowNode]] = None):
        line = _node_line(node)
        self.vulns.append(Vulnerability(
            title=title, severity=severity, confidence=confidence,
            cwe=cwe, owasp=owasp, file_path=self.file_path,
            line_number=line, column_offset=_node_col(node),
            end_line=_node_end_line(node),
            code_snippet=_get_snippet(self.lines, line),
            remediation=remediation, category=category,
            data_flow=data_flow or [],
        ))

    def _build_data_flow(self, var_name: str, sink_line: int, sink_code: str) -> List[DataFlowNode]:
        """Build a data-flow trace from source to sink for a tainted variable."""
        flow: List[DataFlowNode] = []
        origin = self.taint_origins.get(var_name)
        if origin:
            line_no, src = origin
            flow.append(DataFlowNode(file=self.file_path, line=line_no,
                                     code=_get_source_line(self.lines, line_no)))
        # Check intermediate assignments
        if var_name in self.var_assignments:
            for assign_line, _ in self.var_assignments[var_name]:
                if assign_line != (origin[0] if origin else 0) and assign_line != sink_line:
                    flow.append(DataFlowNode(file=self.file_path, line=assign_line,
                                             code=_get_source_line(self.lines, assign_line)))
        # Sink
        flow.append(DataFlowNode(file=self.file_path, line=sink_line,
                                 code=_get_source_line(self.lines, sink_line)))
        # Sort by line
        flow.sort(key=lambda n: n.line)
        return flow

    # ═══════════════════════════════════════════════════════════════════
    #  TAINT SINK CHECK  (the main taint-tracking rule)
    # ═══════════════════════════════════════════════════════════════════
    def _check_taint_sinks(self, node: ast.Call):
        fn = _call_name(node)
        if not fn:
            return
        sink_info = TAINT_SINKS.get(fn)
        if not sink_info:
            # Check partial matches (e.g. subprocess.run vs subprocess.run)
            for sink_name, info in TAINT_SINKS.items():
                if fn.endswith(sink_name) or fn == sink_name.split(".")[-1]:
                    sink_info = info
                    break
        if not sink_info:
            return

        # Check each argument for taint
        for arg in node.args:
            is_tainted, source = _is_tainted_expr(arg, self.tainted_vars)
            if is_tainted:
                sev = Severity(sink_info["sev"])
                data_flow = self._build_data_flow(source or "unknown",
                                                  _node_line(node),
                                                  _get_source_line(self.lines, _node_line(node)))
                self._add(node,
                         f"{sink_info['cat']}: tainted data flows to {fn}()",
                         sev, Confidence.HIGH,
                         sink_info["cwe"], sink_info["owasp"],
                         sink_info["cat"],
                         f"Sanitize or validate the input before passing it to {fn}(). "
                         f"Taint source: {source}",
                         data_flow=data_flow)
                return  # one finding per call

        # Keyword arguments
        for kw in node.keywords:
            is_tainted, source = _is_tainted_expr(kw.value, self.tainted_vars)
            if is_tainted:
                sev = Severity(sink_info["sev"])
                data_flow = self._build_data_flow(source or "unknown",
                                                  _node_line(node),
                                                  _get_source_line(self.lines, _node_line(node)))
                self._add(node,
                         f"{sink_info['cat']}: tainted data flows to {fn}() via kwarg '{kw.arg}'",
                         sev, Confidence.HIGH,
                         sink_info["cwe"], sink_info["owasp"],
                         sink_info["cat"],
                         f"Sanitize or validate the input before passing it to {fn}(). "
                         f"Taint source: {source}",
                         data_flow=data_flow)
                return

    # ═══════════════════════════════════════════════════════════════════
    #  1. SQL INJECTION
    # ═══════════════════════════════════════════════════════════════════
    def _check_sql_injection(self, node: ast.Call):
        fn = _call_name(node)
        sql_funcs = {"execute", "executemany", "raw", "extra", "cursor.execute",
                     "cursor.executemany", "connection.execute", "engine.execute",
                     "session.execute", "db.execute", "db.engine.execute"}

        is_sql_func = False
        for sf in sql_funcs:
            if fn and (fn == sf or fn.endswith("." + sf)):
                is_sql_func = True
                break

        if not is_sql_func:
            return

        if not node.args:
            return

        query_arg = node.args[0]

        # Check for string concatenation in query
        if isinstance(query_arg, ast.BinOp) and isinstance(query_arg.op, ast.Add):
            self._add(node,
                     "SQL Injection: String concatenation in SQL query",
                     Severity.CRITICAL, Confidence.HIGH,
                     "CWE-89", "A03:2021", "Injection",
                     "Use parameterized queries instead of string concatenation. "
                     "Example: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))")
            return

        # Check for f-string in query
        if isinstance(query_arg, ast.JoinedStr):
            self._add(node,
                     "SQL Injection: f-string used in SQL query",
                     Severity.CRITICAL, Confidence.HIGH,
                     "CWE-89", "A03:2021", "Injection",
                     "Never use f-strings for SQL queries. Use parameterized queries instead.")
            return

        # Check for % formatting in query
        if isinstance(query_arg, ast.BinOp) and isinstance(query_arg.op, ast.Mod):
            self._add(node,
                     "SQL Injection: %-format string in SQL query",
                     Severity.CRITICAL, Confidence.HIGH,
                     "CWE-89", "A03:2021", "Injection",
                     "Use parameterized queries instead of % string formatting.")
            return

        # Check for .format() in query
        if isinstance(query_arg, ast.Call):
            qfn = _call_name(query_arg)
            if qfn and qfn.endswith(".format"):
                self._add(node,
                         "SQL Injection: .format() used in SQL query",
                         Severity.CRITICAL, Confidence.HIGH,
                         "CWE-89", "A03:2021", "Injection",
                         "Use parameterized queries instead of .format() for SQL queries.")
                return

        # SQLAlchemy text() with string formatting
        if fn and fn.endswith("text"):
            if isinstance(query_arg, (ast.JoinedStr, ast.BinOp)):
                self._add(node,
                         "SQL Injection: Dynamic string in SQLAlchemy text()",
                         Severity.CRITICAL, Confidence.HIGH,
                         "CWE-89", "A03:2021", "Injection",
                         "Use bound parameters with text(): text('SELECT * FROM users WHERE id = :id').bindparams(id=user_id)")
                return

    # ═══════════════════════════════════════════════════════════════════
    #  2. COMMAND INJECTION
    # ═══════════════════════════════════════════════════════════════════
    def _check_command_injection(self, node: ast.Call):
        fn = _call_name(node)
        if not fn:
            return

        cmd_funcs = {"os.system", "os.popen", "os.popen2", "os.popen3", "os.popen4",
                     "commands.getoutput", "commands.getstatusoutput"}

        for cf in cmd_funcs:
            if fn == cf or fn.endswith("." + cf.split(".")[-1]) and cf.split(".")[0] in fn:
                if node.args:
                    arg = node.args[0]
                    # Any string formatting = critical
                    if isinstance(arg, (ast.BinOp, ast.JoinedStr)):
                        self._add(node,
                                 f"Command Injection: Dynamic string in {fn}()",
                                 Severity.CRITICAL, Confidence.HIGH,
                                 "CWE-78", "A03:2021", "Injection",
                                 "Never pass user-controlled data to OS commands. "
                                 "Use subprocess with a list of arguments and shell=False.")
                    elif isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                        df = self._build_data_flow(arg.id, _node_line(node),
                                                   _get_source_line(self.lines, _node_line(node)))
                        self._add(node,
                                 f"Command Injection: Tainted variable in {fn}()",
                                 Severity.CRITICAL, Confidence.HIGH,
                                 "CWE-78", "A03:2021", "Injection",
                                 "Never pass user-controlled data to OS commands. "
                                 "Use subprocess with a list of arguments and shell=False.",
                                 data_flow=df)
                    else:
                        # Even static strings in os.system are a code smell
                        self._add(node,
                                 f"Command Injection risk: Use of {fn}()",
                                 Severity.MEDIUM, Confidence.MEDIUM,
                                 "CWE-78", "A03:2021", "Injection",
                                 f"Avoid {fn}(). Use subprocess.run() with shell=False and a list of arguments.")
                return

    # ═══════════════════════════════════════════════════════════════════
    #  3. CODE INJECTION
    # ═══════════════════════════════════════════════════════════════════
    def _check_code_injection(self, node: ast.Call):
        fn = _call_name(node)
        if fn not in ("eval", "exec", "compile", "execfile"):
            return

        if not node.args:
            return

        arg = node.args[0]

        # With tainted data
        is_tainted, source = _is_tainted_expr(arg, self.tainted_vars)
        if is_tainted:
            df = self._build_data_flow(source or "unknown", _node_line(node),
                                       _get_source_line(self.lines, _node_line(node)))
            self._add(node,
                     f"Code Injection: User input in {fn}()",
                     Severity.CRITICAL, Confidence.HIGH,
                     "CWE-94", "A03:2021", "Injection",
                     f"Never pass user input to {fn}(). Use safe alternatives like ast.literal_eval() for eval, "
                     "or redesign to avoid dynamic code execution.",
                     data_flow=df)
            return

        # Dynamic string (concat, format, f-string)
        if isinstance(arg, (ast.BinOp, ast.JoinedStr)):
            self._add(node,
                     f"Code Injection: Dynamic string in {fn}()",
                     Severity.HIGH, Confidence.MEDIUM,
                     "CWE-94", "A03:2021", "Injection",
                     f"Avoid {fn}() with dynamic strings. Use ast.literal_eval() or safe alternatives.")
            return

        # Even with static string, eval/exec is risky
        if fn in ("eval", "exec"):
            self._add(node,
                     f"Code Injection risk: Use of {fn}()",
                     Severity.MEDIUM, Confidence.LOW,
                     "CWE-94", "A03:2021", "Injection",
                     f"Avoid {fn}(). Consider using ast.literal_eval() or other safe alternatives.")

    # ═══════════════════════════════════════════════════════════════════
    #  4. XSS
    # ═══════════════════════════════════════════════════════════════════
    def _check_xss(self, node: ast.Call):
        fn = _call_name(node)
        if not fn:
            return

        # mark_safe / Markup with dynamic content
        if fn in ("mark_safe", "Markup", "markupsafe.Markup"):
            if node.args:
                arg = node.args[0]
                is_tainted, src = _is_tainted_expr(arg, self.tainted_vars)
                if is_tainted or isinstance(arg, (ast.BinOp, ast.JoinedStr)):
                    self._add(node,
                             "XSS: User input passed to mark_safe/Markup",
                             Severity.HIGH, Confidence.HIGH,
                             "CWE-79", "A03:2021", "XSS",
                             "Never pass user-controlled data to mark_safe() or Markup(). "
                             "Use template auto-escaping instead.")
                else:
                    self._add(node,
                             "XSS: Use of mark_safe/Markup",
                             Severity.MEDIUM, Confidence.LOW,
                             "CWE-79", "A03:2021", "XSS",
                             "Review mark_safe/Markup usage. Prefer template auto-escaping.")

        # Flask render_template_string
        if fn in ("render_template_string",) or (fn and fn.endswith("render_template_string")):
            if node.args:
                arg = node.args[0]
                if isinstance(arg, (ast.BinOp, ast.JoinedStr)) or isinstance(arg, ast.Name):
                    self._add(node,
                             "XSS/Template Injection: Dynamic render_template_string",
                             Severity.HIGH, Confidence.HIGH,
                             "CWE-79", "A03:2021", "XSS",
                             "Use render_template() with a file-based template instead of render_template_string(). "
                             "Never construct templates from user input.")

        # Django |safe or autoescape off — checked in string constants
        # HttpResponse with content_type text/html
        if fn in ("HttpResponse",) or (fn and fn.endswith("HttpResponse")):
            if node.args:
                arg = node.args[0]
                is_tainted, _ = _is_tainted_expr(arg, self.tainted_vars)
                if is_tainted or isinstance(arg, (ast.BinOp, ast.JoinedStr)):
                    self._add(node,
                             "XSS: User input in HttpResponse",
                             Severity.HIGH, Confidence.MEDIUM,
                             "CWE-79", "A03:2021", "XSS",
                             "Use Django template rendering instead of constructing HTML in HttpResponse directly.")

    # ═══════════════════════════════════════════════════════════════════
    #  5. PATH TRAVERSAL
    # ═══════════════════════════════════════════════════════════════════
    def _check_path_traversal(self, node: ast.Call):
        fn = _call_name(node)
        if not fn:
            return

        path_funcs = {"open", "builtins.open", "io.open",
                      "os.path.join", "pathlib.Path",
                      "shutil.copy", "shutil.copy2", "shutil.move", "shutil.copytree",
                      "os.rename", "os.remove", "os.unlink", "os.mkdir", "os.makedirs",
                      "os.rmdir", "os.listdir", "os.scandir",
                      "send_file", "send_from_directory"}

        matched = False
        for pf in path_funcs:
            if fn == pf or fn.endswith("." + pf.split(".")[-1]):
                matched = True
                break

        if not matched:
            return

        if not node.args:
            return

        arg = node.args[0]
        is_tainted, source = _is_tainted_expr(arg, self.tainted_vars)
        if is_tainted:
            df = self._build_data_flow(source or "unknown", _node_line(node),
                                       _get_source_line(self.lines, _node_line(node)))
            self._add(node,
                     f"Path Traversal: User input in {fn}()",
                     Severity.HIGH, Confidence.HIGH,
                     "CWE-22", "A01:2021", "Path Traversal",
                     "Validate and sanitize file paths. Use os.path.realpath() and verify "
                     "the resolved path is within the expected directory. "
                     "Never directly use user input in file operations.",
                     data_flow=df)
        elif isinstance(arg, (ast.BinOp, ast.JoinedStr)):
            self._add(node,
                     f"Path Traversal: Dynamic path in {fn}()",
                     Severity.MEDIUM, Confidence.MEDIUM,
                     "CWE-22", "A01:2021", "Path Traversal",
                     "Validate file paths to prevent directory traversal. "
                     "Use os.path.realpath() to resolve and check against allowed directories.")

    # ═══════════════════════════════════════════════════════════════════
    #  6. DESERIALIZATION
    # ═══════════════════════════════════════════════════════════════════
    def _check_deserialization(self, node: ast.Call):
        fn = _call_name(node)
        if not fn:
            return

        # pickle
        pickle_funcs = {"pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load",
                        "_pickle.loads", "_pickle.load", "dill.loads", "dill.load",
                        "cloudpickle.loads", "cloudpickle.load"}
        for pf in pickle_funcs:
            if fn == pf or fn.endswith("." + pf.split(".")[-1]):
                self._add(node,
                         f"Insecure Deserialization: {fn}() allows arbitrary code execution",
                         Severity.CRITICAL, Confidence.HIGH,
                         "CWE-502", "A08:2021", "Deserialization",
                         "Never unpickle data from untrusted sources. Use JSON, MessagePack, or "
                         "Protocol Buffers for safe serialization. If pickle is required, use "
                         "hmac to verify the data integrity.")
                return

        # marshal
        if fn in ("marshal.loads", "marshal.load"):
            self._add(node,
                     f"Insecure Deserialization: {fn}() is unsafe",
                     Severity.CRITICAL, Confidence.HIGH,
                     "CWE-502", "A08:2021", "Deserialization",
                     "marshal module is not secure. Use JSON or other safe formats.")
            return

        # shelve
        if fn in ("shelve.open",):
            self._add(node,
                     "Insecure Deserialization: shelve uses pickle internally",
                     Severity.HIGH, Confidence.MEDIUM,
                     "CWE-502", "A08:2021", "Deserialization",
                     "shelve uses pickle internally and is unsafe for untrusted data. Use a database instead.")
            return

        # jsonpickle
        if fn in ("jsonpickle.decode", "jsonpickle.loads"):
            self._add(node,
                     f"Insecure Deserialization: {fn}() allows code execution",
                     Severity.CRITICAL, Confidence.HIGH,
                     "CWE-502", "A08:2021", "Deserialization",
                     "jsonpickle.decode can execute arbitrary code. Use json.loads() instead.")
            return

    # ═══════════════════════════════════════════════════════════════════
    #  7. SSRF
    # ═══════════════════════════════════════════════════════════════════
    def _check_ssrf(self, node: ast.Call):
        fn = _call_name(node)
        if not fn:
            return

        http_funcs = {"requests.get", "requests.post", "requests.put", "requests.delete",
                      "requests.head", "requests.patch", "requests.request",
                      "urllib.request.urlopen", "urllib.urlopen",
                      "httpx.get", "httpx.post", "httpx.put", "httpx.delete",
                      "aiohttp.ClientSession.get", "aiohttp.ClientSession.post"}

        matched_fn = None
        for hf in http_funcs:
            if fn == hf or fn.endswith("." + hf.split(".")[-1]):
                matched_fn = hf
                break

        if not matched_fn:
            return

        if not node.args:
            return

        url_arg = node.args[0]
        is_tainted, source = _is_tainted_expr(url_arg, self.tainted_vars)
        if is_tainted:
            df = self._build_data_flow(source or "unknown", _node_line(node),
                                       _get_source_line(self.lines, _node_line(node)))
            self._add(node,
                     f"SSRF: User-controlled URL in {fn}()",
                     Severity.HIGH, Confidence.HIGH,
                     "CWE-918", "A10:2021", "SSRF",
                     "Validate and whitelist allowed URLs/domains. Never let users "
                     "control the full URL in server-side HTTP requests. "
                     "Use an allowlist of permitted hosts.",
                     data_flow=df)
        elif isinstance(url_arg, (ast.BinOp, ast.JoinedStr)):
            self._add(node,
                     f"SSRF: Dynamic URL in {fn}()",
                     Severity.MEDIUM, Confidence.MEDIUM,
                     "CWE-918", "A10:2021", "SSRF",
                     "Validate and whitelist URLs before making server-side requests.")

    # ═══════════════════════════════════════════════════════════════════
    #  8. XXE
    # ═══════════════════════════════════════════════════════════════════
    def _check_xxe(self, node: ast.Call):
        fn = _call_name(node)
        if not fn:
            return

        # xml.etree.ElementTree.parse / fromstring
        xml_parse_funcs = {"ElementTree.parse", "ET.parse", "ET.fromstring",
                           "ElementTree.fromstring", "etree.parse", "etree.fromstring",
                           "xml.etree.ElementTree.parse", "xml.etree.ElementTree.fromstring",
                           "minidom.parse", "minidom.parseString",
                           "xml.dom.minidom.parse", "xml.dom.minidom.parseString",
                           "sax.parse", "sax.parseString",
                           "pulldom.parse", "pulldom.parseString"}

        for xf in xml_parse_funcs:
            if fn == xf or fn.endswith("." + xf.split(".")[-1]):
                self._add(node,
                         f"XXE: {fn}() may be vulnerable to XML External Entity attacks",
                         Severity.HIGH, Confidence.MEDIUM,
                         "CWE-611", "A05:2021", "XXE",
                         "Use defusedxml library instead: import defusedxml.ElementTree as ET. "
                         "Alternatively, disable external entity processing explicitly.")
                return

        # lxml
        if fn and ("lxml" in fn or fn.endswith("XMLParser") or fn.endswith("HTMLParser")):
            # Check for resolve_entities=True or no resolve_entities kwarg
            has_safe = False
            for kw in node.keywords:
                if kw.arg == "resolve_entities":
                    if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        has_safe = True
                if kw.arg == "no_network":
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        has_safe = True
            if not has_safe:
                self._add(node,
                         f"XXE: {fn}() without safe parser configuration",
                         Severity.HIGH, Confidence.MEDIUM,
                         "CWE-611", "A05:2021", "XXE",
                         "Use defusedxml or set resolve_entities=False and no_network=True on lxml parsers.")

    # ═══════════════════════════════════════════════════════════════════
    #  9. LDAP INJECTION
    # ═══════════════════════════════════════════════════════════════════
    def _check_ldap_injection(self, node: ast.Call):
        fn = _call_name(node)
        if not fn:
            return

        ldap_funcs = {"search_s", "search", "search_st", "search_ext_s",
                      "ldap.search_s", "ldap.search", "conn.search_s",
                      "l.search_s", "l.search", "ldap_conn.search_s"}

        for lf in ldap_funcs:
            if fn == lf or fn.endswith("." + lf.split(".")[-1]):
                # Check filter argument (usually second or third arg)
                for arg in node.args:
                    if isinstance(arg, (ast.BinOp, ast.JoinedStr)):
                        self._add(node,
                                 "LDAP Injection: Dynamic filter string",
                                 Severity.HIGH, Confidence.HIGH,
                                 "CWE-90", "A03:2021", "LDAP Injection",
                                 "Use ldap.filter.escape_filter_chars() to sanitize user input "
                                 "in LDAP filters. Never construct LDAP filters with string concatenation.")
                        return
                    is_tainted, src = _is_tainted_expr(arg, self.tainted_vars)
                    if is_tainted:
                        df = self._build_data_flow(src or "unknown", _node_line(node),
                                                   _get_source_line(self.lines, _node_line(node)))
                        self._add(node,
                                 "LDAP Injection: Tainted data in LDAP filter",
                                 Severity.HIGH, Confidence.HIGH,
                                 "CWE-90", "A03:2021", "LDAP Injection",
                                 "Use ldap.filter.escape_filter_chars() to sanitize user input.",
                                 data_flow=df)
                        return

    # ═══════════════════════════════════════════════════════════════════
    # 10. HARDCODED SECRETS
    # ═══════════════════════════════════════════════════════════════════
    def _check_hardcoded_secrets(self, node: ast.Assign):
        """Check for secrets in assignments like PASSWORD = 'hardcoded'."""
        secret_patterns = {
            "password", "passwd", "pwd", "secret", "api_key", "apikey",
            "access_key", "secret_key", "private_key", "token", "auth_token",
            "api_secret", "client_secret", "db_password", "database_password",
            "aws_secret", "aws_access_key", "jwt_secret", "encryption_key",
        }

        for target in node.targets:
            name = _node_name(target)
            if not name:
                continue
            name_lower = name.lower()

            for pattern in secret_patterns:
                if pattern in name_lower:
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        val = node.value.value
                        if len(val) >= 3 and val.lower() not in ("", "none", "null", "true", "false",
                                                                   "changeme", "xxx", "todo", "fixme",
                                                                   "placeholder", "example"):
                            self._add(node,
                                     f"Hardcoded Secret: '{name}' contains a hardcoded credential",
                                     Severity.HIGH, Confidence.HIGH,
                                     "CWE-798", "A07:2021", "Hardcoded Secrets",
                                     "Store secrets in environment variables or a secrets manager "
                                     "(e.g., AWS Secrets Manager, HashiCorp Vault). "
                                     "Never hardcode credentials in source code.")
                    break

    def _check_hardcoded_secrets_strings(self):
        """Check all string constants in the file for patterns like API keys, tokens."""
        # Patterns that look like real secrets
        secret_prefixes = [
            ("sk-", 20, "API Key"),
            ("sk_live_", 20, "Stripe Secret Key"),
            ("sk_test_", 20, "Stripe Test Key"),
            ("pk_live_", 20, "Stripe Public Key"),
            ("AKIA", 16, "AWS Access Key"),
            ("ghp_", 36, "GitHub Personal Access Token"),
            ("gho_", 36, "GitHub OAuth Token"),
            ("ghu_", 36, "GitHub User Token"),
            ("ghs_", 36, "GitHub Server Token"),
            ("glpat-", 20, "GitLab Personal Access Token"),
            ("xoxb-", 20, "Slack Bot Token"),
            ("xoxp-", 20, "Slack User Token"),
            ("eyJ", 30, "JWT Token"),
        ]

        for node in ast.walk(self.tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                val = node.value
                for prefix, min_len, label in secret_prefixes:
                    if val.startswith(prefix) and len(val) >= min_len:
                        self._add(node,
                                 f"Hardcoded Secret: Possible {label} found in string literal",
                                 Severity.HIGH, Confidence.MEDIUM,
                                 "CWE-798", "A07:2021", "Hardcoded Secrets",
                                 "Remove hardcoded tokens and use environment variables or a secrets manager.")
                        break

    # ═══════════════════════════════════════════════════════════════════
    # 11. WEAK CRYPTOGRAPHY
    # ═══════════════════════════════════════════════════════════════════
    def _check_weak_crypto(self, node: ast.Call):
        fn = _call_name(node)
        if not fn:
            return

        weak_hashes = {
            "hashlib.md5":     ("MD5",   "SHA-256 or SHA-3"),
            "hashlib.sha1":    ("SHA-1", "SHA-256 or SHA-3"),
            "MD5.new":         ("MD5",   "SHA-256 or SHA-3"),
            "SHA.new":         ("SHA-1", "SHA-256 or SHA-3"),
            "Crypto.Hash.MD5.new": ("MD5", "SHA-256"),
            "Crypto.Hash.SHA.new": ("SHA-1", "SHA-256"),
        }

        for wh, (algo, replacement) in weak_hashes.items():
            if fn == wh or fn.endswith("." + wh.split(".")[-1]):
                self._add(node,
                         f"Weak Cryptography: {algo} is cryptographically broken",
                         Severity.MEDIUM, Confidence.HIGH,
                         "CWE-328", "A02:2021", "Weak Cryptography",
                         f"Replace {algo} with {replacement} for cryptographic purposes. "
                         f"{algo} is vulnerable to collision attacks.")
                return

        # hashlib.new("md5") / hashlib.new("sha1")
        if fn in ("hashlib.new", "new") and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if arg.value.lower() in ("md5", "sha1", "sha", "md4", "md2"):
                    self._add(node,
                             f"Weak Cryptography: {arg.value.upper()} hash is insecure",
                             Severity.MEDIUM, Confidence.HIGH,
                             "CWE-328", "A02:2021", "Weak Cryptography",
                             f"Use SHA-256 or SHA-3 instead of {arg.value.upper()}.")
                    return

        # Weak DES/RC4
        weak_ciphers = {"DES.new", "ARC4.new", "RC4.new", "Blowfish.new",
                        "Crypto.Cipher.DES.new", "Crypto.Cipher.ARC4.new"}
        for wc in weak_ciphers:
            if fn == wc or fn.endswith("." + wc.split(".")[-1]):
                self._add(node,
                         f"Weak Cryptography: {fn}() uses a deprecated cipher",
                         Severity.HIGH, Confidence.HIGH,
                         "CWE-327", "A02:2021", "Weak Cryptography",
                         "Use AES-256-GCM or ChaCha20-Poly1305 instead of deprecated ciphers.")
                return

        # Small RSA key
        if fn and ("generate" in fn or "RSA" in fn):
            for kw in node.keywords:
                if kw.arg in ("bits", "key_size"):
                    if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                        if kw.value.value < 2048:
                            self._add(node,
                                     f"Weak Cryptography: RSA key size {kw.value.value} bits is too small",
                                     Severity.HIGH, Confidence.HIGH,
                                     "CWE-326", "A02:2021", "Weak Cryptography",
                                     "Use at least 2048-bit RSA keys. 4096 bits is recommended.")
                            return
            # Check positional arg
            if node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, int) and arg.value < 2048:
                    if fn and "RSA" in fn:
                        self._add(node,
                                 f"Weak Cryptography: RSA key size {arg.value} bits is too small",
                                 Severity.HIGH, Confidence.HIGH,
                                 "CWE-326", "A02:2021", "Weak Cryptography",
                                 "Use at least 2048-bit RSA keys. 4096 bits is recommended.")
                        return

    # ═══════════════════════════════════════════════════════════════════
    # 12. INSECURE RANDOM
    # ═══════════════════════════════════════════════════════════════════
    def _check_insecure_random(self, node: ast.Call):
        fn = _call_name(node)
        if not fn:
            return

        insecure_funcs = {
            "random.random", "random.randint", "random.randrange",
            "random.choice", "random.shuffle", "random.sample",
            "random.uniform", "random.getrandbits",
        }

        for rf in insecure_funcs:
            if fn == rf or fn.endswith("." + rf.split(".")[-1]):
                self._add(node,
                         f"Insecure Random: {fn}() is not cryptographically secure",
                         Severity.MEDIUM, Confidence.MEDIUM,
                         "CWE-330", "A02:2021", "Insecure Random",
                         "Use secrets module (secrets.token_hex(), secrets.token_urlsafe(), "
                         "secrets.randbelow()) or os.urandom() for security-sensitive randomness.")
                return

    # ═══════════════════════════════════════════════════════════════════
    # 13. DEBUG MODE
    # ═══════════════════════════════════════════════════════════════════
    def _check_debug_mode(self, node: ast.Assign):
        for target in node.targets:
            name = _node_name(target)
            if not name:
                continue
            if name == "DEBUG" and isinstance(node.value, ast.Constant) and node.value.value is True:
                self._add(node,
                         "Debug Mode: DEBUG = True in production",
                         Severity.MEDIUM, Confidence.HIGH,
                         "CWE-489", "A05:2021", "Security Misconfiguration",
                         "Set DEBUG = False in production. Debug mode exposes sensitive "
                         "information including stack traces, SQL queries, and settings.")

    # ═══════════════════════════════════════════════════════════════════
    # 14. MISSING AUTHENTICATION
    # ═══════════════════════════════════════════════════════════════════
    def _check_missing_auth(self, node):
        """Check for route handlers missing authentication decorators."""
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return

        decs = [_node_name(d) for d in node.decorator_list]
        dec_str = " ".join(d for d in decs if d)

        # Is this a route handler?
        is_route = False
        for d in decs:
            if d and ("route" in d or "app.get" in d or "app.post" in d
                      or "app.put" in d or "app.delete" in d
                      or "api_view" in d or "router." in d):
                is_route = True
                break

        if not is_route:
            return

        # Check for auth decorators
        auth_decorators = {"login_required", "permission_required", "user_passes_test",
                          "permissions_classes", "authentication_classes",
                          "Depends", "Security", "requires_auth", "jwt_required",
                          "auth_required", "token_required", "protected",
                          "csrf_exempt"}  # csrf_exempt implies awareness

        has_auth = False
        for d in decs:
            if d:
                for ad in auth_decorators:
                    if ad in d:
                        has_auth = True
                        break

        if not has_auth:
            # Check for state-changing operations (POST/PUT/DELETE are higher risk)
            for d in decs:
                if d and ("post" in d.lower() or "put" in d.lower() or "delete" in d.lower() or "patch" in d.lower()):
                    self._add(node,
                             f"Missing Authentication: Route handler '{node.name}' lacks auth decorator",
                             Severity.MEDIUM, Confidence.LOW,
                             "CWE-306", "A07:2021", "Missing Authentication",
                             "Add authentication decorators like @login_required (Django), "
                             "@jwt_required (Flask-JWT), or Depends() (FastAPI) to protect routes.")
                    return

    # ═══════════════════════════════════════════════════════════════════
    # 15. INFORMATION DISCLOSURE
    # ═══════════════════════════════════════════════════════════════════
    def _check_information_disclosure(self, tree: ast.AST):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = _call_name(node)
                if not fn:
                    continue

                # traceback.print_exc() / traceback.format_exc() in production
                if fn in ("traceback.print_exc", "traceback.format_exc", "traceback.print_stack"):
                    self._add(node,
                             "Information Disclosure: Stack trace exposure",
                             Severity.MEDIUM, Confidence.MEDIUM,
                             "CWE-209", "A04:2021", "Information Disclosure",
                             "Log stack traces internally but never expose them to users. "
                             "Return generic error messages to clients.")

            # Bare except that re-raises with str(e)
            if isinstance(node, ast.ExceptHandler):
                if node.type is None:  # bare except
                    self._add(node,
                             "Information Disclosure: Bare except clause may leak error details",
                             Severity.LOW, Confidence.LOW,
                             "CWE-209", "A04:2021", "Information Disclosure",
                             "Use specific exception types and handle errors gracefully. "
                             "Never expose raw exception messages to users.")

    # ═══════════════════════════════════════════════════════════════════
    # 16. INSECURE FILE UPLOAD
    # ═══════════════════════════════════════════════════════════════════
    def _check_insecure_file_upload(self, node):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return

        # Look for file save without extension check
        has_file_save = False
        has_extension_check = False

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                fn = _call_name(child)
                if fn and ("save" in fn or "write" in fn):
                    # Check if it's file.save() or similar
                    if fn.endswith(".save") or fn.endswith(".write"):
                        has_file_save = True
                if fn and ("secure_filename" in fn or "allowed_file" in fn):
                    has_extension_check = True

            # Check for extension validation
            if isinstance(child, ast.Attribute):
                if child.attr in ("filename", "content_type"):
                    # Check if there's a comparison nearby
                    pass

            if isinstance(child, ast.Compare):
                for comp in child.comparators:
                    if isinstance(comp, (ast.Set, ast.List, ast.Tuple)):
                        for elt in comp.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                if elt.value.startswith("."):
                                    has_extension_check = True

        if has_file_save and not has_extension_check:
            self._add(node,
                     f"Insecure File Upload: '{node.name}' saves files without extension validation",
                     Severity.HIGH, Confidence.MEDIUM,
                     "CWE-434", "A04:2021", "Insecure File Upload",
                     "Validate file extensions against an allowlist. Use secure_filename() from werkzeug. "
                     "Store uploads outside the web root and scan for malware.")

    # ═══════════════════════════════════════════════════════════════════
    # 17. RACE CONDITIONS (TOCTOU)
    # ═══════════════════════════════════════════════════════════════════
    def _check_race_conditions(self, node):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return

        check_calls = set()
        action_calls = set()

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                fn = _call_name(child)
                if not fn:
                    continue
                # TOCTOU: check then act
                if fn in ("os.path.exists", "os.path.isfile", "os.path.isdir",
                          "os.access", "os.stat", "Path.exists", "Path.is_file"):
                    check_calls.add((_node_line(child), fn))
                elif fn in ("open", "os.remove", "os.unlink", "os.rename",
                            "os.mkdir", "shutil.copy", "shutil.move"):
                    action_calls.add((_node_line(child), fn))

        # If we have both check and action on similar paths, flag TOCTOU
        if check_calls and action_calls:
            for check_line, check_fn in check_calls:
                for action_line, action_fn in action_calls:
                    if action_line > check_line:  # action after check
                        self._add(node,
                                 f"Race Condition (TOCTOU): Check ({check_fn}) then act ({action_fn})",
                                 Severity.MEDIUM, Confidence.MEDIUM,
                                 "CWE-367", "A04:2021", "Race Conditions",
                                 "Use atomic operations instead of check-then-act patterns. "
                                 "For files, use os.open() with O_CREAT|O_EXCL flags or try/except around the operation.")
                        return

    # ═══════════════════════════════════════════════════════════════════
    # 18. MASS ASSIGNMENT
    # ═══════════════════════════════════════════════════════════════════
    def _check_mass_assignment(self, node: ast.Assign):
        """Check Django Model forms without explicit fields."""
        pass  # Handled in _check_django_model_form

    def _check_django_model_form(self, node: ast.ClassDef):
        """Check for Django ModelForm without fields restriction."""
        bases = [_node_name(b) for b in node.bases]

        if "ModelForm" not in bases and "forms.ModelForm" not in bases:
            return

        has_fields = False
        has_exclude = False
        has_fields_all = False

        for child in ast.walk(node):
            if isinstance(child, ast.ClassDef) and child.name == "Meta":
                for meta_child in ast.walk(child):
                    if isinstance(meta_child, ast.Assign):
                        for target in meta_child.targets:
                            tname = _node_name(target)
                            if tname == "fields":
                                has_fields = True
                                # Check if fields = '__all__'
                                if isinstance(meta_child.value, ast.Constant):
                                    if meta_child.value.value == "__all__":
                                        has_fields_all = True
                            elif tname == "exclude":
                                has_exclude = True

        if not has_fields and not has_exclude:
            self._add(node,
                     f"Mass Assignment: ModelForm '{node.name}' has no field restrictions",
                     Severity.HIGH, Confidence.HIGH,
                     "CWE-915", "A04:2021", "Mass Assignment",
                     "Always specify 'fields' in ModelForm Meta class. "
                     "Never use fields = '__all__'. List only the fields you want exposed.")
        elif has_fields_all:
            self._add(node,
                     f"Mass Assignment: ModelForm '{node.name}' uses fields = '__all__'",
                     Severity.HIGH, Confidence.HIGH,
                     "CWE-915", "A04:2021", "Mass Assignment",
                     "Replace fields = '__all__' with an explicit list of allowed fields. "
                     "This prevents exposing sensitive model fields.")

    # ═══════════════════════════════════════════════════════════════════
    # 19. OPEN REDIRECT
    # ═══════════════════════════════════════════════════════════════════
    def _check_open_redirect(self, node: ast.Call):
        fn = _call_name(node)
        if not fn:
            return

        redirect_funcs = {"redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect",
                         "RedirectResponse", "flask.redirect", "django.shortcuts.redirect"}

        for rf in redirect_funcs:
            if fn == rf or fn.endswith("." + rf.split(".")[-1]):
                if not node.args:
                    return
                url_arg = node.args[0]
                is_tainted, src = _is_tainted_expr(url_arg, self.tainted_vars)
                if is_tainted:
                    df = self._build_data_flow(src or "unknown", _node_line(node),
                                               _get_source_line(self.lines, _node_line(node)))
                    self._add(node,
                             "Open Redirect: User-controlled redirect URL",
                             Severity.MEDIUM, Confidence.HIGH,
                             "CWE-601", "A01:2021", "Open Redirect",
                             "Validate redirect URLs against an allowlist of permitted domains. "
                             "Use url_has_allowed_host_and_scheme() in Django.",
                             data_flow=df)
                elif isinstance(url_arg, (ast.BinOp, ast.JoinedStr)):
                    self._add(node,
                             "Open Redirect: Dynamic redirect URL",
                             Severity.MEDIUM, Confidence.MEDIUM,
                             "CWE-601", "A01:2021", "Open Redirect",
                             "Validate redirect URLs. Never construct redirect URLs from user input.")
                return

    # ═══════════════════════════════════════════════════════════════════
    # 20. TEMPLATE INJECTION
    # ═══════════════════════════════════════════════════════════════════
    def _check_template_injection(self, node: ast.Call):
        fn = _call_name(node)
        if not fn:
            return

        # Jinja2 Template with user input
        if fn in ("Template", "jinja2.Template", "Environment.from_string",
                   "env.from_string"):
            if node.args:
                arg = node.args[0]
                is_tainted, src = _is_tainted_expr(arg, self.tainted_vars)
                if is_tainted or isinstance(arg, (ast.BinOp, ast.JoinedStr)):
                    self._add(node,
                             "Template Injection (SSTI): User input in template construction",
                             Severity.CRITICAL, Confidence.HIGH,
                             "CWE-1336", "A03:2021", "Template Injection",
                             "Never construct templates from user input. Use render_template() "
                             "with file-based templates and pass user data as context variables.")
                    return

        # Django Template with user input
        if fn in ("django.template.Template",):
            if node.args:
                arg = node.args[0]
                is_tainted, _ = _is_tainted_expr(arg, self.tainted_vars)
                if is_tainted or isinstance(arg, (ast.BinOp, ast.JoinedStr)):
                    self._add(node,
                             "Template Injection: User input in Django Template()",
                             Severity.CRITICAL, Confidence.HIGH,
                             "CWE-1336", "A03:2021", "Template Injection",
                             "Never construct Django templates from user input.")

    # ═══════════════════════════════════════════════════════════════════
    # 21. BROKEN ACCESS CONTROL (checked via missing auth - see #14)
    # ═══════════════════════════════════════════════════════════════════

    # ═══════════════════════════════════════════════════════════════════
    # 22. SECURITY MISCONFIGURATION
    # ═══════════════════════════════════════════════════════════════════
    def _check_security_misconfiguration(self, tree: ast.AST):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = _call_name(node)
                if not fn:
                    continue
                # Flask app.run(debug=True)
                if fn in ("app.run", "application.run"):
                    for kw in node.keywords:
                        if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            self._add(node,
                                     "Security Misconfiguration: Flask debug mode enabled in app.run()",
                                     Severity.HIGH, Confidence.HIGH,
                                     "CWE-489", "A05:2021", "Security Misconfiguration",
                                     "Never use debug=True in production. It enables the interactive debugger "
                                     "which allows arbitrary code execution.")

                # CORS allow all origins
                if fn in ("CORS", "cors.CORS"):
                    for kw in node.keywords:
                        if kw.arg == "origins" or kw.arg == "resources":
                            if isinstance(kw.value, ast.Constant) and kw.value.value == "*":
                                self._add(node,
                                         "Security Misconfiguration: CORS allows all origins",
                                         Severity.MEDIUM, Confidence.HIGH,
                                         "CWE-942", "A05:2021", "Security Misconfiguration",
                                         "Restrict CORS to specific trusted origins instead of '*'.")

    # ═══════════════════════════════════════════════════════════════════
    # 23. LOGGING SENSITIVE DATA
    # ═══════════════════════════════════════════════════════════════════
    def _check_logging_sensitive(self, node: ast.Call):
        fn = _call_name(node)
        if not fn:
            return

        log_funcs = {"logging.info", "logging.debug", "logging.warning", "logging.error",
                     "logger.info", "logger.debug", "logger.warning", "logger.error",
                     "log.info", "log.debug", "log.warning", "log.error",
                     "print"}

        is_log = False
        for lf in log_funcs:
            if fn == lf or fn.endswith("." + lf.split(".")[-1]):
                is_log = True
                break

        if not is_log:
            return

        sensitive_names = {"password", "passwd", "secret", "token", "api_key",
                          "credit_card", "ssn", "social_security", "private_key",
                          "auth_token", "session_id", "cookie"}

        for arg in node.args:
            # Check if logging a variable with sensitive name
            if isinstance(arg, ast.Name):
                for sn in sensitive_names:
                    if sn in arg.id.lower():
                        self._add(node,
                                 f"Logging Sensitive Data: '{arg.id}' logged",
                                 Severity.MEDIUM, Confidence.MEDIUM,
                                 "CWE-532", "A09:2021", "Logging Sensitive Data",
                                 "Never log sensitive data like passwords, tokens, or PII. "
                                 "Mask or redact sensitive values before logging.")
                        return
            # Check f-strings / format strings containing sensitive vars
            if isinstance(arg, ast.JoinedStr):
                for val in arg.values:
                    if isinstance(val, ast.FormattedValue):
                        vname = _node_name(val.value)
                        if vname:
                            for sn in sensitive_names:
                                if sn in vname.lower():
                                    self._add(node,
                                             f"Logging Sensitive Data: '{vname}' in log message",
                                             Severity.MEDIUM, Confidence.MEDIUM,
                                             "CWE-532", "A09:2021", "Logging Sensitive Data",
                                             "Never log sensitive data. Mask sensitive values before logging.")
                                    return

    # ═══════════════════════════════════════════════════════════════════
    # 24. INSUFFICIENT INPUT VALIDATION
    # ═══════════════════════════════════════════════════════════════════
    def _check_input_validation(self, node):
        """Check route handlers for missing input validation."""
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return

        decs = [_node_name(d) for d in node.decorator_list]
        is_route = any(d and ("route" in d or "app." in d or "router." in d) for d in decs)
        if not is_route:
            return

        # Check if function body uses request data without validation
        uses_request_data = False
        has_validation = False

        for child in ast.walk(node):
            if isinstance(child, ast.Attribute):
                name = _node_name(child)
                if name and any(s in name for s in ("request.form", "request.args",
                                                     "request.json", "request.data",
                                                     "request.GET", "request.POST")):
                    uses_request_data = True

            if isinstance(child, ast.Call):
                cfn = _call_name(child)
                if cfn and any(v in cfn for v in ("validate", "clean", "is_valid",
                                                    "ValidationError", "Schema",
                                                    "serializer", "Form", "WTForm")):
                    has_validation = True

            # Type checking / isinstance
            if isinstance(child, ast.Call):
                cfn = _call_name(child)
                if cfn in ("isinstance", "type", "int", "float"):
                    has_validation = True

            # If / assert for validation
            if isinstance(child, ast.Assert):
                has_validation = True

        if uses_request_data and not has_validation:
            self._add(node,
                     f"Insufficient Input Validation: Route '{node.name}' uses request data without validation",
                     Severity.MEDIUM, Confidence.LOW,
                     "CWE-20", "A03:2021", "Insufficient Input Validation",
                     "Validate all input data using a schema validation library (e.g., marshmallow, pydantic, WTForms). "
                     "Check types, lengths, ranges, and formats.")

    # ═══════════════════════════════════════════════════════════════════
    # 25. PROTOTYPE POLLUTION (__class__ manipulation)
    # ═══════════════════════════════════════════════════════════════════
    def _check_prototype_pollution(self, node: ast.ClassDef):
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute):
                if child.attr in ("__class__", "__bases__", "__subclasses__",
                                   "__mro__", "__dict__", "__globals__",
                                   "__builtins__", "__import__"):
                    # Check if it's being assigned to or called with user data
                    self._add(child,
                             f"Prototype Pollution: Access to {child.attr} detected",
                             Severity.MEDIUM, Confidence.LOW,
                             "CWE-1321", "A03:2021", "Prototype Pollution",
                             f"Avoid accessing {child.attr} with user-controlled data. "
                             "This can lead to attribute injection attacks.")

    # ═══════════════════════════════════════════════════════════════════
    # 26. ReDoS
    # ═══════════════════════════════════════════════════════════════════
    def _check_redos(self, node: ast.Constant):
        """Check for regex patterns vulnerable to ReDoS."""
        if not isinstance(node.value, str):
            return

        val = node.value

        # Heuristic: patterns with nested quantifiers are likely ReDoS-vulnerable
        # e.g. (a+)+, (a*)*b, (a|b+)*c
        redos_patterns = [
            (r'\([^)]*[+*][^)]*\)[+*]', "nested quantifier"),
            (r'\([^)]*\|[^)]*[+*][^)]*\)[+*]', "alternation with nested quantifier"),
            (r'\.?\*.*\.?\*', "multiple wildcards"),
            (r'\([^)]+\)\{[^}]+\}\{', "nested repetition"),
        ]

        # Only check strings that look like regex patterns
        if not any(c in val for c in ('+', '*', '|', '(', '{')):
            return
        if len(val) < 3 or len(val) > 500:
            return

        for pattern, desc in redos_patterns:
            try:
                if _re.search(pattern, val):
                    self._add(node,
                             f"ReDoS: Regex pattern with {desc} may cause catastrophic backtracking",
                             Severity.MEDIUM, Confidence.MEDIUM,
                             "CWE-1333", "A06:2021", "ReDoS",
                             "Simplify the regex to avoid nested quantifiers. "
                             "Use atomic groups or possessive quantifiers if supported. "
                             "Set a timeout for regex operations.")
                    return
            except _re.error:
                pass

    # ═══════════════════════════════════════════════════════════════════
    # 27. INTEGER OVERFLOW
    # ═══════════════════════════════════════════════════════════════════
    def _check_integer_overflow(self, tree: ast.AST):
        """Check for potential integer overflow in ctypes or struct operations."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = _call_name(node)
                if not fn:
                    continue

                # ctypes integer types with user input
                ctypes_types = {"ctypes.c_int", "ctypes.c_short", "ctypes.c_byte",
                               "ctypes.c_uint", "ctypes.c_ushort", "ctypes.c_ubyte",
                               "c_int", "c_short", "c_byte", "c_uint"}
                for ct in ctypes_types:
                    if fn == ct or fn.endswith("." + ct.split(".")[-1]):
                        if node.args:
                            is_tainted, _ = _is_tainted_expr(node.args[0], self.tainted_vars)
                            if is_tainted:
                                self._add(node,
                                         f"Integer Overflow: User input in {fn}() may overflow",
                                         Severity.MEDIUM, Confidence.MEDIUM,
                                         "CWE-190", "A03:2021", "Integer Overflow",
                                         "Validate integer bounds before passing to ctypes. "
                                         "Python integers are arbitrary precision but ctypes types have fixed sizes.")

                # struct.pack/unpack with user-controlled format or data
                if fn in ("struct.pack", "struct.unpack"):
                    if node.args:
                        is_tainted, _ = _is_tainted_expr(node.args[0], self.tainted_vars)
                        if is_tainted:
                            self._add(node,
                                     "Integer Overflow: User-controlled struct format",
                                     Severity.MEDIUM, Confidence.MEDIUM,
                                     "CWE-190", "A03:2021", "Integer Overflow",
                                     "Validate struct format strings from user input.")

    # ═══════════════════════════════════════════════════════════════════
    # 28. BUFFER / MEMORY ISSUES
    # ═══════════════════════════════════════════════════════════════════
    def _check_buffer_issues(self, tree: ast.AST):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = _call_name(node)
                if not fn:
                    continue

                # ctypes buffer allocation
                if fn in ("ctypes.create_string_buffer", "ctypes.create_unicode_buffer",
                          "create_string_buffer", "create_unicode_buffer"):
                    if node.args:
                        is_tainted, _ = _is_tainted_expr(node.args[0], self.tainted_vars)
                        if is_tainted:
                            self._add(node,
                                     "Buffer Issue: User-controlled buffer size",
                                     Severity.HIGH, Confidence.MEDIUM,
                                     "CWE-120", "A06:2021", "Buffer/Memory Issues",
                                     "Validate buffer sizes from user input. Set maximum limits to prevent "
                                     "memory exhaustion attacks.")

                # mmap with user-controlled size
                if fn in ("mmap.mmap", "mmap"):
                    if len(node.args) >= 2:
                        is_tainted, _ = _is_tainted_expr(node.args[1], self.tainted_vars)
                        if is_tainted:
                            self._add(node,
                                     "Buffer Issue: User-controlled mmap size",
                                     Severity.HIGH, Confidence.MEDIUM,
                                     "CWE-120", "A06:2021", "Buffer/Memory Issues",
                                     "Validate mmap sizes. Set maximum limits.")

    # ═══════════════════════════════════════════════════════════════════
    # 29. TIMING ATTACKS
    # ═══════════════════════════════════════════════════════════════════
    def _check_timing_attack(self, node: ast.Assign):
        """Check for string comparison of secrets."""
        pass  # Handled in _check_timing_attack_compare

    def _check_timing_attack_compare(self, node: ast.Compare):
        """Check for == comparison of secret-like variables."""
        # Check if comparing variables with secret-like names
        secret_names = {"password", "token", "secret", "api_key", "hash",
                       "digest", "signature", "hmac", "mac", "auth"}

        left_name = _node_name(node.left)
        if not left_name:
            return

        for op, comparator in zip(node.ops, node.comparators):
            if isinstance(op, (ast.Eq, ast.NotEq)):
                right_name = _node_name(comparator)
                names_to_check = [left_name]
                if right_name:
                    names_to_check.append(right_name)

                for name in names_to_check:
                    for sn in secret_names:
                        if sn in name.lower():
                            self._add(node,
                                     f"Timing Attack: String comparison of '{name}' with == operator",
                                     Severity.MEDIUM, Confidence.MEDIUM,
                                     "CWE-208", "A02:2021", "Timing Attacks",
                                     "Use hmac.compare_digest() or secrets.compare_digest() "
                                     "for constant-time comparison of secrets and tokens.")
                            return

    # ═══════════════════════════════════════════════════════════════════
    # 30. DJANGO-SPECIFIC
    # ═══════════════════════════════════════════════════════════════════
    def _check_django_settings(self, node: ast.Assign):
        for target in node.targets:
            name = _node_name(target)
            if not name:
                continue

            # ALLOWED_HOSTS = ['*']
            if name == "ALLOWED_HOSTS":
                if isinstance(node.value, ast.List):
                    for elt in node.value.elts:
                        if isinstance(elt, ast.Constant) and elt.value == "*":
                            self._add(node,
                                     "Django Misconfiguration: ALLOWED_HOSTS = ['*']",
                                     Severity.HIGH, Confidence.HIGH,
                                     "CWE-16", "A05:2021", "Security Misconfiguration",
                                     "Never use ALLOWED_HOSTS = ['*'] in production. "
                                     "Specify exact hostnames.")

            # SECRET_KEY hardcoded
            if name == "SECRET_KEY":
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    self._add(node,
                             "Django Misconfiguration: SECRET_KEY hardcoded in source",
                             Severity.HIGH, Confidence.HIGH,
                             "CWE-798", "A05:2021", "Security Misconfiguration",
                             "Load SECRET_KEY from environment variables: "
                             "SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')")

            # SESSION_COOKIE_SECURE / CSRF_COOKIE_SECURE = False
            if name in ("SESSION_COOKIE_SECURE", "CSRF_COOKIE_SECURE", "SESSION_COOKIE_HTTPONLY"):
                if isinstance(node.value, ast.Constant) and node.value.value is False:
                    self._add(node,
                             f"Django Misconfiguration: {name} = False",
                             Severity.MEDIUM, Confidence.HIGH,
                             "CWE-614", "A05:2021", "Security Misconfiguration",
                             f"Set {name} = True in production to protect cookies.")

            # SECURE_SSL_REDIRECT = False
            if name == "SECURE_SSL_REDIRECT":
                if isinstance(node.value, ast.Constant) and node.value.value is False:
                    self._add(node,
                             "Django Misconfiguration: SECURE_SSL_REDIRECT = False",
                             Severity.MEDIUM, Confidence.MEDIUM,
                             "CWE-319", "A05:2021", "Security Misconfiguration",
                             "Set SECURE_SSL_REDIRECT = True to enforce HTTPS.")

    def _check_django_csrf(self, tree: ast.AST):
        """Check for @csrf_exempt decorator."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    name = _node_name(dec)
                    if name and "csrf_exempt" in name:
                        self._add(node,
                                 f"CSRF Disabled: @csrf_exempt on '{node.name}'",
                                 Severity.MEDIUM, Confidence.HIGH,
                                 "CWE-352", "A05:2021", "Security Misconfiguration",
                                 "Avoid @csrf_exempt. If CSRF protection must be disabled, "
                                 "ensure alternative protection (e.g., token-based auth).")

    # ═══════════════════════════════════════════════════════════════════
    # 31. FLASK-SPECIFIC
    # ═══════════════════════════════════════════════════════════════════
    def _check_flask_settings(self, node: ast.Assign):
        for target in node.targets:
            name = _node_name(target)
            if not name:
                continue

            # app.secret_key = 'weak'
            if name in ("secret_key", "app.secret_key", "SECRET_KEY"):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    val = node.value.value
                    if len(val) < 20:
                        self._add(node,
                                 "Flask Misconfiguration: Weak secret_key",
                                 Severity.HIGH, Confidence.HIGH,
                                 "CWE-330", "A05:2021", "Security Misconfiguration",
                                 "Use a strong random secret key (at least 32 bytes). "
                                 "Generate with: secrets.token_hex(32)")

    # ═══════════════════════════════════════════════════════════════════
    # 32. FASTAPI-SPECIFIC
    # ═══════════════════════════════════════════════════════════════════
    def _check_fastapi_no_auth(self, node):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return

        decs = [_node_name(d) for d in node.decorator_list]
        is_route = any(d and ("app.post" in d or "app.put" in d or "app.delete" in d
                              or "app.patch" in d or "router.post" in d or "router.put" in d
                              or "router.delete" in d) for d in decs)
        if not is_route:
            return

        # Check if function has Depends() for auth
        has_depends = False
        for arg in node.args.args:
            if arg.annotation:
                ann_name = _node_name(arg.annotation)
                if ann_name and "Depends" in ann_name:
                    has_depends = True
        # Check defaults
        for default in node.args.defaults:
            if isinstance(default, ast.Call):
                dfn = _call_name(default)
                if dfn and ("Depends" in dfn or "Security" in dfn):
                    has_depends = True

        if not has_depends:
            # Already handled by missing auth check
            pass

    def _check_cors_star(self, node: ast.Assign):
        """Check for CORS * in FastAPI middleware."""
        for target in node.targets:
            name = _node_name(target)
            if name and "allow_origin" in name.lower():
                if isinstance(node.value, ast.List):
                    for elt in node.value.elts:
                        if isinstance(elt, ast.Constant) and elt.value == "*":
                            self._add(node,
                                     "CORS Misconfiguration: allow_origins = ['*']",
                                     Severity.MEDIUM, Confidence.HIGH,
                                     "CWE-942", "A05:2021", "Security Misconfiguration",
                                     "Restrict CORS to specific trusted origins.")

    # ═══════════════════════════════════════════════════════════════════
    # 33. UNSAFE YAML
    # ═══════════════════════════════════════════════════════════════════
    def _check_unsafe_yaml(self, node: ast.Call):
        fn = _call_name(node)
        if not fn:
            return

        if fn in ("yaml.load", "yaml.load_all"):
            # Check if Loader is specified
            has_safe_loader = False
            for kw in node.keywords:
                if kw.arg == "Loader":
                    loader_name = _node_name(kw.value)
                    if loader_name and ("SafeLoader" in loader_name or "CSafeLoader" in loader_name
                                        or "BaseLoader" in loader_name):
                        has_safe_loader = True

            if not has_safe_loader:
                self._add(node,
                         "Unsafe YAML: yaml.load() without SafeLoader",
                         Severity.HIGH, Confidence.HIGH,
                         "CWE-502", "A08:2021", "Deserialization",
                         "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader). "
                         "yaml.load() with the default Loader allows arbitrary code execution.")

        if fn in ("yaml.unsafe_load", "yaml.full_load"):
            self._add(node,
                     f"Unsafe YAML: {fn}() allows code execution",
                     Severity.HIGH, Confidence.HIGH,
                     "CWE-502", "A08:2021", "Deserialization",
                     "Use yaml.safe_load() instead. Unsafe YAML loading allows arbitrary Python object construction.")

    # ═══════════════════════════════════════════════════════════════════
    # 34. UNSAFE JSON/XML PARSING
    # ═══════════════════════════════════════════════════════════════════
    def _check_unsafe_xml(self, node: ast.Call):
        """Already covered in XXE check."""
        pass

    # ═══════════════════════════════════════════════════════════════════
    # 35. SUBPROCESS WITHOUT shell=False
    # ═══════════════════════════════════════════════════════════════════
    def _check_subprocess_shell(self, node: ast.Call):
        fn = _call_name(node)
        if not fn:
            return

        sub_funcs = {"subprocess.call", "subprocess.run", "subprocess.Popen",
                     "subprocess.check_output", "subprocess.check_call"}

        matched = False
        for sf in sub_funcs:
            if fn == sf or fn.endswith("." + sf.split(".")[-1]):
                matched = True
                break

        if not matched:
            return

        for kw in node.keywords:
            if kw.arg == "shell":
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    sev = Severity.HIGH
                    conf = Confidence.HIGH
                    # Even worse if first arg is dynamic
                    if node.args:
                        arg = node.args[0]
                        is_tainted, src = _is_tainted_expr(arg, self.tainted_vars)
                        if is_tainted or isinstance(arg, (ast.BinOp, ast.JoinedStr)):
                            sev = Severity.CRITICAL
                            df = []
                            if is_tainted and src:
                                df = self._build_data_flow(src, _node_line(node),
                                                           _get_source_line(self.lines, _node_line(node)))
                            self._add(node,
                                     f"Command Injection: {fn}(shell=True) with dynamic command",
                                     sev, conf,
                                     "CWE-78", "A03:2021", "Injection",
                                     "Never use shell=True with user-controlled input. "
                                     "Use a list of arguments instead: subprocess.run(['cmd', arg1, arg2]).",
                                     data_flow=df)
                            return

                    self._add(node,
                             f"Command Injection risk: {fn}(shell=True)",
                             Severity.MEDIUM, Confidence.MEDIUM,
                             "CWE-78", "A03:2021", "Injection",
                             "Avoid shell=True. Pass commands as a list: subprocess.run(['cmd', 'arg1']).")
                return

    # ═══════════════════════════════════════════════════════════════════
    # 36. TEMP FILE ISSUES
    # ═══════════════════════════════════════════════════════════════════
    def _check_temp_file_issues(self, node: ast.Call):
        fn = _call_name(node)
        if not fn:
            return

        # tempfile.mktemp is insecure (race condition)
        if fn in ("tempfile.mktemp", "mktemp"):
            self._add(node,
                     "Insecure Temp File: tempfile.mktemp() has a race condition",
                     Severity.MEDIUM, Confidence.HIGH,
                     "CWE-377", "A04:2021", "Race Conditions",
                     "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() which "
                     "atomically create the file.")

        # os.tmpnam, os.tempnam
        if fn in ("os.tmpnam", "os.tempnam"):
            self._add(node,
                     f"Insecure Temp File: {fn}() is insecure",
                     Severity.MEDIUM, Confidence.HIGH,
                     "CWE-377", "A04:2021", "Race Conditions",
                     "Use tempfile.mkstemp() instead.")

    # ═══════════════════════════════════════════════════════════════════
    # 37. SSL/TLS VERIFICATION DISABLED
    # ═══════════════════════════════════════════════════════════════════
    def _check_ssl_verify_disabled(self, node: ast.Call):
        fn = _call_name(node)
        if not fn:
            return

        # requests.get(url, verify=False)
        http_funcs = {"requests.get", "requests.post", "requests.put", "requests.delete",
                      "requests.head", "requests.patch", "requests.request",
                      "httpx.get", "httpx.post", "httpx.Client"}

        matched = False
        for hf in http_funcs:
            if fn == hf or fn.endswith("." + hf.split(".")[-1]):
                matched = True
                break

        if not matched:
            return

        for kw in node.keywords:
            if kw.arg == "verify":
                if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    self._add(node,
                             "SSL/TLS Verification Disabled: verify=False",
                             Severity.HIGH, Confidence.HIGH,
                             "CWE-295", "A07:2021", "SSL/TLS Verification Disabled",
                             "Never disable SSL certificate verification. This allows "
                             "man-in-the-middle attacks. Remove verify=False.")

        # Also check for ssl context with check_hostname=False
        if fn and ("SSLContext" in fn or "create_default_context" in fn):
            pass  # complex to check, skip for now

    # ═══════════════════════════════════════════════════════════════════
    # 38. CLEARTEXT CREDENTIALS (handled by #10 hardcoded secrets)
    # ═══════════════════════════════════════════════════════════════════

    # ═══════════════════════════════════════════════════════════════════
    # 39. INSUFFICIENT LOGGING
    # ═══════════════════════════════════════════════════════════════════
    def _check_insufficient_logging(self, tree: ast.AST):
        """Check for except blocks without logging."""
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                has_logging = False
                has_pass = False
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        cfn = _call_name(child)
                        if cfn and any(x in cfn for x in ("log", "logger", "logging",
                                                            "print", "warn", "error")):
                            has_logging = True
                    if isinstance(child, ast.Pass):
                        has_pass = True
                    if isinstance(child, ast.Raise):
                        has_logging = True  # re-raising is OK

                if has_pass and not has_logging:
                    self._add(node,
                             "Insufficient Logging: Exception silently swallowed (pass in except)",
                             Severity.LOW, Confidence.HIGH,
                             "CWE-778", "A09:2021", "Insufficient Logging",
                             "Log exceptions before suppressing them. Silent error handling "
                             "makes debugging impossible and can hide security issues.")

    # ═══════════════════════════════════════════════════════════════════
    # 40. JWT ISSUES
    # ═══════════════════════════════════════════════════════════════════
    def _check_jwt_issues(self, node: ast.Call):
        fn = _call_name(node)
        if not fn:
            return

        # jwt.decode without algorithms
        if fn in ("jwt.decode", "decode"):
            has_algorithms = False
            has_verify = True
            has_none_algo = False
            for kw in node.keywords:
                if kw.arg == "algorithms":
                    has_algorithms = True
                    # Check for "none" in algorithms list
                    if isinstance(kw.value, ast.List):
                        for elt in kw.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                if elt.value.lower() == "none":
                                    has_none_algo = True
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    has_verify = False
                if kw.arg == "options":
                    # Check for verify_signature=False
                    if isinstance(kw.value, ast.Dict):
                        for k, v in zip(kw.value.keys, kw.value.values):
                            if isinstance(k, ast.Constant) and k.value == "verify_signature":
                                if isinstance(v, ast.Constant) and v.value is False:
                                    has_verify = False

            if has_none_algo:
                self._add(node,
                         "JWT Vulnerability: 'none' algorithm allowed",
                         Severity.CRITICAL, Confidence.HIGH,
                         "CWE-347", "A02:2021", "JWT Issues",
                         "Never allow the 'none' algorithm in JWT. Specify only the expected algorithm(s).")
            elif not has_algorithms:
                self._add(node,
                         "JWT Vulnerability: jwt.decode() without explicit algorithms",
                         Severity.HIGH, Confidence.MEDIUM,
                         "CWE-347", "A02:2021", "JWT Issues",
                         "Always specify algorithms=['HS256'] (or your expected algorithm) "
                         "in jwt.decode() to prevent algorithm confusion attacks.")
            if not has_verify:
                self._add(node,
                         "JWT Vulnerability: Signature verification disabled",
                         Severity.CRITICAL, Confidence.HIGH,
                         "CWE-347", "A02:2021", "JWT Issues",
                         "Never disable JWT signature verification. "
                         "Remove verify=False or options={'verify_signature': False}.")

        # jwt.encode with weak secret
        if fn in ("jwt.encode", "encode"):
            if len(node.args) >= 2:
                secret_arg = node.args[1]
                if isinstance(secret_arg, ast.Constant) and isinstance(secret_arg.value, str):
                    if len(secret_arg.value) < 20:
                        self._add(node,
                                 "JWT Vulnerability: Weak signing secret",
                                 Severity.HIGH, Confidence.HIGH,
                                 "CWE-326", "A02:2021", "JWT Issues",
                                 "Use a strong, random secret for JWT signing (at least 256 bits). "
                                 "Store it in environment variables, not in source code.")


# ═══════════════════════════════════════════════════════════════════════════
# 5.  SCANNER ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════

class PythonScanner:
    """Orchestrate scanning of multiple Python files."""

    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB per file
    MAX_PARSE_TIME = 30  # seconds per file

    def scan(self, files: Dict[str, str], scan_id: str) -> dict:
        start_time = time.time()
        all_vulns: List[dict] = []
        files_scanned = 0
        errors: List[str] = []

        for file_path, content in files.items():
            # Skip non-Python files
            if not file_path.endswith(".py"):
                continue

            # Skip oversized files
            if len(content) > self.MAX_FILE_SIZE:
                errors.append(f"{file_path}: File too large (>{self.MAX_FILE_SIZE} bytes)")
                continue

            try:
                analyzer = FileAnalyzer(file_path, content)
                vulns = analyzer.analyze()
                all_vulns.extend(v.to_dict() for v in vulns)
                files_scanned += 1
            except Exception as e:
                errors.append(f"{file_path}: {str(e)}")
                files_scanned += 1

        elapsed = time.time() - start_time

        # Build summary
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for v in all_vulns:
            sev = v.get("severity", "Info")
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Deduplicate: same file + same line + same title = same finding
        seen = set()
        unique_vulns = []
        for v in all_vulns:
            key = (v["filePath"], v["lineNumber"], v["title"])
            if key not in seen:
                seen.add(key)
                unique_vulns.append(v)

        # Recount after dedup
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for v in unique_vulns:
            sev = v.get("severity", "Info")
            if sev in severity_counts:
                severity_counts[sev] += 1

        return {
            "vulnerabilities": unique_vulns,
            "summary": {
                "total": len(unique_vulns),
                "critical": severity_counts["Critical"],
                "high": severity_counts["High"],
                "medium": severity_counts["Medium"],
                "low": severity_counts["Low"],
            },
            "scanDuration": f"{elapsed:.2f}s",
            "filesScanned": files_scanned,
            "errors": errors if errors else None,
        }


# ═══════════════════════════════════════════════════════════════════════════
# 6.  FASTAPI APPLICATION
# ═══════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="Offensive360 Python SAST Scanner",
    version="1.0.0",
    description="AST-based static analysis for Python code",
)

class ScanRequest(BaseModel):
    files: Dict[str, str]
    scanId: str = ""

class ScanResponse(BaseModel):
    vulnerabilities: list
    summary: dict
    scanDuration: str
    filesScanned: int
    errors: Optional[list] = None

scanner = PythonScanner()


@app.post("/scan", response_model=ScanResponse)
async def scan_endpoint(request: ScanRequest):
    """Scan Python files for security vulnerabilities."""
    if not request.files:
        raise HTTPException(status_code=400, detail="No files provided")

    scan_id = request.scanId or str(uuid.uuid4())

    try:
        result = scanner.scan(request.files, scan_id)
        return result
    except Exception as e:
        logger.error(f"Scan error: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@app.get("/health")
async def health():
    return {"status": "healthy", "scanner": "python", "version": "1.0.0"}


@app.get("/")
async def root():
    return {"scanner": "python-sast", "version": "1.0.0", "port": 9001}


# ═══════════════════════════════════════════════════════════════════════════
# 7.  ENTRYPOINT
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logger.info("Starting Python SAST Scanner on port 9001...")
    uvicorn.run(app, host="0.0.0.0", port=9001, log_level="info")
