#!/usr/bin/env python3
"""
Rust SAST Scanner - Static Application Security Testing for Rust source code.
Custom tokenizer and AST analyzer with 30+ vulnerability categories.
FastAPI server on port 9009.
"""

import re
import uuid
import hashlib
import logging
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("rust-scanner")

# ─────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    files: Dict[str, str]
    scanId: Optional[str] = None

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
class Vulnerability:
    id: str
    category: str
    title: str
    description: str
    severity: str
    confidence: str
    file_path: str
    line_number: int
    column: int
    end_line: int
    code_snippet: str
    recommendation: str
    cwe_id: str
    owasp: str
    references: List[str] = field(default_factory=list)

# ─────────────────────────────────────────────────────────
# Rust Tokenizer
# ─────────────────────────────────────────────────────────

class TokenType(Enum):
    KEYWORD = "keyword"
    IDENT = "ident"
    STRING = "string"
    RAW_STRING = "raw_string"
    CHAR = "char"
    NUMBER = "number"
    COMMENT = "comment"
    DOC_COMMENT = "doc_comment"
    BLOCK_COMMENT = "block_comment"
    OPERATOR = "operator"
    DELIMITER = "delimiter"
    LIFETIME = "lifetime"
    ATTRIBUTE = "attribute"
    MACRO = "macro"
    WHITESPACE = "whitespace"
    EOF = "eof"

@dataclass
class Token:
    type: TokenType
    value: str
    line: int
    column: int
    end_line: int
    end_column: int

RUST_KEYWORDS = {
    "as", "async", "await", "break", "const", "continue", "crate", "dyn",
    "else", "enum", "extern", "false", "fn", "for", "if", "impl", "in",
    "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
    "self", "Self", "static", "struct", "super", "trait", "true", "type",
    "union", "unsafe", "use", "where", "while", "yield",
}

class RustTokenizer:
    """Custom Rust source tokenizer that handles all Rust lexical elements."""

    def __init__(self, source: str):
        self.source = source
        self.pos = 0
        self.line = 1
        self.column = 1
        self.tokens: List[Token] = []

    def peek(self, offset=0) -> Optional[str]:
        idx = self.pos + offset
        return self.source[idx] if idx < len(self.source) else None

    def advance(self) -> str:
        ch = self.source[self.pos]
        self.pos += 1
        if ch == "\n":
            self.line += 1
            self.column = 1
        else:
            self.column += 1
        return ch

    def match_str(self, s: str) -> bool:
        return self.source[self.pos:self.pos + len(s)] == s

    def tokenize(self) -> List[Token]:
        self.tokens = []
        while self.pos < len(self.source):
            ch = self.peek()
            start_line, start_col = self.line, self.column

            if ch in (" ", "\t", "\r", "\n"):
                self._skip_whitespace()
                continue

            # Comments
            if ch == "/" and self.peek(1) == "/":
                tok = self._read_line_comment()
                self.tokens.append(tok)
                continue
            if ch == "/" and self.peek(1) == "*":
                tok = self._read_block_comment()
                self.tokens.append(tok)
                continue

            # Attributes
            if ch == "#" and self.peek(1) == "[":
                tok = self._read_attribute()
                self.tokens.append(tok)
                continue
            if ch == "#" and self.peek(1) == "!" and self.peek(2) == "[":
                tok = self._read_attribute()
                self.tokens.append(tok)
                continue

            # Raw strings r"..." or r#"..."#
            if ch == "r" and self.peek(1) in ('"', "#"):
                tok = self._read_raw_string(start_line, start_col)
                self.tokens.append(tok)
                continue

            # Byte strings b"..."
            if ch == "b" and self.peek(1) == '"':
                self.advance()  # skip b
                tok = self._read_string(start_line, start_col)
                self.tokens.append(tok)
                continue

            # Strings
            if ch == '"':
                tok = self._read_string(start_line, start_col)
                self.tokens.append(tok)
                continue

            # Chars
            if ch == "'" and self._is_char_literal():
                tok = self._read_char(start_line, start_col)
                self.tokens.append(tok)
                continue

            # Lifetimes
            if ch == "'" and self._is_lifetime():
                tok = self._read_lifetime(start_line, start_col)
                self.tokens.append(tok)
                continue

            # Numbers
            if ch.isdigit() or (ch == "." and self.peek(1) and self.peek(1).isdigit()):
                tok = self._read_number(start_line, start_col)
                self.tokens.append(tok)
                continue

            # Identifiers / keywords / macros
            if ch.isalpha() or ch == "_":
                tok = self._read_ident(start_line, start_col)
                self.tokens.append(tok)
                continue

            # Multi-character operators
            if ch in "=!<>|&+-*/%^" and self.peek(1):
                two = ch + (self.peek(1) or "")
                if two in ("==", "!=", "<=", ">=", "||", "&&", "+=", "-=", "*=",
                           "/=", "%=", "^=", "|=", "&=", "<<", ">>", "->", "=>",
                           "::", ".."):
                    self.advance()
                    self.advance()
                    self.tokens.append(Token(TokenType.OPERATOR, two, start_line, start_col, self.line, self.column))
                    continue

            # Single operators / delimiters
            if ch in "(){}[]<>;:,.?@~!#$%^&*+-=/|":
                self.advance()
                tt = TokenType.DELIMITER if ch in "(){}[]" else TokenType.OPERATOR
                self.tokens.append(Token(tt, ch, start_line, start_col, self.line, self.column))
                continue

            # Unknown char
            self.advance()

        self.tokens.append(Token(TokenType.EOF, "", self.line, self.column, self.line, self.column))
        return self.tokens

    def _skip_whitespace(self):
        while self.pos < len(self.source) and self.source[self.pos] in (" ", "\t", "\r", "\n"):
            self.advance()

    def _read_line_comment(self) -> Token:
        start_line, start_col = self.line, self.column
        buf = ""
        is_doc = self.match_str("///") or self.match_str("//!")
        while self.pos < len(self.source) and self.source[self.pos] != "\n":
            buf += self.advance()
        tt = TokenType.DOC_COMMENT if is_doc else TokenType.COMMENT
        return Token(tt, buf, start_line, start_col, self.line, self.column)

    def _read_block_comment(self) -> Token:
        start_line, start_col = self.line, self.column
        buf = self.advance() + self.advance()  # /*
        depth = 1
        while self.pos < len(self.source) and depth > 0:
            if self.match_str("/*"):
                depth += 1
                buf += self.advance() + self.advance()
            elif self.match_str("*/"):
                depth -= 1
                buf += self.advance() + self.advance()
            else:
                buf += self.advance()
        return Token(TokenType.BLOCK_COMMENT, buf, start_line, start_col, self.line, self.column)

    def _read_attribute(self) -> Token:
        start_line, start_col = self.line, self.column
        buf = ""
        depth = 0
        while self.pos < len(self.source):
            ch = self.source[self.pos]
            buf += self.advance()
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth <= 0:
                    break
        return Token(TokenType.ATTRIBUTE, buf, start_line, start_col, self.line, self.column)

    def _read_string(self, start_line, start_col) -> Token:
        buf = self.advance()  # opening quote
        while self.pos < len(self.source):
            ch = self.source[self.pos]
            if ch == "\\":
                buf += self.advance()
                if self.pos < len(self.source):
                    buf += self.advance()
            elif ch == '"':
                buf += self.advance()
                break
            else:
                buf += self.advance()
        return Token(TokenType.STRING, buf, start_line, start_col, self.line, self.column)

    def _read_raw_string(self, start_line, start_col) -> Token:
        buf = self.advance()  # r
        hashes = 0
        while self.pos < len(self.source) and self.source[self.pos] == "#":
            buf += self.advance()
            hashes += 1
        if self.pos < len(self.source) and self.source[self.pos] == '"':
            buf += self.advance()
        closing = '"' + "#" * hashes
        while self.pos < len(self.source):
            if self.source[self.pos:self.pos + len(closing)] == closing:
                for _ in range(len(closing)):
                    buf += self.advance()
                break
            buf += self.advance()
        return Token(TokenType.RAW_STRING, buf, start_line, start_col, self.line, self.column)

    def _is_char_literal(self) -> bool:
        if self.pos + 2 >= len(self.source):
            return False
        rest = self.source[self.pos:]
        m = re.match(r"'(\\.|[^'\\])'", rest)
        return m is not None

    def _read_char(self, start_line, start_col) -> Token:
        buf = self.advance()  # opening '
        while self.pos < len(self.source):
            ch = self.source[self.pos]
            if ch == "\\":
                buf += self.advance()
                if self.pos < len(self.source):
                    buf += self.advance()
            elif ch == "'":
                buf += self.advance()
                break
            else:
                buf += self.advance()
        return Token(TokenType.CHAR, buf, start_line, start_col, self.line, self.column)

    def _is_lifetime(self) -> bool:
        if self.pos + 1 >= len(self.source):
            return False
        next_ch = self.source[self.pos + 1]
        return next_ch.isalpha() or next_ch == "_"

    def _read_lifetime(self, start_line, start_col) -> Token:
        buf = self.advance()  # '
        while self.pos < len(self.source) and (self.source[self.pos].isalnum() or self.source[self.pos] == "_"):
            buf += self.advance()
        return Token(TokenType.LIFETIME, buf, start_line, start_col, self.line, self.column)

    def _read_number(self, start_line, start_col) -> Token:
        buf = ""
        if self.source[self.pos] == "0" and self.pos + 1 < len(self.source) and self.source[self.pos + 1] in "xXoObB":
            buf += self.advance() + self.advance()
            while self.pos < len(self.source) and (self.source[self.pos] in "0123456789abcdefABCDEF_"):
                buf += self.advance()
        else:
            while self.pos < len(self.source) and (self.source[self.pos].isdigit() or self.source[self.pos] == "_"):
                buf += self.advance()
            if self.pos < len(self.source) and self.source[self.pos] == "." and self.peek(1) and self.peek(1).isdigit():
                buf += self.advance()
                while self.pos < len(self.source) and (self.source[self.pos].isdigit() or self.source[self.pos] == "_"):
                    buf += self.advance()
        # Type suffix
        for suffix in ("u128", "usize", "u64", "u32", "u16", "u8", "i128", "isize", "i64", "i32", "i16", "i8", "f64", "f32"):
            if self.pos < len(self.source) and self.source[self.pos:self.pos + len(suffix)] == suffix:
                for _ in range(len(suffix)):
                    buf += self.advance()
                break
        return Token(TokenType.NUMBER, buf, start_line, start_col, self.line, self.column)

    def _read_ident(self, start_line, start_col) -> Token:
        buf = ""
        while self.pos < len(self.source) and (self.source[self.pos].isalnum() or self.source[self.pos] == "_"):
            buf += self.advance()
        # Check if macro invocation
        if self.pos < len(self.source) and self.source[self.pos] == "!":
            buf += self.advance()
            return Token(TokenType.MACRO, buf, start_line, start_col, self.line, self.column)
        if buf in RUST_KEYWORDS:
            return Token(TokenType.KEYWORD, buf, start_line, start_col, self.line, self.column)
        return Token(TokenType.IDENT, buf, start_line, start_col, self.line, self.column)


# ─────────────────────────────────────────────────────────
# Rust AST Analyzer
# ─────────────────────────────────────────────────────────

@dataclass
class FnDef:
    name: str
    line: int
    end_line: int
    is_async: bool
    is_unsafe: bool
    is_pub: bool
    params: List[str]
    body_start: int
    body_end: int

@dataclass
class StructDef:
    name: str
    line: int
    derives: List[str]
    fields: List[str]

@dataclass
class ImplBlock:
    name: str
    line: int
    is_unsafe: bool
    trait_name: Optional[str]

@dataclass
class UseStmt:
    path: str
    line: int

class RustASTAnalyzer:
    """Lightweight AST analysis built on tokens."""

    def __init__(self, tokens: List[Token], source: str):
        self.tokens = [t for t in tokens if t.type not in (TokenType.WHITESPACE,)]
        self.source = source
        self.lines = source.split("\n")
        self.functions: List[FnDef] = []
        self.structs: List[StructDef] = []
        self.impls: List[ImplBlock] = []
        self.uses: List[UseStmt] = []
        self.unsafe_blocks: List[Tuple[int, int]] = []
        self._analyze()

    def _analyze(self):
        i = 0
        while i < len(self.tokens):
            tok = self.tokens[i]
            # use statements
            if tok.type == TokenType.KEYWORD and tok.value == "use":
                path_parts = []
                j = i + 1
                while j < len(self.tokens) and self.tokens[j].value != ";":
                    path_parts.append(self.tokens[j].value)
                    j += 1
                self.uses.append(UseStmt("".join(path_parts), tok.line))
                i = j + 1
                continue

            # unsafe blocks / fns / impls
            if tok.type == TokenType.KEYWORD and tok.value == "unsafe":
                nxt = self.tokens[i + 1] if i + 1 < len(self.tokens) else None
                if nxt and nxt.type == TokenType.KEYWORD and nxt.value == "fn":
                    fn = self._parse_fn(i, is_unsafe=True)
                    if fn:
                        self.functions.append(fn)
                        i += 1
                        continue
                elif nxt and nxt.type == TokenType.KEYWORD and nxt.value == "impl":
                    impl_ = self._parse_impl(i, is_unsafe=True)
                    if impl_:
                        self.impls.append(impl_)
                    i += 1
                    continue
                elif nxt and nxt.type == TokenType.DELIMITER and nxt.value == "{":
                    end = self._find_matching_brace(i + 1)
                    self.unsafe_blocks.append((nxt.line, self.tokens[end].line if end < len(self.tokens) else nxt.line))
                    i += 1
                    continue

            # fn
            if tok.type == TokenType.KEYWORD and tok.value == "fn":
                fn = self._parse_fn(i)
                if fn:
                    self.functions.append(fn)
                i += 1
                continue

            # async fn
            if tok.type == TokenType.KEYWORD and tok.value == "async":
                nxt = self.tokens[i + 1] if i + 1 < len(self.tokens) else None
                if nxt and nxt.type == TokenType.KEYWORD and nxt.value == "fn":
                    fn = self._parse_fn(i + 1, is_async=True)
                    if fn:
                        self.functions.append(fn)
                i += 1
                continue

            # struct
            if tok.type == TokenType.KEYWORD and tok.value == "struct":
                st = self._parse_struct(i)
                if st:
                    self.structs.append(st)
                i += 1
                continue

            # impl
            if tok.type == TokenType.KEYWORD and tok.value == "impl":
                impl_ = self._parse_impl(i)
                if impl_:
                    self.impls.append(impl_)
                i += 1
                continue

            i += 1

    def _parse_fn(self, idx: int, is_async=False, is_unsafe=False) -> Optional[FnDef]:
        fn_tok = self.tokens[idx]
        name_idx = idx + 1
        if name_idx >= len(self.tokens):
            return None
        name = self.tokens[name_idx].value
        is_pub = idx > 0 and self.tokens[idx - 1].value == "pub"
        if not is_pub and idx > 1:
            is_pub = self.tokens[idx - 2].value == "pub"
        params = []
        j = name_idx + 1
        if j < len(self.tokens) and self.tokens[j].value == "(":
            depth = 1
            j += 1
            while j < len(self.tokens) and depth > 0:
                if self.tokens[j].value == "(":
                    depth += 1
                elif self.tokens[j].value == ")":
                    depth -= 1
                elif depth == 1 and self.tokens[j].type == TokenType.IDENT:
                    params.append(self.tokens[j].value)
                j += 1
        while j < len(self.tokens) and self.tokens[j].value != "{":
            j += 1
        body_start = j
        body_end = self._find_matching_brace(j)
        return FnDef(
            name=name, line=fn_tok.line,
            end_line=self.tokens[body_end].line if body_end < len(self.tokens) else fn_tok.line,
            is_async=is_async, is_unsafe=is_unsafe, is_pub=is_pub,
            params=params, body_start=body_start, body_end=body_end,
        )

    def _parse_struct(self, idx: int) -> Optional[StructDef]:
        if idx + 1 >= len(self.tokens):
            return None
        name = self.tokens[idx + 1].value
        derives = []
        for j in range(max(0, idx - 5), idx):
            if self.tokens[j].type == TokenType.ATTRIBUTE and "derive" in self.tokens[j].value:
                m = re.findall(r"\w+", self.tokens[j].value.replace("derive", "").replace("#[", "").replace("]", ""))
                derives = m
        fields = []
        return StructDef(name=name, line=self.tokens[idx].line, derives=derives, fields=fields)

    def _parse_impl(self, idx: int, is_unsafe=False) -> Optional[ImplBlock]:
        j = idx + 1
        if is_unsafe:
            j += 1
        if j >= len(self.tokens):
            return None
        name = self.tokens[j].value
        trait_name = None
        if j + 2 < len(self.tokens) and self.tokens[j + 1].value == "for":
            trait_name = name
            name = self.tokens[j + 2].value
        return ImplBlock(name=name, line=self.tokens[idx].line, is_unsafe=is_unsafe, trait_name=trait_name)

    def _find_matching_brace(self, idx: int) -> int:
        if idx >= len(self.tokens) or self.tokens[idx].value != "{":
            return idx
        depth = 1
        j = idx + 1
        while j < len(self.tokens) and depth > 0:
            if self.tokens[j].value == "{":
                depth += 1
            elif self.tokens[j].value == "}":
                depth -= 1
            j += 1
        return j - 1

    def get_line(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1]
        return ""

    def get_snippet(self, lineno: int, context: int = 2) -> str:
        start = max(1, lineno - context)
        end = min(len(self.lines), lineno + context)
        result_lines = []
        for i in range(start, end + 1):
            marker = ">>>" if i == lineno else "   "
            result_lines.append(f"{marker} {i:4d} | {self.lines[i - 1]}")
        return "\n".join(result_lines)


# ─────────────────────────────────────────────────────────
# Vulnerability Rules Engine
# ─────────────────────────────────────────────────────────

class RustVulnerabilityScanner:
    """Scans Rust source for 30+ vulnerability categories."""

    def __init__(self):
        self.vulns: List[Vulnerability] = []

    def scan_file(self, filepath: str, source: str) -> List[Vulnerability]:
        self.vulns = []
        try:
            tokenizer = RustTokenizer(source)
            tokens = tokenizer.tokenize()
            ast = RustASTAnalyzer(tokens, source)
        except Exception as e:
            logger.error(f"Parse error in {filepath}: {e}")
            return []

        lines = source.split("\n")

        # Run all 30+ checks
        self._check_unsafe_code(filepath, tokens, ast, lines)
        self._check_command_injection(filepath, tokens, ast, lines)
        self._check_sql_injection(filepath, tokens, ast, lines)
        self._check_path_traversal(filepath, tokens, ast, lines)
        self._check_xss(filepath, tokens, ast, lines)
        self._check_ssrf(filepath, tokens, ast, lines)
        self._check_deserialization(filepath, tokens, ast, lines)
        self._check_hardcoded_secrets(filepath, tokens, ast, lines)
        self._check_weak_crypto(filepath, tokens, ast, lines)
        self._check_insecure_random(filepath, tokens, ast, lines)
        self._check_unwrap_overuse(filepath, tokens, ast, lines)
        self._check_race_conditions(filepath, tokens, ast, lines)
        self._check_integer_overflow(filepath, tokens, ast, lines)
        self._check_insecure_tls(filepath, tokens, ast, lines)
        self._check_info_disclosure(filepath, tokens, ast, lines)
        self._check_actix_issues(filepath, tokens, ast, lines)
        self._check_rocket_issues(filepath, tokens, ast, lines)
        self._check_tokio_blocking(filepath, tokens, ast, lines)
        self._check_resource_exhaustion(filepath, tokens, ast, lines)
        self._check_timing_attacks(filepath, tokens, ast, lines)
        self._check_jwt_issues(filepath, tokens, ast, lines)
        self._check_cors_misconfig(filepath, tokens, ast, lines)
        self._check_missing_auth(filepath, tokens, ast, lines)
        self._check_ffi_unsafe(filepath, tokens, ast, lines)
        self._check_memory_leaks(filepath, tokens, ast, lines)
        self._check_silenced_errors(filepath, tokens, ast, lines)
        self._check_file_permissions(filepath, tokens, ast, lines)
        self._check_logging_sensitive(filepath, tokens, ast, lines)
        self._check_open_redirect(filepath, tokens, ast, lines)
        self._check_clippy_security(filepath, tokens, ast, lines)

        return self.vulns

    def _add_vuln(self, filepath, line, col, end_line, category, title, desc, severity, confidence, snippet, rec, cwe, owasp, refs=None):
        self.vulns.append(Vulnerability(
            id=str(uuid.uuid4()),
            category=category,
            title=title,
            description=desc,
            severity=severity,
            confidence=confidence,
            file_path=filepath,
            line_number=line,
            column=col,
            end_line=end_line,
            code_snippet=snippet,
            recommendation=rec,
            cwe_id=cwe,
            owasp=owasp,
            references=refs or [],
        ))

    def _get_snippet(self, lines, lineno, context=2):
        start = max(0, lineno - 1 - context)
        end = min(len(lines), lineno + context)
        result = []
        for i in range(start, end):
            marker = ">>>" if i == lineno - 1 else "   "
            result.append(f"{marker} {i+1:4d} | {lines[i]}")
        return "\n".join(result)

    # ── 1. Unsafe Code ──

    def _check_unsafe_code(self, fp, tokens, ast, lines):
        for start, end in ast.unsafe_blocks:
            snip = self._get_snippet(lines, start)
            self._add_vuln(fp, start, 1, end, "Unsafe Code", "Unsafe block detected",
                "Unsafe block bypasses Rust memory safety guarantees. Raw pointer dereferencing, "
                "transmute, union access, and unsafe trait implementations can cause undefined behavior.",
                Severity.HIGH, Confidence.HIGH, snip,
                "Minimize unsafe code. Encapsulate unsafe operations in safe abstractions with thorough documentation and testing.",
                "CWE-119", "A06:2021", ["https://doc.rust-lang.org/book/ch19-01-unsafe-rust.html"])

        for fn in ast.functions:
            if fn.is_unsafe:
                snip = self._get_snippet(lines, fn.line)
                self._add_vuln(fp, fn.line, 1, fn.end_line, "Unsafe Code", f"Unsafe function: {fn.name}",
                    f"Function `{fn.name}` is marked unsafe. Callers must uphold safety invariants manually.",
                    Severity.HIGH, Confidence.HIGH, snip,
                    "Document all safety invariants. Consider providing a safe wrapper.",
                    "CWE-119", "A06:2021")

        for impl in ast.impls:
            if impl.is_unsafe:
                snip = self._get_snippet(lines, impl.line)
                self._add_vuln(fp, impl.line, 1, impl.line, "Unsafe Code", f"Unsafe impl: {impl.name}",
                    f"Unsafe impl block for `{impl.name}`. Implementing unsafe traits requires manual verification of safety contracts.",
                    Severity.HIGH, Confidence.HIGH, snip,
                    "Verify all safety invariants of the trait are upheld.",
                    "CWE-119", "A06:2021")

        for i, line in enumerate(lines, 1):
            if "transmute" in line and ("mem::transmute" in line or "transmute(" in line):
                snip = self._get_snippet(lines, i)
                self._add_vuln(fp, i, 1, i, "Unsafe Code", "Use of std::mem::transmute",
                    "transmute reinterprets bits of one type as another, bypassing type checking entirely. "
                    "This can cause undefined behavior if types have different layouts.",
                    Severity.CRITICAL, Confidence.HIGH, snip,
                    "Use safe alternatives like From/Into traits, as casts, or bytemuck crate.",
                    "CWE-704", "A06:2021")

            if re.search(r'\*\s*(mut|const)\s+\w+', line) and ('as *' in line or '*raw' in line.lower()):
                snip = self._get_snippet(lines, i)
                self._add_vuln(fp, i, 1, i, "Unsafe Code", "Raw pointer manipulation",
                    "Raw pointer creation or casting detected. Dereferencing raw pointers requires unsafe and can cause memory corruption.",
                    Severity.HIGH, Confidence.MEDIUM, snip,
                    "Prefer references over raw pointers. If raw pointers are necessary, carefully document safety invariants.",
                    "CWE-119", "A06:2021")

    # ── 2. Command Injection ──

    def _check_command_injection(self, fp, tokens, ast, lines):
        cmd_patterns = [
            (r'Command::new\s*\(\s*(?:&?\s*\w+|format!\s*\()', "Command::new with dynamic argument"),
            (r'\.arg\s*\(\s*(?:&?\s*\w+|format!\s*\()', ".arg() with dynamic value"),
            (r'\.args\s*\(\s*(?:&?\s*\w+|format!\s*\()', ".args() with dynamic values"),
            (r'Command::new\s*\(\s*"(?:sh|bash|cmd|powershell)"', "Shell invocation via Command"),
            (r'\.arg\s*\(\s*"-c"\s*\)', "Shell -c flag (command string execution)"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in cmd_patterns:
                if re.search(pattern, line):
                    severity = Severity.CRITICAL if "format!" in line else Severity.HIGH
                    conf = Confidence.HIGH if "format!" in line else Confidence.MEDIUM
                    snip = self._get_snippet(lines, i)
                    self._add_vuln(fp, i, 1, i, "Command Injection", desc,
                        f"Potential command injection: {desc}. If user input flows into Command arguments "
                        "without validation, an attacker can execute arbitrary system commands.",
                        severity, conf, snip,
                        "Never pass unsanitized user input to Command. Use allowlists for permitted commands and arguments. "
                        "Avoid shell invocations entirely when possible.",
                        "CWE-78", "A03:2021",
                        ["https://owasp.org/www-community/attacks/Command_Injection"])

    # ── 3. SQL Injection ──

    def _check_sql_injection(self, fp, tokens, ast, lines):
        sql_patterns = [
            (r'sql_query\s*\(\s*&?\s*format!\s*\(', "Diesel sql_query with format!"),
            (r'raw_sql\s*\(\s*&?\s*format!\s*\(', "Raw SQL with format!"),
            (r'sqlx::query\s*\(\s*&?\s*format!\s*\(', "sqlx query with format!"),
            (r'execute\s*\(\s*&?\s*format!\s*\(.*(?:SELECT|INSERT|UPDATE|DELETE|DROP)', "SQL execute with format!"),
            (r'query\s*\(\s*&?\s*format!\s*\(.*(?:SELECT|INSERT|UPDATE|DELETE)', "Query with format! containing SQL"),
            (r'rusqlite.*execute\s*\(\s*&?\s*format!\s*\(', "rusqlite execute with format!"),
            (r'prepare\s*\(\s*&?\s*format!\s*\(', "SQL prepare with format!"),
        ]
        for i, line in enumerate(lines, 1):
            for entry in sql_patterns:
                pattern, desc = entry[0], entry[1]
                if re.search(pattern, line, re.IGNORECASE):
                    snip = self._get_snippet(lines, i)
                    self._add_vuln(fp, i, 1, i, "SQL Injection", desc,
                        f"SQL injection risk: {desc}. Using format! or string concatenation to build SQL queries "
                        "allows attackers to inject malicious SQL statements.",
                        Severity.CRITICAL, Confidence.HIGH, snip,
                        "Use parameterized queries. With Diesel, use the query builder. With sqlx, use $1 placeholders. "
                        "Never use format! to build SQL strings.",
                        "CWE-89", "A03:2021",
                        ["https://owasp.org/www-community/attacks/SQL_Injection"])

    # ── 4. Path Traversal ──

    def _check_path_traversal(self, fp, tokens, ast, lines):
        fs_ops = [
            r'(?:std::)?fs::(?:read_to_string|write|read|remove_file|remove_dir|create_dir|copy|rename|metadata|read_dir|canonicalize)\s*\(',
            r'File::(?:open|create)\s*\(',
            r'OpenOptions::new\(\)',
            r'Path::new\s*\(\s*(?:&?\s*\w+|format!\s*\()',
            r'PathBuf::from\s*\(\s*(?:&?\s*\w+|format!\s*\()',
        ]
        for i, line in enumerate(lines, 1):
            for pattern in fs_ops:
                if re.search(pattern, line):
                    if any(hint in line for hint in ["path", "file", "dir", "name", "input", "param", "query", "request", "user", "format!", "arg"]):
                        snip = self._get_snippet(lines, i)
                        self._add_vuln(fp, i, 1, i, "Path Traversal", "File system operation with potentially user-controlled path",
                            "File system operation uses a path that may be influenced by user input. "
                            "Path traversal attacks (../) can access files outside intended directories.",
                            Severity.HIGH, Confidence.MEDIUM, snip,
                            "Canonicalize paths and verify they are within the expected directory. "
                            "Use Path::starts_with() to validate path prefixes. Reject paths containing '..'.",
                            "CWE-22", "A01:2021",
                            ["https://owasp.org/www-community/attacks/Path_Traversal"])

    # ── 5. XSS ──

    def _check_xss(self, fp, tokens, ast, lines):
        xss_patterns = [
            (r'HttpResponse::Ok\(\)\.content_type\s*\(\s*"text/html"', "actix-web HTML response without escaping"),
            (r'\.body\s*\(\s*format!\s*\(', "Dynamic body content with format!"),
            (r'content::Html\s*\(\s*format!\s*\(', "Rocket HTML response with format!"),
            (r'Html\s*\(\s*format!\s*\(', "Axum HTML response with format!"),
            (r'Response::builder\(\).*\.body\s*\(\s*format!\s*\(', "Raw HTML response with format!"),
            (r'\.html\s*\(\s*format!\s*\(', "HTML method with format!"),
            (r'write!\s*\(.*"<[a-zA-Z]', "HTML tag in write! macro"),
            (r'format!\s*\(.*"<(?:script|iframe|img|svg|body|div|span|a|form)', "HTML tags in format!"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in xss_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    snip = self._get_snippet(lines, i)
                    self._add_vuln(fp, i, 1, i, "Cross-Site Scripting (XSS)", desc,
                        f"Potential XSS: {desc}. Rendering user input in HTML responses without escaping "
                        "allows attackers to inject malicious scripts.",
                        Severity.HIGH, Confidence.MEDIUM, snip,
                        "Use template engines with auto-escaping (Askama, Tera). Never embed user input directly in HTML. "
                        "Use Content-Type: application/json for API responses.",
                        "CWE-79", "A03:2021",
                        ["https://owasp.org/www-community/attacks/xss/"])

    # ── 6. SSRF ──

    def _check_ssrf(self, fp, tokens, ast, lines):
        ssrf_patterns = [
            (r'reqwest::(?:get|Client).*\(\s*(?:&?\s*\w+|format!\s*\()', "reqwest with dynamic URL"),
            (r'hyper::(?:Client|Uri).*\(\s*(?:&?\s*\w+|format!\s*\()', "hyper with dynamic URL"),
            (r'\.get\s*\(\s*(?:&?\s*\w+|format!\s*\().*\.send\(\)', "HTTP GET with dynamic URL"),
            (r'\.post\s*\(\s*(?:&?\s*\w+|format!\s*\().*\.send\(\)', "HTTP POST with dynamic URL"),
            (r'Url::parse\s*\(\s*(?:&?\s*\w+|format!\s*\()', "URL parse from dynamic input"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in ssrf_patterns:
                if re.search(pattern, line):
                    snip = self._get_snippet(lines, i)
                    self._add_vuln(fp, i, 1, i, "SSRF", desc,
                        f"Potential Server-Side Request Forgery: {desc}. If the URL is user-controlled, "
                        "attackers can make the server access internal resources, cloud metadata endpoints, or other services.",
                        Severity.HIGH, Confidence.MEDIUM, snip,
                        "Validate URLs against an allowlist of permitted domains. Block requests to private IP ranges "
                        "(127.0.0.0/8, 10.0.0.0/8, 169.254.169.254, etc.). Use a URL parser to validate scheme and host.",
                        "CWE-918", "A10:2021",
                        ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"])

    # ── 7. Deserialization ──

    def _check_deserialization(self, fp, tokens, ast, lines):
        deser_patterns = [
            (r'serde_json::from_str\s*\(', "serde_json deserialization from string"),
            (r'serde_json::from_slice\s*\(', "serde_json deserialization from bytes"),
            (r'serde_json::from_reader\s*\(', "serde_json deserialization from reader"),
            (r'serde_yaml::from_str\s*\(', "serde_yaml deserialization"),
            (r'serde_yaml::from_reader\s*\(', "serde_yaml deserialization from reader"),
            (r'bincode::deserialize\s*\(', "bincode deserialization"),
            (r'rmp_serde::from_read\s*\(', "MessagePack deserialization"),
            (r'toml::from_str\s*\(', "TOML deserialization"),
            (r'ciborium::from_reader\s*\(', "CBOR deserialization"),
            (r'postcard::from_bytes\s*\(', "postcard deserialization"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in deser_patterns:
                if re.search(pattern, line):
                    is_direct = any(w in line for w in ["body", "request", "input", "payload", "data", "bytes"])
                    snip = self._get_snippet(lines, i)
                    self._add_vuln(fp, i, 1, i, "Insecure Deserialization", desc,
                        f"Deserialization of potentially untrusted data: {desc}. Deserializing untrusted input "
                        "can lead to denial of service via deeply nested structures, or logic bugs via crafted data.",
                        Severity.HIGH if is_direct else Severity.MEDIUM,
                        Confidence.HIGH if is_direct else Confidence.LOW, snip,
                        "Validate and sanitize input before deserialization. Set size limits on input. "
                        "Use #[serde(deny_unknown_fields)] to reject unexpected fields. Consider using a schema validator.",
                        "CWE-502", "A08:2021",
                        ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests"])

    # ── 8. Hardcoded Secrets ──

    def _check_hardcoded_secrets(self, fp, tokens, ast, lines):
        secret_patterns = [
            (r'(?:password|passwd|pwd)\s*[:=]\s*"[^"]{4,}"', "Hardcoded password"),
            (r'(?:api[_-]?key|apikey)\s*[:=]\s*"[^"]{8,}"', "Hardcoded API key"),
            (r'(?:secret[_-]?key|secret)\s*[:=]\s*"[^"]{8,}"', "Hardcoded secret key"),
            (r'(?:token|auth[_-]?token|access[_-]?token)\s*[:=]\s*"[^"]{8,}"', "Hardcoded token"),
            (r'(?:private[_-]?key)\s*[:=]\s*"[^"]{8,}"', "Hardcoded private key"),
            (r'"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}"', "GitHub token in source"),
            (r'"(?:sk-[A-Za-z0-9]{32,})"', "OpenAI/Anthropic API key in source"),
            (r'"(?:AKIA[0-9A-Z]{16})"', "AWS Access Key in source"),
            (r'"Bearer\s+[A-Za-z0-9\-._~+/]+=*"', "Hardcoded Bearer token"),
            (r'(?:connection[_-]?string|conn[_-]?str)\s*[:=]\s*"[^"]*(?:password|pwd)=[^"]*"', "Database connection string with password"),
        ]
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue
            for pattern, desc in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    if any(fp_part in fp.lower() for fp_part in ["test", "mock", "example", "fixture"]):
                        conf = Confidence.LOW
                    else:
                        conf = Confidence.HIGH
                    snip = self._get_snippet(lines, i)
                    self._add_vuln(fp, i, 1, i, "Hardcoded Secrets", desc,
                        f"{desc} found in source code. Secrets in source code can be extracted from version control "
                        "history, compiled binaries, or by anyone with repository access.",
                        Severity.CRITICAL, conf, snip,
                        "Use environment variables, a secrets manager (HashiCorp Vault, AWS Secrets Manager), "
                        "or configuration files excluded from version control (.env files in .gitignore).",
                        "CWE-798", "A07:2021",
                        ["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"])

    # ── 9. Weak Crypto ──

    def _check_weak_crypto(self, fp, tokens, ast, lines):
        crypto_patterns = [
            (r'(?:Md5|MD5|md5)::(?:new|digest|hash)', "MD5 usage", Severity.HIGH),
            (r'(?:Sha1|SHA1|sha1)::(?:new|digest|hash)', "SHA-1 usage", Severity.HIGH),
            (r'use\s+md5', "MD5 crate import", Severity.HIGH),
            (r'use\s+sha1\b', "SHA-1 crate import", Severity.HIGH),
            (r'(?:Des|DES|des|RC4|rc4|Rc4)::(?:new|encrypt)', "Weak cipher (DES/RC4)", Severity.CRITICAL),
            (r'Rsa::generate\s*\(\s*(?:512|768|1024)\s*\)', "Weak RSA key size", Severity.CRITICAL),
            (r'ECB\b', "ECB mode usage", Severity.HIGH),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc, sev in crypto_patterns:
                if re.search(pattern, line):
                    snip = self._get_snippet(lines, i)
                    self._add_vuln(fp, i, 1, i, "Weak Cryptography", desc,
                        f"Weak cryptographic algorithm: {desc}. MD5 and SHA-1 are broken for security purposes. "
                        "DES and RC4 have known vulnerabilities. ECB mode reveals patterns in ciphertext.",
                        sev, Confidence.HIGH, snip,
                        "Use SHA-256/SHA-3 for hashing, AES-GCM for encryption, Argon2/bcrypt for password hashing. "
                        "Use RSA keys >= 2048 bits. Use the `ring` or `rustcrypto` crates.",
                        "CWE-327", "A02:2021",
                        ["https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"])

    # ── 10. Insecure Random ──

    def _check_insecure_random(self, fp, tokens, ast, lines):
        for i, line in enumerate(lines, 1):
            if re.search(r'thread_rng\(\)', line):
                context_lines = "\n".join(lines[max(0, i-5):min(len(lines), i+5)])
                if any(w in context_lines.lower() for w in ["token", "secret", "key", "password", "session", "nonce", "salt", "csrf"]):
                    snip = self._get_snippet(lines, i)
                    self._add_vuln(fp, i, 1, i, "Insecure Random", "thread_rng() used for security-sensitive purpose",
                        "thread_rng() is a fast but not cryptographically secure RNG. Using it for tokens, keys, "
                        "or other security-critical values makes them predictable.",
                        Severity.HIGH, Confidence.MEDIUM, snip,
                        "Use OsRng or rand::rngs::StdRng seeded from OsRng for cryptographic purposes. "
                        "Consider the `ring` crate for cryptographic random number generation.",
                        "CWE-330", "A02:2021")

            if re.search(r'(?:SmallRng|XorShiftRng)::(?:from_seed|seed_from_u64)', line):
                snip = self._get_snippet(lines, i)
                self._add_vuln(fp, i, 1, i, "Insecure Random", "Non-cryptographic RNG used",
                    "SmallRng/XorShiftRng are explicitly non-cryptographic. They must not be used for security purposes.",
                    Severity.HIGH, Confidence.HIGH, snip,
                    "Use OsRng for cryptographic random number generation.",
                    "CWE-330", "A02:2021")

    # ── 11. unwrap()/expect() Overuse ──

    def _check_unwrap_overuse(self, fp, tokens, ast, lines):
        unwrap_count = 0
        unwrap_lines = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("#[") or stripped.startswith("/*"):
                continue
            unwraps = len(re.findall(r'\.unwrap\(\)', line))
            expects = len(re.findall(r'\.expect\(', line))
            count = unwraps + expects
            if count > 0:
                if any(fp_part in fp.lower() for fp_part in ["test", "tests", "_test.rs"]):
                    continue
                unwrap_count += count
                unwrap_lines.append(i)

        if unwrap_count >= 5:
            for lineno in unwrap_lines[:10]:
                snip = self._get_snippet(lines, lineno)
                self._add_vuln(fp, lineno, 1, lineno, "Unwrap Overuse", "unwrap()/expect() in production code",
                    f"unwrap()/expect() will panic if the Result/Option is Err/None, crashing the process. "
                    f"Found {unwrap_count} instances in this file.",
                    Severity.MEDIUM, Confidence.MEDIUM, snip,
                    "Use proper error handling with match, if let, or the ? operator. "
                    "Reserve unwrap() for cases proven safe by invariants, and document why.",
                    "CWE-248", "A06:2021")

    # ── 12. Race Conditions ──

    def _check_race_conditions(self, fp, tokens, ast, lines):
        source = "\n".join(lines)
        for i, line in enumerate(lines, 1):
            if re.search(r'static\s+mut\s+', line):
                snip = self._get_snippet(lines, i)
                self._add_vuln(fp, i, 1, i, "Race Condition", "static mut variable",
                    "static mut variables are inherently unsafe for concurrent access. Any read or write requires "
                    "unsafe, and concurrent access is undefined behavior.",
                    Severity.HIGH, Confidence.HIGH, snip,
                    "Use std::sync::Mutex, RwLock, or atomic types instead. Consider once_cell::sync::Lazy for lazy initialization.",
                    "CWE-362", "A04:2021")

        has_arc = "Arc<" in source or "Arc::new" in source
        has_mutex = "Mutex" in source or "RwLock" in source
        if has_arc and not has_mutex:
            for i, line in enumerate(lines, 1):
                if "Arc::new" in line and "Mutex" not in line and "RwLock" not in line:
                    snip = self._get_snippet(lines, i)
                    self._add_vuln(fp, i, 1, i, "Race Condition", "Arc without Mutex/RwLock",
                        "Arc provides shared ownership but not mutual exclusion. Wrapping data in Arc without "
                        "Mutex or RwLock may indicate missing synchronization for mutable data.",
                        Severity.MEDIUM, Confidence.LOW, snip,
                        "Wrap shared mutable data in Arc<Mutex<T>> or Arc<RwLock<T>>.",
                        "CWE-362", "A04:2021")

        if "RefCell" in source and ("thread" in source.lower() or "async" in source or "tokio" in source):
            for i, line in enumerate(lines, 1):
                if "RefCell" in line:
                    snip = self._get_snippet(lines, i)
                    self._add_vuln(fp, i, 1, i, "Race Condition", "RefCell in potentially multi-threaded context",
                        "RefCell provides interior mutability but is not thread-safe. Using it across threads causes UB.",
                        Severity.HIGH, Confidence.LOW, snip,
                        "Use Mutex or RwLock for thread-safe interior mutability.",
                        "CWE-362", "A04:2021")

    # ── 13. Integer Overflow ──

    def _check_integer_overflow(self, fp, tokens, ast, lines):
        for i, line in enumerate(lines, 1):
            if re.search(r'as\s+(?:u8|u16|u32|i8|i16|i32|usize)\b', line):
                if any(w in line for w in ["input", "param", "arg", "parse", "from_str", "request"]):
                    snip = self._get_snippet(lines, i)
                    self._add_vuln(fp, i, 1, i, "Integer Overflow", "Unchecked integer cast from user input",
                        "Casting user-controlled values to smaller integer types can cause truncation or overflow. "
                        "In debug mode Rust panics on overflow; in release mode it wraps silently.",
                        Severity.MEDIUM, Confidence.MEDIUM, snip,
                        "Use checked_add/checked_mul/checked_sub for arithmetic. Use TryFrom/TryInto for safe conversions. "
                        "Validate ranges before casting.",
                        "CWE-190", "A06:2021")

            if re.search(r'\.wrapping_(?:add|sub|mul)\(', line):
                snip = self._get_snippet(lines, i)
                self._add_vuln(fp, i, 1, i, "Integer Overflow", "Wrapping arithmetic used",
                    "wrapping_* operations intentionally allow overflow. Verify this is the desired behavior "
                    "and not masking a bug.",
                    Severity.LOW, Confidence.LOW, snip,
                    "Ensure wrapping behavior is intentional and documented.",
                    "CWE-190", "A06:2021")

    # ── 14. Insecure TLS ──

    def _check_insecure_tls(self, fp, tokens, ast, lines):
        tls_patterns = [
            (r'danger_accept_invalid_certs\s*\(\s*true\s*\)', "TLS certificate validation disabled"),
            (r'danger_accept_invalid_hostnames\s*\(\s*true\s*\)', "TLS hostname validation disabled"),
            (r'set_verify\s*\(\s*SslVerifyMode::NONE\s*\)', "OpenSSL verification disabled"),
            (r'\.danger_disable_cert_verification\(\)', "Certificate verification disabled"),
            (r'TlsConnector.*danger', "Dangerous TLS configuration"),
            (r'\.verify_mode\s*\(\s*None\s*\)', "TLS verify mode set to None"),
            (r'min_protocol_version.*Tls10', "TLS 1.0 minimum version"),
            (r'min_protocol_version.*Ssl', "SSL protocol (deprecated)"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, desc in tls_patterns:
                if re.search(pattern, line):
                    snip = self._get_snippet(lines, i)
                    self._add_vuln(fp, i, 1, i, "Insecure TLS", desc,
                        f"Insecure TLS configuration: {desc}. Disabling certificate or hostname validation "
                        "enables man-in-the-middle attacks.",
                        Severity.CRITICAL, Confidence.HIGH, snip,
                        "Always validate TLS certificates and hostnames. Use system CA store. "
                        "Set minimum TLS version to 1.2. Use rustls with safe defaults.",
                        "CWE-295", "A07:2021",
                        ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"])

    # ── 15. Information Disclosure ──

    def _check_info_disclosure(self, fp, tokens, ast, lines):
        for st in ast.structs:
            if "Debug" in st.derives:
                name_lower = st.name.lower()
                if any(w in name_lower for w in ["user", "auth", "cred", "secret", "key", "token", "password", "session", "config"]):
                    snip = self._get_snippet(lines, st.line)
                    self._add_vuln(fp, st.line, 1, st.line, "Information Disclosure",
                        f"Debug derive on sensitive struct: {st.name}",
                        f"Struct `{st.name}` derives Debug, which may expose sensitive fields in logs or error messages. "
                        "Debug output can leak passwords, tokens, and other secrets.",
                        Severity.MEDIUM, Confidence.MEDIUM, snip,
                        "Implement a custom Debug trait that redacts sensitive fields, or remove Debug derive from sensitive structs.",
                        "CWE-200", "A01:2021")

        for i, line in enumerate(lines, 1):
            if re.search(r'(?:backtrace|RUST_BACKTRACE)', line):
                if re.search(r'(?:response|body|json|html|HttpResponse)', "\n".join(lines[max(0,i-5):min(len(lines),i+5)])):
                    snip = self._get_snippet(lines, i)
                    self._add_vuln(fp, i, 1, i, "Information Disclosure", "Backtrace exposure in response",
                        "Stack traces expose internal implementation details to attackers.",
                        Severity.MEDIUM, Confidence.MEDIUM, snip,
                        "Never expose stack traces to end users. Log them server-side only.",
                        "CWE-209", "A04:2021")

    # ── 16. Actix-web Issues ──

    def _check_actix_issues(self, fp, tokens, ast, lines):
        source = "\n".join(lines)
        if "actix_web" not in source and "actix-web" not in source:
            return

        for i, line in enumerate(lines, 1):
            if re.search(r'HttpServer::new', line):
                if "RateLimiter" not in source and "rate_limit" not in source and "Governor" not in source:
                    snip = self._get_snippet(lines, i)
                    self._add_vuln(fp, i, 1, i, "Actix-web Security", "No rate limiting configured",
                        "Actix-web server without rate limiting middleware. This enables brute-force attacks and DoS.",
                        Severity.MEDIUM, Confidence.MEDIUM, snip,
                        "Add rate limiting middleware (actix-governor, actix-limitation).",
                        "CWE-770", "A04:2021")

            if re.search(r'\.error_response\(\)', line) or re.search(r'ResponseError.*fn error_response', line):
                ctx = "\n".join(lines[max(0,i-3):min(len(lines),i+3)])
                if "debug" in ctx.lower() or 'format!("{:?' in ctx:
                    snip = self._get_snippet(lines, i)
                    self._add_vuln(fp, i, 1, i, "Actix-web Security", "Debug info in error responses",
                        "Error responses may include debug information that exposes internal implementation details.",
                        Severity.MEDIUM, Confidence.LOW, snip,
                        "Return generic error messages to clients. Log detailed errors server-side.",
                        "CWE-209", "A04:2021")

    # ── 17. Rocket Issues ──

    def _check_rocket_issues(self, fp, tokens, ast, lines):
        source = "\n".join(lines)
        if "rocket" not in source.lower():
            return

        for i, line in enumerate(lines, 1):
            if re.search(r'secret_key\s*=\s*"', line):
                snip = self._get_snippet(lines, i)
                self._add_vuln(fp, i, 1, i, "Rocket Security", "Hardcoded secret_key in Rocket config",
                    "Secret key for cookie signing is hardcoded. Anyone with source access can forge cookies.",
                    Severity.CRITICAL, Confidence.HIGH, snip,
                    "Use environment variables for Rocket secret_key. Generate with `openssl rand -base64 32`.",
                    "CWE-798", "A07:2021")

            if re.search(r'(?:environment|profile)\s*=\s*"debug"', line, re.IGNORECASE):
                snip = self._get_snippet(lines, i)
                self._add_vuln(fp, i, 1, i, "Rocket Security", "Debug profile in configuration",
                    "Running Rocket in debug mode exposes detailed error pages and stack traces.",
                    Severity.MEDIUM, Confidence.HIGH, snip,
                    "Set profile to 'release' for production deployments.",
                    "CWE-489", "A05:2021")

    # ── 18. Tokio Blocking in Async ──

    def _check_tokio_blocking(self, fp, tokens, ast, lines):
        for fn in ast.functions:
            if not fn.is_async:
                continue
            fn_body_lines = lines[fn.line - 1:fn.end_line]
            fn_body = "\n".join(fn_body_lines)

            blocking_patterns = [
                (r'std::thread::sleep\(', "std::thread::sleep in async function"),
                (r'std::fs::', "std::fs (blocking I/O) in async function"),
                (r'\.read_to_string\(', "Blocking read in async function"),
                (r'std::net::', "std::net (blocking networking) in async function"),
                (r'\.lock\(\)\.unwrap\(\)', "Blocking mutex lock in async function"),
            ]
            for pattern, desc in blocking_patterns:
                m = re.search(pattern, fn_body)
                if m:
                    for j, bl in enumerate(fn_body_lines):
                        if re.search(pattern, bl):
                            actual_line = fn.line + j
                            snip = self._get_snippet(lines, actual_line)
                            self._add_vuln(fp, actual_line, 1, actual_line, "Blocking in Async", desc,
                                f"{desc}. Blocking operations in async functions stall the entire executor thread, "
                                "causing performance degradation and potential deadlocks.",
                                Severity.MEDIUM, Confidence.HIGH, snip,
                                "Use tokio::time::sleep, tokio::fs, tokio::net for async equivalents. "
                                "For CPU-bound work, use tokio::task::spawn_blocking().",
                                "CWE-400", "A06:2021")
                            break

    # ── 19. Resource Exhaustion ──

    def _check_resource_exhaustion(self, fp, tokens, ast, lines):
        for i, line in enumerate(lines, 1):
            if re.search(r'Vec::new\(\)|Vec::with_capacity\(', line):
                context = "\n".join(lines[max(0,i-3):min(len(lines),i+10)])
                if any(w in context for w in ["request", "body", "input", "query", "param"]) and "limit" not in context.lower() and "max" not in context.lower():
                    snip = self._get_snippet(lines, i)
                    self._add_vuln(fp, i, 1, i, "Resource Exhaustion", "Unbounded collection from user input",
                        "Creating collections from user input without size limits can exhaust memory.",
                        Severity.MEDIUM, Confidence.LOW, snip,
                        "Set maximum size limits on collections populated from user input. Use bounded channels and buffers.",
                        "CWE-400", "A05:2021")

            if re.search(r'loop\s*\{', line):
                context = "\n".join(lines[i:min(len(lines), i+15)])
                if "read" in context and "break" not in context and "return" not in context:
                    snip = self._get_snippet(lines, i)
                    self._add_vuln(fp, i, 1, i, "Resource Exhaustion", "Potentially infinite read loop",
                        "Loop reading data without clear termination condition can hang or exhaust resources.",
                        Severity.MEDIUM, Confidence.LOW, snip,
                        "Add size limits, timeouts, and explicit break conditions.",
                        "CWE-835", "A05:2021")

            if re.search(r'(?:Json|Bytes|Payload)::configure', line) and "limit" not in line:
                snip = self._get_snippet(lines, i)
                self._add_vuln(fp, i, 1, i, "Resource Exhaustion", "Payload configuration without size limit",
                    "Request payload configuration without explicit size limit.",
                    Severity.MEDIUM, Confidence.MEDIUM, snip,
                    "Set explicit payload size limits: .limit(1_048_576) for 1MB.",
                    "CWE-400", "A05:2021")

    # ── 20. Timing Attacks ──

    def _check_timing_attacks(self, fp, tokens, ast, lines):
        for i, line in enumerate(lines, 1):
            if re.search(r'==\s*(?:password|token|secret|key|hash|api_key|auth)', line, re.IGNORECASE):
                snip = self._get_snippet(lines, i)
                self._add_vuln(fp, i, 1, i, "Timing Attack", "Non-constant-time comparison of secret",
                    "Using == for comparing secrets enables timing attacks. An attacker can determine "
                    "the correct value byte-by-byte by measuring response times.",
                    Severity.MEDIUM, Confidence.MEDIUM, snip,
                    "Use constant-time comparison: ring::constant_time::verify_slices_are_equal() "
                    "or subtle::ConstantTimeEq.",
                    "CWE-208", "A02:2021")

            if re.search(r'(?:password|token|secret).*(?:==|!=|eq\()', line, re.IGNORECASE):
                if "constant_time" not in line and "subtle" not in line and "verify_slices" not in line:
                    snip = self._get_snippet(lines, i)
                    self._add_vuln(fp, i, 1, i, "Timing Attack", "Secret comparison not using constant-time",
                        "Comparing security tokens/passwords with standard equality enables timing side-channel attacks.",
                        Severity.MEDIUM, Confidence.MEDIUM, snip,
                        "Use constant_time_eq or ring::constant_time for secret comparisons.",
                        "CWE-208", "A02:2021")

    # ── 21. JWT Issues ──

    def _check_jwt_issues(self, fp, tokens, ast, lines):
        source = "\n".join(lines)
        if "jwt" not in source.lower() and "jsonwebtoken" not in source.lower():
            return

        for i, line in enumerate(lines, 1):
            if re.search(r'Algorithm::None|alg.*none', line, re.IGNORECASE):
                snip = self._get_snippet(lines, i)
                self._add_vuln(fp, i, 1, i, "JWT Security", "JWT 'none' algorithm allowed",
                    "Allowing the 'none' algorithm means tokens can be forged without any signing.",
                    Severity.CRITICAL, Confidence.HIGH, snip,
                    "Never allow Algorithm::None. Explicitly set the expected algorithm in validation.",
                    "CWE-347", "A02:2021")

            if re.search(r'Validation.*validate_exp.*false', line):
                snip = self._get_snippet(lines, i)
                self._add_vuln(fp, i, 1, i, "JWT Security", "JWT expiry validation disabled",
                    "Disabling expiry validation means tokens never expire, increasing the window for stolen token abuse.",
                    Severity.HIGH, Confidence.HIGH, snip,
                    "Always validate JWT expiry claims.",
                    "CWE-613", "A07:2021")

            if re.search(r'(?:HS256|Hs256)', line):
                context = "\n".join(lines[max(0,i-5):min(len(lines),i+5)])
                if re.search(r'(?:secret|key)\s*[:=]\s*"[^"]{1,15}"', context, re.IGNORECASE):
                    snip = self._get_snippet(lines, i)
                    self._add_vuln(fp, i, 1, i, "JWT Security", "HS256 with short/weak secret",
                        "HMAC-SHA256 with a short secret key is vulnerable to brute-force attacks.",
                        Severity.HIGH, Confidence.MEDIUM, snip,
                        "Use a secret key of at least 256 bits (32+ bytes). Consider RS256 with asymmetric keys.",
                        "CWE-326", "A02:2021")

    # ── 22. CORS Misconfig ──

    def _check_cors_misconfig(self, fp, tokens, ast, lines):
        for i, line in enumerate(lines, 1):
            if re.search(r'\.allow_any_origin\(\)', line) or re.search(r'Cors::permissive\(\)', line):
                snip = self._get_snippet(lines, i)
                self._add_vuln(fp, i, 1, i, "CORS Misconfiguration", "Permissive CORS: allow any origin",
                    "CORS configured to allow any origin. This permits any website to make authenticated "
                    "requests to your API, enabling cross-site data theft.",
                    Severity.HIGH, Confidence.HIGH, snip,
                    "Explicitly list allowed origins. Never use allow_any_origin() with credentials.",
                    "CWE-942", "A05:2021")

            if re.search(r'\.allow_any_header\(\)', line):
                snip = self._get_snippet(lines, i)
                self._add_vuln(fp, i, 1, i, "CORS Misconfiguration", "CORS allows any header",
                    "Allowing any header in CORS responses can expose the application to header-injection attacks.",
                    Severity.MEDIUM, Confidence.MEDIUM, snip,
                    "Explicitly list required headers instead of allowing all.",
                    "CWE-942", "A05:2021")

            if re.search(r'Access-Control-Allow-Origin.*\*', line):
                snip = self._get_snippet(lines, i)
                self._add_vuln(fp, i, 1, i, "CORS Misconfiguration", "Access-Control-Allow-Origin: * header",
                    "Wildcard CORS origin allows any site to access your API responses.",
                    Severity.HIGH, Confidence.HIGH, snip,
                    "Set specific allowed origins instead of wildcard.",
                    "CWE-942", "A05:2021")

    # ── 23. Missing Auth Middleware ──

    def _check_missing_auth(self, fp, tokens, ast, lines):
        source = "\n".join(lines)
        route_annotations = [
            r'#\[(?:get|post|put|delete|patch)\s*\("',
            r'\.route\s*\(\s*"',
            r'\.resource\s*\(\s*"',
        ]
        has_auth_middleware = any(w in source for w in [
            "Auth", "auth_middleware", "JwtMiddleware", "Identity", "bearer",
            "Authorization", "authenticate", "Claims", "guard", "AuthGuard",
        ])

        if not has_auth_middleware:
            for i, line in enumerate(lines, 1):
                for pattern in route_annotations:
                    if re.search(pattern, line):
                        route_path = re.search(r'"(/[^"]*)"', line)
                        if route_path:
                            path = route_path.group(1)
                            public_paths = ["/health", "/login", "/register", "/public", "/status", "/docs", "/swagger"]
                            if not any(path.startswith(p) for p in public_paths):
                                snip = self._get_snippet(lines, i)
                                self._add_vuln(fp, i, 1, i, "Missing Authentication", "Route without authentication middleware",
                                    f"Route handler for '{path}' does not appear to have authentication middleware. "
                                    "Unauthenticated endpoints may expose sensitive data or functionality.",
                                    Severity.HIGH, Confidence.LOW, snip,
                                    "Add authentication middleware/guard to all non-public routes.",
                                    "CWE-306", "A07:2021")
                                break

    # ── 24. FFI Unsafe Calls ──

    def _check_ffi_unsafe(self, fp, tokens, ast, lines):
        for i, line in enumerate(lines, 1):
            if re.search(r'extern\s+"C"\s*\{', line):
                snip = self._get_snippet(lines, i)
                self._add_vuln(fp, i, 1, i, "FFI Safety", "Foreign Function Interface (extern C) block",
                    "FFI calls bypass Rust safety guarantees. C functions can cause memory corruption, "
                    "buffer overflows, and undefined behavior.",
                    Severity.HIGH, Confidence.MEDIUM, snip,
                    "Wrap FFI calls in safe Rust abstractions. Validate all inputs before passing to C code. "
                    "Use bindgen for generating bindings. Handle null pointers explicitly.",
                    "CWE-119", "A06:2021")

            if re.search(r'libc::', line):
                snip = self._get_snippet(lines, i)
                self._add_vuln(fp, i, 1, i, "FFI Safety", "Direct libc function call",
                    "Direct libc calls bypass Rust safety and can cause undefined behavior if used incorrectly.",
                    Severity.MEDIUM, Confidence.MEDIUM, snip,
                    "Prefer Rust standard library equivalents over direct libc calls.",
                    "CWE-119", "A06:2021")

    # ── 25. Memory Leaks via mem::forget ──

    def _check_memory_leaks(self, fp, tokens, ast, lines):
        for i, line in enumerate(lines, 1):
            if re.search(r'mem::forget\s*\(', line) or re.search(r'std::mem::forget\s*\(', line):
                snip = self._get_snippet(lines, i)
                self._add_vuln(fp, i, 1, i, "Memory Leak", "Use of mem::forget",
                    "mem::forget prevents Drop from running, leaking resources. This can cause memory leaks, "
                    "file descriptor leaks, or other resource exhaustion.",
                    Severity.MEDIUM, Confidence.HIGH, snip,
                    "Use ManuallyDrop if you need to prevent dropping. Ensure mem::forget is truly necessary.",
                    "CWE-401", "A06:2021")

            if re.search(r'ManuallyDrop::new\s*\(', line):
                snip = self._get_snippet(lines, i)
                self._add_vuln(fp, i, 1, i, "Memory Leak", "ManuallyDrop usage",
                    "ManuallyDrop suppresses automatic Drop. If not manually dropped, resources will leak.",
                    Severity.LOW, Confidence.LOW, snip,
                    "Ensure ManuallyDrop values are explicitly dropped when no longer needed.",
                    "CWE-401", "A06:2021")

            if re.search(r'Box::leak\s*\(', line):
                snip = self._get_snippet(lines, i)
                self._add_vuln(fp, i, 1, i, "Memory Leak", "Use of Box::leak",
                    "Box::leak intentionally leaks memory. This is occasionally valid for creating 'static references "
                    "but can cause unbounded memory growth if used in loops or request handlers.",
                    Severity.MEDIUM, Confidence.MEDIUM, snip,
                    "Use Box::leak only for truly 'static data. Consider using lazy_static or once_cell instead.",
                    "CWE-401", "A06:2021")

    # ── 26. Silenced Errors ──

    def _check_silenced_errors(self, fp, tokens, ast, lines):
        for i, line in enumerate(lines, 1):
            if re.search(r'let\s+_\s*=\s*\w+.*\(', line):
                if any(w in line for w in [
                    "write", "send", "flush", "close", "remove", "delete",
                    "insert", "update", "execute", "connect", "bind", "listen",
                    "read", "set", "save", "create", "open",
                ]):
                    snip = self._get_snippet(lines, i)
                    self._add_vuln(fp, i, 1, i, "Silenced Error", "Result discarded with let _ =",
                        "Discarding a Result with `let _ =` silently ignores errors. Failed I/O operations, "
                        "network calls, or database operations will go unnoticed.",
                        Severity.MEDIUM, Confidence.MEDIUM, snip,
                        "Handle errors explicitly with match, if let Err(e), or propagate with ?. "
                        "At minimum, log the error.",
                        "CWE-252", "A06:2021")

    # ── 27. File Permissions ──

    def _check_file_permissions(self, fp, tokens, ast, lines):
        for i, line in enumerate(lines, 1):
            if re.search(r'Permissions::from_mode\s*\(\s*0o?7[0-7]{2}\s*\)', line):
                snip = self._get_snippet(lines, i)
                self._add_vuln(fp, i, 1, i, "File Permissions", "World-accessible file permissions",
                    "File permissions set to world-readable/writable/executable. Sensitive files should restrict access.",
                    Severity.HIGH, Confidence.HIGH, snip,
                    "Use restrictive permissions: 0o600 for private files, 0o644 for readable files. Never use 0o777.",
                    "CWE-732", "A01:2021")

            if re.search(r'set_permissions.*0o?777', line):
                snip = self._get_snippet(lines, i)
                self._add_vuln(fp, i, 1, i, "File Permissions", "chmod 777 equivalent",
                    "Setting permissions to 777 (rwxrwxrwx) allows any user to read, write, and execute the file.",
                    Severity.HIGH, Confidence.HIGH, snip,
                    "Use minimum necessary permissions.",
                    "CWE-732", "A01:2021")

            if re.search(r'(?:tempfile|temp_dir|tmp)', line, re.IGNORECASE) and "create" in line:
                if "permissions" not in "\n".join(lines[max(0,i-2):min(len(lines),i+2)]).lower():
                    snip = self._get_snippet(lines, i)
                    self._add_vuln(fp, i, 1, i, "File Permissions", "Temp file without explicit permissions",
                        "Temporary file created without explicit permissions may be world-readable by default.",
                        Severity.LOW, Confidence.LOW, snip,
                        "Use tempfile crate which creates files with restrictive permissions by default.",
                        "CWE-732", "A01:2021")

    # ── 28. Logging Sensitive Data ──

    def _check_logging_sensitive(self, fp, tokens, ast, lines):
        log_patterns = [
            r'(?:log|tracing|println|eprintln|dbg).*(?:password|passwd|secret|token|api_key|private_key|ssn|credit_card)',
            r'(?:info|warn|error|debug|trace)!\s*\(.*(?:password|passwd|secret|token|api_key|private_key)',
            r'println!\s*\(.*(?:password|token|secret|key|credential)',
        ]
        for i, line in enumerate(lines, 1):
            for pattern in log_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    if any(w in line for w in ["redact", "mask", "****", "[REDACTED]", "***"]):
                        continue
                    snip = self._get_snippet(lines, i)
                    self._add_vuln(fp, i, 1, i, "Sensitive Data Logging", "Potentially logging sensitive data",
                        "Log statement may include sensitive data (passwords, tokens, keys). "
                        "Log files are often stored insecurely and accessible to multiple systems/people.",
                        Severity.HIGH, Confidence.MEDIUM, snip,
                        "Never log sensitive data. Redact or mask sensitive fields before logging. "
                        "Implement a custom Display trait that redacts sensitive fields.",
                        "CWE-532", "A09:2021",
                        ["https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"])

    # ── 29. Open Redirect ──

    def _check_open_redirect(self, fp, tokens, ast, lines):
        for i, line in enumerate(lines, 1):
            redirect_patterns = [
                (r'Redirect::to\s*\(\s*(?:&?\s*\w+|format!\s*\()', "Redirect with dynamic URL"),
                (r'(?:redirect|location)\s*[:=]\s*(?:&?\s*\w+|format!\s*\()', "Redirect from dynamic value"),
                (r'Header.*Location.*(?:format!\s*\(|&\s*\w+)', "Location header with dynamic value"),
                (r'\.redirect\s*\(\s*(?:301|302|303|307|308)\s*,\s*(?:&?\s*\w+|format!\s*\()', "HTTP redirect with dynamic URL"),
            ]
            for pattern, desc in redirect_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    snip = self._get_snippet(lines, i)
                    self._add_vuln(fp, i, 1, i, "Open Redirect", desc,
                        f"Potential open redirect: {desc}. If the redirect URL comes from user input, "
                        "attackers can redirect users to malicious sites for phishing.",
                        Severity.MEDIUM, Confidence.MEDIUM, snip,
                        "Validate redirect URLs against an allowlist. Only allow relative redirects. "
                        "Reject URLs with different schemes or hosts.",
                        "CWE-601", "A01:2021",
                        ["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"])

    # ── 30. Clippy Security Lints ──

    def _check_clippy_security(self, fp, tokens, ast, lines):
        for i, line in enumerate(lines, 1):
            if re.search(r'#!\s*\[\s*allow\s*\(\s*unsafe_code\s*\)\s*\]', line):
                snip = self._get_snippet(lines, i)
                self._add_vuln(fp, i, 1, i, "Clippy Security", "Crate-level allow(unsafe_code)",
                    "Crate-level #![allow(unsafe_code)] suppresses all unsafe warnings, hiding potentially dangerous code.",
                    Severity.HIGH, Confidence.HIGH, snip,
                    "Remove crate-level allow(unsafe_code). Apply #[allow(unsafe_code)] only to specific items with justification.",
                    "CWE-710", "A06:2021")

            security_lints = [
                "clippy::unwrap_used", "clippy::expect_used", "clippy::panic",
                "clippy::todo", "clippy::unimplemented", "clippy::unreachable",
                "unused_must_use", "clippy::indexing_slicing",
            ]
            for lint in security_lints:
                if f"allow({lint})" in line:
                    snip = self._get_snippet(lines, i)
                    self._add_vuln(fp, i, 1, i, "Clippy Security", f"Security lint suppressed: {lint}",
                        f"Clippy security lint `{lint}` is suppressed. This hides potential issues "
                        "that could cause panics or undefined behavior in production.",
                        Severity.LOW, Confidence.HIGH, snip,
                        f"Fix the underlying issue instead of suppressing `{lint}`.",
                        "CWE-710", "A06:2021")

            if re.search(r'\w+\[\s*\w+\s*\]', line) and not re.search(r'\.get\(', line):
                m = re.search(r'(\w+)\[\s*(\w+)\s*\]', line)
                if m and not m.group(2).isdigit():
                    context = "\n".join(lines[max(0,i-5):min(len(lines),i+5)])
                    if "len()" not in context and ".get(" not in context and "assert" not in context:
                        snip = self._get_snippet(lines, i)
                        self._add_vuln(fp, i, 1, i, "Clippy Security", "Unchecked indexing with variable index",
                            f"Indexing `{m.group(1)}[{m.group(2)}]` without bounds checking will panic on out-of-bounds access.",
                            Severity.LOW, Confidence.LOW, snip,
                            "Use .get() for safe indexing that returns Option instead of panicking.",
                            "CWE-129", "A06:2021")


# ─────────────────────────────────────────────────────────
# FastAPI Application
# ─────────────────────────────────────────────────────────

app = FastAPI(title="Rust SAST Scanner", version="1.0.0")
scanner = RustVulnerabilityScanner()

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "scanner": "rust",
        "version": "1.0.0",
        "language": "Rust",
        "vulnerability_categories": 30,
        "engine": "custom-tokenizer-ast",
    }

@app.post("/scan")
async def scan(request: ScanRequest):
    start_time = time.time()
    scan_id = request.scanId or str(uuid.uuid4())

    if not request.files:
        raise HTTPException(status_code=400, detail="No files provided")

    all_vulns: List[Dict[str, Any]] = []
    files_scanned = 0
    files_with_issues = 0
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    category_counts: Dict[str, int] = {}

    for filepath, content in request.files.items():
        if not filepath.endswith(".rs"):
            continue
        files_scanned += 1
        try:
            vulns = scanner.scan_file(filepath, content)
            if vulns:
                files_with_issues += 1
            for v in vulns:
                severity_counts[v.severity] += 1
                category_counts[v.category] = category_counts.get(v.category, 0) + 1
                all_vulns.append(asdict(v))
        except Exception as e:
            logger.error(f"Error scanning {filepath}: {e}")

    elapsed = round(time.time() - start_time, 3)

    return {
        "scanId": scan_id,
        "language": "Rust",
        "engine": "custom-tokenizer-ast",
        "status": "completed",
        "summary": {
            "totalFiles": len(request.files),
            "filesScanned": files_scanned,
            "filesWithIssues": files_with_issues,
            "totalVulnerabilities": len(all_vulns),
            "severityCounts": severity_counts,
            "categoryCounts": category_counts,
            "scanDurationMs": int(elapsed * 1000),
        },
        "vulnerabilities": all_vulns,
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9009, log_level="info")
