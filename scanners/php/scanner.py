#!/usr/bin/env python3
"""
Offensive360 PHP SAST Scanner v1.0.0
Comprehensive custom-tokenizer-based static analysis for PHP code.
Runs as a FastAPI service on port 9006.

Features:
- Custom PHP tokenizer handling: <?php, namespaces, use statements,
  class/interface/trait, functions, arrow functions (fn), null coalescing (??),
  spaceship (<=>), heredoc/nowdoc, variable variables ($$var),
  string interpolation ("$var", "{$var}")
- 30+ vulnerability detection categories
- Data flow tracking for taint analysis
- Framework-specific detections (Laravel, WordPress, Symfony, CodeIgniter)
"""

import sys
import uuid
import time
import re
import hashlib
import logging
import traceback
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("php-sast")

START_TIME = time.time()

# ============================================================================
# 1. DATA MODELS
# ============================================================================

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
            "startLine": self.line_number,
            "endLine": self.end_line,
            "codeSnippet": self.code_snippet,
            "remediation": self.remediation,
            "category": self.category,
            "dataFlow": [{"file": n.file, "line": n.line, "code": n.code} for n in self.data_flow],
        }


# ============================================================================
# 2. PHP TOKENIZER
# ============================================================================

class TokenType(str, Enum):
    PHP_OPEN = "PHP_OPEN"
    PHP_CLOSE = "PHP_CLOSE"
    NAMESPACE = "NAMESPACE"
    USE = "USE"
    CLASS_DEF = "CLASS"
    INTERFACE = "INTERFACE"
    TRAIT = "TRAIT"
    EXTENDS = "EXTENDS"
    IMPLEMENTS = "IMPLEMENTS"
    FUNCTION = "FUNCTION"
    FN = "FN"                    # arrow function
    RETURN = "RETURN"
    IF = "IF"
    ELSE = "ELSE"
    ELSEIF = "ELSEIF"
    WHILE = "WHILE"
    FOR = "FOR"
    FOREACH = "FOREACH"
    SWITCH = "SWITCH"
    CASE = "CASE"
    TRY = "TRY"
    CATCH = "CATCH"
    FINALLY = "FINALLY"
    THROW = "THROW"
    NEW = "NEW"
    ECHO = "ECHO"
    PRINT = "PRINT"
    INCLUDE = "INCLUDE"
    REQUIRE = "REQUIRE"
    INCLUDE_ONCE = "INCLUDE_ONCE"
    REQUIRE_ONCE = "REQUIRE_ONCE"
    VARIABLE = "VARIABLE"
    VAR_VAR = "VAR_VAR"          # $$var
    STRING = "STRING"
    HEREDOC = "HEREDOC"
    NOWDOC = "NOWDOC"
    INTERP_STRING = "INTERP_STRING"
    NUMBER = "NUMBER"
    IDENTIFIER = "IDENTIFIER"
    ARROW = "ARROW"              # ->
    DOUBLE_ARROW = "DOUBLE_ARROW"  # =>
    NULL_COALESCE = "NULL_COALESCE"  # ??
    NULL_COALESCE_ASSIGN = "NULL_COALESCE_ASSIGN"  # ??=
    SPACESHIP = "SPACESHIP"      # <=>
    SCOPE = "SCOPE"              # ::
    CONCAT = "CONCAT"            # .
    CONCAT_ASSIGN = "CONCAT_ASSIGN"  # .=
    ASSIGN = "ASSIGN"
    EQUALS = "EQUALS"            # ==
    IDENTICAL = "IDENTICAL"      # ===
    NOT_EQUALS = "NOT_EQUALS"    # !=
    NOT_IDENTICAL = "NOT_IDENTICAL"  # !==
    SEMICOLON = "SEMICOLON"
    COMMA = "COMMA"
    LPAREN = "LPAREN"
    RPAREN = "RPAREN"
    LBRACE = "LBRACE"
    RBRACE = "RBRACE"
    LBRACKET = "LBRACKET"
    RBRACKET = "RBRACKET"
    BACKTICK = "BACKTICK"
    COMMENT = "COMMENT"
    WHITESPACE = "WHITESPACE"
    OPERATOR = "OPERATOR"
    AT = "AT"                    # @ error suppression
    ELLIPSIS = "ELLIPSIS"        # ...
    EOF = "EOF"

@dataclass
class Token:
    type: TokenType
    value: str
    line: int
    col: int = 0

KEYWORDS = {
    "namespace": TokenType.NAMESPACE,
    "use": TokenType.USE,
    "class": TokenType.CLASS_DEF,
    "interface": TokenType.INTERFACE,
    "trait": TokenType.TRAIT,
    "extends": TokenType.EXTENDS,
    "implements": TokenType.IMPLEMENTS,
    "function": TokenType.FUNCTION,
    "fn": TokenType.FN,
    "return": TokenType.RETURN,
    "if": TokenType.IF,
    "else": TokenType.ELSE,
    "elseif": TokenType.ELSEIF,
    "while": TokenType.WHILE,
    "for": TokenType.FOR,
    "foreach": TokenType.FOREACH,
    "switch": TokenType.SWITCH,
    "case": TokenType.CASE,
    "try": TokenType.TRY,
    "catch": TokenType.CATCH,
    "finally": TokenType.FINALLY,
    "throw": TokenType.THROW,
    "new": TokenType.NEW,
    "echo": TokenType.ECHO,
    "print": TokenType.PRINT,
    "include": TokenType.INCLUDE,
    "require": TokenType.REQUIRE,
    "include_once": TokenType.INCLUDE_ONCE,
    "require_once": TokenType.REQUIRE_ONCE,
}


class PHPTokenizer:
    """Custom PHP tokenizer that handles all PHP-specific syntax."""

    def __init__(self, source: str, filename: str = ""):
        self.source = source
        self.filename = filename
        self.pos = 0
        self.line = 1
        self.col = 0
        self.tokens: List[Token] = []
        self.in_php = False

    def _peek(self, offset: int = 0) -> str:
        p = self.pos + offset
        return self.source[p] if p < len(self.source) else ""

    def _advance(self, n: int = 1) -> str:
        result = ""
        for _ in range(n):
            if self.pos < len(self.source):
                ch = self.source[self.pos]
                result += ch
                if ch == "\n":
                    self.line += 1
                    self.col = 0
                else:
                    self.col += 1
                self.pos += 1
        return result

    def _match(self, text: str) -> bool:
        return self.source[self.pos:self.pos + len(text)] == text

    def _remaining(self) -> str:
        return self.source[self.pos:]

    def tokenize(self) -> List[Token]:
        while self.pos < len(self.source):
            if not self.in_php:
                self._scan_html()
            else:
                self._scan_php_token()
        self.tokens.append(Token(TokenType.EOF, "", self.line))
        return self.tokens

    def _scan_html(self):
        start = self.pos
        while self.pos < len(self.source):
            if self._match("<?php"):
                self._advance(5)
                self.in_php = True
                self.tokens.append(Token(TokenType.PHP_OPEN, "<?php", self.line))
                return
            if self._match("<?="):
                self._advance(3)
                self.in_php = True
                self.tokens.append(Token(TokenType.PHP_OPEN, "<?=", self.line))
                return
            if self._match("<?"):
                self._advance(2)
                self.in_php = True
                self.tokens.append(Token(TokenType.PHP_OPEN, "<?", self.line))
                return
            self._advance()

    def _scan_php_token(self):
        self._skip_whitespace()
        if self.pos >= len(self.source):
            return

        ch = self._peek()

        # PHP close tag
        if self._match("?>"):
            self._advance(2)
            self.in_php = False
            self.tokens.append(Token(TokenType.PHP_CLOSE, "?>", self.line))
            return

        # Comments
        if self._match("//") or self._match("#"):
            self._scan_line_comment()
            return
        if self._match("/*"):
            self._scan_block_comment()
            return

        # Heredoc / Nowdoc
        if self._match("<<<"):
            self._scan_heredoc_nowdoc()
            return

        # Backtick strings (command execution)
        if ch == "`":
            self._scan_backtick()
            return

        # Double-quoted strings with interpolation
        if ch == '"':
            self._scan_double_string()
            return

        # Single-quoted strings
        if ch == "'":
            self._scan_single_string()
            return

        # Variable variables $$var
        if ch == "$" and self._peek(1) == "$":
            self._scan_var_var()
            return

        # Variables $var
        if ch == "$":
            self._scan_variable()
            return

        # Numbers
        if ch.isdigit() or (ch == "." and self._peek(1).isdigit()):
            self._scan_number()
            return

        # Identifiers and keywords
        if ch.isalpha() or ch == "_" or ch == "\\":
            self._scan_identifier()
            return

        # Multi-char operators
        if self._match("<=>"):
            self._advance(3)
            self.tokens.append(Token(TokenType.SPACESHIP, "<=>", self.line))
            return
        if self._match("??="):
            self._advance(3)
            self.tokens.append(Token(TokenType.NULL_COALESCE_ASSIGN, "??=", self.line))
            return
        if self._match("??"):
            self._advance(2)
            self.tokens.append(Token(TokenType.NULL_COALESCE, "??", self.line))
            return
        if self._match("..."):
            self._advance(3)
            self.tokens.append(Token(TokenType.ELLIPSIS, "...", self.line))
            return
        if self._match("==="):
            self._advance(3)
            self.tokens.append(Token(TokenType.IDENTICAL, "===", self.line))
            return
        if self._match("!=="):
            self._advance(3)
            self.tokens.append(Token(TokenType.NOT_IDENTICAL, "!==", self.line))
            return
        if self._match("=="):
            self._advance(2)
            self.tokens.append(Token(TokenType.EQUALS, "==", self.line))
            return
        if self._match("!="):
            self._advance(2)
            self.tokens.append(Token(TokenType.NOT_EQUALS, "!=", self.line))
            return
        if self._match("->"):
            self._advance(2)
            self.tokens.append(Token(TokenType.ARROW, "->", self.line))
            return
        if self._match("=>"):
            self._advance(2)
            self.tokens.append(Token(TokenType.DOUBLE_ARROW, "=>", self.line))
            return
        if self._match("::"):
            self._advance(2)
            self.tokens.append(Token(TokenType.SCOPE, "::", self.line))
            return
        if self._match(".="):
            self._advance(2)
            self.tokens.append(Token(TokenType.CONCAT_ASSIGN, ".=", self.line))
            return

        # Single-char tokens
        single_map = {
            "(": TokenType.LPAREN, ")": TokenType.RPAREN,
            "{": TokenType.LBRACE, "}": TokenType.RBRACE,
            "[": TokenType.LBRACKET, "]": TokenType.RBRACKET,
            ";": TokenType.SEMICOLON, ",": TokenType.COMMA,
            ".": TokenType.CONCAT, "=": TokenType.ASSIGN,
            "@": TokenType.AT,
        }
        if ch in single_map:
            self._advance()
            self.tokens.append(Token(single_map[ch], ch, self.line))
            return

        # Any other operator char
        if ch in "+-*/%&|^~<>!?:":
            val = self._advance()
            # consume second char for two-char operators
            nch = self._peek()
            if nch and (val + nch) in ("++", "--", "**", "<<", ">>", "&&", "||",
                                        "+=", "-=", "*=", "/=", "%=", "&=", "|=",
                                        "^=", "<=", ">="):
                val += self._advance()
            self.tokens.append(Token(TokenType.OPERATOR, val, self.line))
            return

        # Skip unknown chars
        self._advance()

    def _skip_whitespace(self):
        while self.pos < len(self.source) and self.source[self.pos] in " \t\r\n":
            self._advance()

    def _scan_line_comment(self):
        start_line = self.line
        val = ""
        while self.pos < len(self.source) and self.source[self.pos] != "\n":
            val += self._advance()
        self.tokens.append(Token(TokenType.COMMENT, val, start_line))

    def _scan_block_comment(self):
        start_line = self.line
        val = self._advance(2)  # /*
        while self.pos < len(self.source):
            if self._match("*/"):
                val += self._advance(2)
                break
            val += self._advance()
        self.tokens.append(Token(TokenType.COMMENT, val, start_line))

    def _scan_heredoc_nowdoc(self):
        start_line = self.line
        self._advance(3)  # <<<
        # skip optional whitespace
        while self.pos < len(self.source) and self.source[self.pos] in " \t":
            self._advance()
        # Nowdoc: <<<'LABEL'
        is_nowdoc = False
        if self._peek() == "'":
            is_nowdoc = True
            self._advance()
        # Read label
        label = ""
        while self.pos < len(self.source) and (self.source[self.pos].isalnum() or self.source[self.pos] == "_"):
            label += self._advance()
        if is_nowdoc and self._peek() == "'":
            self._advance()
        # Skip to end of line
        while self.pos < len(self.source) and self.source[self.pos] != "\n":
            self._advance()
        if self.pos < len(self.source):
            self._advance()  # consume newline
        # Read content until label on its own line
        content = ""
        while self.pos < len(self.source):
            line_start = self.pos
            line_text = ""
            while self.pos < len(self.source) and self.source[self.pos] != "\n":
                line_text += self._advance()
            if self.pos < len(self.source):
                self._advance()  # newline
            stripped = line_text.strip().rstrip(";")
            if stripped == label:
                break
            content += line_text + "\n"
        tok_type = TokenType.NOWDOC if is_nowdoc else TokenType.HEREDOC
        self.tokens.append(Token(tok_type, content, start_line))

    def _scan_backtick(self):
        start_line = self.line
        self._advance()  # opening `
        val = ""
        while self.pos < len(self.source) and self.source[self.pos] != "`":
            if self.source[self.pos] == "\\":
                val += self._advance(2)
            else:
                val += self._advance()
        if self.pos < len(self.source):
            self._advance()  # closing `
        self.tokens.append(Token(TokenType.BACKTICK, val, start_line))

    def _scan_double_string(self):
        start_line = self.line
        self._advance()  # opening "
        val = ""
        has_interp = False
        while self.pos < len(self.source) and self.source[self.pos] != '"':
            if self.source[self.pos] == "\\":
                val += self._advance(2)
                continue
            if self.source[self.pos] == "$":
                has_interp = True
            if self.source[self.pos] == "{" and self._peek(1) == "$":
                has_interp = True
            val += self._advance()
        if self.pos < len(self.source):
            self._advance()  # closing "
        tok_type = TokenType.INTERP_STRING if has_interp else TokenType.STRING
        self.tokens.append(Token(tok_type, val, start_line))

    def _scan_single_string(self):
        start_line = self.line
        self._advance()  # opening '
        val = ""
        while self.pos < len(self.source) and self.source[self.pos] != "'":
            if self.source[self.pos] == "\\" and self._peek(1) in ("\\", "'"):
                val += self._advance(2)
            else:
                val += self._advance()
        if self.pos < len(self.source):
            self._advance()  # closing '
        self.tokens.append(Token(TokenType.STRING, val, start_line))

    def _scan_var_var(self):
        start_line = self.line
        self._advance(2)  # $$
        name = ""
        while self.pos < len(self.source) and (self.source[self.pos].isalnum() or self.source[self.pos] == "_"):
            name += self._advance()
        self.tokens.append(Token(TokenType.VAR_VAR, "$$" + name, start_line))

    def _scan_variable(self):
        start_line = self.line
        self._advance()  # $
        name = ""
        while self.pos < len(self.source) and (self.source[self.pos].isalnum() or self.source[self.pos] == "_"):
            name += self._advance()
        self.tokens.append(Token(TokenType.VARIABLE, "$" + name, start_line))

    def _scan_number(self):
        start_line = self.line
        val = ""
        if self._match("0x") or self._match("0X"):
            val += self._advance(2)
            while self.pos < len(self.source) and self.source[self.pos] in "0123456789abcdefABCDEF_":
                val += self._advance()
        elif self._match("0b") or self._match("0B"):
            val += self._advance(2)
            while self.pos < len(self.source) and self.source[self.pos] in "01_":
                val += self._advance()
        else:
            while self.pos < len(self.source) and (self.source[self.pos].isdigit() or self.source[self.pos] in "._eE+-"):
                val += self._advance()
        self.tokens.append(Token(TokenType.NUMBER, val, start_line))

    def _scan_identifier(self):
        start_line = self.line
        val = ""
        # Allow leading backslash for fully qualified names
        if self._peek() == "\\":
            val += self._advance()
        while self.pos < len(self.source) and (self.source[self.pos].isalnum() or self.source[self.pos] in "_\\"):
            val += self._advance()
        lower = val.lower()
        if lower in KEYWORDS:
            self.tokens.append(Token(KEYWORDS[lower], val, start_line))
        else:
            self.tokens.append(Token(TokenType.IDENTIFIER, val, start_line))

# ============================================================================
# 3. PHP AST-LIKE STRUCTURES (extracted from token stream)
# ============================================================================

@dataclass
class PHPFunction:
    name: str
    line: int
    end_line: int
    params: List[str]
    body_tokens: List[Token]
    class_name: str = ""
    is_arrow: bool = False

@dataclass
class PHPClass:
    name: str
    line: int
    extends: str = ""
    implements: List[str] = field(default_factory=list)
    methods: List[PHPFunction] = field(default_factory=list)
    is_interface: bool = False
    is_trait: bool = False

@dataclass
class PHPFile:
    path: str
    namespace: str = ""
    uses: List[str] = field(default_factory=list)
    classes: List[PHPClass] = field(default_factory=list)
    functions: List[PHPFunction] = field(default_factory=list)
    tokens: List[Token] = field(default_factory=list)
    lines: List[str] = field(default_factory=list)


class PHPParser:
    """Extracts structural information from token stream."""

    def __init__(self, tokens: List[Token], source: str, filepath: str):
        self.tokens = [t for t in tokens if t.type not in (TokenType.COMMENT, TokenType.WHITESPACE)]
        self.source = source
        self.filepath = filepath
        self.pos = 0
        self.file = PHPFile(path=filepath, tokens=self.tokens, lines=source.splitlines())

    def _current(self) -> Token:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return Token(TokenType.EOF, "", 0)

    def _peek_type(self, offset: int = 0) -> TokenType:
        idx = self.pos + offset
        if idx < len(self.tokens):
            return self.tokens[idx].type
        return TokenType.EOF

    def _advance(self) -> Token:
        t = self._current()
        self.pos += 1
        return t

    def _skip_until(self, *types: TokenType) -> None:
        while self.pos < len(self.tokens) and self._current().type not in types:
            self.pos += 1

    def _collect_balanced(self, open_type: TokenType, close_type: TokenType) -> List[Token]:
        """Collect tokens within balanced braces/parens."""
        result = []
        depth = 0
        if self._current().type == open_type:
            depth = 1
            self._advance()
        while self.pos < len(self.tokens) and depth > 0:
            t = self._current()
            if t.type == open_type:
                depth += 1
            elif t.type == close_type:
                depth -= 1
                if depth == 0:
                    self._advance()
                    break
            result.append(t)
            self._advance()
        return result

    def parse(self) -> PHPFile:
        while self.pos < len(self.tokens) and self._current().type != TokenType.EOF:
            t = self._current()
            if t.type == TokenType.NAMESPACE:
                self._parse_namespace()
            elif t.type == TokenType.USE:
                self._parse_use()
            elif t.type in (TokenType.CLASS_DEF, TokenType.INTERFACE, TokenType.TRAIT):
                self._parse_class()
            elif t.type == TokenType.FUNCTION:
                fn = self._parse_function()
                if fn:
                    self.file.functions.append(fn)
            else:
                self._advance()
        return self.file

    def _parse_namespace(self):
        self._advance()  # namespace
        parts = []
        while self.pos < len(self.tokens) and self._current().type not in (TokenType.SEMICOLON, TokenType.LBRACE):
            parts.append(self._advance().value)
        self.file.namespace = "".join(parts)
        if self._current().type == TokenType.SEMICOLON:
            self._advance()

    def _parse_use(self):
        self._advance()  # use
        parts = []
        while self.pos < len(self.tokens) and self._current().type != TokenType.SEMICOLON:
            parts.append(self._advance().value)
        self.file.uses.append("".join(parts))
        if self._current().type == TokenType.SEMICOLON:
            self._advance()

    def _parse_class(self):
        is_iface = self._current().type == TokenType.INTERFACE
        is_trait = self._current().type == TokenType.TRAIT
        self._advance()  # class/interface/trait
        name_tok = self._advance()
        cls = PHPClass(name=name_tok.value, line=name_tok.line, is_interface=is_iface, is_trait=is_trait)

        while self.pos < len(self.tokens) and self._current().type != TokenType.LBRACE:
            if self._current().type == TokenType.EXTENDS:
                self._advance()
                cls.extends = self._advance().value
            elif self._current().type == TokenType.IMPLEMENTS:
                self._advance()
                while self.pos < len(self.tokens) and self._current().type not in (TokenType.LBRACE,):
                    if self._current().type in (TokenType.IDENTIFIER, TokenType.VARIABLE):
                        cls.implements.append(self._current().value)
                    self._advance()
            else:
                self._advance()

        # Parse class body
        if self._current().type == TokenType.LBRACE:
            self._advance()
            depth = 1
            while self.pos < len(self.tokens) and depth > 0:
                if self._current().type == TokenType.FUNCTION:
                    fn = self._parse_function(class_name=cls.name)
                    if fn:
                        cls.methods.append(fn)
                elif self._current().type == TokenType.LBRACE:
                    depth += 1
                    self._advance()
                elif self._current().type == TokenType.RBRACE:
                    depth -= 1
                    self._advance()
                else:
                    self._advance()

        self.file.classes.append(cls)

    def _parse_function(self, class_name: str = "") -> Optional[PHPFunction]:
        line = self._current().line
        self._advance()  # function
        if self._current().type not in (TokenType.IDENTIFIER, TokenType.LPAREN):
            return None
        name = ""
        if self._current().type == TokenType.IDENTIFIER:
            name = self._advance().value

        params = []
        if self._current().type == TokenType.LPAREN:
            param_tokens = self._collect_balanced(TokenType.LPAREN, TokenType.RPAREN)
            for pt in param_tokens:
                if pt.type == TokenType.VARIABLE:
                    params.append(pt.value)

        # Skip return type hints
        while self.pos < len(self.tokens) and self._current().type not in (TokenType.LBRACE, TokenType.SEMICOLON):
            self._advance()

        body_tokens = []
        end_line = line
        if self._current().type == TokenType.LBRACE:
            body_tokens = self._collect_balanced(TokenType.LBRACE, TokenType.RBRACE)
            end_line = body_tokens[-1].line if body_tokens else line
        elif self._current().type == TokenType.SEMICOLON:
            self._advance()

        return PHPFunction(
            name=name, line=line, end_line=end_line,
            params=params, body_tokens=body_tokens,
            class_name=class_name,
        )


# ============================================================================
# 4. VULNERABILITY DETECTORS
# ============================================================================

# User input sources
USER_INPUT_VARS = {
    "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER", "$_FILES",
    "$_ENV", "$HTTP_RAW_POST_DATA", "$HTTP_GET_VARS", "$HTTP_POST_VARS",
}

# Dangerous function sets by category
SQL_SINKS = {
    "mysql_query", "mysqli_query", "mysqli_multi_query", "mysqli_real_query",
    "pg_query", "pg_query_params", "pg_execute", "sqlite_query",
    "sqlite_exec", "mssql_query", "oci_parse", "db2_exec", "db2_prepare",
}

CMD_SINKS = {
    "exec", "system", "passthru", "shell_exec", "popen", "proc_open",
    "pcntl_exec",
}

CODE_SINKS = {
    "eval", "assert", "create_function", "call_user_func", "call_user_func_array",
    "preg_replace",  # with /e modifier
}

FILE_SINKS = {
    "file_get_contents", "file_put_contents", "fopen", "readfile",
    "file", "fread", "fgets", "fgetc", "fpassthru", "copy", "rename",
    "unlink", "rmdir", "mkdir", "tempnam",
}

SSRF_SINKS = {
    "file_get_contents", "fopen", "curl_setopt", "curl_init",
    "get_headers", "getimagesize",
}

WEAK_HASH = {"md5", "sha1", "crc32"}

INSECURE_RANDOM = {"rand", "mt_rand", "array_rand", "shuffle", "str_shuffle", "uniqid"}


class VulnerabilityDetector:
    """Runs all detection rules on parsed PHP files."""

    def __init__(self):
        self.vulns: List[Vulnerability] = []

    def scan_file(self, php_file: PHPFile, source: str) -> List[Vulnerability]:
        self.vulns = []
        self.file = php_file
        self.source = source
        self.lines = source.splitlines()

        self._detect_sql_injection()
        self._detect_command_injection()
        self._detect_code_injection()
        self._detect_xss()
        self._detect_path_traversal()
        self._detect_file_upload()
        self._detect_deserialization()
        self._detect_ssrf()
        self._detect_xxe()
        self._detect_hardcoded_secrets()
        self._detect_weak_crypto()
        self._detect_insecure_random()
        self._detect_laravel_vulns()
        self._detect_wordpress_vulns()
        self._detect_symfony_vulns()
        self._detect_codeigniter_vulns()
        self._detect_type_juggling()
        self._detect_open_redirect()
        self._detect_session_fixation()
        self._detect_csrf_missing()
        self._detect_information_disclosure()
        self._detect_insecure_permissions()
        self._detect_missing_input_validation()
        self._detect_register_globals()
        self._detect_object_injection()
        self._detect_ldap_injection()
        self._detect_email_injection()
        self._detect_timing_attacks()
        self._detect_logging_sensitive()
        self._detect_missing_auth()
        self._detect_backtick_execution()
        self._detect_variable_variables()

        return self.vulns

    def _snippet(self, line: int, context: int = 2) -> str:
        start = max(0, line - 1 - context)
        end = min(len(self.lines), line + context)
        return "\n".join(self.lines[start:end])

    def _add(self, title, sev, conf, cwe, owasp, line, cat, remed, end_line=None):
        self.vulns.append(Vulnerability(
            title=title, severity=sev, confidence=conf,
            cwe=cwe, owasp=owasp,
            file_path=self.file.path, line_number=line,
            end_line=end_line or line,
            code_snippet=self._snippet(line),
            remediation=remed, category=cat,
        ))

    def _tokens_contain_user_input(self, tokens: List[Token]) -> bool:
        for t in tokens:
            if t.type == TokenType.VARIABLE and t.value in USER_INPUT_VARS:
                return True
        return False

    def _get_call_sequences(self, tokens: List[Token]) -> List[Tuple[str, int, List[Token]]]:
        """Extract function call name, line, and argument tokens."""
        calls = []
        i = 0
        while i < len(tokens):
            # Check for method calls: ->method( or ::method(
            if (tokens[i].type in (TokenType.IDENTIFIER,) and
                    i + 1 < len(tokens) and tokens[i + 1].type == TokenType.LPAREN):
                name = tokens[i].value
                line = tokens[i].line
                # Look back for -> or ::
                if i > 1 and tokens[i - 1].type in (TokenType.ARROW, TokenType.SCOPE):
                    if i > 2:
                        prefix = tokens[i - 2].value
                        name = prefix + tokens[i - 1].value + name
                # Collect args
                j = i + 2
                depth = 1
                arg_tokens = []
                while j < len(tokens) and depth > 0:
                    if tokens[j].type == TokenType.LPAREN:
                        depth += 1
                    elif tokens[j].type == TokenType.RPAREN:
                        depth -= 1
                        if depth == 0:
                            break
                    arg_tokens.append(tokens[j])
                    j += 1
                calls.append((name, line, arg_tokens))
                i = j + 1
                continue
            i += 1
        return calls

    def _scan_tokens_for_calls(self, func_names: set) -> List[Tuple[str, int, List[Token]]]:
        """Find calls to specific functions across all tokens."""
        results = []
        all_tokens = self.file.tokens
        for name, line, args in self._get_call_sequences(all_tokens):
            base_name = name.split("->")[-1].split("::")[-1] if "->" in name or "::" in name else name
            if base_name in func_names:
                results.append((name, line, args))
        return results

    def _find_pattern_in_lines(self, pattern: str) -> List[Tuple[int, str]]:
        """Regex search across source lines."""
        results = []
        for i, line in enumerate(self.lines):
            if re.search(pattern, line, re.IGNORECASE):
                results.append((i + 1, line))
        return results

    # -- 1. SQL Injection --
    def _detect_sql_injection(self):
        # Pattern: SQL functions with string concatenation or variable interpolation
        for name, line, args in self._scan_tokens_for_calls(SQL_SINKS):
            if self._tokens_contain_user_input(args):
                self._add(
                    f"SQL Injection via {name}()", Severity.CRITICAL, Confidence.HIGH,
                    "CWE-89", "A03:2021", line, "SQL Injection",
                    f"Use parameterized queries or prepared statements instead of passing user input directly to {name}()."
                )
            elif any(t.type in (TokenType.VARIABLE, TokenType.CONCAT, TokenType.INTERP_STRING) for t in args):
                self._add(
                    f"Potential SQL Injection via {name}()", Severity.HIGH, Confidence.MEDIUM,
                    "CWE-89", "A03:2021", line, "SQL Injection",
                    f"Use parameterized queries with prepared statements. Avoid string concatenation in SQL queries."
                )
        # PDO with string concat
        for match in self._find_pattern_in_lines(r'\$\w+->query\s*\(\s*["\'].*\$'):
            self._add(
                "SQL Injection via PDO::query() with variable interpolation",
                Severity.HIGH, Confidence.MEDIUM, "CWE-89", "A03:2021",
                match[0], "SQL Injection",
                "Use PDO::prepare() with bound parameters instead of string interpolation in queries."
            )
        for match in self._find_pattern_in_lines(r'\$\w+->query\s*\(\s*\$'):
            self._add(
                "SQL Injection via PDO::query() with variable",
                Severity.HIGH, Confidence.MEDIUM, "CWE-89", "A03:2021",
                match[0], "SQL Injection",
                "Use PDO::prepare() with bound parameters."
            )

    # -- 2. Command Injection --
    def _detect_command_injection(self):
        for name, line, args in self._scan_tokens_for_calls(CMD_SINKS):
            if self._tokens_contain_user_input(args):
                self._add(
                    f"Command Injection via {name}()", Severity.CRITICAL, Confidence.HIGH,
                    "CWE-78", "A03:2021", line, "Command Injection",
                    f"Never pass user input to {name}(). Use escapeshellarg()/escapeshellcmd() or avoid shell commands entirely."
                )
            elif any(t.type == TokenType.VARIABLE for t in args):
                self._add(
                    f"Potential Command Injection via {name}()", Severity.HIGH, Confidence.MEDIUM,
                    "CWE-78", "A03:2021", line, "Command Injection",
                    f"Validate and sanitize all input passed to {name}(). Use escapeshellarg() for arguments."
                )

    # -- 3. Code Injection --
    def _detect_code_injection(self):
        for name, line, args in self._scan_tokens_for_calls(CODE_SINKS):
            if name == "preg_replace":
                # Check for /e modifier
                for t in args:
                    if t.type == TokenType.STRING and "/e" in t.value:
                        self._add(
                            "Code Injection via preg_replace() with /e modifier",
                            Severity.CRITICAL, Confidence.HIGH, "CWE-94", "A03:2021",
                            line, "Code Injection",
                            "The /e modifier is deprecated. Use preg_replace_callback() instead."
                        )
                        break
            elif self._tokens_contain_user_input(args):
                self._add(
                    f"Code Injection via {name}()", Severity.CRITICAL, Confidence.HIGH,
                    "CWE-94", "A03:2021", line, "Code Injection",
                    f"Never pass user input to {name}(). Refactor to avoid dynamic code execution."
                )
            elif any(t.type == TokenType.VARIABLE for t in args):
                self._add(
                    f"Potential Code Injection via {name}()", Severity.HIGH, Confidence.MEDIUM,
                    "CWE-94", "A03:2021", line, "Code Injection",
                    f"Avoid using {name}() with dynamic input. Use safer alternatives."
                )

    # -- 4. XSS --
    def _detect_xss(self):
        # echo/print with user input without htmlspecialchars
        all_tokens = self.file.tokens
        i = 0
        while i < len(all_tokens):
            t = all_tokens[i]
            if t.type in (TokenType.ECHO, TokenType.PRINT):
                j = i + 1
                has_user_input = False
                has_escape = False
                while j < len(all_tokens) and all_tokens[j].type != TokenType.SEMICOLON:
                    if all_tokens[j].type == TokenType.VARIABLE and all_tokens[j].value in USER_INPUT_VARS:
                        has_user_input = True
                    if all_tokens[j].type == TokenType.IDENTIFIER and all_tokens[j].value in (
                            "htmlspecialchars", "htmlentities", "strip_tags", "esc_html", "esc_attr", "e"):
                        has_escape = True
                    j += 1
                if has_user_input and not has_escape:
                    self._add(
                        "Cross-Site Scripting (XSS) - Unescaped user input in output",
                        Severity.HIGH, Confidence.HIGH, "CWE-79", "A03:2021",
                        t.line, "Cross-Site Scripting",
                        "Use htmlspecialchars($input, ENT_QUOTES, 'UTF-8') before outputting user data."
                    )
            i += 1

        # Blade raw output {!! !!}
        for match in self._find_pattern_in_lines(r'\{!!\s*\$'):
            self._add(
                "XSS via Blade raw output {!! !!}", Severity.HIGH, Confidence.HIGH,
                "CWE-79", "A03:2021", match[0], "Cross-Site Scripting",
                "Use {{ }} (escaped) instead of {!! !!} (raw) in Blade templates."
            )

    # -- 5. Path Traversal --
    def _detect_path_traversal(self):
        include_types = {TokenType.INCLUDE, TokenType.REQUIRE, TokenType.INCLUDE_ONCE, TokenType.REQUIRE_ONCE}
        all_tokens = self.file.tokens
        for i, t in enumerate(all_tokens):
            if t.type in include_types:
                j = i + 1
                while j < len(all_tokens) and all_tokens[j].type in (TokenType.LPAREN,):
                    j += 1
                if j < len(all_tokens) and all_tokens[j].type == TokenType.VARIABLE and all_tokens[j].value in USER_INPUT_VARS:
                    self._add(
                        f"Path Traversal / Local File Inclusion via {t.value}",
                        Severity.CRITICAL, Confidence.HIGH, "CWE-22", "A01:2021",
                        t.line, "Path Traversal",
                        "Never use user input directly in include/require. Use a whitelist of allowed files."
                    )

        for name, line, args in self._scan_tokens_for_calls(FILE_SINKS):
            if self._tokens_contain_user_input(args):
                self._add(
                    f"Path Traversal via {name}() with user input",
                    Severity.HIGH, Confidence.HIGH, "CWE-22", "A01:2021",
                    line, "Path Traversal",
                    f"Validate and sanitize file paths. Use basename() and realpath() to prevent directory traversal."
                )

    # -- 6. File Upload --
    def _detect_file_upload(self):
        for name, line, args in self._scan_tokens_for_calls({"move_uploaded_file"}):
            self._add(
                "Insecure File Upload - move_uploaded_file() detected",
                Severity.HIGH, Confidence.MEDIUM, "CWE-434", "A04:2021",
                line, "File Upload",
                "Validate file type, size, and content. Use allow-list for extensions. Store outside webroot."
            )
        # Check for missing MIME validation
        for match in self._find_pattern_in_lines(r'move_uploaded_file'):
            # Look nearby for mime/type checking
            region_start = max(0, match[0] - 10)
            region_end = min(len(self.lines), match[0] + 5)
            region = "\n".join(self.lines[region_start:region_end])
            if not re.search(r'mime|finfo|getimagesize|pathinfo.*extension', region, re.IGNORECASE):
                self._add(
                    "File Upload without MIME type validation",
                    Severity.HIGH, Confidence.MEDIUM, "CWE-434", "A04:2021",
                    match[0], "File Upload",
                    "Verify file MIME type using finfo_file() or getimagesize(). Never trust client-provided MIME type."
                )

    # -- 7. Deserialization --
    def _detect_deserialization(self):
        for name, line, args in self._scan_tokens_for_calls({"unserialize"}):
            if self._tokens_contain_user_input(args):
                self._add(
                    "Insecure Deserialization - unserialize() with user input",
                    Severity.CRITICAL, Confidence.HIGH, "CWE-502", "A08:2021",
                    line, "Insecure Deserialization",
                    "Never unserialize user-controlled data. Use json_decode() instead or use allowed_classes parameter."
                )
            else:
                self._add(
                    "Potential Insecure Deserialization - unserialize() usage",
                    Severity.MEDIUM, Confidence.MEDIUM, "CWE-502", "A08:2021",
                    line, "Insecure Deserialization",
                    "Use the allowed_classes option: unserialize($data, ['allowed_classes' => false])."
                )
        # __wakeup / __destruct gadget chains
        for cls in self.file.classes:
            for method in cls.methods:
                if method.name in ("__wakeup", "__destruct", "__toString"):
                    # Check if body has dangerous calls
                    for t in method.body_tokens:
                        if t.type == TokenType.IDENTIFIER and t.value in CMD_SINKS | CODE_SINKS | FILE_SINKS:
                            self._add(
                                f"Deserialization Gadget: {cls.name}::{method.name}() calls {t.value}()",
                                Severity.HIGH, Confidence.MEDIUM, "CWE-502", "A08:2021",
                                method.line, "Insecure Deserialization",
                                f"Magic method {method.name}() should not call dangerous functions. This could be exploited in deserialization attacks."
                            )

    # -- 8. SSRF --
    def _detect_ssrf(self):
        for name, line, args in self._scan_tokens_for_calls(SSRF_SINKS):
            if self._tokens_contain_user_input(args):
                self._add(
                    f"Server-Side Request Forgery via {name}()",
                    Severity.HIGH, Confidence.HIGH, "CWE-918", "A10:2021",
                    line, "SSRF",
                    "Validate and whitelist URLs. Block internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)."
                )
        # curl_setopt with user URL
        for match in self._find_pattern_in_lines(r'curl_setopt.*CURLOPT_URL.*\$_(GET|POST|REQUEST)'):
            self._add(
                "SSRF via cURL with user-controlled URL",
                Severity.HIGH, Confidence.HIGH, "CWE-918", "A10:2021",
                match[0], "SSRF",
                "Never pass user input directly as a cURL URL. Validate against a whitelist of allowed hosts."
            )

    # -- 9. XXE --
    def _detect_xxe(self):
        for match in self._find_pattern_in_lines(r'simplexml_load_string|SimpleXMLElement|DOMDocument'):
            region_start = max(0, match[0] - 5)
            region_end = min(len(self.lines), match[0] + 10)
            region = "\n".join(self.lines[region_start:region_end])
            if "LIBXML_NOENT" not in region and "libxml_disable_entity_loader" not in region:
                self._add(
                    "XML External Entity (XXE) - XML parsing without entity restriction",
                    Severity.HIGH, Confidence.MEDIUM, "CWE-611", "A05:2021",
                    match[0], "XXE Injection",
                    "Disable external entities: libxml_disable_entity_loader(true) and avoid LIBXML_NOENT flag. Use LIBXML_NONET."
                )

    # -- 10. Hardcoded Secrets --
    def _detect_hardcoded_secrets(self):
        secret_patterns = [
            (r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']', "Hardcoded Password"),
            (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\'][^"\']{8,}["\']', "Hardcoded API Key"),
            (r'(?:secret|token|auth)\s*[=:]\s*["\'][^"\']{8,}["\']', "Hardcoded Secret/Token"),
            (r'(?:db_pass|database_password|mysql_pass)\s*[=:]\s*["\'][^"\']{4,}["\']', "Hardcoded Database Password"),
            (r'(?:aws_access_key_id|aws_secret_access_key)\s*[=:]\s*["\'][A-Za-z0-9/+=]{16,}["\']', "Hardcoded AWS Credential"),
            (r'(?:private[_-]?key)\s*[=:]\s*["\'][^"\']{10,}["\']', "Hardcoded Private Key"),
        ]
        for pattern, label in secret_patterns:
            for match in self._find_pattern_in_lines(pattern):
                self._add(
                    f"Hardcoded Secret: {label}", Severity.HIGH, Confidence.HIGH,
                    "CWE-798", "A07:2021", match[0], "Hardcoded Secrets",
                    "Use environment variables or a secrets manager. Never hardcode credentials in source code."
                )

    # -- 11. Weak Crypto --
    def _detect_weak_crypto(self):
        for name, line, args in self._scan_tokens_for_calls(WEAK_HASH):
            self._add(
                f"Weak Cryptographic Hash: {name}()", Severity.MEDIUM, Confidence.HIGH,
                "CWE-328", "A02:2021", line, "Weak Cryptography",
                "Use password_hash()/password_verify() for passwords. Use hash('sha256', ...) or stronger for data integrity."
            )
        for match in self._find_pattern_in_lines(r'mcrypt_|MCRYPT_'):
            self._add(
                "Deprecated mcrypt extension usage", Severity.MEDIUM, Confidence.HIGH,
                "CWE-327", "A02:2021", match[0], "Weak Cryptography",
                "mcrypt is deprecated. Use openssl_encrypt()/openssl_decrypt() with AES-256-GCM."
            )
        for match in self._find_pattern_in_lines(r'openssl_encrypt.*ECB|DES-|RC4'):
            self._add(
                "Weak cipher mode or algorithm", Severity.HIGH, Confidence.HIGH,
                "CWE-327", "A02:2021", match[0], "Weak Cryptography",
                "Use AES-256-GCM or AES-256-CBC with HMAC. Avoid ECB mode, DES, and RC4."
            )

    # -- 12. Insecure Random --
    def _detect_insecure_random(self):
        for name, line, args in self._scan_tokens_for_calls(INSECURE_RANDOM):
            self._add(
                f"Insecure Random Number Generator: {name}()", Severity.MEDIUM, Confidence.HIGH,
                "CWE-330", "A02:2021", line, "Insecure Randomness",
                f"Use random_int() or random_bytes() instead of {name}() for security-sensitive operations."
            )

    # -- 13. Laravel-specific --
    def _detect_laravel_vulns(self):
        # Mass assignment
        for match in self._find_pattern_in_lines(r'::create\s*\(\s*\$_(GET|POST|REQUEST)'):
            self._add(
                "Laravel Mass Assignment with user input",
                Severity.HIGH, Confidence.HIGH, "CWE-915", "A04:2021",
                match[0], "Laravel Security",
                "Define $fillable or $guarded on models. Never pass raw request data to create()/update()."
            )
        # Raw queries
        for match in self._find_pattern_in_lines(r'DB::raw\s*\(\s*["\'].*\$'):
            self._add(
                "Laravel Raw SQL with variable interpolation",
                Severity.HIGH, Confidence.HIGH, "CWE-89", "A03:2021",
                match[0], "Laravel Security",
                "Use query builder bindings: DB::raw('SELECT * WHERE id = ?', [$id])"
            )
        for match in self._find_pattern_in_lines(r'DB::select\s*\(\s*["\'].*\$|DB::statement\s*\(\s*["\'].*\$'):
            self._add(
                "Laravel Raw SQL with variable interpolation",
                Severity.HIGH, Confidence.MEDIUM, "CWE-89", "A03:2021",
                match[0], "Laravel Security",
                "Use parameter binding: DB::select('SELECT * WHERE id = ?', [$id])"
            )
        # Debug mode
        for match in self._find_pattern_in_lines(r"APP_DEBUG\s*=\s*true|'debug'\s*=>\s*true"):
            self._add(
                "Laravel Debug Mode Enabled", Severity.MEDIUM, Confidence.HIGH,
                "CWE-215", "A05:2021", match[0], "Laravel Security",
                "Set APP_DEBUG=false in production. Debug mode exposes sensitive configuration and stack traces."
            )
        # Blade {!! !!} already covered in XSS

    # -- 14. WordPress-specific --
    def _detect_wordpress_vulns(self):
        for match in self._find_pattern_in_lines(r'\$wpdb->query\s*\(\s*["\'].*\$'):
            self._add(
                "WordPress SQL Injection - $wpdb->query() without prepare()",
                Severity.CRITICAL, Confidence.HIGH, "CWE-89", "A03:2021",
                match[0], "WordPress Security",
                "Use $wpdb->prepare(): $wpdb->query($wpdb->prepare('SELECT * WHERE id = %d', $id))"
            )
        for match in self._find_pattern_in_lines(r'\$wpdb->get_results\s*\(\s*["\'].*\$'):
            self._add(
                "WordPress SQL Injection - $wpdb->get_results() without prepare()",
                Severity.HIGH, Confidence.MEDIUM, "CWE-89", "A03:2021",
                match[0], "WordPress Security",
                "Use $wpdb->prepare() for all queries with dynamic data."
            )
        # Nonce checks
        for match in self._find_pattern_in_lines(r'wp_ajax_|admin_post_'):
            region_start = max(0, match[0] - 2)
            region_end = min(len(self.lines), match[0] + 20)
            region = "\n".join(self.lines[region_start:region_end])
            if "wp_verify_nonce" not in region and "check_ajax_referer" not in region:
                self._add(
                    "WordPress Missing Nonce Verification in AJAX handler",
                    Severity.HIGH, Confidence.MEDIUM, "CWE-352", "A01:2021",
                    match[0], "WordPress Security",
                    "Add wp_verify_nonce() or check_ajax_referer() at the start of AJAX handlers."
                )

    # -- 15. Symfony-specific --
    def _detect_symfony_vulns(self):
        for match in self._find_pattern_in_lines(r"kernel\.debug.*true|APP_ENV.*dev"):
            self._add(
                "Symfony Debug Mode / Dev Environment", Severity.MEDIUM, Confidence.MEDIUM,
                "CWE-215", "A05:2021", match[0], "Symfony Security",
                "Ensure production uses APP_ENV=prod and kernel.debug=false."
            )
        for match in self._find_pattern_in_lines(r'security\.firewalls.*main.*anonymous.*true'):
            self._add(
                "Symfony Anonymous Firewall Access", Severity.MEDIUM, Confidence.LOW,
                "CWE-284", "A01:2021", match[0], "Symfony Security",
                "Review firewall configuration. Ensure sensitive routes require authentication."
            )

    # -- 16. CodeIgniter-specific --
    def _detect_codeigniter_vulns(self):
        for match in self._find_pattern_in_lines(r'\$this->db->query\s*\(\s*["\'].*\$'):
            self._add(
                "CodeIgniter SQL Injection - $this->db->query() with variable interpolation",
                Severity.HIGH, Confidence.HIGH, "CWE-89", "A03:2021",
                match[0], "CodeIgniter Security",
                "Use query bindings: $this->db->query('SELECT * WHERE id = ?', array($id))"
            )

    # -- 17. Type Juggling --
    def _detect_type_juggling(self):
        tokens = self.file.tokens
        for i, t in enumerate(tokens):
            if t.type == TokenType.EQUALS:  # ==
                # Check context for security comparisons
                context_start = max(0, i - 5)
                context_end = min(len(tokens), i + 5)
                context_tokens = tokens[context_start:context_end]
                context_str = " ".join(ct.value for ct in context_tokens)
                if re.search(r'password|hash|token|secret|key|nonce|admin|role', context_str, re.IGNORECASE):
                    self._add(
                        "PHP Type Juggling - Loose comparison (==) in security context",
                        Severity.HIGH, Confidence.MEDIUM, "CWE-1025", "A02:2021",
                        t.line, "Type Juggling",
                        "Use strict comparison (===) for security-sensitive comparisons to prevent type juggling bypasses."
                    )
        # strcmp bypass
        for name, line, args in self._scan_tokens_for_calls({"strcmp", "strcasecmp"}):
            self._add(
                f"Potential Type Juggling via {name}() - array bypass possible",
                Severity.MEDIUM, Confidence.MEDIUM, "CWE-1025", "A02:2021",
                line, "Type Juggling",
                f"{name}() returns NULL when passed an array instead of a string. Use === 0 to check the result."
            )

    # -- 18. Open Redirect --
    def _detect_open_redirect(self):
        for match in self._find_pattern_in_lines(r'header\s*\(\s*["\']Location:\s*["\']?\s*\.?\s*\$_(GET|POST|REQUEST)'):
            self._add(
                "Open Redirect via header() with user-controlled URL",
                Severity.MEDIUM, Confidence.HIGH, "CWE-601", "A01:2021",
                match[0], "Open Redirect",
                "Validate redirect URLs against a whitelist. Never use user input directly in Location headers."
            )
        for match in self._find_pattern_in_lines(r'header\s*\(\s*["\']Location:\s*["\']?\s*\.?\s*\$'):
            self._add(
                "Potential Open Redirect via header() with variable URL",
                Severity.MEDIUM, Confidence.MEDIUM, "CWE-601", "A01:2021",
                match[0], "Open Redirect",
                "Validate redirect URLs. Use relative paths or a whitelist of allowed domains."
            )

    # -- 19. Session Fixation --
    def _detect_session_fixation(self):
        has_session_start = any(
            re.search(r'session_start', line) for line in self.lines
        )
        has_regenerate = any(
            re.search(r'session_regenerate_id', line) for line in self.lines
        )
        if has_session_start and not has_regenerate:
            # Find login-like functions
            for fn in self.file.functions:
                if re.search(r'login|auth|sign_in', fn.name, re.IGNORECASE):
                    self._add(
                        "Session Fixation - No session_regenerate_id() after login",
                        Severity.HIGH, Confidence.MEDIUM, "CWE-384", "A07:2021",
                        fn.line, "Session Fixation",
                        "Call session_regenerate_id(true) after successful authentication to prevent session fixation."
                    )
            for cls in self.file.classes:
                for method in cls.methods:
                    if re.search(r'login|auth|sign_in', method.name, re.IGNORECASE):
                        self._add(
                            "Session Fixation - No session_regenerate_id() in auth method",
                            Severity.HIGH, Confidence.MEDIUM, "CWE-384", "A07:2021",
                            method.line, "Session Fixation",
                            "Call session_regenerate_id(true) after successful authentication."
                        )

    # -- 20. CSRF Missing --
    def _detect_csrf_missing(self):
        for match in self._find_pattern_in_lines(r'\$_POST\[|file_get_contents.*php://input'):
            region_start = max(0, match[0] - 20)
            region_end = min(len(self.lines), match[0] + 5)
            region = "\n".join(self.lines[region_start:region_end])
            if not re.search(r'csrf|token|nonce|verify_nonce|check_referer|validate_token', region, re.IGNORECASE):
                self._add(
                    "Missing CSRF Protection on form handler",
                    Severity.MEDIUM, Confidence.LOW, "CWE-352", "A01:2021",
                    match[0], "CSRF",
                    "Implement CSRF token validation. Generate a token per session and verify it on form submission."
                )

    # -- 21. Information Disclosure --
    def _detect_information_disclosure(self):
        for match in self._find_pattern_in_lines(r'phpinfo\s*\('):
            self._add(
                "Information Disclosure via phpinfo()", Severity.MEDIUM, Confidence.HIGH,
                "CWE-200", "A01:2021", match[0], "Information Disclosure",
                "Remove phpinfo() calls from production code. It exposes server configuration and PHP settings."
            )
        for match in self._find_pattern_in_lines(r'display_errors\s*[=,]\s*["\']?(on|1|true)'):
            self._add(
                "Information Disclosure - display_errors enabled", Severity.MEDIUM, Confidence.HIGH,
                "CWE-209", "A05:2021", match[0], "Information Disclosure",
                "Set display_errors = Off in production. Log errors to a file instead."
            )
        for match in self._find_pattern_in_lines(r'error_reporting\s*\(\s*E_ALL'):
            self._add(
                "Verbose Error Reporting enabled", Severity.LOW, Confidence.MEDIUM,
                "CWE-209", "A05:2021", match[0], "Information Disclosure",
                "Use error_reporting(0) in production and log errors to a file."
            )
        for match in self._find_pattern_in_lines(r'var_dump\s*\(|print_r\s*\(.*\$_(GET|POST|REQUEST|SERVER)'):
            self._add(
                "Information Disclosure via debug output", Severity.LOW, Confidence.MEDIUM,
                "CWE-200", "A01:2021", match[0], "Information Disclosure",
                "Remove var_dump()/print_r() calls from production code."
            )

    # -- 22. Insecure File Permissions --
    def _detect_insecure_permissions(self):
        for match in self._find_pattern_in_lines(r'chmod\s*\(\s*.*0?777'):
            self._add(
                "Insecure File Permissions: chmod 777", Severity.HIGH, Confidence.HIGH,
                "CWE-732", "A01:2021", match[0], "Insecure File Permissions",
                "Use restrictive permissions (0644 for files, 0755 for directories). Never use 777."
            )
        for match in self._find_pattern_in_lines(r'chmod\s*\(\s*.*0?666'):
            self._add(
                "Insecure File Permissions: chmod 666", Severity.MEDIUM, Confidence.HIGH,
                "CWE-732", "A01:2021", match[0], "Insecure File Permissions",
                "Use 0644 for files that need to be readable. Avoid world-writable permissions."
            )

    # -- 23. Missing Input Validation --
    def _detect_missing_input_validation(self):
        # Direct use of superglobals without any validation
        for fn in self.file.functions + [m for c in self.file.classes for m in c.methods]:
            user_input_used = False
            has_validation = False
            for t in fn.body_tokens:
                if t.type == TokenType.VARIABLE and t.value in USER_INPUT_VARS:
                    user_input_used = True
                if t.type == TokenType.IDENTIFIER and t.value in (
                        "filter_input", "filter_var", "is_numeric", "is_int", "is_string",
                        "ctype_alpha", "ctype_digit", "preg_match", "htmlspecialchars",
                        "intval", "floatval", "absint", "sanitize_text_field"):
                    has_validation = True
            if user_input_used and not has_validation:
                self._add(
                    f"Missing Input Validation in {fn.class_name + '::' if fn.class_name else ''}{fn.name}()",
                    Severity.MEDIUM, Confidence.MEDIUM, "CWE-20", "A03:2021",
                    fn.line, "Missing Input Validation",
                    "Validate and sanitize all user input using filter_input(), filter_var(), or type-specific validation functions."
                )

    # -- 24. Register Globals --
    def _detect_register_globals(self):
        for match in self._find_pattern_in_lines(r'register_globals\s*=\s*[Oo]n|import_request_variables|extract\s*\(\s*\$_(GET|POST|REQUEST)'):
            self._add(
                "Register Globals / Variable Import from User Input",
                Severity.HIGH, Confidence.HIGH, "CWE-621", "A05:2021",
                match[0], "Register Globals",
                "Never use register_globals, import_request_variables(), or extract() on user input."
            )

    # -- 25. Object Injection --
    def _detect_object_injection(self):
        # Already partly covered by deserialization, but check for broader patterns
        for match in self._find_pattern_in_lines(r'unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'):
            self._add(
                "PHP Object Injection via unserialize() with user input",
                Severity.CRITICAL, Confidence.HIGH, "CWE-502", "A08:2021",
                match[0], "Object Injection",
                "Never unserialize user input. Use json_decode() or use allowed_classes parameter."
            )

    # -- 26. LDAP Injection --
    def _detect_ldap_injection(self):
        for name, line, args in self._scan_tokens_for_calls({"ldap_search", "ldap_list", "ldap_read", "ldap_bind"}):
            if self._tokens_contain_user_input(args):
                self._add(
                    f"LDAP Injection via {name}() with user input",
                    Severity.HIGH, Confidence.HIGH, "CWE-90", "A03:2021",
                    line, "LDAP Injection",
                    "Sanitize LDAP filter input using ldap_escape() (PHP 5.6+). Validate against expected patterns."
                )

    # -- 27. Email Injection --
    def _detect_email_injection(self):
        for name, line, args in self._scan_tokens_for_calls({"mail"}):
            if self._tokens_contain_user_input(args):
                self._add(
                    "Email Header Injection via mail() with user input",
                    Severity.HIGH, Confidence.HIGH, "CWE-93", "A03:2021",
                    line, "Email Injection",
                    "Sanitize email headers. Remove \\r\\n from user input used in mail() headers. Use a library like PHPMailer or SwiftMailer."
                )

    # -- 28. Timing Attacks --
    def _detect_timing_attacks(self):
        tokens = self.file.tokens
        for i, t in enumerate(tokens):
            if t.type in (TokenType.EQUALS, TokenType.IDENTICAL):
                context_start = max(0, i - 5)
                context_end = min(len(tokens), i + 5)
                context_vals = [ct.value for ct in tokens[context_start:context_end]]
                context_str = " ".join(context_vals)
                if re.search(r'hash|hmac|token|signature|digest|mac', context_str, re.IGNORECASE):
                    # Check it's not using hash_equals
                    if "hash_equals" not in context_str:
                        self._add(
                            "Timing Attack - Direct string comparison of hash/token",
                            Severity.MEDIUM, Confidence.MEDIUM, "CWE-208", "A02:2021",
                            t.line, "Timing Attack",
                            "Use hash_equals() for constant-time string comparison of hashes and tokens."
                        )

    # -- 29. Logging Sensitive Data --
    def _detect_logging_sensitive(self):
        log_funcs = {"error_log", "syslog", "openlog"}
        for name, line, args in self._scan_tokens_for_calls(log_funcs):
            for t in args:
                if t.type == TokenType.VARIABLE and t.value in ("$password", "$passwd", "$secret",
                                                                  "$token", "$api_key", "$credit_card",
                                                                  "$ssn", "$_POST"):
                    self._add(
                        f"Logging Sensitive Data via {name}()",
                        Severity.MEDIUM, Confidence.MEDIUM, "CWE-532", "A09:2021",
                        line, "Logging Sensitive Data",
                        "Never log passwords, tokens, or other sensitive data. Mask or redact sensitive fields."
                    )
        for match in self._find_pattern_in_lines(r'(?:error_log|Log::info|Log::debug|log_message).*(?:password|token|secret|api_key|credit)'):
            self._add(
                "Logging Sensitive Data", Severity.MEDIUM, Confidence.MEDIUM,
                "CWE-532", "A09:2021", match[0], "Logging Sensitive Data",
                "Never log sensitive information. Redact sensitive fields before logging."
            )

    # -- 30. Missing Authentication --
    def _detect_missing_auth(self):
        # Admin-like functions without auth checks
        for fn in self.file.functions + [m for c in self.file.classes for m in c.methods]:
            if re.search(r'admin|delete|update|modify|remove|destroy|create', fn.name, re.IGNORECASE):
                has_auth = False
                for t in fn.body_tokens:
                    if t.type == TokenType.IDENTIFIER and t.value in (
                            "auth", "authenticate", "is_admin", "check_permission",
                            "isAuthenticated", "isLoggedIn", "wp_verify_nonce",
                            "current_user_can", "Gate", "can", "authorize",
                            "middleware", "session_id", "Auth"):
                        has_auth = True
                    if t.type == TokenType.VARIABLE and t.value in ("$_SESSION",):
                        has_auth = True
                if not has_auth and len(fn.body_tokens) > 5:
                    self._add(
                        f"Potential Missing Authentication in {fn.class_name + '::' if fn.class_name else ''}{fn.name}()",
                        Severity.MEDIUM, Confidence.LOW, "CWE-306", "A07:2021",
                        fn.line, "Missing Authentication",
                        "Ensure administrative/destructive operations have proper authentication and authorization checks."
                    )

    # -- Extra: Backtick Execution --
    def _detect_backtick_execution(self):
        for t in self.file.tokens:
            if t.type == TokenType.BACKTICK:
                has_var = "$" in t.value
                self._add(
                    "Command Execution via backtick operator",
                    Severity.HIGH if has_var else Severity.MEDIUM,
                    Confidence.HIGH if has_var else Confidence.MEDIUM,
                    "CWE-78", "A03:2021", t.line, "Command Injection",
                    "Avoid using backtick operator for command execution. Use escapeshellarg() if necessary."
                )

    # -- Extra: Variable Variables --
    def _detect_variable_variables(self):
        for t in self.file.tokens:
            if t.type == TokenType.VAR_VAR:
                self._add(
                    f"Variable Variable Usage: {t.value}",
                    Severity.LOW, Confidence.MEDIUM, "CWE-914", "A05:2021",
                    t.line, "Variable Variables",
                    "Variable variables ($$var) make code harder to audit and can lead to unexpected variable overwrites. Use arrays instead."
                )

# ============================================================================
# 5. MAIN SCANNER CLASS
# ============================================================================

class PHPScanner:
    """Main scanner that orchestrates tokenization, parsing, and detection."""

    PHP_EXTENSIONS = {".php", ".phtml", ".inc", ".module", ".install", ".theme"}

    CATEGORIES = [
        "SQL Injection", "Command Injection", "Code Injection",
        "Cross-Site Scripting", "Path Traversal", "File Upload",
        "Insecure Deserialization", "SSRF", "XXE Injection",
        "Hardcoded Secrets", "Weak Cryptography", "Insecure Randomness",
        "Laravel Security", "WordPress Security", "Symfony Security",
        "CodeIgniter Security", "Type Juggling", "Open Redirect",
        "Session Fixation", "CSRF", "Information Disclosure",
        "Insecure File Permissions", "Missing Input Validation",
        "Register Globals", "Object Injection", "LDAP Injection",
        "Email Injection", "Timing Attack", "Logging Sensitive Data",
        "Missing Authentication", "Variable Variables",
    ]

    def scan(self, files: Dict[str, str], scan_id: str) -> dict:
        start = time.time()
        all_vulns = []
        errors = []
        scanned = 0

        for path, content in files.items():
            if not any(path.endswith(ext) for ext in self.PHP_EXTENSIONS):
                if not content.lstrip().startswith("<?php") and not content.lstrip().startswith("<?"):
                    continue

            scanned += 1
            try:
                vulns = self._scan_single_file(path, content)
                all_vulns.extend(vulns)
            except Exception as e:
                errors.append({"file": path, "error": str(e)})
                logger.warning(f"Error scanning {path}: {e}")

        duration = time.time() - start

        # Deduplicate
        seen = set()
        unique_vulns = []
        for v in all_vulns:
            key = (v.file_path, v.line_number, v.title)
            if key not in seen:
                seen.add(key)
                unique_vulns.append(v)

        # Build summary
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        category_counts: Dict[str, int] = {}
        for v in unique_vulns:
            severity_counts[v.severity.value] = severity_counts.get(v.severity.value, 0) + 1
            category_counts[v.category] = category_counts.get(v.category, 0) + 1

        return {
            "vulnerabilities": [v.to_dict() for v in unique_vulns],
            "summary": {
                "totalVulnerabilities": len(unique_vulns),
                "severityCounts": severity_counts,
                "categoryCounts": category_counts,
                "scanId": scan_id,
            },
            "scanDuration": f"{duration:.2f}s",
            "filesScanned": scanned,
            "errors": errors if errors else None,
        }

    def _scan_single_file(self, path: str, content: str) -> List[Vulnerability]:
        # Tokenize
        tokenizer = PHPTokenizer(content, path)
        try:
            tokens = tokenizer.tokenize()
        except Exception as e:
            logger.warning(f"Tokenizer error on {path}: {e}")
            return []

        # Parse structure
        parser = PHPParser(tokens, content, path)
        try:
            php_file = parser.parse()
        except Exception as e:
            logger.warning(f"Parser error on {path}: {e}")
            # Fall back to token-only analysis
            php_file = PHPFile(path=path, tokens=tokens, lines=content.splitlines())

        # Run detectors
        detector = VulnerabilityDetector()
        return detector.scan_file(php_file, content)


# ============================================================================
# 6. FASTAPI APPLICATION
# ============================================================================

app = FastAPI(
    title="Offensive360 PHP SAST Scanner",
    version="1.0.0",
    description="Custom tokenizer-based static analysis for PHP code",
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


scanner = PHPScanner()


@app.post("/scan", response_model=ScanResponse)
async def scan_endpoint(request: ScanRequest):
    """Scan PHP files for security vulnerabilities."""
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
    return {
        "status": "healthy",
        "language": "PHP",
        "version": "1.0.0",
        "port": 9006,
        "uptime": int(time.time() - START_TIME),
        "categories": PHPScanner.CATEGORIES,
    }


@app.get("/")
async def root():
    return {"scanner": "php-sast", "version": "1.0.0", "port": 9006}


# ============================================================================
# 7. ENTRYPOINT
# ============================================================================

if __name__ == "__main__":
    logger.info("Starting PHP SAST Scanner on port 9006...")
    uvicorn.run(app, host="0.0.0.0", port=9006, log_level="info")
