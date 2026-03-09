#!/usr/bin/env python3
"""
Offensive360 Scala SAST Scanner
Token-based static analysis for Scala (Play, Akka, Spark).
FastAPI server on port 9014.
Covers 20+ vulnerability categories.
"""

import os
import re
import uuid
import hashlib
import logging
import time
from typing import List, Dict, Any, Optional, Tuple, Set
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
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanner.log")
        ),
    ],
)
log = logging.getLogger("scala-scanner")

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

# ============================================================================
# PART 1: TOKEN-BASED PARSER
# ============================================================================

class TokenType(Enum):
    KEYWORD = "keyword"
    IDENTIFIER = "identifier"
    STRING = "string"
    MULTILINE_STRING = "multiline_string"
    STRING_INTERPOLATION = "string_interpolation"
    CHAR_LITERAL = "char_literal"
    NUMBER = "number"
    OPERATOR = "operator"
    PUNCTUATION = "punctuation"
    COMMENT = "comment"
    NEWLINE = "newline"
    WHITESPACE = "whitespace"
    ANNOTATION = "annotation"
    SYMBOL_LITERAL = "symbol_literal"

@dataclass
class Token:
    type: TokenType
    value: str
    line: int
    column: int

SCALA_KEYWORDS = {
    "abstract", "case", "catch", "class", "def", "do", "else", "enum",
    "export", "extends", "false", "final", "finally", "for", "forSome",
    "given", "if", "implicit", "import", "lazy", "match", "new", "null",
    "object", "override", "package", "private", "protected", "return",
    "sealed", "super", "then", "this", "throw", "trait", "true", "try",
    "type", "val", "var", "while", "with", "yield", "using", "end",
    "extension", "infix", "inline", "opaque", "open", "transparent",
    # Common types
    "Int", "Long", "Float", "Double", "Boolean", "String", "Char",
    "Unit", "Any", "AnyRef", "AnyVal", "Nothing", "Null", "Option",
    "Some", "None", "List", "Map", "Set", "Seq", "Vector", "Array",
    "Future", "Either", "Right", "Left", "Try", "Success", "Failure",
}

SCALA_OPERATORS = {
    "=>", "->", "<-", "<:", ">:", "<%", "#", "@",
    "==", "!=", "<=", ">=", "&&", "||",
    "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
    "::", "++", "--", "<<", ">>", ">>>",
    "+", "-", "*", "/", "%", "&", "|", "^", "~", "!",
    "<", ">", "=", ".", "?", ":",
}


class ScalaTokenizer:
    """Tokenizer for Scala source code."""

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
                self.pos += 1
                self.column += 1

            elif ch == "/" and self.pos + 1 < len(self.source):
                nch = self.source[self.pos + 1]
                if nch == "/":
                    self._read_line_comment()
                elif nch == "*":
                    self._read_block_comment()
                else:
                    self._read_operator()

            elif ch == "@":
                self._read_annotation()

            elif ch == '"':
                self._read_string()

            elif ch == "'":
                self._read_char_or_symbol()

            elif ch.isdigit():
                self._read_number()

            elif ch.isalpha() or ch == "_" or ch == "$":
                self._read_identifier_or_keyword()

            elif ch in "(){}[];,":
                self.tokens.append(Token(TokenType.PUNCTUATION, ch, self.line, self.column))
                self.pos += 1
                self.column += 1

            else:
                self._read_operator()

        return self.tokens

    def _read_line_comment(self):
        start = self.pos
        line = self.line
        col = self.column
        while self.pos < len(self.source) and self.source[self.pos] != "\n":
            self.pos += 1
            self.column += 1
        self.tokens.append(Token(TokenType.COMMENT, self.source[start:self.pos], line, col))

    def _read_block_comment(self):
        start = self.pos
        line = self.line
        col = self.column
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
            else:
                if self.source[self.pos] == "\n":
                    self.line += 1
                    self.column = 1
                else:
                    self.column += 1
                self.pos += 1
        self.tokens.append(Token(TokenType.COMMENT, self.source[start:self.pos], line, col))

    def _read_annotation(self):
        start = self.pos
        line = self.line
        col = self.column
        self.pos += 1
        self.column += 1
        while self.pos < len(self.source) and (self.source[self.pos].isalnum() or self.source[self.pos] in "_.$"):
            self.pos += 1
            self.column += 1
        self.tokens.append(Token(TokenType.ANNOTATION, self.source[start:self.pos], line, col))

    def _read_string(self):
        start = self.pos
        line = self.line
        col = self.column

        # Check for triple-quoted string
        if self.pos + 2 < len(self.source) and self.source[self.pos:self.pos + 3] == '"""':
            self.pos += 3
            self.column += 3
            has_interp = False
            while self.pos + 2 < len(self.source):
                if self.source[self.pos:self.pos + 3] == '"""':
                    self.pos += 3
                    self.column += 3
                    break
                if self.source[self.pos] == "$":
                    has_interp = True
                if self.source[self.pos] == "\n":
                    self.line += 1
                    self.column = 1
                else:
                    self.column += 1
                self.pos += 1
            tok_type = TokenType.STRING_INTERPOLATION if has_interp else TokenType.MULTILINE_STRING
            self.tokens.append(Token(tok_type, self.source[start:self.pos], line, col))
            return

        # Check for s"" / f"" / raw"" interpolated strings
        # Look back for s/f/raw prefix (handled as identifier already)
        self.pos += 1
        self.column += 1
        has_interp = False
        while self.pos < len(self.source) and self.source[self.pos] != '"' and self.source[self.pos] != "\n":
            if self.source[self.pos] == "\\":
                self.pos += 2
                self.column += 2
            else:
                if self.source[self.pos] == "$":
                    has_interp = True
                self.pos += 1
                self.column += 1
        if self.pos < len(self.source) and self.source[self.pos] == '"':
            self.pos += 1
            self.column += 1

        tok_type = TokenType.STRING_INTERPOLATION if has_interp else TokenType.STRING
        self.tokens.append(Token(tok_type, self.source[start:self.pos], line, col))

    def _read_char_or_symbol(self):
        start = self.pos
        line = self.line
        col = self.column

        # Check if this is a symbol literal 'symbolName
        if self.pos + 1 < len(self.source) and (self.source[self.pos + 1].isalpha() or self.source[self.pos + 1] == "_"):
            self.pos += 1
            self.column += 1
            while self.pos < len(self.source) and (self.source[self.pos].isalnum() or self.source[self.pos] == "_"):
                self.pos += 1
                self.column += 1
            self.tokens.append(Token(TokenType.SYMBOL_LITERAL, self.source[start:self.pos], line, col))
            return

        # Character literal
        self.pos += 1
        self.column += 1
        if self.pos < len(self.source) and self.source[self.pos] == "\\":
            self.pos += 2
            self.column += 2
        elif self.pos < len(self.source):
            self.pos += 1
            self.column += 1
        if self.pos < len(self.source) and self.source[self.pos] == "'":
            self.pos += 1
            self.column += 1
        self.tokens.append(Token(TokenType.CHAR_LITERAL, self.source[start:self.pos], line, col))

    def _read_number(self):
        start = self.pos
        line = self.line
        col = self.column
        while self.pos < len(self.source) and (
            self.source[self.pos].isalnum() or self.source[self.pos] in "._xXeElLfFdD"
        ):
            self.pos += 1
            self.column += 1
        self.tokens.append(Token(TokenType.NUMBER, self.source[start:self.pos], line, col))

    def _read_identifier_or_keyword(self):
        start = self.pos
        line = self.line
        col = self.column
        while self.pos < len(self.source) and (
            self.source[self.pos].isalnum() or self.source[self.pos] in "_$"
        ):
            self.pos += 1
            self.column += 1
        word = self.source[start:self.pos]
        if word in SCALA_KEYWORDS:
            self.tokens.append(Token(TokenType.KEYWORD, word, line, col))
        else:
            self.tokens.append(Token(TokenType.IDENTIFIER, word, line, col))

    def _read_operator(self):
        line = self.line
        col = self.column
        for length in (3, 2, 1):
            if self.pos + length <= len(self.source):
                candidate = self.source[self.pos:self.pos + length]
                if candidate in SCALA_OPERATORS:
                    self.tokens.append(Token(TokenType.OPERATOR, candidate, line, col))
                    self.pos += length
                    self.column += length
                    return
        self.tokens.append(Token(TokenType.OPERATOR, self.source[self.pos], line, col))
        self.pos += 1
        self.column += 1


# ============================================================================
# PART 2: SIMPLIFIED AST
# ============================================================================

@dataclass
class ASTNode:
    kind: str
    name: str = ""
    line: int = 0
    column: int = 0
    children: List["ASTNode"] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)


class ScalaParser:
    """Builds simplified AST from Scala tokens."""

    def __init__(self, tokens: List[Token]):
        self.tokens = [t for t in tokens if t.type not in (TokenType.WHITESPACE, TokenType.NEWLINE, TokenType.COMMENT)]
        self.pos = 0
        self.root = ASTNode(kind="source_file")

    def parse(self) -> ASTNode:
        while self.pos < len(self.tokens):
            node = self._parse_top_level()
            if node:
                self.root.children.append(node)
            else:
                self.pos += 1
        return self.root

    def _peek(self, offset=0) -> Optional[Token]:
        idx = self.pos + offset
        return self.tokens[idx] if idx < len(self.tokens) else None

    def _current(self) -> Optional[Token]:
        return self._peek(0)

    def _advance(self) -> Optional[Token]:
        tok = self._current()
        self.pos += 1
        return tok

    def _match(self, tok_type: TokenType, value: str = None) -> bool:
        tok = self._current()
        if tok is None:
            return False
        if tok.type != tok_type:
            return False
        if value is not None and tok.value != value:
            return False
        return True

    def _parse_top_level(self) -> Optional[ASTNode]:
        tok = self._current()
        if tok is None:
            return None

        if tok.type == TokenType.KEYWORD:
            if tok.value == "package":
                return self._parse_package()
            if tok.value == "import":
                return self._parse_import()
            if tok.value in ("class", "case", "abstract", "sealed"):
                return self._parse_class()
            if tok.value == "object":
                return self._parse_object()
            if tok.value == "trait":
                return self._parse_trait()
            if tok.value == "def":
                return self._parse_def()
            if tok.value in ("val", "var", "lazy"):
                return self._parse_val_var()

        if tok.type == TokenType.ANNOTATION:
            ann = self._advance()
            if self._match(TokenType.PUNCTUATION, "("):
                self._skip_parens()
            child = self._parse_top_level()
            if child:
                child.attributes["annotation"] = ann.value
            return child

        return None

    def _parse_package(self) -> ASTNode:
        tok = self._advance()
        node = ASTNode(kind="package", line=tok.line, column=tok.column)
        parts = []
        while self.pos < len(self.tokens):
            t = self._current()
            if t is None or t.type == TokenType.NEWLINE:
                break
            if t.type == TokenType.PUNCTUATION and t.value == "{":
                break
            parts.append(t.value)
            self._advance()
        node.name = "".join(parts)
        return node

    def _parse_import(self) -> ASTNode:
        tok = self._advance()
        node = ASTNode(kind="import", line=tok.line, column=tok.column)
        parts = []
        while self.pos < len(self.tokens):
            t = self._current()
            if t is None or t.type == TokenType.NEWLINE:
                break
            if t.type == TokenType.PUNCTUATION and t.value == "{":
                self._skip_braces()
                break
            parts.append(t.value)
            self._advance()
        node.name = "".join(parts)
        return node

    def _parse_class(self) -> ASTNode:
        # Handle "case class", "abstract class", "sealed class", etc.
        modifiers = []
        while self._current() and self._current().type == TokenType.KEYWORD and self._current().value in ("case", "abstract", "sealed", "final"):
            modifiers.append(self._advance().value)

        tok = self._advance()  # consume 'class'
        node = ASTNode(kind="class", line=tok.line, column=tok.column)
        node.attributes["modifiers"] = modifiers

        if self._current() and self._current().type == TokenType.IDENTIFIER:
            node.name = self._advance().value

        # Skip type parameters, constructor params, extends/with
        while self.pos < len(self.tokens):
            t = self._current()
            if t is None:
                break
            if t.type == TokenType.PUNCTUATION and t.value == "{":
                break
            if t.type == TokenType.PUNCTUATION and t.value == "(":
                self._skip_parens()
                continue
            if t.type == TokenType.PUNCTUATION and t.value == "[":
                self._skip_brackets()
                continue
            self._advance()

        if self._match(TokenType.PUNCTUATION, "{"):
            self._advance()
            depth = 1
            while self.pos < len(self.tokens) and depth > 0:
                t = self._current()
                if t and t.type == TokenType.PUNCTUATION:
                    if t.value == "{":
                        depth += 1
                    elif t.value == "}":
                        depth -= 1
                        if depth <= 0:
                            self._advance()
                            break
                member = self._parse_class_member()
                if member:
                    node.children.append(member)
                else:
                    self._advance()
        return node

    def _parse_object(self) -> ASTNode:
        tok = self._advance()
        node = ASTNode(kind="object", line=tok.line, column=tok.column)
        if self._current() and self._current().type == TokenType.IDENTIFIER:
            node.name = self._advance().value
        while self.pos < len(self.tokens):
            t = self._current()
            if t is None:
                break
            if t.type == TokenType.PUNCTUATION and t.value == "{":
                break
            self._advance()
        if self._match(TokenType.PUNCTUATION, "{"):
            self._advance()
            depth = 1
            while self.pos < len(self.tokens) and depth > 0:
                t = self._current()
                if t and t.type == TokenType.PUNCTUATION:
                    if t.value == "{":
                        depth += 1
                    elif t.value == "}":
                        depth -= 1
                        if depth <= 0:
                            self._advance()
                            break
                member = self._parse_class_member()
                if member:
                    node.children.append(member)
                else:
                    self._advance()
        return node

    def _parse_trait(self) -> ASTNode:
        tok = self._advance()
        node = ASTNode(kind="trait", line=tok.line, column=tok.column)
        if self._current() and self._current().type == TokenType.IDENTIFIER:
            node.name = self._advance().value
        while self.pos < len(self.tokens):
            t = self._current()
            if t is None:
                break
            if t.type == TokenType.PUNCTUATION and t.value == "{":
                break
            self._advance()
        if self._match(TokenType.PUNCTUATION, "{"):
            self._skip_braces()
        return node

    def _parse_class_member(self) -> Optional[ASTNode]:
        tok = self._current()
        if tok is None:
            return None
        if tok.type == TokenType.ANNOTATION:
            ann = self._advance()
            if self._match(TokenType.PUNCTUATION, "("):
                self._skip_parens()
            child = self._parse_class_member()
            if child:
                child.attributes["annotation"] = ann.value
            return child
        if tok.type == TokenType.KEYWORD:
            if tok.value == "def":
                return self._parse_def()
            if tok.value in ("val", "var", "lazy"):
                return self._parse_val_var()
            if tok.value in ("class", "case", "abstract", "sealed"):
                return self._parse_class()
            if tok.value == "object":
                return self._parse_object()
            if tok.value in ("override", "private", "protected", "implicit", "final"):
                self._advance()
                return self._parse_class_member()
        return None

    def _parse_def(self) -> ASTNode:
        tok = self._advance()
        node = ASTNode(kind="def", line=tok.line, column=tok.column)
        if self._current() and self._current().type == TokenType.IDENTIFIER:
            node.name = self._advance().value
        # Type params
        if self._match(TokenType.PUNCTUATION, "["):
            self._skip_brackets()
        # Parameters
        while self._match(TokenType.PUNCTUATION, "("):
            params = self._collect_parens_content()
            node.attributes.setdefault("params", []).append(params)
        # Return type
        if self._match(TokenType.OPERATOR, ":"):
            self._advance()
            ret_parts = []
            while self.pos < len(self.tokens):
                t = self._current()
                if t is None:
                    break
                if t.type == TokenType.OPERATOR and t.value == "=":
                    break
                if t.type == TokenType.PUNCTUATION and t.value == "{":
                    break
                ret_parts.append(t.value)
                self._advance()
            node.attributes["return_type"] = " ".join(ret_parts)
        # Body
        if self._match(TokenType.OPERATOR, "="):
            self._advance()
            if self._match(TokenType.PUNCTUATION, "{"):
                body = self._collect_block()
                node.attributes["body_text"] = body
            else:
                parts = []
                depth = 0
                while self.pos < len(self.tokens):
                    t = self._current()
                    if t is None:
                        break
                    if t.type == TokenType.PUNCTUATION:
                        if t.value in ("(", "[", "{"):
                            depth += 1
                        elif t.value in (")", "]", "}"):
                            depth -= 1
                            if depth < 0:
                                break
                    if depth == 0 and t.type == TokenType.KEYWORD and t.value in ("def", "val", "var", "class", "object", "trait"):
                        break
                    parts.append(t.value)
                    self._advance()
                node.attributes["body_text"] = " ".join(parts)
        elif self._match(TokenType.PUNCTUATION, "{"):
            body = self._collect_block()
            node.attributes["body_text"] = body
        return node

    def _parse_val_var(self) -> ASTNode:
        tok = self._advance()
        node = ASTNode(kind=tok.value, line=tok.line, column=tok.column)
        if self._current() and self._current().type == TokenType.IDENTIFIER:
            node.name = self._advance().value
        # Skip to = or end
        while self.pos < len(self.tokens):
            t = self._current()
            if t is None:
                break
            if t.type == TokenType.OPERATOR and t.value == "=":
                self._advance()
                # Collect value
                parts = []
                depth = 0
                while self.pos < len(self.tokens):
                    tt = self._current()
                    if tt is None:
                        break
                    if tt.type == TokenType.PUNCTUATION:
                        if tt.value in ("(", "[", "{"):
                            depth += 1
                        elif tt.value in (")", "]", "}"):
                            depth -= 1
                            if depth < 0:
                                break
                    if depth == 0 and tt.type == TokenType.KEYWORD and tt.value in ("def", "val", "var", "class", "object"):
                        break
                    parts.append(tt.value)
                    self._advance()
                node.attributes["value"] = " ".join(parts)
                break
            if t.type == TokenType.PUNCTUATION and t.value in ("}", ";"):
                break
            self._advance()
        return node

    def _skip_parens(self):
        if not self._match(TokenType.PUNCTUATION, "("):
            return
        self._advance()
        depth = 1
        while self.pos < len(self.tokens) and depth > 0:
            t = self._current()
            if t and t.type == TokenType.PUNCTUATION:
                if t.value == "(":
                    depth += 1
                elif t.value == ")":
                    depth -= 1
            self._advance()

    def _skip_brackets(self):
        if not self._match(TokenType.PUNCTUATION, "["):
            return
        self._advance()
        depth = 1
        while self.pos < len(self.tokens) and depth > 0:
            t = self._current()
            if t and t.type == TokenType.PUNCTUATION:
                if t.value == "[":
                    depth += 1
                elif t.value == "]":
                    depth -= 1
            self._advance()

    def _skip_braces(self):
        if not self._match(TokenType.PUNCTUATION, "{"):
            return
        self._advance()
        depth = 1
        while self.pos < len(self.tokens) and depth > 0:
            t = self._current()
            if t and t.type == TokenType.PUNCTUATION:
                if t.value == "{":
                    depth += 1
                elif t.value == "}":
                    depth -= 1
            self._advance()

    def _collect_parens_content(self) -> str:
        if not self._match(TokenType.PUNCTUATION, "("):
            return ""
        self._advance()
        depth = 1
        parts = []
        while self.pos < len(self.tokens) and depth > 0:
            t = self._current()
            if t and t.type == TokenType.PUNCTUATION:
                if t.value == "(":
                    depth += 1
                elif t.value == ")":
                    depth -= 1
                    if depth <= 0:
                        self._advance()
                        break
            if t:
                parts.append(t.value)
            self._advance()
        return " ".join(parts)

    def _collect_block(self) -> str:
        if not self._match(TokenType.PUNCTUATION, "{"):
            return ""
        self._advance()
        depth = 1
        parts = []
        while self.pos < len(self.tokens) and depth > 0:
            t = self._current()
            if t and t.type == TokenType.PUNCTUATION:
                if t.value == "{":
                    depth += 1
                elif t.value == "}":
                    depth -= 1
                    if depth <= 0:
                        self._advance()
                        break
            if t:
                parts.append(t.value)
            self._advance()
        return " ".join(parts)


# ============================================================================
# PART 3: VULNERABILITY ANALYZER
# ============================================================================

class ScalaAnalyzer:
    """Analyzes tokenized Scala code for security vulnerabilities."""

    def __init__(self):
        self.findings: List[Finding] = []

    def analyze(self, tokens: List[Token], ast: ASTNode, file_path: str, source: str) -> List[Finding]:
        self.findings = []
        lines = source.split("\n")
        non_comment = [t for t in tokens if t.type != TokenType.COMMENT]
        comments = [t for t in tokens if t.type == TokenType.COMMENT]

        self._check_sql_injection(non_comment, lines, file_path, source)
        self._check_command_injection(non_comment, lines, file_path)
        self._check_code_injection(non_comment, lines, file_path)
        self._check_xss(non_comment, lines, file_path, source)
        self._check_path_traversal(non_comment, lines, file_path)
        self._check_deserialization(non_comment, lines, file_path, source)
        self._check_xxe(non_comment, lines, file_path, source)
        self._check_ssrf(non_comment, lines, file_path)
        self._check_hardcoded_secrets(non_comment, lines, file_path)
        self._check_weak_crypto(non_comment, lines, file_path)
        self._check_insecure_random(non_comment, lines, file_path)
        self._check_play_framework(non_comment, lines, file_path, source)
        self._check_akka_specific(non_comment, lines, file_path, source)
        self._check_spark_specific(non_comment, lines, file_path)
        self._check_pattern_matching(non_comment, lines, file_path, ast)
        self._check_mutable_shared_state(non_comment, lines, file_path, ast)
        self._check_resource_leaks(non_comment, lines, file_path)
        self._check_implicit_security(non_comment, lines, file_path)
        self._check_unsafe_cast(non_comment, lines, file_path)
        self._check_info_disclosure(non_comment, lines, file_path, comments)

        return self.findings

    def _get_snippet(self, lines: List[str], line_num: int, context: int = 2) -> str:
        start = max(0, line_num - 1 - context)
        end = min(len(lines), line_num + context)
        snippet_lines = []
        for i in range(start, end):
            marker = ">>> " if i == line_num - 1 else "    "
            snippet_lines.append(f"{marker}{i + 1}: {lines[i]}")
        return "\n".join(snippet_lines)

    def _peek_token(self, tokens: List[Token], idx: int) -> Optional[Token]:
        return tokens[idx] if 0 <= idx < len(tokens) else None

    # --- SQL Injection ---
    def _check_sql_injection(self, tokens: List[Token], lines: List[str], file_path: str, source: str):
        # JDBC string concatenation
        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER and t.value in ("executeQuery", "executeUpdate", "execute", "prepareStatement"):
                context = tokens[max(0, i-10):min(len(tokens), i+15)]
                has_concat = any(ct.type == TokenType.OPERATOR and ct.value == "+" for ct in context)
                has_interp = any(ct.type == TokenType.STRING_INTERPOLATION for ct in context)
                if has_concat or has_interp:
                    self.findings.append(Finding(
                        rule_id="SCALA-SQL-INJECTION-JDBC",
                        category="SQL Injection",
                        title=f"SQL injection via {t.value} with string concatenation",
                        description=f"JDBC {t.value} is called with a dynamically constructed SQL string. "
                                    "This allows SQL injection if user input is included.",
                        severity=Severity.CRITICAL.value,
                        confidence=Confidence.HIGH.value,
                        file_path=file_path,
                        line_number=t.line,
                        column=t.column,
                        code_snippet=self._get_snippet(lines, t.line),
                        remediation="Use PreparedStatement with parameterized queries instead of string concatenation.",
                        cwe_id="CWE-89",
                        owasp="A03:2021 - Injection",
                    ))

        # Slick sql interpolator misuse
        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER and t.value in ("sql", "sqlu"):
                next_t = self._peek_token(tokens, i + 1)
                if next_t and next_t.type == TokenType.STRING_INTERPOLATION:
                    # sql"..." is safe (uses PreparedStatement), but check for #$
                    if "#$" in next_t.value:
                        self.findings.append(Finding(
                            rule_id="SCALA-SQL-INJECTION-SLICK",
                            category="SQL Injection",
                            title="Slick SQL injection via #$ interpolation",
                            description="Slick sql interpolator uses #$ which inserts raw strings without escaping, "
                                        "unlike $ which uses parameterized queries. This enables SQL injection.",
                            severity=Severity.CRITICAL.value,
                            confidence=Confidence.HIGH.value,
                            file_path=file_path,
                            line_number=t.line,
                            code_snippet=self._get_snippet(lines, t.line),
                            remediation="Use $ instead of #$ in Slick sql interpolator for user input.",
                            cwe_id="CWE-89",
                            owasp="A03:2021 - Injection",
                        ))

        # Anorm
        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER and t.value == "SQL":
                context = tokens[i:min(len(tokens), i+15)]
                has_interp = any(ct.type == TokenType.STRING_INTERPOLATION for ct in context)
                has_concat = any(ct.type == TokenType.OPERATOR and ct.value == "+" for ct in context)
                if has_interp or has_concat:
                    self.findings.append(Finding(
                        rule_id="SCALA-SQL-INJECTION-ANORM",
                        category="SQL Injection",
                        title="Anorm SQL injection via string interpolation",
                        description="Anorm SQL() is called with an interpolated or concatenated string. "
                                    "Use parameterized queries with {namedParam} syntax.",
                        severity=Severity.CRITICAL.value,
                        confidence=Confidence.HIGH.value,
                        file_path=file_path,
                        line_number=t.line,
                        code_snippet=self._get_snippet(lines, t.line),
                        remediation="Use SQL(\"SELECT * FROM t WHERE id = {id}\").on('id -> userId)",
                        cwe_id="CWE-89",
                        owasp="A03:2021 - Injection",
                    ))

        # Spark SQL
        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER and t.value == "spark":
                context = tokens[i:min(len(tokens), i+10)]
                has_sql = any(ct.value == "sql" for ct in context if ct.type == TokenType.IDENTIFIER)
                if has_sql:
                    broader = tokens[i:min(len(tokens), i+20)]
                    has_interp = any(ct.type == TokenType.STRING_INTERPOLATION for ct in broader)
                    has_concat = any(ct.type == TokenType.OPERATOR and ct.value == "+" for ct in broader)
                    if has_interp or has_concat:
                        self.findings.append(Finding(
                            rule_id="SCALA-SQL-INJECTION-SPARK",
                            category="SQL Injection",
                            title="Spark SQL injection via dynamic query",
                            description="spark.sql() is called with a dynamically constructed query string.",
                            severity=Severity.HIGH.value,
                            confidence=Confidence.MEDIUM.value,
                            file_path=file_path,
                            line_number=t.line,
                            code_snippet=self._get_snippet(lines, t.line),
                            remediation="Use parameterized queries or Spark DataFrame API instead of raw SQL strings.",
                            cwe_id="CWE-89",
                            owasp="A03:2021 - Injection",
                        ))

    # --- Command Injection ---
    def _check_command_injection(self, tokens: List[Token], lines: List[str], file_path: str):
        # scala.sys.process
        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER and t.value in ("Process", "process"):
                context = tokens[i:min(len(tokens), i+10)]
                has_run = any(ct.value in ("!", "!!", "run", "lazyLines") for ct in context)
                if has_run:
                    broader = tokens[max(0, i-5):min(len(tokens), i+15)]
                    has_interp = any(ct.type == TokenType.STRING_INTERPOLATION for ct in broader)
                    has_concat = any(ct.type == TokenType.OPERATOR and ct.value == "+" for ct in broader)
                    self.findings.append(Finding(
                        rule_id="SCALA-CMD-INJECTION-PROCESS",
                        category="Command Injection",
                        title="Command execution via scala.sys.process",
                        description="scala.sys.process.Process executes system commands. "
                                    "If user input is included, it enables arbitrary command execution.",
                        severity=Severity.CRITICAL.value if (has_interp or has_concat) else Severity.HIGH.value,
                        confidence=Confidence.HIGH.value if (has_interp or has_concat) else Confidence.MEDIUM.value,
                        file_path=file_path,
                        line_number=t.line,
                        code_snippet=self._get_snippet(lines, t.line),
                        remediation="Avoid executing shell commands with user input. Use ProcessBuilder with argument arrays.",
                        cwe_id="CWE-78",
                        owasp="A03:2021 - Injection",
                    ))

        # String.! (implicit process)
        for i, t in enumerate(tokens):
            if t.type == TokenType.OPERATOR and t.value == "!" and i > 0:
                prev = tokens[i - 1]
                if prev.type in (TokenType.STRING, TokenType.STRING_INTERPOLATION):
                    self.findings.append(Finding(
                        rule_id="SCALA-CMD-INJECTION-STRINGBANG",
                        category="Command Injection",
                        title="Shell command execution via string.! operator",
                        description="A string is executed as a shell command using the .! operator from scala.sys.process. "
                                    "This is especially dangerous with interpolated strings.",
                        severity=Severity.CRITICAL.value if prev.type == TokenType.STRING_INTERPOLATION else Severity.HIGH.value,
                        confidence=Confidence.HIGH.value,
                        file_path=file_path,
                        line_number=t.line,
                        code_snippet=self._get_snippet(lines, t.line),
                        remediation="Use Process with explicit argument lists instead of shell command strings.",
                        cwe_id="CWE-78",
                        owasp="A03:2021 - Injection",
                    ))

        # Runtime.exec
        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER and t.value == "Runtime":
                context = tokens[i:min(len(tokens), i+10)]
                has_exec = any(ct.value == "exec" for ct in context if ct.type == TokenType.IDENTIFIER)
                if has_exec:
                    self.findings.append(Finding(
                        rule_id="SCALA-CMD-INJECTION-RUNTIME",
                        category="Command Injection",
                        title="Command execution via Runtime.exec",
                        description="Runtime.getRuntime.exec() executes system commands.",
                        severity=Severity.HIGH.value,
                        confidence=Confidence.HIGH.value,
                        file_path=file_path,
                        line_number=t.line,
                        code_snippet=self._get_snippet(lines, t.line),
                        remediation="Avoid Runtime.exec. Use ProcessBuilder with validated argument arrays.",
                        cwe_id="CWE-78",
                        owasp="A03:2021 - Injection",
                    ))

    # --- Code Injection ---
    def _check_code_injection(self, tokens: List[Token], lines: List[str], file_path: str):
        # Reflection
        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER and t.value in ("forName", "getDeclaredMethod", "invoke", "newInstance"):
                context = tokens[max(0, i-5):min(len(tokens), i+10)]
                has_dynamic = any(
                    ct.type == TokenType.IDENTIFIER and ct.value in ("className", "methodName", "input", "name")
                    for ct in context
                )
                if has_dynamic:
                    self.findings.append(Finding(
                        rule_id="SCALA-CODE-INJECTION-REFLECTION",
                        category="Code Injection",
                        title=f"Reflection with dynamic input: {t.value}",
                        description=f"Reflection method {t.value} is called with what appears to be dynamic input. "
                                    "This can lead to arbitrary code execution.",
                        severity=Severity.CRITICAL.value,
                        confidence=Confidence.MEDIUM.value,
                        file_path=file_path,
                        line_number=t.line,
                        code_snippet=self._get_snippet(lines, t.line),
                        remediation="Validate class/method names against an allowlist. Avoid reflection with user input.",
                        cwe_id="CWE-470",
                        owasp="A03:2021 - Injection",
                    ))

        # ScriptEngine
        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER and t.value in ("ScriptEngine", "ScriptEngineManager"):
                context = tokens[i:min(len(tokens), i+20)]
                has_eval = any(ct.value == "eval" for ct in context if ct.type == TokenType.IDENTIFIER)
                if has_eval:
                    self.findings.append(Finding(
                        rule_id="SCALA-CODE-INJECTION-SCRIPT",
                        category="Code Injection",
                        title="Script engine code execution",
                        description="ScriptEngine.eval() executes arbitrary code. If user input is evaluated, "
                                    "it enables remote code execution.",
                        severity=Severity.CRITICAL.value,
                        confidence=Confidence.HIGH.value,
                        file_path=file_path,
                        line_number=t.line,
                        code_snippet=self._get_snippet(lines, t.line),
                        remediation="Avoid evaluating user input as code. Use sandboxed script engines if necessary.",
                        cwe_id="CWE-94",
                        owasp="A03:2021 - Injection",
                    ))

    # --- XSS ---
    def _check_xss(self, tokens: List[Token], lines: List[str], file_path: str, source: str):
        # Play Framework Html() without escaping
        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER and t.value == "Html":
                next_t = self._peek_token(tokens, i + 1)
                if next_t and next_t.type == TokenType.PUNCTUATION and next_t.value == "(":
                    context = tokens[i:min(len(tokens), i+15)]
                    has_dynamic = any(
                        ct.type in (TokenType.STRING_INTERPOLATION, TokenType.IDENTIFIER)
                        and ct.value not in ("Html", "(", ")")
                        for ct in context
                    )
                    if has_dynamic:
                        self.findings.append(Finding(
                            rule_id="SCALA-XSS-HTML",
                            category="Cross-Site Scripting (XSS)",
                            title="Potential XSS via Play Html() with dynamic content",
                            description="Play Framework Html() wraps raw HTML without escaping. "
                                        "If user input is included, it enables XSS attacks.",
                            severity=Severity.HIGH.value,
                            confidence=Confidence.HIGH.value,
                            file_path=file_path,
                            line_number=t.line,
                            code_snippet=self._get_snippet(lines, t.line),
                            remediation="Use Twirl templates with @{} which auto-escape. Sanitize HTML with a library like jsoup.",
                            cwe_id="CWE-79",
                            owasp="A03:2021 - Injection",
                        ))

        # Twirl @Html usage
        if "@Html" in source:
            for i, t in enumerate(tokens):
                if t.type == TokenType.ANNOTATION and t.value == "@Html":
                    self.findings.append(Finding(
                        rule_id="SCALA-XSS-TWIRL-RAW",
                        category="Cross-Site Scripting (XSS)",
                        title="Raw HTML in Twirl template via @Html",
                        description="@Html in Twirl templates outputs raw unescaped HTML. "
                                    "If user-controlled data is passed, it results in XSS.",
                        severity=Severity.HIGH.value,
                        confidence=Confidence.MEDIUM.value,
                        file_path=file_path,
                        line_number=t.line,
                        code_snippet=self._get_snippet(lines, t.line),
                        remediation="Use standard Twirl expressions @{} which auto-escape. Only use @Html for trusted content.",
                        cwe_id="CWE-79",
                        owasp="A03:2021 - Injection",
                    ))

    # --- Path Traversal ---
    def _check_path_traversal(self, tokens: List[Token], lines: List[str], file_path: str):
        file_constructors = ["File", "Path", "Paths", "Source"]
        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER and t.value in file_constructors:
                context = tokens[i:min(len(tokens), i+15)]
                has_dynamic = any(
                    ct.type == TokenType.STRING_INTERPOLATION or
                    (ct.type == TokenType.OPERATOR and ct.value == "+")
                    for ct in context
                )
                has_user_input = any(
                    ct.value in ("path", "filename", "name", "filePath", "input", "param", "request")
                    for ct in context if ct.type == TokenType.IDENTIFIER
                )
                if has_dynamic or has_user_input:
                    self.findings.append(Finding(
                        rule_id="SCALA-PATH-TRAVERSAL",
                        category="Path Traversal",
                        title=f"Potential path traversal via {t.value} with dynamic path",
                        description=f"{t.value} is constructed with user-controlled input. "
                                    "Attackers can use '../' sequences to access arbitrary files.",
                        severity=Severity.HIGH.value,
                        confidence=Confidence.MEDIUM.value,
                        file_path=file_path,
                        line_number=t.line,
                        code_snippet=self._get_snippet(lines, t.line),
                        remediation="Validate and canonicalize paths. Reject paths containing '..' sequences.",
                        cwe_id="CWE-22",
                        owasp="A01:2021 - Broken Access Control",
                    ))

    # --- Deserialization ---
    def _check_deserialization(self, tokens: List[Token], lines: List[str], file_path: str, source: str):
        # Java serialization
        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER and t.value in ("ObjectInputStream", "readObject", "readUnshared"):
                self.findings.append(Finding(
                    rule_id="SCALA-DESERIALIZATION-JAVA",
                    category="Insecure Deserialization",
                    title=f"Java deserialization via {t.value}",
                    description=f"Java {t.value} deserializes objects from untrusted data. "
                                "This can lead to remote code execution via gadget chains.",
                    severity=Severity.CRITICAL.value,
                    confidence=Confidence.HIGH.value,
                    file_path=file_path,
                    line_number=t.line,
                    code_snippet=self._get_snippet(lines, t.line),
                    remediation="Avoid Java serialization. Use JSON with explicit type mapping. "
                                "If required, use ObjectInputFilter to restrict allowed classes.",
                    cwe_id="CWE-502",
                    owasp="A08:2021 - Software and Data Integrity Failures",
                ))

        # Kryo without registration
        if "Kryo" in source:
            has_registration = "setRegistrationRequired" in source or "register(" in source
            if not has_registration:
                for t in tokens:
                    if t.type == TokenType.IDENTIFIER and t.value == "Kryo":
                        self.findings.append(Finding(
                            rule_id="SCALA-DESERIALIZATION-KRYO",
                            category="Insecure Deserialization",
                            title="Kryo deserialization without class registration",
                            description="Kryo is used without setRegistrationRequired(true). "
                                        "This allows deserialization of arbitrary classes.",
                            severity=Severity.HIGH.value,
                            confidence=Confidence.MEDIUM.value,
                            file_path=file_path,
                            line_number=t.line,
                            code_snippet=self._get_snippet(lines, t.line),
                            remediation="Call kryo.setRegistrationRequired(true) and register only allowed classes.",
                            cwe_id="CWE-502",
                            owasp="A08:2021 - Software and Data Integrity Failures",
                        ))
                        break

    # --- XXE ---
    def _check_xxe(self, tokens: List[Token], lines: List[str], file_path: str, source: str):
        xml_parsers = ["SAXParser", "SAXParserFactory", "DocumentBuilder", "DocumentBuilderFactory",
                      "XMLReader", "XMLInputFactory", "TransformerFactory", "SchemaFactory",
                      "XML", "scala.xml.XML"]
        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER and t.value in xml_parsers:
                # Check for safe configuration
                context = tokens[i:min(len(tokens), i+30)]
                has_safe = any(
                    ct.value in ("disallow-doctype-decl", "FEATURE_SECURE_PROCESSING",
                                 "external-general-entities", "setFeature")
                    for ct in context if ct.type in (TokenType.IDENTIFIER, TokenType.STRING)
                )
                if not has_safe:
                    self.findings.append(Finding(
                        rule_id="SCALA-XXE",
                        category="XML External Entity (XXE)",
                        title=f"Potential XXE via {t.value} without safe configuration",
                        description=f"{t.value} parses XML without disabling external entity processing. "
                                    "This can lead to file disclosure, SSRF, and denial of service.",
                        severity=Severity.HIGH.value,
                        confidence=Confidence.MEDIUM.value,
                        file_path=file_path,
                        line_number=t.line,
                        code_snippet=self._get_snippet(lines, t.line),
                        remediation="Disable DTDs and external entities: setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)",
                        cwe_id="CWE-611",
                        owasp="A05:2021 - Security Misconfiguration",
                    ))

    # --- SSRF ---
    def _check_ssrf(self, tokens: List[Token], lines: List[str], file_path: str):
        http_clients = ["WS", "ws", "HttpClient", "Http", "sttp", "dispatch", "requests"]
        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER and t.value in http_clients:
                context = tokens[i:min(len(tokens), i+15)]
                has_url_methods = any(
                    ct.value in ("url", "get", "post", "put", "delete", "request")
                    for ct in context if ct.type == TokenType.IDENTIFIER
                )
                has_user_url = any(
                    ct.type == TokenType.IDENTIFIER and ct.value in ("url", "uri", "target", "endpoint", "host")
                    for ct in context
                )
                if has_url_methods and has_user_url:
                    self.findings.append(Finding(
                        rule_id="SCALA-SSRF",
                        category="Server-Side Request Forgery (SSRF)",
                        title=f"Potential SSRF via {t.value} with user-controlled URL",
                        description=f"{t.value} makes HTTP requests with a URL that may be user-controlled. "
                                    "Attackers can access internal services or cloud metadata endpoints.",
                        severity=Severity.HIGH.value,
                        confidence=Confidence.MEDIUM.value,
                        file_path=file_path,
                        line_number=t.line,
                        code_snippet=self._get_snippet(lines, t.line),
                        remediation="Validate URLs against an allowlist of permitted hosts. Block internal/private IP ranges.",
                        cwe_id="CWE-918",
                        owasp="A10:2021 - Server-Side Request Forgery",
                    ))

    # --- Hardcoded Secrets ---
    def _check_hardcoded_secrets(self, tokens: List[Token], lines: List[str], file_path: str):
        secret_patterns = {
            "password", "passwd", "pwd", "secret", "apikey", "api_key", "apiKey",
            "privatekey", "private_key", "privateKey", "token", "authToken",
            "auth_token", "accessKey", "access_key", "secretKey", "secret_key",
            "encryptionKey", "encryption_key", "clientSecret", "client_secret",
            "masterKey", "master_key", "dbPassword", "db_password",
        }

        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER:
                name_lower = t.value.lower()
                if any(s in name_lower for s in secret_patterns):
                    j = i + 1
                    while j < len(tokens) and tokens[j].type == TokenType.OPERATOR and tokens[j].value in (":", "="):
                        j += 1
                    if j < len(tokens) and tokens[j].type in (TokenType.STRING, TokenType.MULTILINE_STRING):
                        val = tokens[j].value.strip('"')
                        if len(val) > 3 and val.lower() not in ("null", "none", "", "todo", "changeme", "placeholder", "test", "xxx"):
                            self.findings.append(Finding(
                                rule_id="SCALA-HARDCODED-SECRET",
                                category="Hardcoded Secrets",
                                title=f"Hardcoded secret in '{t.value}'",
                                description=f"Variable '{t.value}' contains a hardcoded secret. "
                                            "Secrets in source code can be extracted from compiled JARs.",
                                severity=Severity.CRITICAL.value,
                                confidence=Confidence.HIGH.value,
                                file_path=file_path,
                                line_number=t.line,
                                code_snippet=self._get_snippet(lines, t.line),
                                remediation="Use environment variables, typesafe-config, or a vault service for secrets.",
                                cwe_id="CWE-798",
                                owasp="A07:2021 - Identification and Authentication Failures",
                            ))

    # --- Weak Crypto ---
    def _check_weak_crypto(self, tokens: List[Token], lines: List[str], file_path: str):
        weak_algorithms = {
            "MD5": ("MD5 is cryptographically broken", "SHA-256"),
            "SHA1": ("SHA-1 has known collisions", "SHA-256"),
            "DES": ("DES uses 56-bit keys", "AES-256"),
            "DESede": ("Triple DES is deprecated", "AES-256"),
            "RC4": ("RC4 has multiple vulnerabilities", "AES-256-GCM"),
            "RC2": ("RC2 is weak", "AES-256"),
            "Blowfish": ("Blowfish has a 64-bit block size", "AES-256"),
        }

        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER and t.value == "getInstance":
                # Check the algorithm string
                context = tokens[i:min(len(tokens), i+10)]
                for ct in context:
                    if ct.type == TokenType.STRING:
                        val = ct.value.strip('"')
                        for algo, (reason, alt) in weak_algorithms.items():
                            if algo in val:
                                self.findings.append(Finding(
                                    rule_id=f"SCALA-WEAK-CRYPTO-{algo.upper()}",
                                    category="Weak Cryptography",
                                    title=f"Weak cryptographic algorithm: {algo}",
                                    description=f"Algorithm '{val}' uses {algo}. {reason}.",
                                    severity=Severity.HIGH.value,
                                    confidence=Confidence.HIGH.value,
                                    file_path=file_path,
                                    line_number=ct.line,
                                    code_snippet=self._get_snippet(lines, ct.line),
                                    remediation=f"Use {alt} instead. For example: Cipher.getInstance(\"AES/GCM/NoPadding\")",
                                    cwe_id="CWE-327",
                                    owasp="A02:2021 - Cryptographic Failures",
                                ))
                                break

        # ECB mode
        for t in tokens:
            if t.type == TokenType.STRING and "ECB" in t.value.strip('"'):
                self.findings.append(Finding(
                    rule_id="SCALA-WEAK-CRYPTO-ECB",
                    category="Weak Cryptography",
                    title="ECB mode encryption",
                    description="ECB mode encrypts identical blocks identically, leaking patterns.",
                    severity=Severity.HIGH.value,
                    confidence=Confidence.HIGH.value,
                    file_path=file_path,
                    line_number=t.line,
                    code_snippet=self._get_snippet(lines, t.line),
                    remediation="Use GCM or CBC mode with random IV.",
                    cwe_id="CWE-327",
                    owasp="A02:2021 - Cryptographic Failures",
                ))

    # --- Insecure Random ---
    def _check_insecure_random(self, tokens: List[Token], lines: List[str], file_path: str):
        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER and t.value == "Random":
                # Check it's scala.util.Random not java.security.SecureRandom
                prev = self._peek_token(tokens, i - 1)
                if prev and prev.value == "SecureRandom":
                    continue
                next_t = self._peek_token(tokens, i + 1)
                if next_t and next_t.value in ("(", "."):
                    self.findings.append(Finding(
                        rule_id="SCALA-INSECURE-RANDOM",
                        category="Insecure Random",
                        title="Insecure random number generator: scala.util.Random",
                        description="scala.util.Random uses a PRNG that is predictable. "
                                    "For security-sensitive operations, use java.security.SecureRandom.",
                        severity=Severity.MEDIUM.value,
                        confidence=Confidence.HIGH.value,
                        file_path=file_path,
                        line_number=t.line,
                        code_snippet=self._get_snippet(lines, t.line),
                        remediation="Use java.security.SecureRandom for tokens, keys, nonces, and session IDs.",
                        cwe_id="CWE-338",
                        owasp="A02:2021 - Cryptographic Failures",
                    ))

    # --- Play Framework ---
    def _check_play_framework(self, tokens: List[Token], lines: List[str], file_path: str, source: str):
        # CORS misconfiguration
        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER and t.value in ("allowedOrigins", "allowOrigins"):
                context = tokens[i:min(len(tokens), i+10)]
                for ct in context:
                    if ct.type == TokenType.STRING and ct.value.strip('"') == "*":
                        self.findings.append(Finding(
                            rule_id="SCALA-PLAY-CORS",
                            category="Play Framework Security",
                            title="CORS allows all origins",
                            description="CORS is configured to allow all origins (*). This enables cross-origin attacks.",
                            severity=Severity.MEDIUM.value,
                            confidence=Confidence.HIGH.value,
                            file_path=file_path,
                            line_number=t.line,
                            code_snippet=self._get_snippet(lines, t.line),
                            remediation="Restrict allowed origins to specific trusted domains.",
                            cwe_id="CWE-942",
                            owasp="A05:2021 - Security Misconfiguration",
                        ))

        # CSRF disabled
        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER and t.value in ("nocheck", "CSRFCheck"):
                if t.value == "nocheck":
                    self.findings.append(Finding(
                        rule_id="SCALA-PLAY-CSRF-DISABLED",
                        category="Play Framework Security",
                        title="CSRF protection disabled",
                        description="CSRF check is explicitly disabled, making the application vulnerable to CSRF attacks.",
                        severity=Severity.HIGH.value,
                        confidence=Confidence.HIGH.value,
                        file_path=file_path,
                        line_number=t.line,
                        code_snippet=self._get_snippet(lines, t.line),
                        remediation="Enable CSRF protection. Use Play's built-in CSRF filter.",
                        cwe_id="CWE-352",
                        owasp="A01:2021 - Broken Access Control",
                    ))

        # Session security
        for t in tokens:
            if t.type == TokenType.STRING:
                val = t.value.strip('"')
                if val == "play.http.session.secure" or val == "session.secure":
                    context_idx = tokens.index(t)
                    surrounding = tokens[context_idx:min(len(tokens), context_idx+5)]
                    has_false = any(ct.value == "false" for ct in surrounding)
                    if has_false:
                        self.findings.append(Finding(
                            rule_id="SCALA-PLAY-SESSION-INSECURE",
                            category="Play Framework Security",
                            title="Play session cookie not marked secure",
                            description="Session cookie is not marked as secure, allowing transmission over HTTP.",
                            severity=Severity.MEDIUM.value,
                            confidence=Confidence.HIGH.value,
                            file_path=file_path,
                            line_number=t.line,
                            code_snippet=self._get_snippet(lines, t.line),
                            remediation="Set play.http.session.secure = true in production.",
                            cwe_id="CWE-614",
                            owasp="A05:2021 - Security Misconfiguration",
                        ))

    # --- Akka-Specific ---
    def _check_akka_specific(self, tokens: List[Token], lines: List[str], file_path: str, source: str):
        # Unvalidated ActorRef
        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER and t.value in ("actorSelection", "ActorSelection"):
                context = tokens[i:min(len(tokens), i+15)]
                has_dynamic = any(
                    ct.type in (TokenType.STRING_INTERPOLATION,) or
                    (ct.type == TokenType.IDENTIFIER and ct.value in ("path", "address", "input", "name"))
                    for ct in context
                )
                if has_dynamic:
                    self.findings.append(Finding(
                        rule_id="SCALA-AKKA-ACTOR-SELECTION",
                        category="Akka Security",
                        title="Dynamic ActorSelection with user input",
                        description="ActorSelection with dynamic path may allow accessing arbitrary actors, "
                                    "potentially bypassing access controls.",
                        severity=Severity.MEDIUM.value,
                        confidence=Confidence.MEDIUM.value,
                        file_path=file_path,
                        line_number=t.line,
                        code_snippet=self._get_snippet(lines, t.line),
                        remediation="Validate actor paths against an allowlist. Use ActorRef directly when possible.",
                        cwe_id="CWE-20",
                        owasp="A01:2021 - Broken Access Control",
                    ))

        # Akka remote without authentication
        if "akka.remote" in source:
            has_tls = "ssl" in source.lower() or "tls" in source.lower() or "require-mutual-authentication" in source
            if not has_tls:
                for t in tokens:
                    if t.type == TokenType.STRING and "akka.remote" in t.value:
                        self.findings.append(Finding(
                            rule_id="SCALA-AKKA-REMOTE-NO-AUTH",
                            category="Akka Security",
                            title="Akka Remote without TLS/authentication",
                            description="Akka Remote is configured without TLS or mutual authentication. "
                                        "Unauthenticated remote actors can execute arbitrary code.",
                            severity=Severity.CRITICAL.value,
                            confidence=Confidence.MEDIUM.value,
                            file_path=file_path,
                            line_number=t.line,
                            code_snippet=self._get_snippet(lines, t.line),
                            remediation="Enable Akka Remote TLS with mutual authentication (Artery TLS).",
                            cwe_id="CWE-306",
                            owasp="A07:2021 - Identification and Authentication Failures",
                        ))
                        break

    # --- Spark-Specific ---
    def _check_spark_specific(self, tokens: List[Token], lines: List[str], file_path: str):
        # Already covered Spark SQL in SQL injection section
        # Check for Spark UDF with serialized objects
        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER and t.value == "udf":
                context = tokens[i:min(len(tokens), i+20)]
                has_deserialization = any(
                    ct.value in ("ObjectInputStream", "readObject", "fromBytes")
                    for ct in context if ct.type == TokenType.IDENTIFIER
                )
                if has_deserialization:
                    self.findings.append(Finding(
                        rule_id="SCALA-SPARK-UDF-DESER",
                        category="Spark Security",
                        title="Spark UDF with deserialization",
                        description="A Spark UDF performs deserialization which can lead to RCE if untrusted data is processed.",
                        severity=Severity.HIGH.value,
                        confidence=Confidence.MEDIUM.value,
                        file_path=file_path,
                        line_number=t.line,
                        code_snippet=self._get_snippet(lines, t.line),
                        remediation="Avoid deserializing untrusted data in Spark UDFs. Use safe data formats.",
                        cwe_id="CWE-502",
                        owasp="A08:2021 - Software and Data Integrity Failures",
                    ))

    # --- Pattern Matching Exhaustiveness ---
    def _check_pattern_matching(self, tokens: List[Token], lines: List[str], file_path: str, ast: ASTNode):
        # Check match blocks without a default/wildcard case
        for i, t in enumerate(tokens):
            if t.type == TokenType.KEYWORD and t.value == "match":
                # Find the match block
                j = i + 1
                while j < len(tokens) and not (tokens[j].type == TokenType.PUNCTUATION and tokens[j].value == "{"):
                    j += 1
                if j >= len(tokens):
                    continue
                # Scan the match block for case _
                depth = 1
                k = j + 1
                has_wildcard = False
                while k < len(tokens) and depth > 0:
                    if tokens[k].type == TokenType.PUNCTUATION and tokens[k].value == "{":
                        depth += 1
                    elif tokens[k].type == TokenType.PUNCTUATION and tokens[k].value == "}":
                        depth -= 1
                    if depth == 1 and tokens[k].type == TokenType.KEYWORD and tokens[k].value == "case":
                        # Check if next meaningful token is _
                        m = k + 1
                        while m < len(tokens) and tokens[m].type in (TokenType.WHITESPACE, TokenType.NEWLINE):
                            m += 1
                        if m < len(tokens) and tokens[m].type == TokenType.IDENTIFIER and tokens[m].value == "_":
                            has_wildcard = True
                    k += 1
                if not has_wildcard:
                    self.findings.append(Finding(
                        rule_id="SCALA-PATTERN-MATCH-EXHAUSTIVE",
                        category="Pattern Matching",
                        title="Non-exhaustive pattern match (no wildcard case)",
                        description="A match expression does not have a wildcard (case _ =>) clause. "
                                    "This may throw MatchError at runtime if an unexpected value is encountered.",
                        severity=Severity.MEDIUM.value,
                        confidence=Confidence.LOW.value,
                        file_path=file_path,
                        line_number=t.line,
                        code_snippet=self._get_snippet(lines, t.line),
                        remediation="Add a wildcard case (case _ =>) or use sealed traits for exhaustiveness checking.",
                        cwe_id="CWE-754",
                        owasp="A04:2021 - Insecure Design",
                    ))

    # --- Mutable Shared State ---
    def _check_mutable_shared_state(self, tokens: List[Token], lines: List[str], file_path: str, ast: ASTNode):
        # var inside Actor
        in_actor = False
        actor_start = -1
        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER and t.value in ("Actor", "AbstractActor", "ActorLogging"):
                in_actor = True
                actor_start = i
            if in_actor and t.type == TokenType.KEYWORD and t.value == "var":
                next_t = self._peek_token(tokens, i + 1)
                var_name = next_t.value if next_t else "unknown"
                self.findings.append(Finding(
                    rule_id="SCALA-MUTABLE-ACTOR-STATE",
                    category="Mutable Shared State",
                    title=f"Mutable var '{var_name}' inside Actor",
                    description=f"Variable '{var_name}' declared as var inside an Actor. "
                                "While Akka actors process messages sequentially, mutable state can "
                                "cause issues with actor restarts and makes code harder to reason about.",
                    severity=Severity.LOW.value,
                    confidence=Confidence.MEDIUM.value,
                    file_path=file_path,
                    line_number=t.line,
                    code_snippet=self._get_snippet(lines, t.line),
                    remediation="Use context.become() with immutable state, or use Akka Typed.",
                    cwe_id="CWE-362",
                    owasp="A04:2021 - Insecure Design",
                ))
            if in_actor and t.type == TokenType.PUNCTUATION and t.value == "}":
                # Rough end-of-actor heuristic
                pass

    # --- Resource Leaks ---
    def _check_resource_leaks(self, tokens: List[Token], lines: List[str], file_path: str):
        resource_creators = ["Source", "BufferedSource", "InputStream", "OutputStream",
                           "FileInputStream", "FileOutputStream", "Connection",
                           "BufferedReader", "PrintWriter"]
        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER and t.value in resource_creators:
                # Check if wrapped in Using, try-finally, or loan pattern
                context = tokens[max(0, i-10):min(len(tokens), i+30)]
                has_safe = any(
                    ct.value in ("Using", "using", "finally", "close", "managed", "bracket", "resource", "tryWith")
                    for ct in context if ct.type == TokenType.IDENTIFIER
                )
                if not has_safe:
                    self.findings.append(Finding(
                        rule_id="SCALA-RESOURCE-LEAK",
                        category="Resource Leaks",
                        title=f"Potential resource leak: {t.value}",
                        description=f"{t.value} is opened without Using/try-finally for cleanup. "
                                    "This can lead to resource exhaustion (file handles, connections).",
                        severity=Severity.MEDIUM.value,
                        confidence=Confidence.LOW.value,
                        file_path=file_path,
                        line_number=t.line,
                        code_snippet=self._get_snippet(lines, t.line),
                        remediation="Use scala.util.Using, try-finally, or cats-effect Resource for automatic cleanup.",
                        cwe_id="CWE-404",
                        owasp="A04:2021 - Insecure Design",
                    ))

    # --- Implicit Conversion Security ---
    def _check_implicit_security(self, tokens: List[Token], lines: List[str], file_path: str):
        for i, t in enumerate(tokens):
            if t.type == TokenType.KEYWORD and t.value == "implicit":
                next_t = self._peek_token(tokens, i + 1)
                if next_t and next_t.type == TokenType.KEYWORD and next_t.value == "def":
                    # Get the function name
                    name_t = self._peek_token(tokens, i + 2)
                    name = name_t.value if name_t else "unknown"
                    # Check if it's a security-relevant conversion
                    context = tokens[i:min(len(tokens), i+20)]
                    has_string = any(ct.value == "String" for ct in context if ct.type == TokenType.KEYWORD)
                    has_sensitive = any(
                        ct.value.lower() in ("sql", "html", "url", "path", "command")
                        for ct in context if ct.type == TokenType.IDENTIFIER
                    )
                    if has_string and has_sensitive:
                        self.findings.append(Finding(
                            rule_id="SCALA-IMPLICIT-CONVERSION-SECURITY",
                            category="Implicit Conversion Security",
                            title=f"Security-sensitive implicit conversion: {name}",
                            description=f"Implicit conversion '{name}' converts between String and a security-sensitive type. "
                                        "Implicit conversions can mask type safety boundaries that prevent injection attacks.",
                            severity=Severity.MEDIUM.value,
                            confidence=Confidence.MEDIUM.value,
                            file_path=file_path,
                            line_number=t.line,
                            code_snippet=self._get_snippet(lines, t.line),
                            remediation="Use explicit conversions for security-sensitive types. Consider using opaque types.",
                            cwe_id="CWE-704",
                            owasp="A04:2021 - Insecure Design",
                        ))

    # --- Unsafe Type Casting ---
    def _check_unsafe_cast(self, tokens: List[Token], lines: List[str], file_path: str):
        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER and t.value == "asInstanceOf":
                self.findings.append(Finding(
                    rule_id="SCALA-UNSAFE-CAST",
                    category="Unsafe Type Casting",
                    title="Unsafe type cast with asInstanceOf",
                    description="asInstanceOf performs an unchecked type cast that throws ClassCastException at runtime "
                                "if the cast fails. This can lead to unexpected behavior or crashes.",
                    severity=Severity.LOW.value,
                    confidence=Confidence.HIGH.value,
                    file_path=file_path,
                    line_number=t.line,
                    code_snippet=self._get_snippet(lines, t.line),
                    remediation="Use pattern matching with match/case, or isInstanceOf check before casting.",
                    cwe_id="CWE-704",
                    owasp="A04:2021 - Insecure Design",
                ))

    # --- Information Disclosure ---
    def _check_info_disclosure(self, tokens: List[Token], lines: List[str], file_path: str, comments: List[Token]):
        sensitive_terms = {"password", "secret", "token", "key", "ssn", "credit", "pin", "auth"}

        # println/print with sensitive data
        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER and t.value in ("println", "print", "printf"):
                context = tokens[i:min(len(tokens), i+20)]
                for ct in context:
                    if ct.type == TokenType.IDENTIFIER and ct.value.lower() in sensitive_terms:
                        self.findings.append(Finding(
                            rule_id="SCALA-INFO-DISCLOSURE-PRINT",
                            category="Information Disclosure",
                            title=f"{t.value} may expose sensitive data: '{ct.value}'",
                            description=f"{t.value} outputs to stdout/stderr. Sensitive variable '{ct.value}' "
                                        "may be exposed in logs or console output.",
                            severity=Severity.MEDIUM.value,
                            confidence=Confidence.MEDIUM.value,
                            file_path=file_path,
                            line_number=t.line,
                            code_snippet=self._get_snippet(lines, t.line),
                            remediation="Remove print statements with sensitive data. Use structured logging with sensitive data masking.",
                            cwe_id="CWE-532",
                            owasp="A09:2021 - Security Logging and Monitoring Failures",
                        ))
                        break

        # Stack traces in HTTP responses
        for i, t in enumerate(tokens):
            if t.type == TokenType.IDENTIFIER and t.value in ("getMessage", "getStackTrace", "printStackTrace", "stackTrace"):
                context = tokens[max(0, i-10):min(len(tokens), i+10)]
                has_response = any(
                    ct.value in ("Ok", "BadRequest", "InternalServerError", "Result", "Response", "Json")
                    for ct in context if ct.type == TokenType.IDENTIFIER
                )
                if has_response:
                    self.findings.append(Finding(
                        rule_id="SCALA-INFO-DISCLOSURE-STACKTRACE",
                        category="Information Disclosure",
                        title="Stack trace or error message exposed in HTTP response",
                        description="Exception details are returned in HTTP responses, exposing internal implementation details.",
                        severity=Severity.MEDIUM.value,
                        confidence=Confidence.MEDIUM.value,
                        file_path=file_path,
                        line_number=t.line,
                        code_snippet=self._get_snippet(lines, t.line),
                        remediation="Return generic error messages. Log detailed errors server-side only.",
                        cwe_id="CWE-209",
                        owasp="A04:2021 - Insecure Design",
                    ))


# ============================================================================
# PART 4: SCANNER
# ============================================================================

class ScalaScanner:
    """Main scanner class."""

    def __init__(self):
        self.analyzer = ScalaAnalyzer()

    def scan(self, files: Dict[str, str], scan_id: str = "") -> ScanResponse:
        if not scan_id:
            scan_id = str(uuid.uuid4())

        start_time = time.time()
        all_findings: List[Finding] = []
        file_count = 0

        for file_path, content in files.items():
            if not file_path.endswith((".scala", ".sc")):
                continue
            file_count += 1
            try:
                tokenizer = ScalaTokenizer(content)
                tokens = tokenizer.tokenize()
                parser = ScalaParser(tokens)
                ast = parser.parse()
                findings = self.analyzer.analyze(tokens, ast, file_path, content)
                all_findings.extend(findings)
            except Exception as e:
                log.error(f"Error scanning {file_path}: {e}", exc_info=True)

        summary: Dict[str, int] = {}
        for f in all_findings:
            summary[f.category] = summary.get(f.category, 0) + 1

        duration_ms = int((time.time() - start_time) * 1000)

        return ScanResponse(
            scanId=scan_id,
            totalFiles=file_count,
            totalFindings=len(all_findings),
            findings=[asdict(f) for f in all_findings],
            summary=summary,
        )


# ============================================================================
# PART 5: FASTAPI APPLICATION
# ============================================================================

app = FastAPI(
    title="Offensive360 Scala SAST Scanner",
    description="Token-based static analysis for Scala (Play, Akka, Spark)",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner = ScalaScanner()


@app.get("/health")
async def health():
    categories = [
        "SQL Injection", "Command Injection", "Code Injection",
        "Cross-Site Scripting (XSS)", "Path Traversal",
        "Insecure Deserialization", "XML External Entity (XXE)",
        "Server-Side Request Forgery (SSRF)", "Hardcoded Secrets",
        "Weak Cryptography", "Insecure Random",
        "Play Framework Security", "Akka Security", "Spark Security",
        "Pattern Matching", "Mutable Shared State", "Resource Leaks",
        "Implicit Conversion Security", "Unsafe Type Casting",
        "Information Disclosure",
    ]
    return {
        "status": "healthy",
        "scanner": "Scala SAST Scanner",
        "version": "1.0.0",
        "engine": "token-based AST",
        "vulnerability_categories": len(categories),
        "total_rules": 42,
        "categories": categories,
    }


@app.post("/scan", response_model=ScanResponse)
async def scan_files(request: ScanRequest):
    if not request.files:
        raise HTTPException(status_code=400, detail="No files provided")
    log.info(f"Scan request: {len(request.files)} files, scanId={request.scanId}")
    try:
        result = scanner.scan(request.files, request.scanId)
        log.info(f"Scan complete: {result.totalFindings} findings in {result.totalFiles} files")
        return result
    except Exception as e:
        log.error(f"Scan failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    port = int(os.environ.get("SCANNER_PORT", "9014"))
    log.info(f"Starting Scala SAST Scanner on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
