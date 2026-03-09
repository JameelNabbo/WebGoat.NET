from __future__ import annotations
"""
Kotlin SAST Scanner - Production-grade static analysis engine.
FastAPI service on port 9012 with custom tokenizer, parser, data flow, and 35+ vuln detectors.
"""

import asyncio
import enum
import hashlib
import logging
import re
import signal
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set, Any

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("kotlin-scanner")

# ---------------------------------------------------------------------------
# 1. TOKENIZER
# ---------------------------------------------------------------------------

class TT(enum.Enum):
    """Token types for Kotlin."""
    KEYWORD = "KEYWORD"
    IDENT = "IDENT"
    INT_LIT = "INT_LIT"
    FLOAT_LIT = "FLOAT_LIT"
    STRING_LIT = "STRING_LIT"
    RAW_STRING_LIT = "RAW_STRING_LIT"
    CHAR_LIT = "CHAR_LIT"
    STRING_TEMPLATE = "STRING_TEMPLATE"
    OP = "OP"
    PUNCT = "PUNCT"
    ANNOTATION = "ANNOTATION"
    COMMENT = "COMMENT"
    NEWLINE = "NEWLINE"
    EOF = "EOF"


KOTLIN_KEYWORDS = frozenset([
    # Hard keywords
    "as", "break", "class", "continue", "do", "else", "false", "for", "fun",
    "if", "in", "interface", "is", "null", "object", "package", "return",
    "super", "this", "throw", "true", "try", "typealias", "typeof", "val",
    "var", "when", "while",
    # Soft keywords (context-dependent but important for analysis)
    "by", "catch", "constructor", "delegate", "dynamic", "field", "file",
    "finally", "get", "import", "init", "param", "property", "receiver",
    "set", "setparam", "where",
    # Modifier keywords
    "abstract", "actual", "annotation", "companion", "const", "crossinline",
    "data", "enum", "expect", "external", "final", "infix", "inline",
    "inner", "internal", "lateinit", "noinline", "open", "operator", "out",
    "override", "private", "protected", "public", "reified", "sealed",
    "suspend", "tailrec", "vararg",
])


@dataclass
class Token:
    tt: TT
    val: str
    line: int
    col: int


def tokenize(source: str) -> List[Token]:
    """Tokenize Kotlin source into a list of Token objects."""
    tokens: List[Token] = []
    i = 0
    n = len(source)
    line = 1
    col = 1

    while i < n:
        ch = source[i]

        # Whitespace (not newline)
        if ch in " \t\r":
            col += 4 if ch == "\t" else 1
            i += 1
            continue

        # Newline
        if ch == "\n":
            tokens.append(Token(TT.NEWLINE, "\n", line, col))
            line += 1
            col = 1
            i += 1
            continue

        # Line comment
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            start = i
            while i < n and source[i] != "\n":
                i += 1
            tokens.append(Token(TT.COMMENT, source[start:i], line, col))
            continue

        # Block comment (nested allowed in Kotlin)
        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            start = i
            start_line = line
            start_col = col
            i += 2
            col += 2
            depth = 1
            while i < n and depth > 0:
                if source[i] == "/" and i + 1 < n and source[i + 1] == "*":
                    depth += 1
                    i += 2
                    col += 2
                elif source[i] == "*" and i + 1 < n and source[i + 1] == "/":
                    depth -= 1
                    i += 2
                    col += 2
                elif source[i] == "\n":
                    line += 1
                    col = 1
                    i += 1
                else:
                    col += 1
                    i += 1
            tokens.append(Token(TT.COMMENT, source[start:i], start_line, start_col))
            continue

        # Raw string literal (triple-quoted)
        if ch == '"' and i + 2 < n and source[i + 1] == '"' and source[i + 2] == '"':
            start = i
            start_line = line
            start_col = col
            i += 3
            col += 3
            while i < n:
                if source[i] == '"' and i + 2 < n and source[i + 1] == '"' and source[i + 2] == '"':
                    # Check for more quotes (e.g. """" is still closing)
                    i += 3
                    col += 3
                    while i < n and source[i] == '"':
                        i += 1
                        col += 1
                    break
                if source[i] == "\n":
                    line += 1
                    col = 1
                else:
                    col += 1
                i += 1
            raw = source[start:i]
            # Check for string templates
            if "$" in raw:
                tokens.append(Token(TT.STRING_TEMPLATE, raw, start_line, start_col))
            else:
                tokens.append(Token(TT.RAW_STRING_LIT, raw, start_line, start_col))
            continue

        # Regular string literal
        if ch == '"':
            start = i
            start_col = col
            has_template = False
            i += 1
            col += 1
            while i < n and source[i] != '"':
                if source[i] == "\\":
                    i += 2
                    col += 2
                    continue
                if source[i] == "$":
                    has_template = True
                if source[i] == "\n":
                    line += 1
                    col = 1
                    i += 1
                    continue
                i += 1
                col += 1
            if i < n:
                i += 1
                col += 1
            val = source[start:i]
            tt = TT.STRING_TEMPLATE if has_template else TT.STRING_LIT
            tokens.append(Token(tt, val, line, start_col))
            continue

        # Character literal
        if ch == "'":
            start = i
            start_col = col
            i += 1
            col += 1
            while i < n and source[i] != "'":
                if source[i] == "\\":
                    i += 2
                    col += 2
                    continue
                i += 1
                col += 1
            if i < n:
                i += 1
                col += 1
            tokens.append(Token(TT.CHAR_LIT, source[start:i], line, start_col))
            continue

        # Annotation (@Something)
        if ch == "@" and i + 1 < n and (source[i + 1].isalpha() or source[i + 1] == "_"):
            start = i
            start_col = col
            i += 1
            col += 1
            while i < n and (source[i].isalnum() or source[i] in "_.:"):
                i += 1
                col += 1
            tokens.append(Token(TT.ANNOTATION, source[start:i], line, start_col))
            continue

        # Numbers
        if ch.isdigit() or (ch == "." and i + 1 < n and source[i + 1].isdigit()):
            start = i
            start_col = col
            is_float = ch == "."
            # Hex
            if ch == "0" and i + 1 < n and source[i + 1] in "xX":
                i += 2
                col += 2
                while i < n and (source[i] in "0123456789abcdefABCDEF_"):
                    i += 1
                    col += 1
            # Binary
            elif ch == "0" and i + 1 < n and source[i + 1] in "bB":
                i += 2
                col += 2
                while i < n and source[i] in "01_":
                    i += 1
                    col += 1
            else:
                while i < n and (source[i].isdigit() or source[i] == "_"):
                    i += 1
                    col += 1
                if i < n and source[i] == ".":
                    # Check not range operator (..)
                    if i + 1 < n and source[i + 1] != ".":
                        is_float = True
                        i += 1
                        col += 1
                        while i < n and (source[i].isdigit() or source[i] == "_"):
                            i += 1
                            col += 1
                if i < n and source[i] in "eE":
                    is_float = True
                    i += 1
                    col += 1
                    if i < n and source[i] in "+-":
                        i += 1
                        col += 1
                    while i < n and source[i].isdigit():
                        i += 1
                        col += 1
            # Suffixes (L, f, F, u, U)
            if i < n and source[i] in "lLfFuU":
                if source[i] in "fF":
                    is_float = True
                i += 1
                col += 1
            tt = TT.FLOAT_LIT if is_float else TT.INT_LIT
            tokens.append(Token(tt, source[start:i], line, start_col))
            continue

        # Identifiers / keywords
        if ch.isalpha() or ch == "_" or ch == '`':
            start = i
            start_col = col
            if ch == '`':
                # Backtick-quoted identifier
                i += 1
                col += 1
                while i < n and source[i] != '`':
                    i += 1
                    col += 1
                if i < n:
                    i += 1
                    col += 1
                tokens.append(Token(TT.IDENT, source[start:i], line, start_col))
            else:
                while i < n and (source[i].isalnum() or source[i] == "_"):
                    i += 1
                    col += 1
                word = source[start:i]
                tt = TT.KEYWORD if word in KOTLIN_KEYWORDS else TT.IDENT
                tokens.append(Token(tt, word, line, start_col))
            continue

        # Multi-char operators (Kotlin-specific included)
        four = source[i:i + 4] if i + 3 < n else ""
        three = source[i:i + 3] if i + 2 < n else ""
        two = source[i:i + 2] if i + 1 < n else ""

        if three in ("===", "!==", "...", "!in", "!is", "shr", "shl", "ushr"):
            tokens.append(Token(TT.OP, three, line, col))
            i += 3
            col += 3
            continue
        if two in ("?.", "?:", "!!", "::", "->", "..", "+=", "-=", "*=", "/=",
                    "%=", "&&", "||", "==", "!=", "<=", ">=", "++", "--",
                    "<<", ">>", "in", "as"):
            tokens.append(Token(TT.OP, two, line, col))
            i += 2
            col += 2
            continue

        # Single-char ops / punctuation
        if ch in "+-*/%&|^~!<>=?.:":
            tokens.append(Token(TT.OP, ch, line, col))
            i += 1
            col += 1
            continue
        if ch in "(){}[];,":
            tokens.append(Token(TT.PUNCT, ch, line, col))
            i += 1
            col += 1
            continue

        # Skip unknown
        i += 1
        col += 1

    tokens.append(Token(TT.EOF, "", line, col))
    return tokens


# ---------------------------------------------------------------------------
# 2. AST NODES
# ---------------------------------------------------------------------------

@dataclass
class ASTNode:
    kind: str
    line: int = 0
    col: int = 0
    children: List["ASTNode"] = field(default_factory=list)
    attrs: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 3. PARSER (best-effort Kotlin parser for SAST analysis)
# ---------------------------------------------------------------------------

class Parser:
    """
    Best-effort Kotlin parser that extracts structure for SAST analysis:
    functions, classes, data classes, object decls, companion objects,
    variable decls, calls, assignments, lambdas, when expressions, etc.
    """

    def __init__(self, tokens: List[Token]):
        self.tokens = [t for t in tokens if t.tt not in (TT.COMMENT, TT.NEWLINE)]
        self.pos = 0
        self.functions: List[ASTNode] = []
        self.classes: List[ASTNode] = []
        self.objects: List[ASTNode] = []
        self.data_classes: List[ASTNode] = []
        self.companion_objects: List[ASTNode] = []
        self.calls: List[ASTNode] = []
        self.assignments: List[ASTNode] = []
        self.var_decls: List[ASTNode] = []
        self.imports: List[ASTNode] = []
        self.string_literals: List[Token] = []
        self.string_templates: List[Token] = []
        self.annotations: List[Token] = []
        self.when_exprs: List[ASTNode] = []
        self.lambdas: List[ASTNode] = []
        self.null_assertions: List[Token] = []
        self.safe_calls: List[Token] = []
        self.elvis_ops: List[Token] = []
        self.all_tokens = self.tokens

    def cur(self) -> Token:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return Token(TT.EOF, "", 0, 0)

    def peek(self, offset: int = 1) -> Token:
        idx = self.pos + offset
        if idx < len(self.tokens):
            return self.tokens[idx]
        return Token(TT.EOF, "", 0, 0)

    def advance(self) -> Token:
        t = self.cur()
        self.pos += 1
        return t

    def match_val(self, val: str) -> bool:
        if self.cur().val == val:
            self.advance()
            return True
        return False

    def skip_to_matching_brace(self) -> List[Token]:
        depth = 1
        inner: List[Token] = []
        self.advance()  # skip {
        while self.cur().tt != TT.EOF and depth > 0:
            if self.cur().val == "{":
                depth += 1
            elif self.cur().val == "}":
                depth -= 1
                if depth == 0:
                    self.advance()
                    return inner
            inner.append(self.cur())
            self.advance()
        return inner

    def skip_to_matching_paren(self) -> List[Token]:
        depth = 1
        self.advance()  # skip (
        inner: List[Token] = []
        while self.cur().tt != TT.EOF and depth > 0:
            if self.cur().val == "(":
                depth += 1
            elif self.cur().val == ")":
                depth -= 1
                if depth == 0:
                    self.advance()
                    return inner
            inner.append(self.cur())
            self.advance()
        return inner

    def skip_to_matching_bracket(self) -> List[Token]:
        depth = 1
        self.advance()  # skip [
        inner: List[Token] = []
        while self.cur().tt != TT.EOF and depth > 0:
            if self.cur().val == "[":
                depth += 1
            elif self.cur().val == "]":
                depth -= 1
                if depth == 0:
                    self.advance()
                    return inner
            inner.append(self.cur())
            self.advance()
        return inner

    def parse(self):
        """Main parse loop."""
        while self.cur().tt != TT.EOF:
            self._parse_top_level()

        # Collect string literals and templates from all tokens
        for t in self.all_tokens:
            if t.tt == TT.STRING_LIT:
                self.string_literals.append(t)
            elif t.tt == TT.RAW_STRING_LIT:
                self.string_literals.append(t)
            elif t.tt == TT.STRING_TEMPLATE:
                self.string_templates.append(t)
            elif t.tt == TT.ANNOTATION:
                self.annotations.append(t)
            elif t.tt == TT.OP and t.val == "!!":
                self.null_assertions.append(t)
            elif t.tt == TT.OP and t.val == "?.":
                self.safe_calls.append(t)
            elif t.tt == TT.OP and t.val == "?:":
                self.elvis_ops.append(t)

    def _parse_top_level(self):
        t = self.cur()

        # Package
        if t.val == "package":
            self._skip_statement()
            return

        # Import
        if t.val == "import":
            self.advance()
            parts = []
            while self.cur().tt != TT.EOF and self.cur().val not in (";", "\n") and self.cur().tt != TT.KEYWORD:
                parts.append(self.cur().val)
                self.advance()
            if self.cur().val == ";":
                self.advance()
            self.imports.append(ASTNode("import", t.line, t.col,
                                        attrs={"path": "".join(parts)}))
            return

        # Skip annotations
        if t.tt == TT.ANNOTATION:
            self.advance()
            return

        # Modifiers
        modifiers = []
        while self.cur().val in ("public", "private", "protected", "internal",
                                  "open", "abstract", "final", "sealed",
                                  "override", "inline", "suspend", "tailrec",
                                  "external", "actual", "expect", "const",
                                  "lateinit", "inner", "infix", "operator",
                                  "crossinline", "noinline", "reified", "vararg",
                                  "annotation"):
            modifiers.append(self.advance().val)

        # Data class
        if self.cur().val == "data" and self.peek().val == "class":
            self.advance()  # skip data
            self._parse_class(modifiers, is_data=True)
            return

        # Enum class
        if self.cur().val == "enum" and self.peek().val == "class":
            self.advance()  # skip enum
            self._parse_class(modifiers, is_enum=True)
            return

        # Class / interface
        if self.cur().val in ("class", "interface"):
            self._parse_class(modifiers)
            return

        # Object declaration
        if self.cur().val == "object":
            self._parse_object(modifiers)
            return

        # Companion object
        if self.cur().val == "companion" and self.peek().val == "object":
            self.advance()  # skip companion
            self._parse_object(modifiers, is_companion=True)
            return

        # Function
        if self.cur().val == "fun":
            self._parse_function(modifiers)
            return

        # Variable declarations
        if self.cur().val in ("val", "var"):
            self._parse_var_decl(modifiers)
            return

        # When expression
        if self.cur().val == "when":
            self._parse_when()
            return

        # Skip anything else
        self.advance()

    def _parse_class(self, modifiers: List[str] = None, is_data: bool = False,
                     is_enum: bool = False):
        t = self.advance()  # skip class/interface
        name = ""
        if self.cur().tt == TT.IDENT:
            name = self.advance().val

        # Type parameters
        if self.cur().val == "<":
            self._skip_type_params()

        # Primary constructor params
        params = []
        if self.cur().val == "(":
            param_tokens = self.skip_to_matching_paren()
            params = self._extract_params(param_tokens)

        # Superclass / interfaces
        if self.cur().val == ":":
            self.advance()
            while self.cur().tt != TT.EOF and self.cur().val not in ("{", ";"):
                self.advance()

        # Body
        body_tokens = []
        if self.cur().val == "{":
            body_tokens = self.skip_to_matching_brace()

        kind = "data_class" if is_data else ("enum_class" if is_enum else "class")
        node = ASTNode(kind, t.line, t.col,
                       attrs={"name": name, "modifiers": modifiers or [],
                              "params": params, "is_data": is_data,
                              "is_enum": is_enum})

        if is_data:
            self.data_classes.append(node)
        self.classes.append(node)

        # Parse body tokens for nested declarations
        self._parse_body_tokens(body_tokens)

    def _parse_object(self, modifiers: List[str] = None, is_companion: bool = False):
        t = self.advance()  # skip object
        name = ""
        if self.cur().tt == TT.IDENT:
            name = self.advance().val

        # Superclass / interfaces
        if self.cur().val == ":":
            self.advance()
            while self.cur().tt != TT.EOF and self.cur().val not in ("{", ";"):
                self.advance()

        body_tokens = []
        if self.cur().val == "{":
            body_tokens = self.skip_to_matching_brace()

        node = ASTNode("object", t.line, t.col,
                       attrs={"name": name, "modifiers": modifiers or [],
                              "is_companion": is_companion})

        if is_companion:
            self.companion_objects.append(node)
        self.objects.append(node)
        self._parse_body_tokens(body_tokens)

    def _parse_function(self, modifiers: List[str] = None):
        t = self.advance()  # skip fun

        # Extension function receiver type
        receiver = ""
        name = ""
        # Look ahead for Receiver.funcName pattern
        if self.cur().tt == TT.IDENT:
            first_ident = self.cur().val
            if self.peek().val == ".":
                receiver = first_ident
                self.advance()  # skip receiver
                self.advance()  # skip .
                if self.cur().tt == TT.IDENT:
                    name = self.advance().val
            elif self.peek().val == "<":
                # Type params before name
                name = self.advance().val
                self._skip_type_params()
            else:
                name = self.advance().val

        # Type parameters after fun keyword
        if self.cur().val == "<":
            self._skip_type_params()
            if self.cur().tt == TT.IDENT and not name:
                # Type.funcName or just funcName
                first_ident = self.cur().val
                if self.peek().val == ".":
                    receiver = first_ident
                    self.advance()
                    self.advance()
                    if self.cur().tt == TT.IDENT:
                        name = self.advance().val
                else:
                    name = self.advance().val

        # Parameters
        params = []
        if self.cur().val == "(":
            param_tokens = self.skip_to_matching_paren()
            params = self._extract_params(param_tokens)

        # Return type
        return_type = ""
        if self.cur().val == ":":
            self.advance()
            rt_parts = []
            while self.cur().tt != TT.EOF and self.cur().val not in ("{", "=", ";"):
                rt_parts.append(self.cur().val)
                self.advance()
            return_type = " ".join(rt_parts)

        # Body
        body_tokens = []
        if self.cur().val == "{":
            body_tokens = self.skip_to_matching_brace()
        elif self.cur().val == "=":
            self.advance()
            # Expression body
            while self.cur().tt != TT.EOF and self.cur().val not in (";",):
                if self.cur().val == "{":
                    body_tokens.extend(self.skip_to_matching_brace())
                    break
                body_tokens.append(self.cur())
                self.advance()

        node = ASTNode("function", t.line, t.col,
                       attrs={"name": name, "receiver": receiver,
                              "params": params, "return_type": return_type,
                              "modifiers": modifiers or [],
                              "is_extension": bool(receiver),
                              "is_suspend": "suspend" in (modifiers or []),
                              "body_text": " ".join(tk.val for tk in body_tokens)})
        self.functions.append(node)
        self._extract_calls_from_tokens(body_tokens, name)
        self._extract_assignments_from_tokens(body_tokens)

    def _parse_var_decl(self, modifiers: List[str] = None):
        kind = self.advance().val  # val or var
        name = ""
        if self.cur().tt == TT.IDENT:
            name = self.advance().val

        type_str = ""
        if self.cur().val == ":":
            self.advance()
            type_parts = []
            while self.cur().tt != TT.EOF and self.cur().val not in ("=", ";", ",", ")"):
                if self.cur().val in ("{", "("):
                    break
                type_parts.append(self.cur().val)
                self.advance()
            type_str = " ".join(type_parts)

        init = ""
        if self.cur().val == "=":
            self.advance()
            init_parts = []
            depth = 0
            while self.cur().tt != TT.EOF:
                if self.cur().val in ("(", "{", "["):
                    depth += 1
                elif self.cur().val in (")", "}", "]"):
                    depth -= 1
                    if depth < 0:
                        break
                if self.cur().val in (";", ",") and depth <= 0:
                    break
                init_parts.append(self.cur().val)
                self.advance()
            init = " ".join(init_parts)

        if self.cur().val == ";":
            self.advance()

        node = ASTNode("var_decl", self.cur().line, self.cur().col,
                       attrs={"name": name, "kind": kind, "type": type_str,
                              "init": init, "modifiers": modifiers or [],
                              "is_const": "const" in (modifiers or []),
                              "is_lateinit": "lateinit" in (modifiers or [])})
        self.var_decls.append(node)

    def _parse_when(self):
        t = self.advance()  # skip when
        subject = ""
        if self.cur().val == "(":
            inner = self.skip_to_matching_paren()
            subject = " ".join(tk.val for tk in inner)

        body_tokens = []
        if self.cur().val == "{":
            body_tokens = self.skip_to_matching_brace()

        node = ASTNode("when", t.line, t.col,
                       attrs={"subject": subject,
                              "body_text": " ".join(tk.val for tk in body_tokens)})
        self.when_exprs.append(node)

    def _skip_type_params(self):
        if self.cur().val != "<":
            return
        depth = 1
        self.advance()
        while self.cur().tt != TT.EOF and depth > 0:
            if self.cur().val == "<":
                depth += 1
            elif self.cur().val == ">":
                depth -= 1
            self.advance()

    def _skip_statement(self):
        while self.cur().tt != TT.EOF and self.cur().val not in (";",):
            if self.cur().val == "{":
                self.skip_to_matching_brace()
                return
            self.advance()
        if self.cur().val == ";":
            self.advance()

    def _extract_params(self, tokens: List[Token]) -> List[dict]:
        params = []
        i = 0
        while i < len(tokens):
            # Skip modifiers
            while i < len(tokens) and tokens[i].val in ("val", "var", "vararg",
                                                          "crossinline", "noinline"):
                i += 1
            if i >= len(tokens):
                break
            if tokens[i].tt == TT.IDENT:
                name = tokens[i].val
                i += 1
                type_str = ""
                if i < len(tokens) and tokens[i].val == ":":
                    i += 1
                    type_parts = []
                    depth = 0
                    while i < len(tokens):
                        if tokens[i].val in ("<", "("):
                            depth += 1
                        elif tokens[i].val in (">", ")"):
                            depth -= 1
                        if tokens[i].val == "," and depth <= 0:
                            break
                        if tokens[i].val == "=" and depth <= 0:
                            # Default value, skip
                            i += 1
                            d2 = 0
                            while i < len(tokens):
                                if tokens[i].val in ("<", "(", "{"):
                                    d2 += 1
                                elif tokens[i].val in (">", ")", "}"):
                                    d2 -= 1
                                if tokens[i].val == "," and d2 <= 0:
                                    break
                                i += 1
                            break
                        type_parts.append(tokens[i].val)
                        i += 1
                    type_str = " ".join(type_parts)
                params.append({"name": name, "type": type_str})
            # Skip comma
            if i < len(tokens) and tokens[i].val == ",":
                i += 1
            else:
                i += 1
        return params

    def _extract_calls_from_tokens(self, tokens: List[Token], context: str = ""):
        i = 0
        while i < len(tokens):
            t = tokens[i]
            # Function call: ident( or ident.ident(
            if t.tt == TT.IDENT and i + 1 < len(tokens) and tokens[i + 1].val == "(":
                call_name = t.val
                # Check for receiver (obj.method)
                receiver = ""
                if i >= 2 and tokens[i - 1].val == "." and tokens[i - 2].tt == TT.IDENT:
                    receiver = tokens[i - 2].val
                # Collect args
                depth = 1
                j = i + 2
                arg_tokens: List[str] = []
                while j < len(tokens) and depth > 0:
                    if tokens[j].val == "(":
                        depth += 1
                    elif tokens[j].val == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    arg_tokens.append(tokens[j].val)
                    j += 1
                args_str = " ".join(arg_tokens)
                node = ASTNode("call", t.line, t.col,
                               attrs={"name": call_name, "receiver": receiver,
                                      "args": args_str, "context": context,
                                      "full": f"{receiver}.{call_name}" if receiver else call_name})
                self.calls.append(node)
            # Safe call: obj?.method(
            elif t.tt == TT.OP and t.val == "?." and i + 1 < len(tokens):
                if tokens[i + 1].tt == TT.IDENT:
                    call_name = tokens[i + 1].val
                    receiver = ""
                    if i >= 1 and tokens[i - 1].tt == TT.IDENT:
                        receiver = tokens[i - 1].val
                    if i + 2 < len(tokens) and tokens[i + 2].val == "(":
                        node = ASTNode("call", t.line, t.col,
                                       attrs={"name": call_name, "receiver": receiver,
                                              "args": "", "context": context,
                                              "full": f"{receiver}?.{call_name}",
                                              "is_safe_call": True})
                        self.calls.append(node)
            i += 1

    def _extract_assignments_from_tokens(self, tokens: List[Token]):
        for i, t in enumerate(tokens):
            if t.val == "=" and i > 0:
                # Exclude ==, !=, <=, >=, +=, -=, etc.
                if i >= 1 and tokens[i - 1].val in ("=", "!", "<", ">", "+", "-", "*", "/", "%"):
                    continue
                if i + 1 < len(tokens) and tokens[i + 1].val == "=":
                    continue
                lhs = tokens[i - 1].val if i > 0 else ""
                rhs_parts = []
                j = i + 1
                depth = 0
                while j < len(tokens):
                    if tokens[j].val in ("(", "{", "["):
                        depth += 1
                    elif tokens[j].val in (")", "}", "]"):
                        depth -= 1
                    if tokens[j].val in (";",) and depth <= 0:
                        break
                    rhs_parts.append(tokens[j].val)
                    j += 1
                node = ASTNode("assignment", t.line, t.col,
                               attrs={"lhs": lhs, "rhs": " ".join(rhs_parts)})
                self.assignments.append(node)

    def _parse_body_tokens(self, tokens: List[Token]):
        """Sub-parse body tokens for nested declarations."""
        sub = Parser(tokens)
        sub.parse()
        self.functions.extend(sub.functions)
        self.classes.extend(sub.classes)
        self.objects.extend(sub.objects)
        self.data_classes.extend(sub.data_classes)
        self.companion_objects.extend(sub.companion_objects)
        self.calls.extend(sub.calls)
        self.assignments.extend(sub.assignments)
        self.var_decls.extend(sub.var_decls)
        self.when_exprs.extend(sub.when_exprs)
        self.lambdas.extend(sub.lambdas)


# ---------------------------------------------------------------------------
# 4. DATA FLOW ANALYSIS
# ---------------------------------------------------------------------------

@dataclass
class VarState:
    name: str
    tainted: bool = False
    initialized: bool = False
    nullable: bool = False
    type_str: str = ""
    decl_line: int = 0
    source: str = ""  # where the taint came from


class TaintTracker:
    """Track tainted (user-controlled) data flow through Kotlin code."""

    # Sources of user input
    INPUT_SOURCES = frozenset([
        "readLine", "readText", "readBytes", "getParameter", "getHeader",
        "getQueryParameter", "receive", "receiveText", "receiveParameters",
        "getIntent", "getExtra", "getStringExtra", "getIntExtra",
        "getBundleExtra", "getData", "getExtras", "queryParams", "params",
        "body", "requestBody", "formParam", "queryParam", "pathParam",
        "header", "cookie", "getInputStream", "getReader",
        "request", "args", "argv", "environment", "getenv",
    ])

    # Dangerous sinks
    EXEC_SINKS = frozenset([
        "exec", "runtime", "ProcessBuilder", "Runtime",
    ])

    SQL_SINKS = frozenset([
        "executeQuery", "executeUpdate", "execute", "rawQuery",
        "execSQL", "compileStatement", "prepareStatement",
        "createStatement", "query", "insert", "update", "delete",
    ])

    def __init__(self, parser: Parser):
        self.parser = parser
        self.tainted_vars: Dict[str, VarState] = {}

    def analyze(self):
        """Run taint analysis across all parsed data."""
        # Mark initial taint sources from variable declarations
        for vd in self.parser.var_decls:
            init = vd.attrs.get("init", "")
            name = vd.attrs.get("name", "")
            for src in self.INPUT_SOURCES:
                if src in init:
                    self.tainted_vars[name] = VarState(
                        name=name, tainted=True, initialized=True,
                        decl_line=vd.line, source=src,
                        type_str=vd.attrs.get("type", ""))
                    break

        # Propagate through assignments
        for asgn in self.parser.assignments:
            rhs = asgn.attrs.get("rhs", "")
            lhs = asgn.attrs.get("lhs", "")
            for tvar in list(self.tainted_vars.keys()):
                if tvar in rhs:
                    self.tainted_vars[lhs] = VarState(
                        name=lhs, tainted=True, initialized=True,
                        decl_line=asgn.line, source=f"from {tvar}")
                    break

    def is_tainted(self, expr: str) -> bool:
        for tvar in self.tainted_vars:
            if tvar in expr:
                return True
        for src in self.INPUT_SOURCES:
            if src in expr:
                return True
        return False


# ---------------------------------------------------------------------------
# 5. VULNERABILITY DETECTORS (35+ categories)
# ---------------------------------------------------------------------------

@dataclass
class Vulnerability:
    vuln_id: str
    severity: str  # Critical, High, Medium, Low, Info
    confidence: str  # High, Medium, Low
    category: str
    cwe: str
    description: str
    file_path: str
    line: int
    column: int
    code_snippet: str
    recommendation: str


class VulnDetector:
    """Base for all vulnerability detectors."""

    def __init__(self, file_path: str, source: str, parser: Parser, taint: TaintTracker):
        self.file_path = file_path
        self.source = source
        self.lines = source.splitlines()
        self.parser = parser
        self.taint = taint
        self.vulns: List[Vulnerability] = []

    def _snippet(self, line: int, context: int = 2) -> str:
        start = max(0, line - 1 - context)
        end = min(len(self.lines), line + context)
        parts = []
        for i in range(start, end):
            marker = ">>> " if i == line - 1 else "    "
            parts.append(f"{marker}{i + 1}: {self.lines[i]}")
        return "\n".join(parts)

    def _add(self, severity: str, confidence: str, category: str, cwe: str,
             desc: str, line: int, col: int, recommendation: str):
        self.vulns.append(Vulnerability(
            vuln_id=hashlib.sha256(
                f"{self.file_path}:{line}:{category}:{desc[:50]}".encode()
            ).hexdigest()[:16],
            severity=severity, confidence=confidence, category=category,
            cwe=cwe, description=desc, file_path=self.file_path,
            line=line, column=col, code_snippet=self._snippet(line),
            recommendation=recommendation))


# --- 1. SQL Injection ---
class SQLInjectionDetector(VulnDetector):
    SQL_PATTERNS = [
        (r'(?:executeQuery|executeUpdate|execute|rawQuery|execSQL)\s*\(\s*["\']?\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)',
         "Direct SQL query construction"),
        (r'(?:executeQuery|executeUpdate|execute|rawQuery|execSQL)\s*\([^)]*\+', "String concatenation in SQL query"),
        (r'(?:executeQuery|executeUpdate|execute|rawQuery|execSQL)\s*\([^)]*\$\{', "String template in SQL query"),
        (r'(?:executeQuery|executeUpdate|execute|rawQuery|execSQL)\s*\([^)]*\$[a-zA-Z]', "Variable interpolation in SQL"),
        (r'"""[^"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^"]*\$', "Raw string SQL with interpolation"),
        (r'(?:transaction|TransactionManager)\s*\{[^}]*(?:exec|rawQuery)', "Unparameterized query in transaction"),
    ]

    # Exposed framework patterns
    EXPOSED_PATTERNS = [
        (r'\.exec\s*\(\s*"[^"]*\$', "Exposed framework raw SQL with interpolation"),
        (r'SqlExposedTable\s*\.\s*exec', "Raw exec on Exposed table"),
    ]

    # Room database patterns
    ROOM_PATTERNS = [
        (r'@Query\s*\(\s*"[^"]*\+', "Room @Query with concatenation"),
        (r'@RawQuery', "Room @RawQuery may accept arbitrary SQL"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.SQL_PATTERNS:
                if re.search(pat, line_text, re.IGNORECASE):
                    self._add("Critical", "High", "SQL Injection", "CWE-89",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Use parameterized queries or prepared statements. For Room, use :paramName. "
                              "For Exposed, use the DSL API instead of raw SQL.")
            for pat, desc in self.EXPOSED_PATTERNS:
                if re.search(pat, line_text):
                    self._add("Critical", "Medium", "SQL Injection", "CWE-89",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Use Exposed DSL operations (select, insert, update) instead of raw SQL strings.")
            for pat, desc in self.ROOM_PATTERNS:
                if re.search(pat, line_text):
                    sev = "High" if "@RawQuery" in line_text else "Medium"
                    self._add(sev, "Medium", "SQL Injection", "CWE-89",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Use Room's @Query with :paramName bindings instead of string concatenation.")

        # Check calls with tainted args flowing to SQL
        for call in self.parser.calls:
            if call.attrs.get("name", "") in ("executeQuery", "executeUpdate", "execute",
                                               "rawQuery", "execSQL", "query"):
                args = call.attrs.get("args", "")
                if self.taint.is_tainted(args):
                    self._add("Critical", "High", "SQL Injection", "CWE-89",
                              f"Tainted data flows to SQL sink '{call.attrs['name']}' with args: {args}",
                              call.line, call.col,
                              "Sanitize user input and use parameterized queries.")


# --- 2. Command Injection ---
class CommandInjectionDetector(VulnDetector):
    PATTERNS = [
        (r'Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(', "Runtime.exec()"),
        (r'ProcessBuilder\s*\(', "ProcessBuilder"),
        (r'\.exec\s*\(\s*(?:arrayOf|listOf)?\s*\(?[^)]*\$', "exec with string interpolation"),
        (r'ProcessBuilder\s*\([^)]*\$', "ProcessBuilder with interpolation"),
        (r'\.command\s*\([^)]*\$', "Process command with interpolation"),
        (r'ProcessBuilder\s*\([^)]*\+', "ProcessBuilder with concatenation"),
        (r'Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\([^)]*\+', "Runtime.exec with concatenation"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text):
                    self._add("Critical", "High", "Command Injection", "CWE-78",
                              f"{desc} detected: {line_text.strip()}", line_num, 1,
                              "Never pass user input directly to system commands. Use allowlists "
                              "for permitted commands and parameterize arguments.")

        for call in self.parser.calls:
            name = call.attrs.get("name", "")
            full = call.attrs.get("full", "")
            args = call.attrs.get("args", "")
            if name == "exec" and self.taint.is_tainted(args):
                self._add("Critical", "High", "Command Injection", "CWE-78",
                          f"Tainted data in command execution: {full}({args})",
                          call.line, call.col,
                          "Validate and sanitize all input before passing to process execution.")


# --- 3. Code Injection ---
class CodeInjectionDetector(VulnDetector):
    PATTERNS = [
        (r'ScriptEngine\s*\.', "ScriptEngine usage"),
        (r'\.eval\s*\(', "eval() call"),
        (r'ScriptEngineManager', "ScriptEngineManager for dynamic code"),
        (r'GroovyShell', "GroovyShell dynamic execution"),
        (r'Class\s*\.\s*forName\s*\([^)]*\$', "Dynamic class loading with user input"),
        (r'ClassLoader.*loadClass\s*\([^)]*\$', "Dynamic class loading with interpolation"),
        (r'\.invoke\s*\(', "Reflection invoke"),
        (r'KClass.*createInstance', "Reflection-based instantiation"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text):
                    sev = "Critical" if "eval" in pat.lower() or "forName" in pat else "High"
                    self._add(sev, "Medium", "Code Injection", "CWE-94",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Avoid dynamic code execution. If needed, use strict allowlists "
                              "and sandboxing.")


# --- 4. XSS ---
class XSSDetector(VulnDetector):
    PATTERNS = [
        # Ktor
        (r'call\s*\.\s*respondText\s*\([^)]*ContentType\s*\.\s*Text\s*\.\s*Html', "Ktor respondText as HTML"),
        (r'call\s*\.\s*respondHtml', "Ktor respondHtml"),
        (r'respondText\s*\([^)]*\$', "Ktor response with interpolation"),
        # Spring
        (r'@ResponseBody.*\$', "Spring ResponseBody with interpolation"),
        (r'ModelAndView\s*\([^)]*\$', "Spring ModelAndView with interpolation"),
        # Generic HTML
        (r'"""[^"]*<\s*(?:script|img|iframe|div|span)[^"]*\$', "HTML in raw string with interpolation"),
        (r'"[^"]*<\s*(?:script|img|iframe)[^"]*\$', "HTML tag with interpolation"),
        (r'innerHTML\s*=', "innerHTML assignment"),
        (r'document\s*\.\s*write', "document.write"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text, re.IGNORECASE):
                    self._add("High", "Medium", "Cross-Site Scripting (XSS)", "CWE-79",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Always escape/encode user-supplied data before rendering in HTML. "
                              "Use template engines with auto-escaping enabled.")


# --- 5. Path Traversal ---
class PathTraversalDetector(VulnDetector):
    PATTERNS = [
        (r'File\s*\([^)]*\$', "File() with interpolated path"),
        (r'File\s*\([^)]*\+', "File() with concatenated path"),
        (r'Paths\s*\.\s*get\s*\([^)]*\$', "Paths.get() with interpolation"),
        (r'FileInputStream\s*\([^)]*\$', "FileInputStream with interpolation"),
        (r'FileOutputStream\s*\([^)]*\$', "FileOutputStream with interpolation"),
        (r'\.readText\s*\(\s*\)', "readText on potentially user-controlled path"),
        (r'\.resolve\s*\([^)]*\$', "Path resolve with interpolation"),
        (r'getResource\s*\([^)]*\$', "Resource loading with interpolation"),
        (r'ClassLoader.*getResource\s*\([^)]*\$', "ClassLoader resource with interpolation"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text):
                    self._add("High", "Medium", "Path Traversal", "CWE-22",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Validate and canonicalize file paths. Use allowlists for permitted "
                              "directories. Never pass raw user input to file operations.")

        for call in self.parser.calls:
            if call.attrs.get("name", "") in ("File", "Paths", "FileInputStream",
                                                "FileOutputStream"):
                args = call.attrs.get("args", "")
                if self.taint.is_tainted(args):
                    self._add("High", "High", "Path Traversal", "CWE-22",
                              f"Tainted data in file path: {call.attrs.get('full', '')}({args})",
                              call.line, call.col,
                              "Canonicalize paths and check they resolve within allowed directories.")


# --- 6. Deserialization ---
class DeserializationDetector(VulnDetector):
    PATTERNS = [
        (r'ObjectInputStream', "ObjectInputStream usage"),
        (r'\.readObject\s*\(', "readObject() deserialization"),
        (r'\.readUnshared\s*\(', "readUnshared() deserialization"),
        (r'Gson\s*\(\s*\)\s*\.\s*fromJson\s*\(', "Gson deserialization"),
        (r'ObjectMapper\s*\(\s*\)\s*\.\s*readValue', "Jackson deserialization"),
        (r'Moshi.*fromJson', "Moshi deserialization"),
        (r'Json\s*\.\s*decodeFromString', "Kotlin Serialization decode"),
        (r'BinaryFormat.*decodeFrom', "Binary format deserialization"),
        (r'Yaml\s*\.\s*load\s*\(', "YAML deserialization"),
        (r'XMLDecoder', "XMLDecoder deserialization"),
        (r'XStream.*fromXML', "XStream deserialization"),
        (r'Kryo.*readObject', "Kryo deserialization"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text):
                    sev = "Critical" if "ObjectInputStream" in pat or "XMLDecoder" in pat else "High"
                    self._add(sev, "Medium", "Insecure Deserialization", "CWE-502",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Avoid deserializing untrusted data. Use allowlists for permitted classes. "
                              "Prefer data-only formats (JSON with strict schemas) over object serialization.")


# --- 7. SSRF ---
class SSRFDetector(VulnDetector):
    PATTERNS = [
        (r'URL\s*\([^)]*\$', "URL() with interpolation"),
        (r'HttpURLConnection.*\$', "HttpURLConnection with user data"),
        (r'OkHttpClient.*\$', "OkHttp with interpolated URL"),
        (r'\.newCall\s*\(.*Request.*\$', "OkHttp request with interpolation"),
        (r'Retrofit.*baseUrl\s*\([^)]*\$', "Retrofit baseUrl with interpolation"),
        (r'HttpClient.*\$', "Ktor HttpClient with interpolation"),
        (r'\.get\s*\(\s*"[^"]*\$', "HTTP GET with interpolated URL"),
        (r'\.post\s*\(\s*"[^"]*\$', "HTTP POST with interpolated URL"),
        (r'Fuel\s*\.\s*(?:get|post)\s*\([^)]*\$', "Fuel HTTP with interpolation"),
        (r'RestTemplate.*\$', "Spring RestTemplate with interpolation"),
        (r'WebClient.*uri\s*\([^)]*\$', "Spring WebClient with interpolated URI"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text):
                    self._add("High", "Medium", "Server-Side Request Forgery (SSRF)", "CWE-918",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Validate and allowlist URLs before making HTTP requests. "
                              "Block internal/private IP ranges. Use URL parsing to validate schemes.")


# --- 8. Hardcoded Secrets ---
class HardcodedSecretsDetector(VulnDetector):
    PATTERNS = [
        (r'(?:password|passwd|pwd)\s*=\s*"[^"]{4,}"', "Hardcoded password"),
        (r'(?:api[_-]?key|apikey)\s*=\s*"[^"]{8,}"', "Hardcoded API key"),
        (r'(?:secret|token|jwt[_-]?secret)\s*=\s*"[^"]{8,}"', "Hardcoded secret/token"),
        (r'(?:private[_-]?key|priv[_-]?key)\s*=\s*"[^"]{8,}"', "Hardcoded private key"),
        (r'(?:aws[_-]?(?:access|secret)|AKIA[A-Z0-9]{12,})', "AWS credential"),
        (r'Bearer\s+[A-Za-z0-9._-]{20,}', "Hardcoded Bearer token"),
        (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}', "GitHub token"),
        (r'sk-[A-Za-z0-9]{32,}', "API secret key (OpenAI/Stripe pattern)"),
        (r'(?:mongodb|postgres|mysql|redis)://[^"\s]+:[^"\s]+@', "Database connection string with credentials"),
        (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "Embedded private key"),
        (r'(?:encryption[_-]?key|signing[_-]?key)\s*=\s*"[^"]{8,}"', "Hardcoded encryption key"),
        (r'(?:client[_-]?secret)\s*=\s*"[^"]{8,}"', "Hardcoded client secret"),
        (r'(?:firebase|gcp|google)[_-]?(?:api[_-]?key|credentials?)\s*=\s*"', "Cloud credential"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            # Skip comments
            stripped = line_text.strip()
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text, re.IGNORECASE):
                    # Avoid false positives on empty or placeholder values
                    if re.search(r'=\s*"(?:TODO|CHANGE_ME|xxx|your[_-]|example|test|placeholder|<)', line_text, re.IGNORECASE):
                        continue
                    self._add("Critical", "High", "Hardcoded Secrets", "CWE-798",
                              f"{desc}: {line_text.strip()[:120]}", line_num, 1,
                              "Use environment variables, Android Keystore, or a secrets manager. "
                              "Never commit secrets to source code.")


# --- 9. Weak Cryptography ---
class WeakCryptoDetector(VulnDetector):
    PATTERNS = [
        (r'MessageDigest\s*\.\s*getInstance\s*\(\s*"(?:MD5|MD4|MD2)"', "Weak hash: MD5/MD4/MD2"),
        (r'MessageDigest\s*\.\s*getInstance\s*\(\s*"SHA-?1"', "Weak hash: SHA-1"),
        (r'Cipher\s*\.\s*getInstance\s*\(\s*"DES', "Weak cipher: DES"),
        (r'Cipher\s*\.\s*getInstance\s*\(\s*"RC[24]', "Weak cipher: RC2/RC4"),
        (r'Cipher\s*\.\s*getInstance\s*\(\s*"(?:AES/ECB|DESede/ECB)', "ECB mode (no diffusion)"),
        (r'Cipher\s*\.\s*getInstance\s*\(\s*"AES"\s*\)', "AES without mode specified (defaults to ECB)"),
        (r'KeyGenerator.*init\s*\(\s*(?:56|64|128)\s*\)', "Potentially weak key size"),
        (r'SecretKeySpec\s*\([^)]*,\s*"DES', "DES key specification"),
        (r'(?:md5|sha1)\s*\(', "Weak hash function call"),
        (r'\.digest\s*\(\s*"(?:MD5|SHA-?1)"', "Weak digest algorithm"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text, re.IGNORECASE):
                    sev = "High" if "DES" in desc or "ECB" in desc else "Medium"
                    self._add(sev, "High", "Weak Cryptography", "CWE-327",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Use strong algorithms: AES-256-GCM for encryption, SHA-256/SHA-3 for hashing. "
                              "Avoid ECB mode; use GCM or CBC with HMAC.")


# --- 10. Insecure Random ---
class InsecureRandomDetector(VulnDetector):
    PATTERNS = [
        (r'java\s*\.\s*util\s*\.\s*Random\b', "java.util.Random (not cryptographic)"),
        (r'\bRandom\s*\(\s*\)', "Random() without SecureRandom"),
        (r'Math\s*\.\s*random\s*\(', "Math.random() not cryptographically secure"),
        (r'kotlin\s*\.\s*random\s*\.\s*Random\b', "kotlin.random.Random (not for security)"),
        (r'ThreadLocalRandom', "ThreadLocalRandom (not for security use)"),
    ]

    def detect(self):
        source_text = self.source
        has_secure = "SecureRandom" in source_text
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text):
                    # Check context for security usage
                    context_lines = self.lines[max(0, line_num - 3):min(len(self.lines), line_num + 2)]
                    context = " ".join(context_lines).lower()
                    is_security = any(w in context for w in
                                      ["token", "password", "secret", "key", "nonce",
                                       "iv", "salt", "otp", "csrf", "session"])
                    if is_security or not has_secure:
                        self._add("Medium", "Medium", "Insecure Random", "CWE-330",
                                  f"{desc}: {line_text.strip()}", line_num, 1,
                                  "Use java.security.SecureRandom for any security-sensitive random generation "
                                  "(tokens, keys, nonces, OTPs, session IDs).")


# --- 11. Insecure TLS ---
class InsecureTLSDetector(VulnDetector):
    PATTERNS = [
        (r'TrustAll', "TrustAll certificate configuration"),
        (r'X509TrustManager.*checkServerTrusted.*\{\s*\}', "Empty trust manager"),
        (r'ALLOW_ALL_HOSTNAME_VERIFIER', "Hostname verification disabled"),
        (r'HostnameVerifier\s*\{[^}]*true', "HostnameVerifier always returns true"),
        (r'hostnameVerifier\s*=.*\{[^}]*true', "Hostname verifier bypass"),
        (r'\.setHostnameVerifier\s*\(', "Custom hostname verifier (review)"),
        (r'SSLContext.*init\s*\([^)]*null', "SSLContext with null trust manager"),
        (r'\.sslSocketFactory\s*\(', "Custom SSL socket factory (review)"),
        (r'InsecureSocketFactory', "Insecure socket factory"),
        (r'TLSv1[^.]|SSLv[23]', "Outdated TLS/SSL version"),
        (r'certificatePinner\s*\{\s*\}', "Empty certificate pinning"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text, re.IGNORECASE):
                    self._add("High", "High", "Insecure TLS/SSL", "CWE-295",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Use proper certificate validation. Never bypass hostname verification. "
                              "Use TLS 1.2+ with strong cipher suites. Implement certificate pinning for mobile.")


# --- 12. Logging Sensitive Data ---
class SensitiveLoggingDetector(VulnDetector):
    PATTERNS = [
        (r'(?:Log\s*\.\s*[dviewDVIEW]+|println|print|logger\s*\.\s*(?:debug|info|warn|error))\s*\([^)]*(?:password|passwd|pwd|secret|token|apiKey|creditCard|ssn|pin)',
         "Logging sensitive data"),
        (r'(?:Log\s*\.\s*[dviewDVIEW]+|println)\s*\([^)]*(?:getPassword|getToken|getSecret|getApiKey)',
         "Logging return value of sensitive getter"),
        (r'Timber\s*\.\s*[dviewDVIEW]+\s*\([^)]*(?:password|secret|token)',
         "Timber logging sensitive data"),
        (r'e\s*\.\s*printStackTrace\s*\(', "Stack trace exposure"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text, re.IGNORECASE):
                    self._add("Medium", "Medium", "Sensitive Data Logging", "CWE-532",
                              f"{desc}: {line_text.strip()[:120]}", line_num, 1,
                              "Never log passwords, tokens, or PII. Use structured logging with "
                              "redaction. Remove stack traces in production builds.")


# --- 13. Android Exported Components ---
class AndroidComponentDetector(VulnDetector):
    """Detects Android-specific security issues from Kotlin code patterns."""
    PATTERNS = [
        # WebView
        (r'\.settings\s*\.\s*javaScriptEnabled\s*=\s*true', "WebView JavaScript enabled"),
        (r'addJavascriptInterface\s*\(', "WebView addJavascriptInterface"),
        (r'\.settings\s*\.\s*allowFileAccess\s*=\s*true', "WebView file access enabled"),
        (r'\.settings\s*\.\s*allowUniversalAccessFromFileURLs\s*=\s*true',
         "WebView universal file access"),
        (r'\.settings\s*\.\s*allowFileAccessFromFileURLs\s*=\s*true',
         "WebView file URL access"),
        (r'\.settings\s*\.\s*allowContentAccess\s*=\s*true', "WebView content access"),
        # SharedPreferences
        (r'getSharedPreferences\s*\([^)]*MODE_WORLD_READABLE', "SharedPreferences world-readable"),
        (r'getSharedPreferences\s*\([^)]*MODE_WORLD_WRITEABLE', "SharedPreferences world-writeable"),
        (r'SharedPreferences.*(?:password|token|secret|key)', "Sensitive data in SharedPreferences"),
        # Intent
        (r'Intent\s*\(\s*\)\s*', "Implicit intent (no target component)"),
        (r'\.putExtra\s*\([^)]*(?:password|token|secret)', "Sensitive data in Intent extra"),
        (r'sendBroadcast\s*\((?!.*permission)', "Broadcast without permission"),
        # Other
        (r'allowBackup\s*=\s*true', "allowBackup enabled"),
        (r'usesCleartextTraffic\s*=\s*true', "Cleartext traffic allowed"),
        (r'android:debuggable\s*=\s*"true"', "Debuggable in release"),
        (r'\.setMixedContentMode\s*\(\s*MIXED_CONTENT_ALWAYS_ALLOW',
         "WebView mixed content allowed"),
        (r'registerReceiver\s*\([^)]*(?!.*RECEIVER_NOT_EXPORTED)',
         "Receiver without NOT_EXPORTED flag"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text, re.IGNORECASE):
                    sev = "High"
                    cwe = "CWE-926"
                    if "SharedPreferences" in desc:
                        cwe = "CWE-922"
                    elif "WebView" in desc:
                        cwe = "CWE-749"
                        if "JavascriptInterface" in desc:
                            sev = "Critical"
                    elif "Intent" in desc:
                        cwe = "CWE-927"
                    elif "allowBackup" in desc:
                        cwe = "CWE-530"
                        sev = "Medium"
                    elif "Cleartext" in desc or "debuggable" in desc:
                        cwe = "CWE-319"
                    self._add(sev, "High", "Android Security", cwe,
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Review Android security best practices: disable JS in WebView unless needed, "
                              "use EncryptedSharedPreferences, set exported=false, disable allowBackup.")


# --- 14. Android Intent Injection ---
class IntentInjectionDetector(VulnDetector):
    PATTERNS = [
        (r'intent\s*\.\s*data\s*\.\s*toString', "Using intent data without validation"),
        (r'intent\s*\.\s*getStringExtra\s*\([^)]*\)\s*!!', "Force-unwrapping intent extra"),
        (r'getIntent\s*\(\s*\)\s*\.\s*data', "Direct use of intent data"),
        (r'intent\s*\.\s*(?:action|data|type)\s*(?:\.|\s*!!)', "Unvalidated intent property"),
        (r'startActivity\s*\(\s*intent\s*\.', "Forwarding unvalidated intent"),
        (r'PendingIntent\s*\..*FLAG_MUTABLE', "Mutable PendingIntent"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text):
                    self._add("High", "Medium", "Intent Injection", "CWE-940",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Validate intent data before use. Use explicit intents. "
                              "Use FLAG_IMMUTABLE for PendingIntents.")


# --- 15. Android SQL Injection ---
class AndroidSQLDetector(VulnDetector):
    PATTERNS = [
        (r'rawQuery\s*\(\s*"[^"]*\$', "rawQuery with interpolation"),
        (r'rawQuery\s*\(\s*"[^"]*\+', "rawQuery with concatenation"),
        (r'execSQL\s*\(\s*"[^"]*\$', "execSQL with interpolation"),
        (r'compileStatement\s*\(\s*"[^"]*\$', "compileStatement with interpolation"),
        (r'contentResolver\s*\.\s*query\s*\([^)]*\$', "ContentResolver query with interpolation"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text):
                    self._add("Critical", "High", "Android SQL Injection", "CWE-89",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Use parameterized queries with selectionArgs. Use Room with @Query "
                              "and named parameters instead of raw queries.")


# --- 16. Android WebView ---
class AndroidWebViewDetector(VulnDetector):
    PATTERNS = [
        (r'addJavascriptInterface\s*\(', "addJavascriptInterface exposes methods to JS"),
        (r'\.loadUrl\s*\(\s*"javascript:', "loadUrl with javascript: scheme"),
        (r'\.loadUrl\s*\([^)]*\$', "loadUrl with interpolated URL"),
        (r'\.loadData\s*\([^)]*\$', "loadData with interpolated content"),
        (r'\.evaluateJavascript\s*\([^)]*\$', "evaluateJavascript with interpolation"),
        (r'WebViewClient.*shouldOverrideUrlLoading.*return\s+false',
         "WebViewClient not filtering URLs"),
        (r'setWebContentsDebuggingEnabled\s*\(\s*true', "WebView debugging enabled"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text):
                    sev = "Critical" if "JavascriptInterface" in desc else "High"
                    self._add(sev, "High", "Android WebView Security", "CWE-749",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Restrict WebView capabilities: disable JS unless required, validate URLs, "
                              "use @JavascriptInterface annotation, disable file access and debugging.")


# --- 17. Android Crypto ---
class AndroidCryptoDetector(VulnDetector):
    PATTERNS = [
        (r'IvParameterSpec\s*\(\s*"[^"]*"\s*\.toByteArray', "Static IV in encryption"),
        (r'IvParameterSpec\s*\(\s*byteArrayOf\s*\(', "Hardcoded IV bytes"),
        (r'AES/ECB', "ECB mode in Android encryption"),
        (r'KeyGenParameterSpec.*setUserAuthenticationRequired\s*\(\s*false',
         "Keystore key without user authentication"),
        (r'\.setEncryptionPaddings\s*\(\s*ENCRYPTION_PADDING_NONE',
         "No padding in encryption"),
        (r'KeyProperties\s*\.\s*PURPOSE_(?:ENCRYPT|DECRYPT).*\.setRandomizedEncryptionRequired\s*\(\s*false',
         "Non-randomized encryption"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text, re.IGNORECASE):
                    self._add("High", "High", "Android Cryptography", "CWE-329",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Use random IVs, AES-GCM mode, and Android Keystore for key management. "
                              "Enable user authentication for sensitive keys.")


# --- 18. Ktor Security ---
class KtorSecurityDetector(VulnDetector):
    PATTERNS = [
        (r'install\s*\(\s*CORS\s*\)\s*\{[^}]*anyHost', "Ktor CORS anyHost (allows all origins)"),
        (r'CORS\s*\{[^}]*allowHeader\s*\(\s*HttpHeaders\s*\.\s*Any',
         "Ktor CORS allows any header"),
        (r'install\s*\(\s*CORS\s*\)\s*\{[^}]*allowCredentials\s*=\s*true',
         "CORS with credentials and broad origins"),
        (r'route\s*\(\s*"[^"]*"\s*\)\s*\{(?!.*authenticate)',
         "Ktor route potentially missing authentication"),
        (r'respondText\s*\([^)]*\.\s*stackTrace', "Stack trace in response"),
        (r'respondText\s*\([^)]*exception', "Exception details in response"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text, re.IGNORECASE):
                    sev = "Medium" if "route" in desc.lower() else "High"
                    cwe = "CWE-942" if "CORS" in desc else "CWE-209"
                    self._add(sev, "Medium", "Ktor Security", cwe,
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Configure CORS with specific allowed origins. Use Ktor's authentication "
                              "plugin for protected routes. Never expose stack traces to clients.")

        # Multi-line CORS check
        source_lower = self.source.lower()
        if "install(cors)" in source_lower or "install ( cors )" in source_lower:
            if "anyhost" in source_lower:
                # Already caught above
                pass
            if "csrf" not in source_lower and "csrfprotection" not in source_lower:
                # Find the CORS install line
                for line_num, line_text in enumerate(self.lines, 1):
                    if re.search(r'install\s*\(\s*CORS', line_text):
                        self._add("Medium", "Low", "Ktor Security", "CWE-352",
                                  f"CORS configured but no CSRF protection found",
                                  line_num, 1,
                                  "Implement CSRF protection using double-submit cookies or "
                                  "synchronizer tokens alongside CORS.")
                        break


# --- 19. Spring Boot Kotlin ---
class SpringSecurityDetector(VulnDetector):
    PATTERNS = [
        (r'SpEL.*\$|#\{[^}]*\$', "SpEL injection with user input"),
        (r'@Value\s*\(\s*"#\{', "SpEL in @Value annotation"),
        (r'ExpressionParser.*parseExpression\s*\([^)]*\$',
         "Dynamic SpEL expression with interpolation"),
        (r'management\s*\.\s*endpoints\s*\.\s*web\s*\.\s*exposure\s*\.\s*include\s*=\s*\*',
         "All actuator endpoints exposed"),
        (r'@RequestBody.*(?:var|val)\s+\w+\s*:\s*\w+(?!\s*\()',
         "Potential mass assignment via @RequestBody"),
        (r'permitAll\s*\(\s*\)\s*\.\s*antMatchers\s*\(\s*"/\*\*"',
         "Spring Security permits all paths"),
        (r'csrf\s*\(\s*\)\s*\.\s*disable', "CSRF protection disabled"),
        (r'@CrossOrigin\s*\(\s*origins\s*=.*\*', "Spring CORS allows all origins"),
        (r'httpBasic\s*\(\s*\)', "HTTP Basic auth without HTTPS check"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text, re.IGNORECASE):
                    sev = "Critical" if "SpEL" in desc else "High"
                    cwe = "CWE-917" if "SpEL" in desc else "CWE-16"
                    self._add(sev, "Medium", "Spring Boot Security", cwe,
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Avoid dynamic SpEL evaluation with user input. Restrict actuator endpoints. "
                              "Use DTOs to prevent mass assignment. Keep CSRF enabled.")


# --- 20. Coroutine Safety ---
class CoroutineSafetyDetector(VulnDetector):
    def detect(self):
        # Detect shared mutable state in coroutines
        has_coroutines = False
        mutable_shared: List[Tuple[int, str]] = []

        for line_num, line_text in enumerate(self.lines, 1):
            if re.search(r'(?:launch|async|withContext|runBlocking|coroutineScope|supervisorScope)', line_text):
                has_coroutines = True
            if re.search(r'(?:GlobalScope\s*\.\s*(?:launch|async))', line_text):
                self._add("Medium", "Medium", "Coroutine Safety", "CWE-362",
                          f"GlobalScope usage can outlive the enclosing scope: {line_text.strip()}",
                          line_num, 1,
                          "Use structured concurrency (coroutineScope, viewModelScope) instead of GlobalScope.")

        if has_coroutines:
            # Check for var declarations at class level that might be shared
            for vd in self.parser.var_decls:
                if vd.attrs.get("kind") == "var":
                    name = vd.attrs.get("name", "")
                    mods = vd.attrs.get("modifiers", [])
                    if "private" not in mods and name:
                        # Check if variable is accessed in coroutine contexts
                        body_pattern = re.compile(
                            rf'(?:launch|async|withContext)\s*(?:\([^)]*\))?\s*\{{[^}}]*{re.escape(name)}',
                            re.DOTALL
                        )
                        if body_pattern.search(self.source):
                            self._add("Medium", "Low", "Coroutine Safety", "CWE-362",
                                      f"Mutable var '{name}' potentially shared across coroutines",
                                      vd.line, vd.col,
                                      "Use Mutex, AtomicInteger/AtomicReference, or StateFlow for "
                                      "shared mutable state in coroutines.")

        # Detect Dispatchers.Main in non-UI code
        for line_num, line_text in enumerate(self.lines, 1):
            if re.search(r'Dispatchers\s*\.\s*IO', line_text):
                # Check for blocking calls in Dispatchers.IO context
                pass  # This is actually correct usage
            if re.search(r'runBlocking\s*\{', line_text):
                self._add("Low", "Medium", "Coroutine Safety", "CWE-400",
                          f"runBlocking can cause thread starvation: {line_text.strip()}",
                          line_num, 1,
                          "Avoid runBlocking in production code, especially on the main thread. "
                          "Use suspend functions instead.")


# --- 21. Null Safety Bypass ---
class NullSafetyDetector(VulnDetector):
    def detect(self):
        assertion_count = 0
        assertion_lines: List[Tuple[int, str]] = []

        for line_num, line_text in enumerate(self.lines, 1):
            count = line_text.count("!!")
            if count > 0:
                assertion_count += count
                assertion_lines.append((line_num, line_text.strip()))

        # Report individual !! usages only if in dangerous context
        for line_num, line_text in assertion_lines:
            if re.search(r'(?:getExtra|getStringExtra|data|intent|getParameter|get\s*\(|findView)\s*[^!]*!!', line_text):
                self._add("Medium", "High", "Null Safety Bypass", "CWE-476",
                          f"Force-unwrap (!!) on potentially null external data: {line_text}",
                          line_num, 1,
                          "Use safe calls (?.), elvis (?:), or let{} blocks instead of !!. "
                          "The !! operator will throw KotlinNullPointerException at runtime.")

        # Report excessive !! usage as a code smell
        if assertion_count > 10:
            self._add("Low", "High", "Null Safety Bypass", "CWE-476",
                      f"Excessive use of !! operator ({assertion_count} occurrences). "
                      f"This defeats Kotlin's null safety and indicates crash risk.",
                      1, 1,
                      "Refactor to use Kotlin's null-safe operators: ?., ?:, let{}, "
                      "require(), checkNotNull(). Reserve !! for truly impossible null cases.")


# --- 22. Open Redirect ---
class OpenRedirectDetector(VulnDetector):
    PATTERNS = [
        (r'redirect\s*\(\s*[^)]*\$', "Redirect with interpolated URL"),
        (r'respondRedirect\s*\([^)]*\$', "Ktor redirect with interpolation"),
        (r'sendRedirect\s*\([^)]*\$', "sendRedirect with interpolation"),
        (r'HttpHeaders\s*\.\s*Location.*\$', "Location header with interpolation"),
        (r'response\s*\.\s*(?:setHeader|addHeader)\s*\(\s*"Location".*\$',
         "Location header set with user data"),
        (r'redirect\s*\(\s*(?:url|uri|link|returnUrl|redirectUrl|next|goto|target)',
         "Redirect using user-controlled parameter name"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text, re.IGNORECASE):
                    self._add("Medium", "Medium", "Open Redirect", "CWE-601",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Validate redirect URLs against an allowlist of trusted domains. "
                              "Use relative paths instead of absolute URLs for internal redirects.")


# --- 23. JWT Issues ---
class JWTDetector(VulnDetector):
    PATTERNS = [
        (r'algorithm\s*=\s*"none"', "JWT none algorithm"),
        (r'Algorithm\s*\.\s*none', "JWT none algorithm"),
        (r'\.setAllowedClockSkewSeconds\s*\(\s*\d{4,}', "JWT excessive clock skew"),
        (r'JwtParser.*setSigningKey\s*\(\s*"[^"]{1,20}"', "JWT weak signing key"),
        (r'(?:HS256|HS384|HS512).*"[^"]{1,20}"', "JWT weak secret for HMAC"),
        (r'\.parseClaimsJws.*catch.*\{\s*\}', "JWT verification error silenced"),
        (r'ignoreExpiration\s*=\s*true', "JWT expiration check disabled"),
        (r'jwk.*(?:publicKey|privateKey).*=.*"', "Hardcoded JWK key material"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text, re.IGNORECASE):
                    sev = "Critical" if "none" in desc.lower() else "High"
                    self._add(sev, "High", "JWT Security", "CWE-347",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Never use 'none' algorithm. Use strong keys (256+ bits for HMAC, "
                              "2048+ bits for RSA). Always validate expiration and issuer claims.")


# --- 24. Race Conditions ---
class RaceConditionDetector(VulnDetector):
    PATTERNS = [
        (r'(?:launch|async)\s*\{[^}]*(?:var\s+\w+|HashMap|ArrayList|mutableListOf|mutableMapOf)',
         "Mutable collection in coroutine"),
        (r'(?:Thread|Runnable)\s*\{[^}]*(?:var\s+\w+|\+\+|--)',
         "Mutable state in thread"),
        (r'\bHashMap\s*<', "Non-concurrent HashMap (thread-unsafe)"),
        (r'\bArrayList\s*<', "Non-thread-safe ArrayList"),
        (r'\bLinkedList\s*<', "Non-thread-safe LinkedList"),
        (r'@Volatile\s+var\s+\w+\s*:\s*(?:Int|Long|Boolean)',
         "Volatile alone insufficient for compound operations"),
    ]

    def detect(self):
        has_threading = bool(re.search(
            r'(?:launch|async|Thread|Runnable|Executor|synchronized|@Synchronized|Mutex|AtomicInteger)',
            self.source))

        if not has_threading:
            return

        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text):
                    # Skip if thread-safe variant is actually used
                    if "HashMap" in desc and "ConcurrentHashMap" in line_text:
                        continue
                    if "ArrayList" in desc and ("CopyOnWriteArrayList" in line_text or
                                                 "SynchronizedList" in line_text):
                        continue
                    self._add("Medium", "Low", "Race Condition", "CWE-362",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Use thread-safe collections (ConcurrentHashMap, CopyOnWriteArrayList) "
                              "or synchronization primitives (Mutex, synchronized, Atomic*).")


# --- 25. Missing Input Validation ---
class InputValidationDetector(VulnDetector):
    def detect(self):
        for func in self.parser.functions:
            params = func.attrs.get("params", [])
            body = func.attrs.get("body_text", "")
            name = func.attrs.get("name", "")

            # Check for web handler functions
            is_handler = any(kw in name.lower() for kw in
                             ["handle", "process", "route", "endpoint", "api",
                              "post", "get", "put", "delete", "patch"])

            if is_handler and params:
                for p in params:
                    pname = p.get("name", "")
                    ptype = p.get("type", "")
                    if ptype in ("String", "String?", "Any", "Any?"):
                        # Check if any validation is done
                        has_validation = any(v in body for v in [
                            f"{pname}.isEmpty", f"{pname}.isBlank", f"{pname}.length",
                            f"require(", f"check(", f"validate", f"{pname}.matches",
                            f"{pname}.trim", f"Regex", f"Pattern",
                        ])
                        if not has_validation and pname in body:
                            self._add("Medium", "Low", "Missing Input Validation", "CWE-20",
                                      f"Parameter '{pname}' in function '{name}' used without "
                                      f"apparent input validation",
                                      func.line, func.col,
                                      "Validate all input parameters: check for null/empty, "
                                      "validate length/format, sanitize special characters.")


# --- 26. Information Disclosure ---
class InfoDisclosureDetector(VulnDetector):
    PATTERNS = [
        (r'\.stackTrace', "Stack trace exposure"),
        (r'e\s*\.\s*printStackTrace\s*\(', "printStackTrace in production"),
        (r'e\s*\.\s*message', "Exception message in response (review)"),
        (r'(?:respond|return).*(?:stackTrace|exception\s*\.\s*message)',
         "Exception details in HTTP response"),
        (r'BuildConfig\s*\.\s*(?:DEBUG|VERSION)', "BuildConfig reference (review)"),
        (r'System\s*\.\s*getenv\s*\(', "Environment variable access in response"),
        (r'TODO\s*\(\s*"', "TODO marker (incomplete implementation)"),
        (r'FIXME\s*[:(]', "FIXME marker (known issue)"),
        (r'debug\s*=\s*true', "Debug mode enabled"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text, re.IGNORECASE):
                    sev = "Medium" if "stack" in desc.lower() or "exception" in desc.lower() else "Low"
                    conf = "Medium" if "stack" in desc.lower() else "Low"
                    self._add(sev, conf, "Information Disclosure", "CWE-200",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Do not expose internal details (stack traces, environment variables, "
                              "debug info) in responses. Use generic error messages in production.")


# --- 27. File Upload ---
class FileUploadDetector(VulnDetector):
    PATTERNS = [
        (r'\.transferTo\s*\(', "File upload transfer without validation"),
        (r'MultipartFile', "Multipart file upload"),
        (r'receiveMultipart', "Ktor multipart receive"),
        (r'\.copyTo\s*\(\s*File\s*\(', "File copy from upload"),
        (r'\.saveTo\s*\(', "File save from upload"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text):
                    # Check surrounding context for validation
                    context_start = max(0, line_num - 5)
                    context_end = min(len(self.lines), line_num + 5)
                    context = " ".join(self.lines[context_start:context_end]).lower()
                    has_validation = any(v in context for v in
                                         ["contenttype", "extension", "mimetype",
                                          "filesize", "maxsize", "allowedtypes",
                                          "validate", "check"])
                    if not has_validation:
                        self._add("High", "Medium", "File Upload", "CWE-434",
                                  f"File upload without apparent validation: {line_text.strip()}",
                                  line_num, 1,
                                  "Validate file type (MIME and extension), size, and content. "
                                  "Store uploads outside the web root. Generate random filenames.")


# --- 28. Timing Attack ---
class TimingAttackDetector(VulnDetector):
    PATTERNS = [
        (r'(?:password|token|secret|key|hash|hmac|signature|apiKey|api_key)\s*==\s*',
         "String equality for secret comparison"),
        (r'\.equals\s*\(\s*(?:password|token|secret|key|hash|hmac|signature)',
         "equals() for secret comparison"),
        (r'==\s*(?:password|token|secret|key|expectedHash|expectedToken)',
         "Equality check against secret"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text, re.IGNORECASE):
                    # Skip if MessageDigest.isEqual is used nearby
                    context_start = max(0, line_num - 3)
                    context_end = min(len(self.lines), line_num + 3)
                    context = " ".join(self.lines[context_start:context_end])
                    if "isEqual" in context or "constantTimeEquals" in context:
                        continue
                    self._add("Medium", "Medium", "Timing Attack", "CWE-208",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Use MessageDigest.isEqual() or a constant-time comparison function "
                              "for comparing secrets, tokens, and cryptographic values.")


# --- 29. Mass Assignment ---
class MassAssignmentDetector(VulnDetector):
    def detect(self):
        for dc in self.parser.data_classes:
            name = dc.attrs.get("name", "")
            params = dc.attrs.get("params", [])
            # Check if data class is used directly as request body
            has_sensitive_fields = any(
                p.get("name", "").lower() in ("role", "isadmin", "admin", "permission",
                                                "permissions", "privilege", "level",
                                                "status", "verified", "approved", "active",
                                                "salary", "price", "balance", "credit")
                for p in params
            )
            if has_sensitive_fields:
                # Look for Gson/Jackson/request body usage
                for line_num, line_text in enumerate(self.lines, 1):
                    if re.search(rf'(?:fromJson|readValue|receive|@RequestBody).*{re.escape(name)}',
                                 line_text, re.IGNORECASE):
                        self._add("High", "Medium", "Mass Assignment", "CWE-915",
                                  f"Data class '{name}' with sensitive fields used for deserialization: "
                                  f"{line_text.strip()}",
                                  line_num, 1,
                                  "Use separate DTOs for request/response. Filter sensitive fields "
                                  "(role, isAdmin, permissions) from user-controlled deserialization.")
                        break

        # Also check data classes used in @RequestBody annotations
        for line_num, line_text in enumerate(self.lines, 1):
            if re.search(r'@RequestBody', line_text):
                self._add("Low", "Low", "Mass Assignment", "CWE-915",
                          f"@RequestBody binding (verify DTO filtering): {line_text.strip()}",
                          line_num, 1,
                          "Use a DTO with only the fields users should control. Never bind directly "
                          "to entity/domain classes.")


# --- 30. CORS Misconfiguration ---
class CORSDetector(VulnDetector):
    PATTERNS = [
        (r'(?:allowedOrigins?|Access-Control-Allow-Origin)\s*[=(]\s*"\s*\*\s*"',
         "CORS allows all origins (*)"),
        (r'anyHost\s*\(\s*\)', "Ktor CORS anyHost()"),
        (r'allowCredentials\s*=\s*true.*anyHost', "Credentials with wildcard origin"),
        (r'Access-Control-Allow-Origin.*\$', "Dynamic CORS origin from user input"),
        (r'allowedOrigins\s*=\s*listOf\s*\(\s*"\s*\*\s*"\s*\)', "CORS wildcard in list"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text, re.IGNORECASE):
                    sev = "High" if "Credential" in desc else "Medium"
                    self._add(sev, "High", "CORS Misconfiguration", "CWE-942",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Specify exact allowed origins instead of wildcard. "
                              "Never combine credentials with wildcard origin.")


# --- 31. Unsafe Reflection ---
class UnsafeReflectionDetector(VulnDetector):
    PATTERNS = [
        (r'Class\s*\.\s*forName\s*\([^)]*\$', "Dynamic class loading with user input"),
        (r'\.java\s*\.\s*getDeclaredMethod\s*\([^)]*\$', "Reflection method lookup with input"),
        (r'\.java\s*\.\s*getDeclaredField\s*\([^)]*\$', "Reflection field access with input"),
        (r'::class\s*\.\s*(?:createInstance|java)', "Reflection class operations"),
        (r'KClass.*qualifiedName.*\$', "KClass with dynamic name"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text):
                    self._add("High", "Medium", "Unsafe Reflection", "CWE-470",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Avoid using user input in reflection calls. Maintain an allowlist "
                              "of permitted class names if dynamic loading is needed.")


# --- 32. Unvalidated Redirect ---
class UnvalidatedRedirectDetector(VulnDetector):
    PATTERNS = [
        (r'(?:startActivity|startActivityForResult)\s*\(\s*Intent\s*\(\s*Intent\s*\.\s*ACTION_VIEW.*\$',
         "Activity launch with user-controlled URL"),
        (r'Uri\s*\.\s*parse\s*\([^)]*\$', "Uri.parse with user input"),
        (r'CustomTabsIntent.*launchUrl\s*\([^)]*\$', "Custom tab with user URL"),
        (r'Intent\s*\(\s*Intent\s*\.\s*ACTION_VIEW\s*,\s*Uri\s*\.\s*parse\s*\([^)]*\$',
         "ACTION_VIEW intent with user URI"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text):
                    self._add("Medium", "Medium", "Unvalidated Redirect", "CWE-601",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Validate URLs against an allowlist before launching activities. "
                              "Check URL scheme (https only) and domain.")


# --- 33. Firebase Misconfiguration ---
class FirebaseDetector(VulnDetector):
    PATTERNS = [
        (r'"\.read"\s*:\s*"?true"?', "Firebase database read rule too permissive"),
        (r'"\.write"\s*:\s*"?true"?', "Firebase database write rule too permissive"),
        (r'FirebaseDatabase\s*\.\s*getInstance\s*\(\s*\)\s*\.\s*setPersistenceEnabled\s*\(\s*false',
         "Firebase persistence disabled"),
        (r'FirebaseAuth.*signInAnonymously', "Anonymous authentication (review access control)"),
        (r'google-services\.json', "Firebase config file reference"),
        (r'firebase.*apiKey\s*=\s*"[^"]*"', "Firebase API key in source"),
        (r'FirebaseStorage.*getReference\s*\([^)]*\$',
         "Firebase Storage with user-controlled reference"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text, re.IGNORECASE):
                    sev = "High" if "read" in desc.lower() or "write" in desc.lower() else "Medium"
                    self._add(sev, "Medium", "Firebase Misconfiguration", "CWE-732",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Use Firebase Security Rules to restrict access. Never allow public "
                              "read/write. Validate user authentication in rules.")


# --- 34. Jetpack Compose WebView ---
class ComposeSecurityDetector(VulnDetector):
    PATTERNS = [
        (r'AndroidView\s*\(\s*factory\s*=\s*\{[^}]*WebView',
         "WebView in Compose (review JS/file access settings)"),
        (r'AndroidView.*WebView.*javaScriptEnabled\s*=\s*true',
         "JS enabled in Compose WebView"),
        (r'WebView.*loadUrl\s*\([^)]*\$', "Compose WebView loadUrl with interpolation"),
        (r'AndroidView.*WebView.*addJavascriptInterface',
         "JavascriptInterface in Compose WebView"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text, re.DOTALL):
                    self._add("High", "Medium", "Jetpack Compose Security", "CWE-749",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Apply the same WebView security practices in Compose: disable JS "
                              "unless needed, validate URLs, avoid addJavascriptInterface.")

        # Multi-line Compose WebView detection
        in_compose_webview = False
        compose_wv_start = 0
        for line_num, line_text in enumerate(self.lines, 1):
            if re.search(r'AndroidView\s*\(', line_text):
                in_compose_webview = True
                compose_wv_start = line_num
            if in_compose_webview:
                if re.search(r'javaScriptEnabled\s*=\s*true', line_text):
                    self._add("High", "High", "Jetpack Compose Security", "CWE-749",
                              f"JavaScript enabled in Compose WebView: {line_text.strip()}",
                              line_num, 1,
                              "Disable JavaScript in WebView unless strictly required. "
                              "If needed, implement proper content security policies.")
                if re.search(r'\}(?:\s*\))?$', line_text) and line_num > compose_wv_start + 1:
                    in_compose_webview = False


# --- 35. KMM (Kotlin Multiplatform) ---
class KMMSecurityDetector(VulnDetector):
    PATTERNS = [
        (r'expect\s+(?:fun|class).*(?:encrypt|decrypt|hash|sign)',
         "KMM expect crypto (verify platform implementations)"),
        (r'actual\s+(?:fun|class).*(?:encrypt|decrypt|hash|sign)',
         "KMM actual crypto (verify platform-specific security)"),
        (r'expect\s+fun.*(?:store|save|persist).*(?:token|key|secret|password)',
         "KMM expect secure storage"),
        (r'Platform\s*\.\s*(?:isAndroid|isIOS|isJs)',
         "Platform-specific code (review security parity)"),
        (r'@SharedImmutable', "SharedImmutable annotation (review thread safety)"),
        (r'NSUserDefaults.*(?:password|token|secret|key)',
         "iOS NSUserDefaults for sensitive data"),
        (r'localStorage.*(?:password|token|secret|key)',
         "JS localStorage for sensitive data"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text, re.IGNORECASE):
                    sev = "Medium" if "review" in desc.lower() else "High"
                    self._add(sev, "Low", "KMM Security", "CWE-693",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Ensure security parity across all KMM platforms. Use platform-specific "
                              "secure storage (Keystore on Android, Keychain on iOS). Avoid JS localStorage "
                              "for secrets.")


# --- Additional Detectors ---

# --- 36. Insecure Data Storage ---
class InsecureStorageDetector(VulnDetector):
    PATTERNS = [
        (r'openFileOutput\s*\([^)]*MODE_WORLD_READABLE', "World-readable file"),
        (r'openFileOutput\s*\([^)]*MODE_WORLD_WRITEABLE', "World-writeable file"),
        (r'getExternalFilesDir|getExternalStorageDirectory', "External storage (world-readable)"),
        (r'\.writeText\s*\([^)]*(?:password|token|secret|key)', "Sensitive data written to file"),
        (r'Room\s*\.\s*databaseBuilder.*(?!.*\.openHelperFactory)',
         "Room database without encryption"),
        (r'SQLiteDatabase\s*\.\s*openOrCreateDatabase', "SQLite without encryption"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text, re.IGNORECASE):
                    self._add("High", "Medium", "Insecure Data Storage", "CWE-922",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Use EncryptedSharedPreferences or EncryptedFile for sensitive data. "
                              "Use SQLCipher for database encryption. Avoid external storage for secrets.")


# --- 37. Clipboard Vulnerability ---
class ClipboardDetector(VulnDetector):
    PATTERNS = [
        (r'ClipboardManager.*setPrimaryClip.*(?:password|token|secret)',
         "Sensitive data copied to clipboard"),
        (r'clipData.*(?:password|token|secret|key)', "Sensitive data in clipboard"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text, re.IGNORECASE):
                    self._add("Medium", "Medium", "Clipboard Vulnerability", "CWE-200",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Avoid putting sensitive data on the clipboard. If necessary, clear "
                              "it after a timeout. On Android 13+, clipboard is cleared automatically.")


# --- 38. Deep Link Vulnerability ---
class DeepLinkDetector(VulnDetector):
    PATTERNS = [
        (r'(?:intent-filter|IntentFilter).*(?:VIEW|BROWSABLE)',
         "Deep link handler (validate input)"),
        (r'data\s*\.\s*(?:host|path|scheme)\s*!!', "Force-unwrap deep link data"),
        (r'intent\s*\.\s*data\s*\.\s*(?:getQueryParameter|path|host)',
         "Deep link data used directly"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text, re.IGNORECASE):
                    self._add("Medium", "Medium", "Deep Link Vulnerability", "CWE-939",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Validate and sanitize all deep link parameters. Use App Links "
                              "(verified) instead of custom URI schemes when possible.")


# --- 39. Exposed Debug Endpoints ---
class DebugEndpointDetector(VulnDetector):
    PATTERNS = [
        (r'(?:route|get|post)\s*\(\s*"[^"]*(?:debug|test|admin|internal)',
         "Debug/test endpoint"),
        (r'(?:route|get|post)\s*\(\s*"[^"]*(?:dump|trace|phpinfo|status)',
         "Diagnostic endpoint"),
        (r'@GetMapping\s*\(\s*"[^"]*(?:debug|test|admin)',
         "Spring debug endpoint"),
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text, re.IGNORECASE):
                    self._add("Medium", "Low", "Debug Endpoint Exposed", "CWE-489",
                              f"{desc}: {line_text.strip()}", line_num, 1,
                              "Remove or protect debug/test endpoints in production. "
                              "Use feature flags or environment checks to disable them.")


# --- 40. XML External Entity (XXE) ---
class XXEDetector(VulnDetector):
    PATTERNS = [
        (r'DocumentBuilderFactory\s*\.\s*newInstance', "XML parsing (check XXE protection)"),
        (r'SAXParserFactory\s*\.\s*newInstance', "SAX parser (check XXE protection)"),
        (r'XMLInputFactory\s*\.\s*newInstance', "StAX parser (check XXE protection)"),
        (r'TransformerFactory\s*\.\s*newInstance', "XML transformer (check XXE)"),
    ]

    SAFE_FEATURES = [
        "FEATURE_SECURE_PROCESSING",
        "disallow-doctype-decl",
        "external-general-entities",
        "external-parameter-entities",
    ]

    def detect(self):
        for line_num, line_text in enumerate(self.lines, 1):
            for pat, desc in self.PATTERNS:
                if re.search(pat, line_text):
                    # Check surrounding lines for protection
                    context_start = max(0, line_num - 1)
                    context_end = min(len(self.lines), line_num + 10)
                    context = " ".join(self.lines[context_start:context_end])
                    has_protection = any(f in context for f in self.SAFE_FEATURES)
                    if not has_protection:
                        self._add("High", "Medium", "XML External Entity (XXE)", "CWE-611",
                                  f"{desc} without XXE protection: {line_text.strip()}",
                                  line_num, 1,
                                  "Disable external entity processing: set FEATURE_SECURE_PROCESSING, "
                                  "disallow DOCTYPE declarations, disable external entities.")


# ---------------------------------------------------------------------------
# 6. ANALYSIS ORCHESTRATOR
# ---------------------------------------------------------------------------

ALL_DETECTORS = [
    SQLInjectionDetector,       # 1
    CommandInjectionDetector,   # 2
    CodeInjectionDetector,      # 3
    XSSDetector,                # 4
    PathTraversalDetector,      # 5
    DeserializationDetector,    # 6
    SSRFDetector,               # 7
    HardcodedSecretsDetector,   # 8
    WeakCryptoDetector,         # 9
    InsecureRandomDetector,     # 10
    InsecureTLSDetector,        # 11
    SensitiveLoggingDetector,   # 12
    AndroidComponentDetector,   # 13
    IntentInjectionDetector,    # 14
    AndroidSQLDetector,         # 15
    AndroidWebViewDetector,     # 16
    AndroidCryptoDetector,      # 17
    KtorSecurityDetector,       # 18
    SpringSecurityDetector,     # 19
    CoroutineSafetyDetector,    # 20
    NullSafetyDetector,         # 21
    OpenRedirectDetector,       # 22
    JWTDetector,                # 23
    RaceConditionDetector,      # 24
    InputValidationDetector,    # 25
    InfoDisclosureDetector,     # 26
    FileUploadDetector,         # 27
    TimingAttackDetector,       # 28
    MassAssignmentDetector,     # 29
    CORSDetector,               # 30
    UnsafeReflectionDetector,   # 31
    UnvalidatedRedirectDetector,# 32
    FirebaseDetector,           # 33
    ComposeSecurityDetector,    # 34
    KMMSecurityDetector,        # 35
    InsecureStorageDetector,    # 36
    ClipboardDetector,          # 37
    DeepLinkDetector,           # 38
    DebugEndpointDetector,      # 39
    XXEDetector,                # 40
]


def analyze_file(file_path: str, source: str) -> List[dict]:
    """Analyze a single Kotlin file and return vulnerabilities."""
    try:
        tokens = tokenize(source)
    except Exception as e:
        logger.warning("Tokenization failed for %s: %s", file_path, e)
        return []

    try:
        parser = Parser(tokens)
        parser.parse()
    except Exception as e:
        logger.warning("Parsing failed for %s: %s", file_path, e)
        return []

    try:
        taint = TaintTracker(parser)
        taint.analyze()
    except Exception as e:
        logger.warning("Taint analysis failed for %s: %s", file_path, e)
        taint = TaintTracker(parser)

    results: List[dict] = []
    seen: Set[str] = set()

    for DetectorClass in ALL_DETECTORS:
        try:
            detector = DetectorClass(file_path, source, parser, taint)
            detector.detect()
            for v in detector.vulns:
                # Deduplicate by (file, line, category)
                key = f"{v.file_path}:{v.line}:{v.category}:{v.description[:60]}"
                if key in seen:
                    continue
                seen.add(key)
                results.append({
                    "id": v.vuln_id,
                    "severity": v.severity,
                    "confidence": v.confidence,
                    "category": v.category,
                    "cwe": v.cwe,
                    "description": v.description,
                    "filePath": v.file_path,
                    "lineNumber": v.line,
                    "columnNumber": v.column,
                    "codeSnippet": v.code_snippet,
                    "recommendation": v.recommendation,
                })
        except Exception as e:
            logger.warning("Detector %s failed on %s: %s",
                           DetectorClass.__name__, file_path, e)

    return results


# ---------------------------------------------------------------------------
# 7. FASTAPI SERVER
# ---------------------------------------------------------------------------

app = FastAPI(title="Kotlin SAST Scanner", version="1.0.0")

KOTLIN_EXTENSIONS = frozenset([".kt", ".kts"])


class ScanRequest(BaseModel):
    files: Dict[str, str]
    scanId: str = ""


class HealthResponse(BaseModel):
    status: str
    scanner: str
    version: str
    supported_extensions: List[str]
    vulnerability_categories: int


@app.get("/health")
async def health() -> HealthResponse:
    return HealthResponse(
        status="healthy",
        scanner="kotlin",
        version="1.0.0",
        supported_extensions=sorted(KOTLIN_EXTENSIONS),
        vulnerability_categories=len(ALL_DETECTORS),
    )


@app.post("/scan")
async def scan(req: ScanRequest):
    scan_id = req.scanId or str(uuid.uuid4())
    start = time.time()
    logger.info("Scan %s started with %d files", scan_id, len(req.files))

    all_vulns: List[dict] = []
    file_count = 0
    errors: List[str] = []

    for path, content in req.files.items():
        # Filter by extension
        ext = ""
        dot_idx = path.rfind(".")
        if dot_idx >= 0:
            ext = path[dot_idx:]
        if ext.lower() not in {e.lower() for e in KOTLIN_EXTENSIONS}:
            continue

        file_count += 1
        try:
            vulns = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(None, analyze_file, path, content),
                timeout=30.0,
            )
            all_vulns.extend(vulns)
        except asyncio.TimeoutError:
            errors.append(f"Timeout analyzing {path}")
            logger.warning("Timeout analyzing %s in scan %s", path, scan_id)
        except Exception as exc:
            errors.append(f"Error analyzing {path}: {str(exc)}")
            logger.exception("Error analyzing %s in scan %s", path, scan_id)

    elapsed = time.time() - start
    logger.info("Scan %s complete: %d files, %d vulns, %.2fs",
                scan_id, file_count, len(all_vulns), elapsed)

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for v in all_vulns:
        sev = v.get("severity", "Info")
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "scanId": scan_id,
        "scanner": "kotlin",
        "version": "1.0.0",
        "filesScanned": file_count,
        "totalVulnerabilities": len(all_vulns),
        "severityCounts": severity_counts,
        "vulnerabilities": all_vulns,
        "errors": errors,
        "elapsedSeconds": round(elapsed, 3),
    }


# ---------------------------------------------------------------------------
# 8. MAIN
# ---------------------------------------------------------------------------

def main():
    logger.info("Starting Kotlin SAST Scanner on port 9012")
    uvicorn.run(app, host="0.0.0.0", port=9012, log_level="info")


if __name__ == "__main__":
    main()
