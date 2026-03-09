from __future__ import annotations
"""
C/C++ SAST Scanner - Production-grade static analysis engine.
FastAPI service on port 9008 with tokenizer, parser, data flow, and 40+ vuln detectors.
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
logger = logging.getLogger("cpp-scanner")

# ---------------------------------------------------------------------------
# 1. TOKENIZER
# ---------------------------------------------------------------------------

class TT(enum.Enum):
    """Token types."""
    KEYWORD = "KEYWORD"
    IDENT = "IDENT"
    INT_LIT = "INT_LIT"
    FLOAT_LIT = "FLOAT_LIT"
    STRING_LIT = "STRING_LIT"
    CHAR_LIT = "CHAR_LIT"
    OP = "OP"
    PUNCT = "PUNCT"
    PREPROC = "PREPROC"
    COMMENT = "COMMENT"
    EOF = "EOF"


C_KEYWORDS = frozenset([
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if",
    "inline", "int", "long", "register", "restrict", "return", "short",
    "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
    "unsigned", "void", "volatile", "while", "_Bool", "_Complex", "_Imaginary",
    # C++ additions
    "bool", "catch", "class", "const_cast", "delete", "dynamic_cast",
    "explicit", "export", "false", "friend", "mutable", "namespace", "new",
    "operator", "private", "protected", "public", "reinterpret_cast",
    "static_cast", "template", "this", "throw", "true", "try", "typeid",
    "typename", "using", "virtual", "wchar_t",
    # C++11+
    "nullptr", "override", "final", "noexcept", "decltype", "constexpr",
    "static_assert", "thread_local", "alignas", "alignof", "char16_t",
    "char32_t", "unique_ptr", "shared_ptr", "make_unique", "make_shared",
    # Common types
    "size_t", "ssize_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "int8_t", "int16_t", "int32_t", "int64_t", "FILE", "NULL",
])


@dataclass
class Token:
    tt: TT
    val: str
    line: int
    col: int


def tokenize(source: str) -> List[Token]:
    """Tokenize C/C++ source into a list of Token objects."""
    tokens: List[Token] = []
    i = 0
    n = len(source)
    line = 1
    col = 1

    while i < n:
        ch = source[i]

        # Whitespace
        if ch in " \t\r":
            if ch == "\t":
                col += 4
            else:
                col += 1
            i += 1
            continue
        if ch == "\n":
            line += 1
            col = 1
            i += 1
            continue

        # Preprocessor directive
        if ch == "#" and (col == 1 or source[max(0, i - 1)] == "\n" or source[i - 1:i].strip() == ""):
            start = i
            while i < n and source[i] != "\n":
                if source[i] == "\\" and i + 1 < n and source[i + 1] == "\n":
                    i += 2
                    line += 1
                    col = 1
                    continue
                i += 1
            tokens.append(Token(TT.PREPROC, source[start:i], line, col))
            continue

        # Line comment
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            start = i
            while i < n and source[i] != "\n":
                i += 1
            tokens.append(Token(TT.COMMENT, source[start:i], line, col))
            continue

        # Block comment
        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            start = i
            start_line = line
            start_col = col
            i += 2
            col += 2
            while i < n:
                if source[i] == "*" and i + 1 < n and source[i + 1] == "/":
                    i += 2
                    col += 2
                    break
                if source[i] == "\n":
                    line += 1
                    col = 1
                else:
                    col += 1
                i += 1
            tokens.append(Token(TT.COMMENT, source[start:i], start_line, start_col))
            continue

        # String literal
        if ch == '"':
            start = i
            start_col = col
            i += 1
            col += 1
            while i < n and source[i] != '"':
                if source[i] == "\\":
                    i += 2
                    col += 2
                    continue
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
            tokens.append(Token(TT.STRING_LIT, source[start:i], line, start_col))
            continue

        # Char literal
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

        # Numbers
        if ch.isdigit() or (ch == "." and i + 1 < n and source[i + 1].isdigit()):
            start = i
            start_col = col
            is_float = ch == "."
            # hex
            if ch == "0" and i + 1 < n and source[i + 1] in "xX":
                i += 2
                col += 2
                while i < n and (source[i] in "0123456789abcdefABCDEF_"):
                    i += 1
                    col += 1
            else:
                while i < n and (source[i].isdigit() or source[i] == "_"):
                    i += 1
                    col += 1
                if i < n and source[i] == ".":
                    is_float = True
                    i += 1
                    col += 1
                    while i < n and source[i].isdigit():
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
            # Suffixes
            while i < n and source[i] in "uUlLfF":
                i += 1
                col += 1
            tt = TT.FLOAT_LIT if is_float else TT.INT_LIT
            tokens.append(Token(tt, source[start:i], line, start_col))
            continue

        # Identifiers / keywords
        if ch.isalpha() or ch == "_":
            start = i
            start_col = col
            while i < n and (source[i].isalnum() or source[i] == "_"):
                i += 1
                col += 1
            word = source[start:i]
            tt = TT.KEYWORD if word in C_KEYWORDS else TT.IDENT
            tokens.append(Token(tt, word, line, start_col))
            continue

        # Multi-char operators
        two = source[i:i + 2] if i + 1 < n else ""
        three = source[i:i + 3] if i + 2 < n else ""
        if three in ("<<=", ">>=", "..."):
            tokens.append(Token(TT.OP, three, line, col))
            i += 3
            col += 3
            continue
        if two in ("->", "++", "--", "<<", ">>", "<=", ">=", "==", "!=",
                    "&&", "||", "+=", "-=", "*=", "/=", "%=", "&=", "|=",
                    "^=", "::", "##"):
            tokens.append(Token(TT.OP, two, line, col))
            i += 2
            col += 2
            continue

        # Single-char ops and punctuation
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

        # Skip unknown chars
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
# 3. PARSER  (lightweight, best-effort -- does NOT need full C grammar)
# ---------------------------------------------------------------------------

class Parser:
    """
    Best-effort C/C++ parser that extracts enough structure for SAST analysis.
    Produces function defs, variable decls, function calls, assignments, control flow.
    """

    def __init__(self, tokens: List[Token]):
        self.tokens = [t for t in tokens if t.tt not in (TT.COMMENT,)]
        self.pos = 0
        self.functions: List[ASTNode] = []
        self.globals: List[ASTNode] = []
        self.calls: List[ASTNode] = []
        self.assignments: List[ASTNode] = []
        self.var_decls: List[ASTNode] = []
        self.control_flow: List[ASTNode] = []
        self.preprocessor: List[ASTNode] = []
        self.structs: List[ASTNode] = []
        self.string_literals: List[Token] = []
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

    def skip_to_matching_brace(self):
        depth = 1
        self.advance()  # skip opening {
        while self.cur().tt != TT.EOF and depth > 0:
            if self.cur().val == "{":
                depth += 1
            elif self.cur().val == "}":
                depth -= 1
            self.advance()

    def skip_to_matching_paren(self) -> List[Token]:
        """Skip from ( to matching ), returning tokens inside."""
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

    def parse(self):
        """Main parse loop."""
        while self.cur().tt != TT.EOF:
            self._parse_top_level()

    def _parse_top_level(self):
        t = self.cur()

        if t.tt == TT.PREPROC:
            self.preprocessor.append(ASTNode("preprocessor", t.line, t.col, attrs={"text": t.val}))
            self.advance()
            return

        if t.tt == TT.EOF:
            return

        # struct/class/union
        if t.val in ("struct", "class", "union"):
            self._parse_struct_or_class()
            return

        # typedef - skip
        if t.val == "typedef":
            self._skip_statement()
            return

        # Try to detect function definition vs variable declaration
        if self._is_likely_function_def():
            self._parse_function_def()
            return

        # Anything else: try to parse as statement
        self._parse_statement()

    def _is_likely_function_def(self) -> bool:
        """Look ahead to see if this is a function definition (has { after params)."""
        save = self.pos
        # Skip type specifiers
        while self.cur().tt in (TT.KEYWORD, TT.IDENT, TT.OP) and self.cur().val not in ("(", "{", ";", "="):
            if self.cur().val in ("*", "&", "const", "static", "extern", "inline",
                                  "virtual", "unsigned", "signed", "long", "short",
                                  "volatile", "struct", "class", "enum", "::"):
                self.pos += 1
                continue
            if self.cur().tt in (TT.KEYWORD, TT.IDENT):
                self.pos += 1
                continue
            break

        result = False
        if self.cur().val == "(":
            depth = 1
            self.pos += 1
            while self.cur().tt != TT.EOF and depth > 0:
                if self.cur().val == "(":
                    depth += 1
                elif self.cur().val == ")":
                    depth -= 1
                self.pos += 1
            # After ), look for { or : (constructor init list) or const
            while self.cur().val in ("const", "noexcept", "override", "final"):
                self.pos += 1
            if self.cur().val == ":":
                # Constructor init list
                self.pos += 1
                while self.cur().tt != TT.EOF and self.cur().val != "{":
                    self.pos += 1
            if self.cur().val == "{":
                result = True

        self.pos = save
        return result

    def _parse_function_def(self):
        start_line = self.cur().line
        start_col = self.cur().col

        # Collect return type + name
        type_tokens: List[str] = []
        func_name = ""
        while self.cur().val != "(" and self.cur().tt != TT.EOF:
            type_tokens.append(self.cur().val)
            self.advance()

        if len(type_tokens) >= 1:
            func_name = type_tokens[-1]
            ret_type = " ".join(type_tokens[:-1]) if len(type_tokens) > 1 else "void"
        else:
            func_name = "<unknown>"
            ret_type = "void"

        # Parse params
        params: List[dict] = []
        if self.cur().val == "(":
            param_tokens = self.skip_to_matching_paren()
            params = self._parse_params(param_tokens)

        # Skip const/noexcept/override
        while self.cur().val in ("const", "noexcept", "override", "final"):
            self.advance()

        # Skip constructor init list
        if self.cur().val == ":":
            self.advance()
            while self.cur().tt != TT.EOF and self.cur().val != "{":
                self.advance()

        # Parse body
        body_stmts: List[ASTNode] = []
        if self.cur().val == "{":
            body_stmts = self._parse_block()

        node = ASTNode("function_def", start_line, start_col, children=body_stmts,
                        attrs={"name": func_name, "return_type": ret_type, "params": params})
        self.functions.append(node)

    def _parse_params(self, tokens: List[Token]) -> List[dict]:
        params = []
        current: List[Token] = []
        for t in tokens:
            if t.val == "," and not any(tt.val == "(" for tt in current):
                if current:
                    params.append(self._extract_param(current))
                current = []
            else:
                current.append(t)
        if current:
            params.append(self._extract_param(current))
        return params

    def _extract_param(self, tokens: List[Token]) -> dict:
        # Last identifier is the name, rest is type
        names = [t for t in tokens if t.tt == TT.IDENT or (t.tt == TT.KEYWORD and t.val not in ("const", "unsigned", "signed", "volatile", "struct", "class", "enum"))]
        all_vals = [t.val for t in tokens]
        if len(names) >= 1:
            name = names[-1].val
            type_str = " ".join(v for v in all_vals if v != name or all_vals.count(name) > 1)
            if not type_str:
                type_str = name
                name = ""
        else:
            name = ""
            type_str = " ".join(all_vals)
        return {"name": name, "type": type_str}

    def _parse_block(self) -> List[ASTNode]:
        stmts: List[ASTNode] = []
        if self.cur().val != "{":
            return stmts
        self.advance()  # skip {
        depth = 1
        while self.cur().tt != TT.EOF and depth > 0:
            if self.cur().val == "}":
                depth -= 1
                if depth == 0:
                    self.advance()
                    return stmts
            stmt = self._parse_statement()
            if stmt:
                stmts.append(stmt)
        return stmts

    def _parse_statement(self) -> Optional[ASTNode]:
        t = self.cur()

        if t.tt == TT.EOF:
            return None

        if t.val == "{":
            children = self._parse_block()
            return ASTNode("block", t.line, t.col, children=children)

        if t.val == "}":
            self.advance()
            return None

        if t.tt == TT.PREPROC:
            self.preprocessor.append(ASTNode("preprocessor", t.line, t.col, attrs={"text": t.val}))
            self.advance()
            return None

        # Control flow
        if t.val in ("if", "while", "for", "switch", "do"):
            return self._parse_control_flow()

        if t.val == "return":
            return self._parse_return()

        # Variable declaration detection
        if self._is_likely_var_decl():
            return self._parse_var_decl()

        # Try to detect function call or assignment
        return self._parse_expression_statement()

    def _is_likely_var_decl(self) -> bool:
        """Check if current position looks like a variable declaration."""
        t = self.cur()
        if t.val in ("const", "static", "volatile", "extern", "register",
                      "unsigned", "signed", "long", "short", "struct", "class",
                      "enum", "auto", "thread_local", "mutable"):
            return True
        type_keywords = ("int", "char", "float", "double", "void", "bool",
                         "size_t", "ssize_t", "uint8_t", "uint16_t", "uint32_t",
                         "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t",
                         "FILE", "wchar_t", "_Bool")
        if t.val in type_keywords:
            return True
        # Identifier followed by identifier or * identifier => likely type name varname
        if t.tt == TT.IDENT:
            nxt = self.peek()
            if nxt.tt == TT.IDENT:
                return True
            if nxt.val == "*":
                return True
            if nxt.val == "::":
                return True
        return False

    def _parse_var_decl(self) -> Optional[ASTNode]:
        start = self.cur()
        type_parts: List[str] = []
        # Gather type
        while self.cur().tt != TT.EOF and self.cur().val not in (";", "=", "(", "{", ","):
            if self.cur().val in ("*", "&", "[", "]"):
                type_parts.append(self.cur().val)
                self.advance()
                continue
            type_parts.append(self.cur().val)
            self.advance()

        # Extract: last IDENT-like token is the variable name
        var_name = ""
        type_str = ""
        ident_indices = [i for i, p in enumerate(type_parts) if p.isidentifier() and p not in C_KEYWORDS]
        if ident_indices:
            last_ident_idx = ident_indices[-1]
            var_name = type_parts[last_ident_idx]
            remaining = type_parts[:last_ident_idx] + type_parts[last_ident_idx + 1:]
            type_str = " ".join(remaining)
        elif type_parts:
            var_name = type_parts[-1]
            type_str = " ".join(type_parts[:-1])

        # Array size
        array_size = ""
        init_val = ""

        # Check for = initializer
        if self.cur().val == "=":
            self.advance()
            init_tokens: List[str] = []
            depth = 0
            while self.cur().tt != TT.EOF:
                if self.cur().val == "(" or self.cur().val == "{":
                    depth += 1
                elif self.cur().val == ")" or self.cur().val == "}":
                    depth -= 1
                if self.cur().val in (";", ",") and depth <= 0:
                    break
                init_tokens.append(self.cur().val)
                self.advance()
            init_val = " ".join(init_tokens)

        # Check for ( constructor call
        if self.cur().val == "(":
            inner = self.skip_to_matching_paren()
            init_val = "(" + " ".join(t.val for t in inner) + ")"

        node = ASTNode("var_decl", start.line, start.col,
                        attrs={"name": var_name, "type": type_str, "init": init_val})
        self.var_decls.append(node)

        # Skip ; or ,
        if self.cur().val in (";", ","):
            self.advance()

        return node

    def _parse_control_flow(self) -> ASTNode:
        t = self.advance()
        node = ASTNode("control_flow", t.line, t.col, attrs={"keyword": t.val})
        self.control_flow.append(node)

        if t.val == "do":
            if self.cur().val == "{":
                node.children = self._parse_block()
            # while condition
            if self.cur().val == "while":
                self.advance()
            if self.cur().val == "(":
                cond_tokens = self.skip_to_matching_paren()
                node.attrs["condition"] = " ".join(tk.val for tk in cond_tokens)
            if self.cur().val == ";":
                self.advance()
            return node

        # Condition
        if self.cur().val == "(":
            cond_tokens = self.skip_to_matching_paren()
            node.attrs["condition"] = " ".join(tk.val for tk in cond_tokens)

        # Body
        if self.cur().val == "{":
            node.children = self._parse_block()
        else:
            stmt = self._parse_statement()
            if stmt:
                node.children.append(stmt)

        # else
        if t.val == "if" and self.cur().val == "else":
            self.advance()
            if self.cur().val == "{":
                else_stmts = self._parse_block()
                node.attrs["has_else"] = True
                node.children.extend(else_stmts)
            else:
                stmt = self._parse_statement()
                if stmt:
                    node.children.append(stmt)
                node.attrs["has_else"] = True

        return node

    def _parse_return(self) -> ASTNode:
        t = self.advance()  # skip return
        ret_tokens: List[str] = []
        depth = 0
        while self.cur().tt != TT.EOF:
            if self.cur().val in ("(", "{", "["):
                depth += 1
            elif self.cur().val in (")", "}", "]"):
                depth -= 1
            if self.cur().val == ";" and depth <= 0:
                self.advance()
                break
            ret_tokens.append(self.cur().val)
            self.advance()
        node = ASTNode("return", t.line, t.col, attrs={"expr": " ".join(ret_tokens)})
        return node

    def _parse_expression_statement(self) -> Optional[ASTNode]:
        """Parse an expression statement: function call, assignment, etc."""
        t = self.cur()
        if t.tt == TT.EOF:
            return None

        # Collect tokens until ;
        stmt_tokens: List[Token] = []
        depth = 0
        while self.cur().tt != TT.EOF:
            if self.cur().val in ("(", "{", "["):
                depth += 1
            elif self.cur().val in (")", "}", "]"):
                depth -= 1
                if depth < 0:
                    break
            if self.cur().val == ";" and depth <= 0:
                self.advance()
                break
            stmt_tokens.append(self.cur())
            self.advance()

        if not stmt_tokens:
            if self.cur().tt != TT.EOF:
                self.advance()
            return None

        # Detect function calls within statement
        self._extract_calls_from_tokens(stmt_tokens)

        # Detect assignments
        self._extract_assignments_from_tokens(stmt_tokens)

        # Detect string literals
        for tk in stmt_tokens:
            if tk.tt == TT.STRING_LIT:
                self.string_literals.append(tk)

        return ASTNode("expr_stmt", t.line, t.col,
                        attrs={"tokens": [tk.val for tk in stmt_tokens],
                               "raw": " ".join(tk.val for tk in stmt_tokens)})

    def _extract_calls_from_tokens(self, tokens: List[Token]):
        """Find function calls in a token list."""
        for i, t in enumerate(tokens):
            if (t.tt in (TT.IDENT, TT.KEYWORD) and
                    i + 1 < len(tokens) and tokens[i + 1].val == "("):
                # Collect arguments
                args = self._collect_call_args(tokens, i + 1)
                node = ASTNode("call", t.line, t.col,
                                attrs={"name": t.val, "args": args,
                                       "arg_tokens": self._get_arg_token_lists(tokens, i + 1)})
                self.calls.append(node)

    def _collect_call_args(self, tokens: List[Token], paren_idx: int) -> List[str]:
        """Collect argument strings from a call starting at paren_idx."""
        args: List[str] = []
        depth = 0
        current: List[str] = []
        i = paren_idx + 1  # skip (
        while i < len(tokens):
            t = tokens[i]
            if t.val == "(":
                depth += 1
                current.append(t.val)
            elif t.val == ")":
                if depth == 0:
                    if current:
                        args.append(" ".join(current).strip())
                    break
                depth -= 1
                current.append(t.val)
            elif t.val == "," and depth == 0:
                args.append(" ".join(current).strip())
                current = []
            else:
                current.append(t.val)
            i += 1
        return args

    def _get_arg_token_lists(self, tokens: List[Token], paren_idx: int) -> List[List[str]]:
        """Get argument token lists."""
        args: List[List[str]] = []
        depth = 0
        current: List[str] = []
        i = paren_idx + 1
        while i < len(tokens):
            t = tokens[i]
            if t.val == "(":
                depth += 1
                current.append(t.val)
            elif t.val == ")":
                if depth == 0:
                    if current:
                        args.append(current)
                    break
                depth -= 1
                current.append(t.val)
            elif t.val == "," and depth == 0:
                args.append(current)
                current = []
            else:
                current.append(t.val)
            i += 1
        return args

    def _extract_assignments_from_tokens(self, tokens: List[Token]):
        for i, t in enumerate(tokens):
            if t.val == "=" and i > 0 and (i < 1 or tokens[i - 1].val not in ("=", "!", "<", ">")) and (i + 1 >= len(tokens) or tokens[i + 1].val != "="):
                lhs = tokens[i - 1].val if i > 0 else ""
                rhs_parts = [tk.val for tk in tokens[i + 1:]]
                node = ASTNode("assignment", t.line, t.col,
                                attrs={"lhs": lhs, "rhs": " ".join(rhs_parts),
                                       "rhs_tokens": rhs_parts})
                self.assignments.append(node)

    def _parse_struct_or_class(self):
        t = self.advance()
        name = ""
        if self.cur().tt == TT.IDENT:
            name = self.advance().val

        # Skip inheritance
        if self.cur().val == ":":
            while self.cur().tt != TT.EOF and self.cur().val != "{":
                self.advance()

        if self.cur().val == "{":
            self.skip_to_matching_brace()

        if self.cur().val == ";":
            self.advance()

        self.structs.append(ASTNode("struct", t.line, t.col, attrs={"name": name, "keyword": t.val}))

    def _skip_statement(self):
        depth = 0
        while self.cur().tt != TT.EOF:
            if self.cur().val in ("(", "{", "["):
                depth += 1
            elif self.cur().val in (")", "}", "]"):
                depth -= 1
            if self.cur().val == ";" and depth <= 0:
                self.advance()
                return
            if self.cur().val == "}" and depth <= 0:
                self.advance()
                if self.cur().val == ";":
                    self.advance()
                return
            self.advance()


# ---------------------------------------------------------------------------
# 4. DATA FLOW ANALYSIS
# ---------------------------------------------------------------------------

@dataclass
class VarState:
    name: str
    allocated: bool = False        # malloc/calloc/realloc/new
    freed: bool = False            # free/delete called
    initialized: bool = False      # assigned a value
    tainted: bool = False          # from user input
    alloc_line: int = 0
    free_line: int = 0
    decl_line: int = 0
    last_use_line: int = 0
    type_str: str = ""
    is_fd: bool = False            # file descriptor / FILE*
    fd_closed: bool = False
    null_checked: bool = False


class DataFlowAnalyzer:
    """Track variable states through function bodies."""

    ALLOC_FUNCS = frozenset(["malloc", "calloc", "realloc", "strdup", "strndup",
                              "aligned_alloc", "valloc", "pvalloc", "memalign"])
    FREE_FUNCS = frozenset(["free", "cfree"])
    INPUT_FUNCS = frozenset(["scanf", "fscanf", "sscanf", "gets", "fgets", "read",
                              "recv", "recvfrom", "recvmsg", "getenv", "fread",
                              "getline", "getdelim", "readline", "fgetc", "getc",
                              "getchar"])
    OPEN_FUNCS = frozenset(["fopen", "open", "creat", "socket", "accept",
                             "pipe", "dup", "dup2", "fdopen", "tmpfile", "mkstemp"])
    CLOSE_FUNCS = frozenset(["fclose", "close", "closesocket", "shutdown"])

    def __init__(self, parser: Parser):
        self.parser = parser
        self.var_states: Dict[str, VarState] = {}
        self.issues: List[dict] = []

    def analyze_function(self, func: ASTNode):
        """Analyze a single function for data flow issues."""
        self.var_states = {}

        # Register parameters
        for p in func.attrs.get("params", []):
            name = p.get("name", "")
            if name:
                self.var_states[name] = VarState(
                    name=name, initialized=True, decl_line=func.line,
                    type_str=p.get("type", ""))

        # Walk the function body
        self._walk_stmts(func.children, func.attrs.get("name", ""))

        # Check for leaks at end of function
        self._check_end_of_function(func)

    def _walk_stmts(self, stmts: List[ASTNode], func_name: str):
        for stmt in stmts:
            self._process_node(stmt, func_name)

    def _process_node(self, node: ASTNode, func_name: str):
        if node.kind == "var_decl":
            name = node.attrs.get("name", "")
            init = node.attrs.get("init", "")
            type_str = node.attrs.get("type", "")
            if name:
                vs = VarState(name=name, decl_line=node.line, type_str=type_str)
                if init:
                    vs.initialized = True
                    for af in self.ALLOC_FUNCS:
                        if af in init:
                            vs.allocated = True
                            vs.alloc_line = node.line
                            break
                    if "new " in init or "new[" in init:
                        vs.allocated = True
                        vs.alloc_line = node.line
                    for inp in self.INPUT_FUNCS:
                        if inp in init:
                            vs.tainted = True
                            break
                if "FILE" in type_str or "fd" in name.lower() or "socket" in name.lower():
                    vs.is_fd = True
                    for of in self.OPEN_FUNCS:
                        if of in init:
                            vs.is_fd = True
                            break
                self.var_states[name] = vs

        elif node.kind == "call":
            self._process_call(node, func_name)

        elif node.kind == "assignment":
            lhs = node.attrs.get("lhs", "")
            rhs = node.attrs.get("rhs", "")
            if lhs in self.var_states:
                vs = self.var_states[lhs]
                vs.initialized = True
                vs.last_use_line = node.line
                for af in self.ALLOC_FUNCS:
                    if af in rhs:
                        vs.allocated = True
                        vs.alloc_line = node.line
                        vs.freed = False
                        break
                if "new " in rhs or "new[" in rhs:
                    vs.allocated = True
                    vs.alloc_line = node.line
                    vs.freed = False

        elif node.kind == "control_flow":
            cond = node.attrs.get("condition", "")
            # Track null checks
            for vname, vs in self.var_states.items():
                if vname in cond and ("NULL" in cond or "nullptr" in cond or "!" in cond or "== 0" in cond):
                    vs.null_checked = True

        elif node.kind == "return":
            expr = node.attrs.get("expr", "")
            # Check returning pointer to local
            if expr.startswith("&"):
                local_name = expr[1:].strip()
                if local_name in self.var_states:
                    vs = self.var_states[local_name]
                    if not vs.allocated:
                        self.issues.append({
                            "type": "return_local_ptr",
                            "var": local_name,
                            "line": node.line
                        })

        # Recurse into children
        for child in node.children:
            self._process_node(child, func_name)

    def _process_call(self, node: ASTNode, func_name: str):
        call_name = node.attrs.get("name", "")
        args = node.attrs.get("args", [])

        # Track free/delete
        if call_name in self.FREE_FUNCS and args:
            var = args[0].strip()
            if var in self.var_states:
                vs = self.var_states[var]
                if vs.freed:
                    self.issues.append({
                        "type": "double_free",
                        "var": var,
                        "line": node.line,
                        "prev_free_line": vs.free_line
                    })
                vs.freed = True
                vs.free_line = node.line

        # Track close
        if call_name in self.CLOSE_FUNCS and args:
            var = args[0].strip()
            if var in self.var_states:
                self.var_states[var].fd_closed = True

        # Track use-after-free
        for arg in args:
            arg_stripped = arg.strip()
            if arg_stripped in self.var_states:
                vs = self.var_states[arg_stripped]
                vs.last_use_line = node.line
                if vs.freed and call_name not in self.FREE_FUNCS:
                    self.issues.append({
                        "type": "use_after_free",
                        "var": arg_stripped,
                        "line": node.line,
                        "free_line": vs.free_line
                    })

        # Track allocations in call args (e.g. ptr = malloc(...))
        if call_name in self.ALLOC_FUNCS:
            pass  # Handled in assignment tracking

        # Track taint propagation from input functions
        if call_name in self.INPUT_FUNCS:
            for arg in args:
                arg_stripped = arg.strip().lstrip("&")
                if arg_stripped in self.var_states:
                    self.var_states[arg_stripped].tainted = True

    def _check_end_of_function(self, func: ASTNode):
        for name, vs in self.var_states.items():
            if vs.allocated and not vs.freed:
                self.issues.append({
                    "type": "memory_leak",
                    "var": name,
                    "line": vs.alloc_line or vs.decl_line,
                    "func": func.attrs.get("name", "")
                })
            if vs.is_fd and not vs.fd_closed and vs.initialized:
                self.issues.append({
                    "type": "resource_leak",
                    "var": name,
                    "line": vs.decl_line,
                    "func": func.attrs.get("name", "")
                })

    def analyze_all(self):
        for func in self.parser.functions:
            self.analyze_function(func)


# ---------------------------------------------------------------------------
# 5. VULNERABILITY DETECTORS
# ---------------------------------------------------------------------------

@dataclass
class Vulnerability:
    id: str
    title: str
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


BANNED_FUNCTIONS = {
    "gets": ("CWE-120", "Critical", "gets() has no bounds checking and always causes buffer overflow"),
    "mktemp": ("CWE-377", "High", "mktemp() creates predictable temporary file names"),
    "tmpnam": ("CWE-377", "High", "tmpnam() creates predictable temporary file names"),
    "tempnam": ("CWE-377", "High", "tempnam() creates predictable temporary file names"),
    "getwd": ("CWE-120", "High", "getwd() has no buffer length check"),
    "getpass": ("CWE-676", "Medium", "getpass() is obsolete and insecure"),
}

UNSAFE_STRING_FUNCS = {
    "strcpy": ("strncpy or strlcpy", "CWE-120"),
    "strcat": ("strncat or strlcat", "CWE-120"),
    "sprintf": ("snprintf", "CWE-120"),
    "vsprintf": ("vsnprintf", "CWE-120"),
    "wcscpy": ("wcsncpy", "CWE-120"),
    "wcscat": ("wcsncat", "CWE-120"),
}

FORMAT_STRING_FUNCS = frozenset([
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
    "vsprintf", "vsnprintf", "syslog", "wprintf", "fwprintf", "swprintf",
    "dprintf", "asprintf",
])

EXEC_FUNCS = frozenset(["system", "popen", "exec", "execl", "execle", "execlp",
                          "execv", "execvp", "execvpe", "execve", "ShellExecute",
                          "WinExec", "CreateProcess", "CreateProcessA", "CreateProcessW"])

SQL_FUNCS = frozenset(["sqlite3_exec", "mysql_query", "mysql_real_query",
                        "PQexec", "PQexecParams", "sqlite3_prepare",
                        "sqlite3_prepare_v2", "OCIStmtPrepare"])

WEAK_HASH_FUNCS = frozenset(["MD5", "MD5_Init", "MD5_Update", "MD5_Final",
                               "SHA1", "SHA1_Init", "SHA1_Update", "SHA1_Final",
                               "DES_ecb_encrypt", "DES_set_key", "DES_cbc_encrypt",
                               "RC4", "RC4_set_key", "MD4", "MD4_Init"])

SIGNAL_UNSAFE_FUNCS = frozenset(["printf", "fprintf", "sprintf", "malloc", "free",
                                   "calloc", "realloc", "exit", "fopen", "fclose",
                                   "fread", "fwrite", "fflush", "syslog"])


class VulnDetector:
    """Runs all vulnerability detection passes on parsed results."""

    def __init__(self, parser: Parser, dfa: DataFlowAnalyzer,
                 source: str, file_path: str, source_lines: List[str]):
        self.parser = parser
        self.dfa = dfa
        self.source = source
        self.file_path = file_path
        self.lines = source_lines
        self.vulns: List[Vulnerability] = []

    def get_snippet(self, line: int, context: int = 2) -> str:
        start = max(0, line - 1 - context)
        end = min(len(self.lines), line + context)
        snippet_lines = []
        for i in range(start, end):
            marker = ">>> " if i == line - 1 else "    "
            snippet_lines.append(f"{marker}{i + 1}: {self.lines[i]}")
        return "\n".join(snippet_lines)

    def add(self, title: str, severity: str, confidence: str, category: str,
            cwe: str, description: str, line: int, col: int, recommendation: str):
        self.vulns.append(Vulnerability(
            id=str(uuid.uuid4()),
            title=title,
            severity=severity,
            confidence=confidence,
            category=category,
            cwe=cwe,
            description=description,
            file_path=self.file_path,
            line=line,
            column=col,
            code_snippet=self.get_snippet(line),
            recommendation=recommendation
        ))

    def run_all(self):
        self.detect_banned_functions()
        self.detect_buffer_overflow()
        self.detect_format_string()
        self.detect_integer_overflow()
        self.detect_use_after_free()
        self.detect_double_free()
        self.detect_null_deref()
        self.detect_memory_leak()
        self.detect_stack_overflow()
        self.detect_command_injection()
        self.detect_sql_injection()
        self.detect_path_traversal()
        self.detect_race_condition()
        self.detect_insecure_random()
        self.detect_weak_crypto()
        self.detect_hardcoded_secrets()
        self.detect_uninitialized_vars()
        self.detect_off_by_one()
        self.detect_resource_leak()
        self.detect_unchecked_return()
        self.detect_privilege_escalation()
        self.detect_insecure_file_ops()
        self.detect_signal_handler_safety()
        self.detect_thread_safety()
        self.detect_type_confusion()
        self.detect_signed_unsigned_mismatch()
        self.detect_denial_of_service()
        self.detect_cpp_new_delete()
        self.detect_cpp_exception_safety()
        self.detect_cpp_smart_pointer_misuse()
        self.detect_openssl_misuse()
        self.detect_embedded_iot()
        self.detect_missing_stack_protector()
        self.detect_unsafe_cast()
        self.detect_return_local_ptr()
        self.detect_array_out_of_bounds()
        self.detect_overlapping_memcpy()
        self.detect_toctou()
        self.detect_insecure_pragmas()
        self.detect_unvalidated_array_index()
        self.detect_dangerous_scanf()

    # ---- 1. Banned / Dangerous Functions ----
    def detect_banned_functions(self):
        for call in self.parser.calls:
            name = call.attrs["name"]
            if name in BANNED_FUNCTIONS:
                cwe, sev, desc = BANNED_FUNCTIONS[name]
                self.add(
                    f"Use of Dangerous Function: {name}()",
                    sev, "High", "Dangerous Function", cwe,
                    desc,
                    call.line, call.col,
                    f"Remove usage of {name}(). Use a safe alternative."
                )

    # ---- 2. Buffer Overflow ----
    def detect_buffer_overflow(self):
        for call in self.parser.calls:
            name = call.attrs["name"]
            args = call.attrs.get("args", [])
            if name in UNSAFE_STRING_FUNCS:
                safe, cwe = UNSAFE_STRING_FUNCS[name]
                self.add(
                    f"Buffer Overflow: {name}() without bounds checking",
                    "High", "High", "Buffer Overflow", cwe,
                    f"{name}() does not check destination buffer size, leading to potential buffer overflow.",
                    call.line, call.col,
                    f"Replace {name}() with {safe}() and specify buffer size."
                )
            # memcpy with sizeof mismatch hints
            if name == "memcpy" and len(args) >= 3:
                size_arg = args[2]
                dst_arg = args[0].strip()
                if "sizeof" in size_arg and dst_arg not in size_arg:
                    self.add(
                        "Potential Buffer Overflow: memcpy size mismatch",
                        "Medium", "Medium", "Buffer Overflow", "CWE-120",
                        f"memcpy() size argument uses sizeof() but may not match destination buffer '{dst_arg}'.",
                        call.line, call.col,
                        "Ensure memcpy size matches destination buffer size: memcpy(dst, src, sizeof(dst))."
                    )

    # ---- 3. Format String ----
    def detect_format_string(self):
        for call in self.parser.calls:
            name = call.attrs["name"]
            args = call.attrs.get("args", [])
            if name in FORMAT_STRING_FUNCS and args:
                # Determine format arg index
                fmt_idx = 0
                if name in ("fprintf", "dprintf", "syslog"):
                    fmt_idx = 1
                elif name in ("snprintf", "swprintf"):
                    fmt_idx = 2
                elif name in ("sprintf",):
                    fmt_idx = 1

                if fmt_idx < len(args):
                    fmt_arg = args[fmt_idx].strip()
                    # Non-literal format string
                    if not fmt_arg.startswith('"') and fmt_arg not in ("NULL", "nullptr"):
                        self.add(
                            f"Format String Vulnerability: {name}()",
                            "High", "High", "Format String", "CWE-134",
                            f"{name}() called with non-literal format string '{fmt_arg}'. "
                            "An attacker controlling the format string can read/write arbitrary memory.",
                            call.line, call.col,
                            f"Use a literal format string: {name}(..., \"%s\", {fmt_arg})."
                        )

    # ---- 4. Integer Overflow ----
    def detect_integer_overflow(self):
        for call in self.parser.calls:
            name = call.attrs["name"]
            args = call.attrs.get("args", [])
            # malloc with multiplication
            if name in ("malloc", "calloc", "realloc") and args:
                for arg in args:
                    if "*" in arg and not arg.startswith('"'):
                        parts = arg.split("*")
                        if len(parts) >= 2:
                            self.add(
                                "Integer Overflow in Memory Allocation",
                                "High", "Medium", "Integer Overflow", "CWE-190",
                                f"Multiplication in {name}() argument '{arg}' may overflow, "
                                "leading to undersized allocation and heap buffer overflow.",
                                call.line, call.col,
                                "Check for overflow before multiplication, or use calloc() for array allocation."
                            )

        # Signed/unsigned arithmetic in assignments
        for assign in self.parser.assignments:
            rhs = assign.attrs.get("rhs", "")
            lhs = assign.attrs.get("lhs", "")
            # Detect casting patterns that might overflow
            if "( int )" in rhs and ("size_t" in rhs or "unsigned" in rhs):
                self.add(
                    "Potential Integer Overflow: unsigned to signed cast",
                    "Medium", "Medium", "Integer Overflow", "CWE-190",
                    f"Casting unsigned value to signed int in assignment to '{lhs}' may cause overflow.",
                    assign.line, assign.col,
                    "Validate value fits in target type before casting."
                )

    # ---- 5. Use After Free ----
    def detect_use_after_free(self):
        for issue in self.dfa.issues:
            if issue["type"] == "use_after_free":
                self.add(
                    f"Use After Free: '{issue['var']}'",
                    "Critical", "High", "Use After Free", "CWE-416",
                    f"Variable '{issue['var']}' is used at line {issue['line']} after being freed at line {issue['free_line']}.",
                    issue["line"], 1,
                    f"Do not use '{issue['var']}' after calling free(). Set pointer to NULL after free."
                )

    # ---- 6. Double Free ----
    def detect_double_free(self):
        for issue in self.dfa.issues:
            if issue["type"] == "double_free":
                self.add(
                    f"Double Free: '{issue['var']}'",
                    "Critical", "High", "Double Free", "CWE-415",
                    f"Variable '{issue['var']}' is freed at line {issue['line']} but was already freed at line {issue['prev_free_line']}.",
                    issue["line"], 1,
                    f"Set '{issue['var']}' to NULL after free() to prevent double free."
                )

    # ---- 7. Null Pointer Dereference ----
    def detect_null_deref(self):
        for call in self.parser.calls:
            name = call.attrs["name"]
            if name in DataFlowAnalyzer.ALLOC_FUNCS:
                # Check if return value is checked
                line = call.line
                # Look at following statements: is there a null check?
                has_check = False
                for cf in self.parser.control_flow:
                    cond = cf.attrs.get("condition", "")
                    if cf.line > line and cf.line <= line + 5:
                        if "NULL" in cond or "nullptr" in cond or "== 0" in cond or "!" in cond:
                            has_check = True
                            break
                if not has_check:
                    self.add(
                        f"Unchecked Return Value from {name}()",
                        "Medium", "Medium", "Null Pointer Dereference", "CWE-476",
                        f"Return value of {name}() at line {line} is not checked for NULL. "
                        "If allocation fails, subsequent dereference causes undefined behavior.",
                        line, call.col,
                        f"Check the return value of {name}() for NULL before use."
                    )

    # ---- 8. Memory Leak ----
    def detect_memory_leak(self):
        for issue in self.dfa.issues:
            if issue["type"] == "memory_leak":
                self.add(
                    f"Memory Leak: '{issue['var']}'",
                    "Medium", "Medium", "Memory Leak", "CWE-401",
                    f"Memory allocated for '{issue['var']}' (line {issue['line']}) in function "
                    f"'{issue.get('func', '?')}' is never freed.",
                    issue["line"], 1,
                    f"Free '{issue['var']}' before function returns or on all exit paths."
                )

    # ---- 9. Stack Buffer Overflow ----
    def detect_stack_overflow(self):
        for call in self.parser.calls:
            name = call.attrs["name"]
            args = call.attrs.get("args", [])
            # alloca with large or user-controlled size
            if name == "alloca" and args:
                self.add(
                    "Stack Buffer Overflow Risk: alloca()",
                    "High", "Medium", "Stack Buffer Overflow", "CWE-770",
                    "alloca() allocates on the stack. Large or attacker-controlled sizes can cause stack overflow.",
                    call.line, call.col,
                    "Use malloc() instead of alloca(), or validate size is bounded."
                )

        # VLA detection (variable-length arrays)
        for decl in self.parser.var_decls:
            type_str = decl.attrs.get("type", "")
            name = decl.attrs.get("name", "")
            init = decl.attrs.get("init", "")
            # Check for array brackets in nearby tokens
            # Look at raw tokens around the declaration
            if "[" in type_str and not any(c.isdigit() for c in type_str.split("[")[-1].split("]")[0]) and type_str.split("[")[-1].split("]")[0].strip():
                self.add(
                    f"Variable-Length Array (VLA): '{name}'",
                    "Medium", "Medium", "Stack Buffer Overflow", "CWE-770",
                    f"Variable-length array '{name}' size depends on runtime value, risking stack overflow.",
                    decl.line, decl.col,
                    "Use malloc() for dynamic sizes, or validate the size has a reasonable upper bound."
                )

    # ---- 10. Command Injection ----
    def detect_command_injection(self):
        for call in self.parser.calls:
            name = call.attrs["name"]
            args = call.attrs.get("args", [])
            if name in EXEC_FUNCS and args:
                cmd_arg = args[0]
                # Check if argument is a string concatenation or variable
                if not cmd_arg.strip().startswith('"') or "+" in cmd_arg or "strcat" in cmd_arg:
                    sev = "Critical"
                    conf = "High"
                elif any(v in cmd_arg for v in ["%s", "%d"]):
                    sev = "Critical"
                    conf = "High"
                else:
                    # Literal string
                    sev = "Medium"
                    conf = "Low"
                self.add(
                    f"Command Injection: {name}()",
                    sev, conf, "Command Injection", "CWE-78",
                    f"{name}() executes a system command. If the argument includes user input, "
                    "an attacker can inject arbitrary commands.",
                    call.line, call.col,
                    f"Avoid {name}(). Use execve() with a fixed argument list, or validate/sanitize all inputs."
                )

    # ---- 11. SQL Injection ----
    def detect_sql_injection(self):
        for call in self.parser.calls:
            name = call.attrs["name"]
            args = call.attrs.get("args", [])
            if name in SQL_FUNCS and args:
                for arg in args:
                    if not arg.strip().startswith('"') and arg.strip() not in ("NULL", "nullptr", "0"):
                        self.add(
                            f"SQL Injection: {name}()",
                            "Critical", "High", "SQL Injection", "CWE-89",
                            f"{name}() called with non-literal query argument. If user input is concatenated "
                            "into the query string, SQL injection is possible.",
                            call.line, call.col,
                            "Use parameterized queries or prepared statements."
                        )
                        break

    # ---- 12. Path Traversal ----
    def detect_path_traversal(self):
        file_funcs = frozenset(["fopen", "open", "creat", "access", "stat", "lstat",
                                 "unlink", "remove", "rename", "opendir", "mkdir",
                                 "rmdir", "chmod", "chown", "link", "symlink", "readlink"])
        for call in self.parser.calls:
            name = call.attrs["name"]
            args = call.attrs.get("args", [])
            if name in file_funcs and args:
                path_arg = args[0].strip()
                if not path_arg.startswith('"') and path_arg not in ("NULL", "nullptr"):
                    # Check if tainted
                    tainted = False
                    clean_name = path_arg.strip("&*")
                    if clean_name in self.dfa.var_states:
                        if self.dfa.var_states[clean_name].tainted:
                            tainted = True
                    self.add(
                        f"Path Traversal: {name}() with variable path",
                        "High" if tainted else "Medium",
                        "High" if tainted else "Low",
                        "Path Traversal", "CWE-22",
                        f"{name}() uses variable '{path_arg}' as file path. "
                        "If user-controlled, attacker can access arbitrary files via '../' sequences.",
                        call.line, call.col,
                        "Validate and canonicalize file paths. Use realpath() and check the resolved path."
                    )

    # ---- 13. Race Conditions (TOCTOU) ----
    def detect_race_condition(self):
        access_calls: List[ASTNode] = []
        open_calls: List[ASTNode] = []
        stat_calls: List[ASTNode] = []

        for call in self.parser.calls:
            name = call.attrs["name"]
            if name == "access":
                access_calls.append(call)
            elif name in ("open", "fopen", "creat"):
                open_calls.append(call)
            elif name in ("stat", "lstat"):
                stat_calls.append(call)

        # access() then open() on same file
        for ac in access_calls:
            ac_args = ac.attrs.get("args", [])
            if not ac_args:
                continue
            ac_path = ac_args[0]
            for oc in open_calls:
                oc_args = oc.attrs.get("args", [])
                if not oc_args:
                    continue
                if oc.line > ac.line and oc_args[0] == ac_path:
                    self.add(
                        "TOCTOU Race Condition: access() then open()",
                        "High", "High", "Race Condition", "CWE-367",
                        f"access() at line {ac.line} checks file '{ac_path}', then open() at line {oc.line} "
                        "opens it. File state can change between the check and use.",
                        ac.line, ac.col,
                        "Open the file directly and check for errors, or use fstat() on the opened fd."
                    )

        # stat() then open()
        for sc in stat_calls:
            sc_args = sc.attrs.get("args", [])
            if not sc_args:
                continue
            sc_path = sc_args[0]
            for oc in open_calls:
                oc_args = oc.attrs.get("args", [])
                if not oc_args:
                    continue
                if oc.line > sc.line and oc_args[0] == sc_path:
                    self.add(
                        "TOCTOU Race Condition: stat() then open()",
                        "Medium", "Medium", "Race Condition", "CWE-367",
                        f"stat() at line {sc.line} checks '{sc_path}', then open() at line {oc.line}. "
                        "File may be modified between check and use.",
                        sc.line, sc.col,
                        "Open the file first, then use fstat() on the file descriptor."
                    )

    # ---- 14. Insecure Random ----
    def detect_insecure_random(self):
        for call in self.parser.calls:
            name = call.attrs["name"]
            if name == "rand":
                self.add(
                    "Insecure Random Number Generator: rand()",
                    "Medium", "High", "Insecure Random", "CWE-330",
                    "rand() is not cryptographically secure and produces predictable output.",
                    call.line, call.col,
                    "Use a CSPRNG: /dev/urandom, getrandom(), arc4random(), or OpenSSL RAND_bytes()."
                )
            elif name == "srand":
                args = call.attrs.get("args", [])
                if args and "time" in args[0]:
                    self.add(
                        "Predictable Random Seed: srand(time(NULL))",
                        "Medium", "High", "Insecure Random", "CWE-330",
                        "Seeding rand() with time(NULL) makes output predictable to anyone who knows approximate time.",
                        call.line, call.col,
                        "Use a CSPRNG instead of rand()/srand()."
                    )
            elif name == "random":
                self.add(
                    "Insecure Random: random()",
                    "Low", "Medium", "Insecure Random", "CWE-330",
                    "random() is not cryptographically secure.",
                    call.line, call.col,
                    "Use getrandom(), arc4random(), or RAND_bytes() for security-sensitive operations."
                )

    # ---- 15. Weak Cryptography ----
    def detect_weak_crypto(self):
        for call in self.parser.calls:
            name = call.attrs["name"]
            if name in WEAK_HASH_FUNCS:
                algo = "MD5" if "MD5" in name else "SHA1" if "SHA1" in name else "DES" if "DES" in name else "RC4" if "RC4" in name else "MD4"
                self.add(
                    f"Weak Cryptographic Algorithm: {algo}",
                    "High", "High", "Weak Cryptography", "CWE-327",
                    f"{name}() uses the {algo} algorithm which is cryptographically broken.",
                    call.line, call.col,
                    f"Replace {algo} with SHA-256 or SHA-3 for hashing, AES-256 for encryption."
                )

        # Weak key sizes in EVP
        for call in self.parser.calls:
            name = call.attrs["name"]
            args = call.attrs.get("args", [])
            if name == "EVP_EncryptInit_ex" or name == "EVP_EncryptInit":
                for arg in args:
                    if "des" in arg.lower() or "rc4" in arg.lower() or "rc2" in arg.lower():
                        self.add(
                            f"Weak Cipher in EVP: {arg}",
                            "High", "High", "Weak Cryptography", "CWE-327",
                            f"Weak cipher '{arg}' used with OpenSSL EVP interface.",
                            call.line, call.col,
                            "Use AES-256-GCM or ChaCha20-Poly1305."
                        )

    # ---- 16. Hardcoded Secrets ----
    def detect_hardcoded_secrets(self):
        secret_patterns = ["password", "passwd", "secret", "api_key", "apikey",
                           "auth_token", "access_key", "private_key", "encryption_key",
                           "token", "credential"]
        for decl in self.parser.var_decls:
            name = decl.attrs.get("name", "").lower()
            init = decl.attrs.get("init", "")
            if any(p in name for p in secret_patterns) and init.startswith('"') and len(init) > 3:
                self.add(
                    f"Hardcoded Secret: '{decl.attrs.get('name', '')}'",
                    "High", "High", "Hardcoded Secret", "CWE-798",
                    f"Variable '{decl.attrs.get('name', '')}' appears to contain a hardcoded secret.",
                    decl.line, decl.col,
                    "Load secrets from environment variables, a secrets manager, or a config file with restricted permissions."
                )

        # Also check string literals in assignments
        for assign in self.parser.assignments:
            lhs = assign.attrs.get("lhs", "").lower()
            rhs = assign.attrs.get("rhs", "")
            if any(p in lhs for p in secret_patterns) and rhs.strip().startswith('"') and len(rhs.strip()) > 3:
                self.add(
                    f"Hardcoded Secret: '{assign.attrs.get('lhs', '')}'",
                    "High", "High", "Hardcoded Secret", "CWE-798",
                    f"Variable '{assign.attrs.get('lhs', '')}' is assigned a hardcoded string that may be a secret.",
                    assign.line, assign.col,
                    "Externalize secrets to environment variables or a config file."
                )

    # ---- 17. Uninitialized Variables ----
    def detect_uninitialized_vars(self):
        for func in self.parser.functions:
            local_vars: Dict[str, ASTNode] = {}
            initialized: Set[str] = set()
            # Add params as initialized
            for p in func.attrs.get("params", []):
                pname = p.get("name", "")
                if pname:
                    initialized.add(pname)
            self._check_uninit_in_stmts(func.children, local_vars, initialized)

    def _check_uninit_in_stmts(self, stmts: List[ASTNode], local_vars: dict, initialized: set):
        for stmt in stmts:
            if stmt.kind == "var_decl":
                name = stmt.attrs.get("name", "")
                init = stmt.attrs.get("init", "")
                if name:
                    local_vars[name] = stmt
                    if init:
                        initialized.add(name)
            elif stmt.kind == "assignment":
                lhs = stmt.attrs.get("lhs", "")
                if lhs:
                    initialized.add(lhs)
            elif stmt.kind == "call":
                args = stmt.attrs.get("args", [])
                for arg in args:
                    arg_clean = arg.strip().lstrip("&*")
                    if arg_clean in local_vars and arg_clean not in initialized:
                        type_str = local_vars[arg_clean].attrs.get("type", "")
                        # Pointers passed by ref are likely being initialized
                        if "&" not in arg:
                            self.add(
                                f"Uninitialized Variable: '{arg_clean}'",
                                "Medium", "Medium", "Uninitialized Variable", "CWE-457",
                                f"Variable '{arg_clean}' may be used before initialization.",
                                stmt.line, stmt.col,
                                f"Initialize '{arg_clean}' before use."
                            )
            elif stmt.kind == "return":
                expr = stmt.attrs.get("expr", "")
                if expr in local_vars and expr not in initialized:
                    self.add(
                        f"Uninitialized Variable Returned: '{expr}'",
                        "Medium", "High", "Uninitialized Variable", "CWE-457",
                        f"Variable '{expr}' is returned but may not be initialized.",
                        stmt.line, stmt.col,
                        f"Ensure '{expr}' is initialized on all code paths."
                    )
            # Recurse
            if stmt.children:
                self._check_uninit_in_stmts(stmt.children, local_vars, initialized.copy())

    # ---- 18. Off-by-One ----
    def detect_off_by_one(self):
        for cf in self.parser.control_flow:
            if cf.attrs.get("keyword") == "for":
                cond = cf.attrs.get("condition", "")
                # Common pattern: for(i=0; i<=sizeof(buf); i++) or i<=len
                if "<=" in cond and ("sizeof" in cond or "len" in cond or "size" in cond or "count" in cond or "length" in cond):
                    self.add(
                        "Potential Off-by-One Error in Loop",
                        "Medium", "Medium", "Off-by-One", "CWE-193",
                        f"Loop condition '{cond}' uses <=. For array/buffer iteration, this typically "
                        "accesses one element past the end.",
                        cf.line, cf.col,
                        "Use < instead of <= for buffer/array iteration: for(i=0; i < size; i++)."
                    )

    # ---- 19. Resource Leak ----
    def detect_resource_leak(self):
        for issue in self.dfa.issues:
            if issue["type"] == "resource_leak":
                self.add(
                    f"Resource Leak: '{issue['var']}'",
                    "Medium", "Medium", "Resource Leak", "CWE-404",
                    f"File descriptor/handle '{issue['var']}' in function '{issue.get('func', '?')}' "
                    "may not be closed on all paths.",
                    issue["line"], 1,
                    f"Ensure '{issue['var']}' is closed (fclose/close) before function returns."
                )

    # ---- 20. Unchecked Return Value ----
    def detect_unchecked_return(self):
        checked_funcs = frozenset(["read", "write", "send", "recv", "open",
                                    "close", "fclose", "fwrite", "fread",
                                    "connect", "bind", "listen", "accept",
                                    "chdir", "chown", "chmod", "setuid", "setgid",
                                    "seteuid", "setegid", "setreuid", "setregid",
                                    "fork", "pipe", "dup2", "mmap"])
        for call in self.parser.calls:
            name = call.attrs["name"]
            if name in checked_funcs:
                # Check if call result is captured by looking at assignments near this line
                is_captured = False
                for assign in self.parser.assignments:
                    if assign.line == call.line and name in assign.attrs.get("rhs", ""):
                        is_captured = True
                        break
                for decl in self.parser.var_decls:
                    if decl.line == call.line and name in decl.attrs.get("init", ""):
                        is_captured = True
                        break
                # Check if used in if condition
                for cf in self.parser.control_flow:
                    if cf.line == call.line and name in cf.attrs.get("condition", ""):
                        is_captured = True
                        break
                if not is_captured:
                    self.add(
                        f"Unchecked Return Value: {name}()",
                        "Low", "Medium", "Improper Error Handling", "CWE-252",
                        f"Return value of {name}() is not checked. This function can fail and "
                        "ignoring its result may lead to undefined behavior.",
                        call.line, call.col,
                        f"Check the return value of {name}() and handle errors."
                    )

    # ---- 21. Privilege Escalation ----
    def detect_privilege_escalation(self):
        setuid_calls = []
        setgid_calls = []
        for call in self.parser.calls:
            name = call.attrs["name"]
            if name in ("setuid", "seteuid", "setreuid"):
                setuid_calls.append(call)
            if name in ("setgid", "setegid", "setregid"):
                setgid_calls.append(call)
            if name in ("setuid", "seteuid") and call.attrs.get("args"):
                arg = call.attrs["args"][0].strip()
                if arg == "0":
                    self.add(
                        "Privilege Escalation: Setting UID to root",
                        "Critical", "High", "Privilege Escalation", "CWE-250",
                        f"{name}(0) sets process to run as root.",
                        call.line, call.col,
                        "Avoid running as root. Drop privileges as soon as possible."
                    )

        # Check privilege drop order: must drop gid before uid
        if setuid_calls and setgid_calls:
            for uid_call in setuid_calls:
                for gid_call in setgid_calls:
                    if gid_call.line > uid_call.line:
                        self.add(
                            "Improper Privilege Drop Order",
                            "High", "High", "Privilege Escalation", "CWE-250",
                            f"setgid() at line {gid_call.line} is called after setuid() at line {uid_call.line}. "
                            "Must drop group privileges before user privileges.",
                            uid_call.line, uid_call.col,
                            "Call setgid() before setuid() when dropping privileges."
                        )

    # ---- 22. Insecure File Operations ----
    def detect_insecure_file_ops(self):
        for call in self.parser.calls:
            name = call.attrs["name"]
            args = call.attrs.get("args", [])
            if name == "mktemp":
                self.add(
                    "Insecure Temp File: mktemp()",
                    "High", "High", "Insecure File Operation", "CWE-377",
                    "mktemp() creates predictable file names, enabling symlink attacks.",
                    call.line, call.col,
                    "Use mkstemp() or tmpfile() for secure temporary file creation."
                )
            if name == "chmod" and args:
                for arg in args:
                    if "0777" in arg or "0666" in arg or "S_IRWXO" in arg:
                        self.add(
                            "World-Writable File Permissions",
                            "Medium", "High", "Insecure File Operation", "CWE-732",
                            f"chmod() sets overly permissive file permissions ({arg}).",
                            call.line, call.col,
                            "Use restrictive permissions: 0600 for sensitive files, 0644 for public."
                        )
            if name == "open" and len(args) >= 2:
                flags = " ".join(args[1:])
                if "O_CREAT" in flags and "O_EXCL" not in flags:
                    # Missing O_EXCL when creating
                    pass  # Low confidence, skip
                if "O_NOFOLLOW" not in flags and len(args) >= 1:
                    path = args[0]
                    if "/tmp" in path:
                        self.add(
                            "Symlink Attack Risk: open() in /tmp without O_NOFOLLOW",
                            "Medium", "Medium", "Insecure File Operation", "CWE-59",
                            "Opening files in /tmp without O_NOFOLLOW allows symlink attacks.",
                            call.line, call.col,
                            "Use O_NOFOLLOW flag or mkstemp() for temporary files."
                        )

    # ---- 23. Signal Handler Safety ----
    def detect_signal_handler_safety(self):
        # Find signal() calls to identify handler functions
        handlers: List[str] = []
        for call in self.parser.calls:
            if call.attrs["name"] == "signal" and len(call.attrs.get("args", [])) >= 2:
                handler = call.attrs["args"][1].strip()
                if handler not in ("SIG_IGN", "SIG_DFL"):
                    handlers.append(handler)
            if call.attrs["name"] == "sigaction":
                # Would need deeper parsing, skip for now
                pass

        # Check if handler functions use unsafe calls
        for func in self.parser.functions:
            if func.attrs.get("name", "") in handlers:
                self._check_signal_unsafe(func.children, func.attrs["name"])

    def _check_signal_unsafe(self, stmts: List[ASTNode], handler_name: str):
        for stmt in stmts:
            if stmt.kind == "call" or stmt.kind == "expr_stmt":
                raw = stmt.attrs.get("raw", "")
                for unsafe in SIGNAL_UNSAFE_FUNCS:
                    if unsafe + "(" in raw or (stmt.kind == "call" and stmt.attrs.get("name") == unsafe):
                        self.add(
                            f"Async-Signal-Unsafe Function in Signal Handler",
                            "High", "High", "Signal Handler Safety", "CWE-479",
                            f"Signal handler '{handler_name}' calls {unsafe}() which is not async-signal-safe.",
                            stmt.line, stmt.col,
                            f"Only call async-signal-safe functions in signal handlers (see signal-safety(7)). "
                            f"Use write() instead of printf(), set a volatile sig_atomic_t flag."
                        )
                        break
            if stmt.children:
                self._check_signal_unsafe(stmt.children, handler_name)

    # ---- 24. Thread Safety ----
    def detect_thread_safety(self):
        non_reentrant = frozenset(["strtok", "localtime", "gmtime", "asctime", "ctime",
                                    "getenv", "setenv", "strerror", "gethostbyname",
                                    "gethostbyaddr", "inet_ntoa", "readdir", "getpwnam",
                                    "getpwuid", "getgrnam", "getgrgid", "ttyname",
                                    "tmpnam", "ecvt", "fcvt", "gcvt"])
        # Check if file uses threads
        uses_threads = False
        for pp in self.parser.preprocessor:
            if "pthread.h" in pp.attrs.get("text", "") or "thread" in pp.attrs.get("text", ""):
                uses_threads = True
                break
        for call in self.parser.calls:
            if call.attrs["name"] in ("pthread_create", "thrd_create", "CreateThread"):
                uses_threads = True
                break

        if not uses_threads:
            return

        for call in self.parser.calls:
            name = call.attrs["name"]
            if name in non_reentrant:
                safe = name + "_r" if name not in ("getenv", "setenv", "inet_ntoa") else name + " (thread-safe alternative)"
                self.add(
                    f"Non-Reentrant Function in Threaded Code: {name}()",
                    "Medium", "High", "Thread Safety", "CWE-366",
                    f"{name}() is not reentrant/thread-safe and is used in threaded code.",
                    call.line, call.col,
                    f"Use the reentrant version {safe}() or protect with a mutex."
                )

        # Check for shared globals written without mutex
        # (Simplified: look for global var assignments in threaded functions)

    # ---- 25. Type Confusion ----
    def detect_type_confusion(self):
        for call in self.parser.calls:
            name = call.attrs["name"]
            args = call.attrs.get("args", [])
            # void* cast without checking
            for arg in args:
                if "( void * )" in arg or "(void*)" in arg or "(void *)" in arg:
                    self.add(
                        "Potential Type Confusion: void* cast",
                        "Low", "Low", "Type Confusion", "CWE-843",
                        f"Explicit cast to void* in argument to {name}() may hide type errors.",
                        call.line, call.col,
                        "Ensure the original type matches the expected type before casting."
                    )

        # reinterpret_cast (C++)
        for call in self.parser.calls:
            if call.attrs["name"] == "reinterpret_cast":
                self.add(
                    "Dangerous reinterpret_cast",
                    "Medium", "Medium", "Type Confusion", "CWE-843",
                    "reinterpret_cast performs a low-level cast that bypasses type safety.",
                    call.line, call.col,
                    "Prefer static_cast or dynamic_cast. Ensure the cast is correct."
                )

    # ---- 26. Signed/Unsigned Comparison ----
    def detect_signed_unsigned_mismatch(self):
        for cf in self.parser.control_flow:
            cond = cf.attrs.get("condition", "")
            # Heuristic: if condition compares int var with size_t/unsigned
            if ("size_t" in cond or "unsigned" in cond) and ("<" in cond or ">" in cond or "==" in cond):
                # Check if comparing signed with unsigned
                if any(kw in cond for kw in ("int ", "signed ")):
                    self.add(
                        "Signed/Unsigned Comparison Mismatch",
                        "Medium", "Low", "Signed/Unsigned Mismatch", "CWE-195",
                        "Comparison between signed and unsigned values may produce unexpected results.",
                        cf.line, cf.col,
                        "Cast to the same type before comparing, or use matching types."
                    )

    # ---- 27. Denial of Service ----
    def detect_denial_of_service(self):
        for call in self.parser.calls:
            name = call.attrs["name"]
            args = call.attrs.get("args", [])
            if name in ("malloc", "calloc", "realloc", "mmap") and args:
                for arg in args:
                    arg_clean = arg.strip()
                    # If size comes from user input (tainted)
                    if arg_clean in self.dfa.var_states:
                        vs = self.dfa.var_states[arg_clean]
                        if vs.tainted:
                            self.add(
                                f"Denial of Service: Unbounded Allocation from User Input",
                                "High", "High", "Denial of Service", "CWE-400",
                                f"{name}() size is controlled by user input variable '{arg_clean}'. "
                                "Attacker can cause excessive memory allocation.",
                                call.line, call.col,
                                "Validate and cap the allocation size from user input."
                            )

    # ---- 28. C++ new without delete ----
    def detect_cpp_new_delete(self):
        # Track new/delete via data flow
        for issue in self.dfa.issues:
            if issue["type"] == "memory_leak":
                # Already captured in memory_leak detector
                pass

        # Check delete on base class without virtual destructor
        for call in self.parser.calls:
            if call.attrs["name"] == "delete":
                args = call.attrs.get("args", [])
                if args:
                    var = args[0].strip()
                    # Check if the type is a base class pointer
                    if var in self.dfa.var_states:
                        type_str = self.dfa.var_states[var].type_str
                        if "*" in type_str:
                            self.add(
                                f"Potential Missing Virtual Destructor",
                                "Medium", "Low", "C++ Memory Safety", "CWE-weaknesses",
                                f"delete on pointer '{var}' of type '{type_str}'. If this is a base class "
                                "without virtual destructor, derived class data will leak.",
                                call.line, call.col,
                                "Ensure base classes have virtual destructors when used polymorphically."
                            )

    # ---- 29. C++ Exception Safety ----
    def detect_cpp_exception_safety(self):
        # Detect raw pointer allocation in constructor without RAII
        for func in self.parser.functions:
            name = func.attrs.get("name", "")
            # Constructor pattern (same name as a struct/class)
            is_ctor = any(s.attrs.get("name") == name for s in self.parser.structs)
            if not is_ctor:
                continue
            # Check if constructor uses raw new
            has_raw_new = False
            for child in func.children:
                raw = child.attrs.get("raw", "") if child.kind == "expr_stmt" else ""
                if "new " in raw and "unique_ptr" not in raw and "shared_ptr" not in raw and "make_" not in raw:
                    has_raw_new = True
                    self.add(
                        "Exception Safety: Raw new in Constructor",
                        "Medium", "Medium", "C++ Exception Safety", "CWE-404",
                        f"Constructor '{name}' uses raw new. If a subsequent allocation throws, "
                        "previously allocated resources leak.",
                        child.line, child.col,
                        "Use smart pointers (std::unique_ptr/shared_ptr) or RAII wrappers."
                    )

    # ---- 30. Smart Pointer Misuse ----
    def detect_cpp_smart_pointer_misuse(self):
        for call in self.parser.calls:
            name = call.attrs["name"]
            args = call.attrs.get("args", [])
            # shared_ptr constructed from raw new (use make_shared)
            if name == "shared_ptr" and args:
                if "new " in args[0]:
                    self.add(
                        "Inefficient shared_ptr Construction",
                        "Low", "High", "C++ Smart Pointer", "CWE-404",
                        "shared_ptr constructed with raw new instead of make_shared(). "
                        "This causes two allocations and is exception-unsafe.",
                        call.line, call.col,
                        "Use std::make_shared<T>() instead of std::shared_ptr<T>(new T())."
                    )

        # Detect potential shared_ptr cycle
        # Look for shared_ptr member variables pointing to parent type
        for decl in self.parser.var_decls:
            type_str = decl.attrs.get("type", "")
            if "shared_ptr" in type_str:
                # Check if this is inside a class that could be cyclically referenced
                name = decl.attrs.get("name", "")
                if "parent" in name.lower() or "owner" in name.lower():
                    self.add(
                        "Potential shared_ptr Cycle (Memory Leak)",
                        "Medium", "Low", "C++ Smart Pointer", "CWE-401",
                        f"shared_ptr member '{name}' may create a reference cycle preventing deallocation.",
                        decl.line, decl.col,
                        "Use std::weak_ptr for back-references to break potential cycles."
                    )

    # ---- 31. OpenSSL Misuse ----
    def detect_openssl_misuse(self):
        for call in self.parser.calls:
            name = call.attrs["name"]
            args = call.attrs.get("args", [])

            if name == "SSL_CTX_set_verify" and args:
                if "SSL_VERIFY_NONE" in " ".join(args):
                    self.add(
                        "OpenSSL: Certificate Verification Disabled",
                        "Critical", "High", "OpenSSL Misuse", "CWE-295",
                        "SSL_CTX_set_verify() with SSL_VERIFY_NONE disables certificate verification, "
                        "enabling man-in-the-middle attacks.",
                        call.line, call.col,
                        "Use SSL_VERIFY_PEER and provide a proper verification callback."
                    )

            if name in ("SSL_CTX_set_cipher_list", "SSL_set_cipher_list") and args:
                cipher_str = " ".join(args).lower()
                if any(w in cipher_str for w in ["null", "export", "des", "rc4", "md5", "anon"]):
                    self.add(
                        "OpenSSL: Weak Cipher Suite",
                        "High", "High", "OpenSSL Misuse", "CWE-326",
                        f"Weak cipher suite configured: {args[0]}",
                        call.line, call.col,
                        "Use strong cipher suites: TLS_AES_256_GCM_SHA384, ECDHE-RSA-AES256-GCM-SHA384."
                    )

            if name == "SSLv23_method" or name == "SSLv3_method" or name == "TLSv1_method":
                self.add(
                    f"OpenSSL: Deprecated SSL/TLS Method: {name}()",
                    "High", "High", "OpenSSL Misuse", "CWE-327",
                    f"{name}() enables deprecated/insecure protocol versions.",
                    call.line, call.col,
                    "Use TLS_method() and disable old versions with SSL_CTX_set_min_proto_version(TLS1_2_VERSION)."
                )

    # ---- 32. Embedded/IoT ----
    def detect_embedded_iot(self):
        for lit in self.parser.string_literals:
            val = lit.val.strip('"')
            # Hardcoded IPs
            if _looks_like_ip(val):
                self.add(
                    "Hardcoded IP Address",
                    "Low", "High", "Embedded/IoT", "CWE-798",
                    f"Hardcoded IP address '{val}' found. Configuration should be externalized.",
                    lit.line, lit.col,
                    "Use configuration files or environment variables for IP addresses."
                )
            # Unencrypted protocols
            if val.startswith("http://") or val.startswith("ftp://") or val.startswith("telnet://"):
                self.add(
                    f"Unencrypted Protocol: {val[:30]}",
                    "Medium", "High", "Embedded/IoT", "CWE-319",
                    f"Unencrypted protocol URL '{val}' transmits data in cleartext.",
                    lit.line, lit.col,
                    "Use encrypted protocols: https://, sftp://, ssh://."
                )

        # Also scan all string tokens
        for tok in self.parser.all_tokens:
            if tok.tt == TT.STRING_LIT:
                val = tok.val.strip('"')
                if val.startswith("http://") and len(val) > 10:
                    # Already caught above if in string_literals, but also catch inline
                    pass
                if _looks_like_ip(val) and val not in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
                    pass  # Handled above

    # ---- 33. Missing Stack Protector ----
    def detect_missing_stack_protector(self):
        for pp in self.parser.preprocessor:
            text = pp.attrs.get("text", "")
            if "_FORTIFY_SOURCE" in text and "0" in text:
                self.add(
                    "Stack Protection Disabled: _FORTIFY_SOURCE=0",
                    "Medium", "High", "Missing Stack Protector", "CWE-693",
                    "_FORTIFY_SOURCE is explicitly disabled, removing compile-time buffer overflow checks.",
                    pp.line, pp.col,
                    "Set _FORTIFY_SOURCE=2 for maximum protection."
                )
            if "fno-stack-protector" in text:
                self.add(
                    "Stack Protection Disabled: -fno-stack-protector",
                    "Medium", "High", "Missing Stack Protector", "CWE-693",
                    "Stack canary protection is explicitly disabled.",
                    pp.line, pp.col,
                    "Remove -fno-stack-protector and use -fstack-protector-strong."
                )

    # ---- 34. Unsafe Cast ----
    def detect_unsafe_cast(self):
        # Look for C-style casts in expression statements
        for stmt in _flatten(self.parser.functions):
            if stmt.kind == "expr_stmt":
                raw = stmt.attrs.get("raw", "")
                tokens = stmt.attrs.get("tokens", [])
                for i, t in enumerate(tokens):
                    if t == "(" and i + 2 < len(tokens) and tokens[i + 2] == ")":
                        cast_type = tokens[i + 1]
                        if cast_type in ("int", "short", "char", "float") and i + 3 < len(tokens):
                            next_tok = tokens[i + 3] if i + 3 < len(tokens) else ""
                            self.add(
                                f"Unsafe C-Style Cast to '{cast_type}'",
                                "Low", "Low", "Unsafe Cast", "CWE-704",
                                f"C-style cast to '{cast_type}' may silently truncate or reinterpret data.",
                                stmt.line, stmt.col,
                                "Use explicit C++ casts (static_cast, dynamic_cast) for clarity and safety."
                            )

    # ---- 35. Return Pointer to Local ----
    def detect_return_local_ptr(self):
        for issue in self.dfa.issues:
            if issue["type"] == "return_local_ptr":
                self.add(
                    f"Return Pointer to Local Variable: '{issue['var']}'",
                    "Critical", "High", "Dangling Pointer", "CWE-562",
                    f"Function returns address of local variable '{issue['var']}'. "
                    "The pointer becomes dangling when the function returns.",
                    issue["line"], 1,
                    "Return a dynamically allocated copy or use an output parameter."
                )

        # Also check return &localvar pattern in functions
        for func in self.parser.functions:
            for child in _flatten_list(func.children):
                if child.kind == "return":
                    expr = child.attrs.get("expr", "").strip()
                    if expr.startswith("&"):
                        varname = expr[1:].strip()
                        # Check if it's a local variable (declared in function)
                        for decl in self.parser.var_decls:
                            if decl.attrs.get("name") == varname and decl.line >= func.line:
                                is_static = "static" in decl.attrs.get("type", "")
                                if not is_static:
                                    self.add(
                                        f"Return Pointer to Local Variable: '{varname}'",
                                        "Critical", "High", "Dangling Pointer", "CWE-562",
                                        f"Returning address of local variable '{varname}'.",
                                        child.line, child.col,
                                        "Allocate on heap or use static storage."
                                    )

    # ---- 36. Array Out of Bounds ----
    def detect_array_out_of_bounds(self):
        # Detect constant array with constant access beyond bounds
        array_sizes: Dict[str, int] = {}
        for decl in self.parser.var_decls:
            type_str = decl.attrs.get("type", "")
            if "[" in type_str:
                try:
                    size_str = type_str.split("[")[1].split("]")[0].strip()
                    if size_str.isdigit():
                        array_sizes[decl.attrs.get("name", "")] = int(size_str)
                except (IndexError, ValueError):
                    pass

        # Check accesses
        for stmt in _flatten(self.parser.functions):
            tokens = stmt.attrs.get("tokens", [])
            for i, t in enumerate(tokens):
                if t in array_sizes and i + 1 < len(tokens) and tokens[i + 1] == "[":
                    if i + 2 < len(tokens):
                        idx_str = tokens[i + 2]
                        try:
                            idx = int(idx_str)
                            if idx >= array_sizes[t]:
                                self.add(
                                    f"Array Out of Bounds: {t}[{idx}]",
                                    "Critical", "High", "Array Out of Bounds", "CWE-787",
                                    f"Array '{t}' has size {array_sizes[t]} but is accessed at index {idx}.",
                                    stmt.line, stmt.col,
                                    f"Use index < {array_sizes[t]} to stay within bounds."
                                )
                        except ValueError:
                            pass

    # ---- 37. Overlapping memcpy ----
    def detect_overlapping_memcpy(self):
        for call in self.parser.calls:
            if call.attrs["name"] == "memcpy":
                args = call.attrs.get("args", [])
                if len(args) >= 2:
                    dst = args[0].strip()
                    src = args[1].strip()
                    # If dst and src overlap (same base pointer with offset)
                    if dst == src:
                        self.add(
                            "Overlapping memcpy: src and dst are identical",
                            "High", "High", "Overlapping Memory", "CWE-805",
                            "memcpy() with overlapping source and destination causes undefined behavior.",
                            call.line, call.col,
                            "Use memmove() when source and destination may overlap."
                        )
                    # Heuristic: same base name with different offsets
                    dst_base = dst.split("[")[0].split("+")[0].strip()
                    src_base = src.split("[")[0].split("+")[0].strip()
                    if dst_base == src_base and dst != src and dst_base:
                        self.add(
                            "Potentially Overlapping memcpy",
                            "Medium", "Medium", "Overlapping Memory", "CWE-805",
                            f"memcpy() src and dst may overlap (both derived from '{dst_base}'). "
                            "Overlapping memcpy is undefined behavior.",
                            call.line, call.col,
                            "Use memmove() when source and destination may overlap."
                        )

    # ---- 38. TOCTOU (additional patterns) ----
    def detect_toctou(self):
        # Already covered in detect_race_condition, add more patterns
        # realpath then open
        realpath_calls = [c for c in self.parser.calls if c.attrs["name"] == "realpath"]
        open_calls = [c for c in self.parser.calls if c.attrs["name"] in ("open", "fopen")]
        for rp in realpath_calls:
            rp_args = rp.attrs.get("args", [])
            if not rp_args:
                continue
            for oc in open_calls:
                if oc.line > rp.line and oc.line - rp.line < 10:
                    oc_args = oc.attrs.get("args", [])
                    if oc_args:
                        self.add(
                            "TOCTOU: realpath() then open()",
                            "Medium", "Low", "Race Condition", "CWE-367",
                            "realpath() resolves a path, then open() uses the resolved path. "
                            "File may change between the two calls.",
                            rp.line, rp.col,
                            "Open the file first, then use fstat() on the file descriptor."
                        )

    # ---- 39. Insecure Compiler Directives ----
    def detect_insecure_pragmas(self):
        for pp in self.parser.preprocessor:
            text = pp.attrs.get("text", "")
            if "#pragma pack" in text:
                self.add(
                    "Pragma Pack Directive",
                    "Low", "Medium", "Insecure Pragma", "CWE-188",
                    f"#pragma pack modifies struct alignment: '{text.strip()}'. "
                    "This can cause unaligned memory access on some architectures.",
                    pp.line, pp.col,
                    "Document pragma pack usage and ensure it's restored: #pragma pack(push, 1) ... #pragma pack(pop)."
                )
            if "#pragma warning" in text and "disable" in text:
                self.add(
                    "Compiler Warning Suppressed",
                    "Low", "Medium", "Insecure Pragma", "CWE-710",
                    f"Compiler warning disabled: '{text.strip()}'. Suppressing warnings may hide real issues.",
                    pp.line, pp.col,
                    "Fix the underlying issue rather than suppressing the warning."
                )

    # ---- 40. Unvalidated Array Index ----
    def detect_unvalidated_array_index(self):
        # If a tainted variable is used as array index
        for stmt in _flatten(self.parser.functions):
            tokens = stmt.attrs.get("tokens", [])
            for i, t in enumerate(tokens):
                if t == "[" and i + 1 < len(tokens):
                    idx_var = tokens[i + 1]
                    if idx_var in self.dfa.var_states:
                        vs = self.dfa.var_states[idx_var]
                        if vs.tainted:
                            self.add(
                                f"Unvalidated Array Index from User Input: '{idx_var}'",
                                "High", "High", "Unvalidated Array Index", "CWE-129",
                                f"Array indexed with user-controlled variable '{idx_var}' without bounds validation.",
                                stmt.line, stmt.col,
                                f"Validate '{idx_var}' is within array bounds before use."
                            )

    # ---- Extra: dangerous scanf ----
    def detect_dangerous_scanf(self):
        for call in self.parser.calls:
            name = call.attrs["name"]
            args = call.attrs.get("args", [])
            if name in ("scanf", "fscanf", "sscanf") and args:
                # Check format string for %s without width
                fmt_idx = 0 if name == "scanf" else 1
                if fmt_idx < len(args):
                    fmt = args[fmt_idx]
                    if '"%s"' in fmt or "% s" in fmt:
                        self.add(
                            f"Buffer Overflow: {name}() with unbounded %s",
                            "High", "High", "Buffer Overflow", "CWE-120",
                            f"{name}() uses %s without width limit, causing potential buffer overflow.",
                            call.line, call.col,
                            f"Specify a width: %255s instead of %s."
                        )


# ---------------------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------------------

def _flatten(functions: List[ASTNode]) -> List[ASTNode]:
    """Flatten all statements from functions."""
    result = []
    for func in functions:
        result.extend(_flatten_list(func.children))
    return result


def _flatten_list(nodes: List[ASTNode]) -> List[ASTNode]:
    result = []
    for n in nodes:
        result.append(n)
        if n.children:
            result.extend(_flatten_list(n.children))
    return result


def _looks_like_ip(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# 6. SCAN ENGINE
# ---------------------------------------------------------------------------

def analyze_file(file_path: str, source: str) -> List[dict]:
    """Analyze a single C/C++ file and return vulnerability dicts."""
    if not source.strip():
        return []

    lines = source.split("\n")

    # Tokenize
    tokens = tokenize(source)

    # Parse
    parser = Parser(tokens)
    parser.parse()

    # Also collect string literals from all tokens
    for tok in tokens:
        if tok.tt == TT.STRING_LIT:
            parser.string_literals.append(tok)

    # Data flow analysis
    dfa = DataFlowAnalyzer(parser)
    dfa.analyze_all()

    # Run detectors
    detector = VulnDetector(parser, dfa, source, file_path, lines)
    detector.run_all()

    # Convert to dicts
    results = []
    seen = set()
    for v in detector.vulns:
        # Deduplicate
        key = (v.title, v.file_path, v.line)
        if key in seen:
            continue
        seen.add(key)
        results.append({
            "id": v.id,
            "title": v.title,
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

    return results


# ---------------------------------------------------------------------------
# 7. FASTAPI SERVER
# ---------------------------------------------------------------------------

app = FastAPI(title="C/C++ SAST Scanner", version="1.0.0")

C_EXTENSIONS = frozenset([".c", ".h", ".cpp", ".cxx", ".cc", ".hpp", ".hxx",
                           ".hh", ".C", ".H", ".CPP", ".c++", ".h++", ".ipp",
                           ".inl", ".tpp", ".tcc"])


class ScanRequest(BaseModel):
    files: Dict[str, str]
    scanId: str = ""


class HealthResponse(BaseModel):
    status: str
    scanner: str
    version: str
    supported_extensions: List[str]


@app.get("/health")
async def health() -> HealthResponse:
    return HealthResponse(
        status="healthy",
        scanner="cpp",
        version="1.0.0",
        supported_extensions=sorted(C_EXTENSIONS),
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
        if ext.lower() not in {e.lower() for e in C_EXTENSIONS}:
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
    logger.info("Scan %s complete: %d files, %d vulns, %.2fs", scan_id, file_count, len(all_vulns), elapsed)

    # Summary counts
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for v in all_vulns:
        sev = v.get("severity", "Info")
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "scanId": scan_id,
        "scanner": "cpp",
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
    logger.info("Starting C/C++ SAST Scanner on port 9008")
    uvicorn.run(app, host="0.0.0.0", port=9008, log_level="info")


if __name__ == "__main__":
    main()
