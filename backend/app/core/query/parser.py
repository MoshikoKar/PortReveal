"""Inventory query language: tokenizer + recursive-descent parser.

    port:443 product:nginx -tag:lab
    (port:22 OR port:2222) ssh.type:ssh-rsa
    ssl.cert.expires:<30d net:10.1.0.0/16 "web portal"

Grammar (AND binds tighter than OR, juxtaposition means AND):

    query    := or_expr
    or_expr  := and_expr ( ("OR" | "|") and_expr )*
    and_expr := unary ( ["AND"] unary )*
    unary    := ("-" | "NOT") unary | primary
    primary  := "(" or_expr ")" | term
    term     := NAME ":" value | value          (a value alone is free text)
    value    := QUOTED | BAREWORD

The parser only builds an AST; field names and values are validated by the compiler, so the same
tree serves SQL (live inventory) and the Python evaluator (historical snapshots).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

MAX_QUERY_LENGTH = 1000
MAX_TERMS = 40
MAX_DEPTH = 10


class QueryError(ValueError):
    """User-facing query problem (syntax, unknown field, bad value). `pos` is a 0-based offset."""

    def __init__(self, message: str, pos: int | None = None):
        super().__init__(message)
        self.pos = pos


@dataclass(frozen=True)
class Term:
    field: str | None  # None = free text
    value: str
    quoted: bool = False
    pos: int = 0
    op: str = ""  # "", "=", ">", ">=", "<", "<=" (written right after the colon)


@dataclass(frozen=True)
class Not:
    child: Node


@dataclass(frozen=True)
class And:
    children: tuple[Node, ...]


@dataclass(frozen=True)
class Or:
    children: tuple[Node, ...]


Node = Term | Not | And | Or


@dataclass
class _Tok:
    kind: str  # LPAREN RPAREN OR AND NOT NEG TERM
    pos: int
    field: str | None = None
    value: str = ""
    quoted: bool = False
    op: str = ""


_FIELD_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.]*")
_OPS = (">=", "<=", ">", "<", "=")
_STOP = set(" \t\r\n()")


def _read_quoted(text: str, i: int) -> tuple[str, int]:
    """text[i] is the opening quote. Returns (value, index after the closing quote)."""
    out: list[str] = []
    j = i + 1
    while j < len(text):
        ch = text[j]
        if ch == "\\" and j + 1 < len(text) and text[j + 1] in "\"\\":
            out.append(text[j + 1])
            j += 2
            continue
        if ch == '"':
            return "".join(out), j + 1
        out.append(ch)
        j += 1
    raise QueryError("unterminated quote", i)


def _read_bare(text: str, i: int) -> tuple[str, int]:
    j = i
    while j < len(text) and text[j] not in _STOP:
        j += 1
    return text[i:j], j


def tokenize(text: str) -> list[_Tok]:
    toks: list[_Tok] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in " \t\r\n":
            i += 1
            continue
        if ch == "(":
            toks.append(_Tok("LPAREN", i))
            i += 1
            continue
        if ch == ")":
            toks.append(_Tok("RPAREN", i))
            i += 1
            continue
        if ch == "|":
            toks.append(_Tok("OR", i))
            i += 2 if text[i:i + 2] == "||" else 1
            continue
        # "-" directly before a term or "(" negates it; a lone "-" is free text
        if ch == "-" and i + 1 < n and text[i + 1] not in " \t\r\n)":
            toks.append(_Tok("NEG", i))
            i += 1
            continue
        start = i
        if ch == '"':
            value, i = _read_quoted(text, i)
            toks.append(_Tok("TERM", start, None, value, True))
            continue
        m = _FIELD_RE.match(text, i)
        if m and m.end() < n and text[m.end()] == ":":
            name = m.group(0).lower()
            i = m.end() + 1
            op = next((o for o in _OPS if text.startswith(o, i)), "")
            i += len(op)
            if i < n and text[i] == '"':
                value, i = _read_quoted(text, i)
                toks.append(_Tok("TERM", start, name, value, True, op))
            else:
                value, i = _read_bare(text, i)
                if not value:
                    raise QueryError(f"missing value after '{name}:{op}'", start)
                toks.append(_Tok("TERM", start, name, value, False, op))
            continue
        word, i = _read_bare(text, i)
        if word in ("OR", "AND", "NOT"):
            toks.append(_Tok(word, start))
        else:
            toks.append(_Tok("TERM", start, None, word, False))
    return toks


class _Parser:
    def __init__(self, toks: list[_Tok]):
        self.toks = toks
        self.i = 0
        self.terms = 0

    def peek(self) -> _Tok | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self) -> _Tok:
        tok = self.toks[self.i]
        self.i += 1
        return tok

    def parse(self) -> Node:
        node = self.or_expr(0)
        tok = self.peek()
        if tok is not None:
            raise QueryError("unexpected ')'" if tok.kind == "RPAREN" else f"unexpected {tok.kind}", tok.pos)
        return node

    def or_expr(self, depth: int) -> Node:
        parts = [self.and_expr(depth)]
        while (tok := self.peek()) is not None and tok.kind == "OR":
            self.take()
            parts.append(self.and_expr(depth))
        return parts[0] if len(parts) == 1 else Or(tuple(parts))

    def and_expr(self, depth: int) -> Node:
        parts = [self.unary(depth)]
        while (tok := self.peek()) is not None and tok.kind not in ("OR", "RPAREN"):
            if tok.kind == "AND":
                self.take()
            parts.append(self.unary(depth))
        return parts[0] if len(parts) == 1 else And(tuple(parts))

    def unary(self, depth: int) -> Node:
        if depth > MAX_DEPTH:
            raise QueryError(f"query is nested too deeply (max {MAX_DEPTH})")
        tok = self.peek()
        if tok is None:
            raise QueryError("query ends unexpectedly", self.toks[-1].pos if self.toks else 0)
        if tok.kind in ("NEG", "NOT"):
            self.take()
            return Not(self.unary(depth + 1))
        if tok.kind == "LPAREN":
            self.take()
            if (nxt := self.peek()) is not None and nxt.kind == "RPAREN":
                raise QueryError("empty parentheses", nxt.pos)
            node = self.or_expr(depth + 1)
            close = self.peek()
            if close is None or close.kind != "RPAREN":
                raise QueryError("missing ')'", tok.pos)
            self.take()
            return node
        if tok.kind == "TERM":
            self.take()
            self.terms += 1
            if self.terms > MAX_TERMS:
                raise QueryError(f"too many terms (max {MAX_TERMS})", tok.pos)
            return Term(tok.field, tok.value, tok.quoted, tok.pos, tok.op)
        raise QueryError(f"unexpected {tok.kind if tok.kind != 'RPAREN' else ')'}", tok.pos)


def parse(text: str) -> Node | None:
    """Parse a query. Returns None for an empty query (matches everything)."""
    text = (text or "").strip()
    if not text:
        return None
    if len(text) > MAX_QUERY_LENGTH:
        raise QueryError(f"query is too long (max {MAX_QUERY_LENGTH} characters)")
    toks = tokenize(text)
    if not toks:
        return None
    return _Parser(toks).parse()


def terms(node: Node | None) -> list[Term]:
    """Every term in the tree, left to right."""
    out: list[Term] = []

    def walk(n: Node) -> None:
        if isinstance(n, Term):
            out.append(n)
        elif isinstance(n, Not):
            walk(n.child)
        else:
            for c in n.children:
                walk(c)

    if node is not None:
        walk(node)
    return out


@dataclass
class Values:
    """A term value split into its comparison operator and comma-separated alternatives."""

    op: str  # "" | ">" | ">=" | "<" | "<=" | "="
    items: list[str] = field(default_factory=list)


def split_value(term: Term, *, allow_list: bool = True) -> Values:
    op = term.op
    raw = term.value if term.quoted else term.value.strip()
    if not raw:
        raise QueryError(f"empty value for '{term.field}'", term.pos)
    if term.quoted or not allow_list or op in (">", ">=", "<", "<="):
        return Values(op, [raw])
    items = [v.strip() for v in raw.split(",") if v.strip()]
    if not items:
        raise QueryError(f"empty value for '{term.field}'", term.pos)
    return Values(op, items)


def quote_value(value: str) -> str:
    """Render a value for a query string (quotes when it has spaces, commas or quotes)."""
    if value and not any(ch in value for ch in ' \t",()|') and not value.startswith("-"):
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
