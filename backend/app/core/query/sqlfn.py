"""Dialect-aware SQL expressions shared by search, sorting and reports."""
from __future__ import annotations

from sqlalchemy import BigInteger, Integer, cast, func, literal
from sqlalchemy.sql.elements import ColumnElement


def ipv4_int_expr(dialect: str, col) -> ColumnElement:
    """Numeric IPv4 key (matches netutils.ip_sort_key) for SQLite and PostgreSQL; 0 for non-IPv4."""
    if dialect == "postgresql":
        expr = (
            cast(func.nullif(func.split_part(col, ".", 1), ""), BigInteger) * 16777216
            + cast(func.nullif(func.split_part(col, ".", 2), ""), BigInteger) * 65536
            + cast(func.nullif(func.split_part(col, ".", 3), ""), BigInteger) * 256
            + cast(func.nullif(func.split_part(col, ".", 4), ""), BigInteger)
        )
    else:
        dot = literal(".")
        o1 = cast(func.substr(col, 1, func.instr(col, dot) - 1), Integer)
        r1 = func.substr(col, func.instr(col, dot) + 1)
        o2 = cast(func.substr(r1, 1, func.instr(r1, dot) - 1), Integer)
        r2 = func.substr(r1, func.instr(r1, dot) + 1)
        o3 = cast(func.substr(r2, 1, func.instr(r2, dot) - 1), Integer)
        o4 = cast(func.substr(r2, func.instr(r2, dot) + 1), Integer)
        expr = o1 * 16777216 + o2 * 65536 + o3 * 256 + o4
    return func.coalesce(expr, 0)
