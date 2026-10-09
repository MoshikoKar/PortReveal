"""Inventory query language (Shodan-style `field:value` search over the local inventory)."""
from .parser import QueryError, parse
from .search import prepare

__all__ = ["QueryError", "parse", "prepare"]
