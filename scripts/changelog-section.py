#!/usr/bin/env python3
"""Print the CHANGELOG.md body for a version (tag or bare semver)."""

from __future__ import annotations

import pathlib
import re
import sys


def die(msg: str) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    if len(sys.argv) != 2:
        die("usage: changelog-section.py <vX.Y.Z|X.Y.Z>")
    raw = sys.argv[1].strip()
    ver = raw[1:] if raw.lower().startswith("v") else raw
    if not re.fullmatch(r"\d+\.\d+\.\d+", ver):
        die(f"invalid version: {raw}")

    path = pathlib.Path("CHANGELOG.md")
    if not path.is_file():
        die("CHANGELOG.md not found")
    text = path.read_text(encoding="utf-8")
    pat = re.compile(
        rf"^##\s*\[?{re.escape(ver)}\]?[^\n]*\n(.*?)(?=^##\s|\Z)",
        re.M | re.S,
    )
    m = pat.search(text)
    if not m:
        die(f"CHANGELOG.md has no section for {ver}")
    body = m.group(1).strip()
    if not body:
        die(f"CHANGELOG.md section for {ver} is empty")

    print(f"## PortReveal {ver}")
    print()
    print(body)
    print()
    print("---")
    print()
    print("Full history: see CHANGELOG.md in the repository.")


if __name__ == "__main__":
    main()
