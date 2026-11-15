#!/usr/bin/env python3
"""Fail unless the required GitHub check runs succeeded on a commit SHA.

Used by .github/workflows/release.yml. Expects GH_TOKEN for `gh api`.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

REQUIRED = ("backend", "frontend", "e2e", "alembic-check", "alembic-postgres")
ATTEMPTS = 30
SLEEP_SEC = 20


def die(msg: str) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(1)


def check_runs(repo: str, sha: str) -> list[dict]:
    out = subprocess.check_output(
        ["gh", "api", f"repos/{repo}/commits/{sha}/check-runs?per_page=100"],
        text=True,
    )
    data = json.loads(out)
    return list(data.get("check_runs") or [])


def conclusion_for(runs: list[dict], name: str) -> str:
    matched = [r for r in runs if r.get("name") == name]
    if not matched:
        return "missing"
    matched.sort(key=lambda r: r.get("completed_at") or r.get("started_at") or "")
    latest = matched[-1]
    return str(latest.get("conclusion") or latest.get("status") or "unknown")


def main() -> None:
    repo = os.environ.get("REPO")
    sha = os.environ.get("SHA")
    if not repo:
        die("REPO is required")
    if not sha:
        die("SHA is required")
    if not os.environ.get("GH_TOKEN") and not os.environ.get("GITHUB_TOKEN"):
        die("GH_TOKEN or GITHUB_TOKEN is required")

    for attempt in range(1, ATTEMPTS + 1):
        runs = check_runs(repo, sha)
        ok = True
        for name in REQUIRED:
            status = conclusion_for(runs, name)
            print(f"check {name}: {status}")
            if status != "success":
                ok = False
        if ok:
            print(f"all required CI checks succeeded on {sha}")
            return
        print(f"waiting for required checks (attempt {attempt}/{ATTEMPTS})...")
        time.sleep(SLEEP_SEC)

    die(f"required CI checks did not succeed on {sha}")


if __name__ == "__main__":
    main()
