"""ProjectDiscovery subfinder / dnsx as external binaries (same pattern as ffmpeg / FreeRDP).

* Located from SUBFINDER_PATH / DNSX_PATH: a bare name is looked up on PATH and then in
  <data dir>/tools/bin (where setup installs the pinned release); an explicit path is used as is.
* Always run as an argument list (never a shell), JSON-lines output only, with a wall-clock
  timeout. The process is registered with the job context so a cancel kills it.
* Inputs (domains, candidate names, resolvers) are written to files in a private temp directory
  under the app data dir; names are validated (core/domains/validate.py) before they are written.
"""
from __future__ import annotations

import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path

from ...config import get_settings
from ...scanner.types import ScanContext

log = logging.getLogger(__name__)

TOOL_NAMES = ("subfinder", "dnsx")
INSTALL_HINT = "npm run setup:capture-tools (Windows) or npm run setup (Linux); see README"
_VERSION_RE = re.compile(r"v?(\d+\.\d+\.\d+)")
_STATUS_TTL = 60.0
_status_cache: tuple[float, dict[str, ToolStatus]] | None = None
_status_lock = threading.Lock()


@dataclass
class ToolStatus:
    name: str
    found: bool
    path: str | None
    version: str | None
    configured: str
    message: str

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class ToolResult:
    records: list[dict]
    bad_lines: int
    timed_out: bool
    returncode: int | None
    stderr_tail: str


def tools_dir() -> Path:
    return get_settings().data_path / "tools" / "bin"


def _configured(name: str) -> str:
    return (getattr(get_settings(), f"{name}_path", "") or name).strip() or name


def resolve_tool(name: str) -> str | None:
    """Absolute path of the tool binary, or None when it is not installed."""
    configured = _configured(name)
    p = Path(configured)
    if p.is_absolute() or os.sep in configured or (os.altsep and os.altsep in configured):
        if p.is_file():
            return str(p)
        if sys.platform == "win32" and p.with_suffix(".exe").is_file():
            return str(p.with_suffix(".exe"))
        return None
    found = shutil.which(configured)
    if found:
        return found
    local = tools_dir() / (configured + (".exe" if sys.platform == "win32" else ""))
    return str(local) if local.is_file() else None


def _popen_kwargs() -> dict:
    kw: dict = {"stdin": subprocess.DEVNULL, "shell": False}
    if sys.platform == "win32":
        kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return kw


def tool_version(exe: str) -> str | None:
    """`<tool> -version` prints e.g. "Current Version: v2.17.0" (to stderr)."""
    try:
        out = subprocess.run([exe, "-version", "-duc"], capture_output=True, text=True, timeout=15,
                             encoding="utf-8", errors="replace", **_popen_kwargs())
    except (OSError, subprocess.SubprocessError):
        return None
    m = _VERSION_RE.search((out.stdout or "") + "\n" + (out.stderr or ""))
    return m.group(1) if m else None


def tool_status(refresh: bool = False) -> dict[str, ToolStatus]:
    """Detection + version of both tools (cached for a minute; System health and job start)."""
    global _status_cache
    with _status_lock:
        if _status_cache and not refresh and time.monotonic() - _status_cache[0] < _STATUS_TTL:
            return _status_cache[1]
    out: dict[str, ToolStatus] = {}
    for name in TOOL_NAMES:
        configured = _configured(name)
        exe = resolve_tool(name)
        version = tool_version(exe) if exe else None
        if exe:
            msg = f"{name} {version or '(unknown version)'} at {exe}"
        else:
            msg = f"{name} not installed ({configured}) - install with {INSTALL_HINT}"
        out[name] = ToolStatus(name, exe is not None, exe, version, configured, msg)
    with _status_lock:
        _status_cache = (time.monotonic(), out)
    return out


# --- command lines ------------------------------------------------------------------------------
def build_subfinder_cmd(exe: str, domains_file: Path, *, provider_config: Path | None,
                        max_minutes: int, source_timeout_s: int = 30) -> list[str]:
    """Passive enumeration of the domains in `domains_file`, one JSON object per line on stdout."""
    cmd = [
        exe, "-dL", str(domains_file), "-oJ", "-silent", "-nc", "-duc",
        "-timeout", str(int(source_timeout_s)), "-max-time", str(int(max_minutes)),
    ]
    if provider_config is not None:
        cmd += ["-pc", str(provider_config)]
    return cmd


def build_dnsx_cmd(exe: str, hosts_file: Path, resolvers_file: Path, *, rate_per_second: int,
                   threads: int = 10, retries: int = 2) -> list[str]:
    """Resolve every candidate name in `hosts_file` against the resolvers in `resolvers_file`."""
    return [
        exe, "-l", str(hosts_file), "-r", str(resolvers_file), "-json", "-silent", "-nc", "-duc",
        "-a", "-aaaa", "-cname", "-rl", str(max(1, int(rate_per_second))), "-t", str(max(1, int(threads))),
        "-retry", str(max(1, int(retries))),
    ]


# --- execution ---------------------------------------------------------------------------------
def parse_jsonl(lines: Iterable[str]) -> tuple[list[dict], int]:
    """JSON objects, one per line. Blank lines are ignored; anything else that is not an object
    (truncated line, log noise, a bare value) is counted as malformed and skipped."""
    records: list[dict] = []
    bad = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (ValueError, RecursionError):
            bad += 1
            continue
        if isinstance(obj, dict):
            records.append(obj)
        else:
            bad += 1
    return records, bad


def run_jsonl_tool(cmd: list[str], ctx: ScanContext, timeout_s: float) -> ToolResult:
    """Run one tool invocation (argument list, no shell) and parse its JSON-lines stdout."""
    if not isinstance(cmd, list) or not all(isinstance(a, str) for a in cmd):
        raise TypeError("tool command must be a list of strings")
    ctx.check_cancelled()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            encoding="utf-8", errors="replace", **_popen_kwargs())
    ctx.register(proc)
    timed_out = False
    try:
        try:
            stdout, stderr = proc.communicate(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            stdout, stderr = proc.communicate()
    finally:
        ctx.unregister(proc)
    ctx.check_cancelled()
    records, bad = parse_jsonl((stdout or "").splitlines())
    return ToolResult(records, bad, timed_out, proc.returncode, (stderr or "")[-500:])


# --- temp inputs --------------------------------------------------------------------------------
class TempInputs:
    """Private per-job directory under <data dir>/tmp, removed afterwards (also on error/cancel)."""

    def __init__(self, label: str):
        root = get_settings().data_path / "tmp"
        root.mkdir(parents=True, exist_ok=True)
        self.path = root / f"{label}-{secrets.token_hex(6)}"
        self.path.mkdir(mode=0o700)

    def write_lines(self, name: str, lines: Iterable[str]) -> Path:
        p = self.path / name
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            for line in lines:
                fh.write(line + "\n")
        return p

    def cleanup(self) -> None:
        shutil.rmtree(self.path, ignore_errors=True)

    def __enter__(self) -> TempInputs:
        return self

    def __exit__(self, *exc) -> None:
        self.cleanup()
