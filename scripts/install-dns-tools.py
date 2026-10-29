"""Install the pinned subfinder / dnsx releases for Domain scans (Linux setup path and Docker build).

Reads scripts/tools-manifest.json, downloads the asset for this OS/arch, verifies its sha256 BEFORE
anything is written to the destination, extracts only the tool binary and marks it executable.
A tool already on PATH, at the configured SUBFINDER_PATH / DNSX_PATH, or already in the destination
is left alone. Standard library only. Soft-fails by default (exit 0): missing tools only disable the
matching Domain scan steps. Windows uses scripts/install-capture-tools.ps1 instead.

  python3 scripts/install-dns-tools.py                      # -> <data dir>/tools/bin
  python3 scripts/install-dns-tools.py --dest /usr/local/bin --strict   # Docker build
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import io
import json
import os
import platform
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = Path(__file__).resolve().parent / "tools-manifest.json"
TIMEOUT_S = 120
MAX_BYTES = 200 * 1024 * 1024


def log(msg: str, level: str = "INFO") -> None:
    print(f"[dns-tools] [{level}] {msg}", flush=True)


def platform_key() -> str | None:
    system = sys.platform
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)
    if arch is None:
        return None
    if system.startswith("linux"):
        return f"linux-{arch}"
    if system == "win32":
        return f"windows-{arch}"
    return None


def default_dest() -> Path:
    data = os.environ.get("DATA_DIR", "").strip() or "./data"
    p = Path(data)
    return (p if p.is_absolute() else (ROOT / p)).resolve() / "tools" / "bin"


def already_available(name: str, dest: Path) -> str | None:
    configured = os.environ.get(f"{name.upper()}_PATH", "").strip()
    if configured and (os.sep in configured or "/" in configured) and Path(configured).is_file():
        return configured
    found = shutil.which(configured or name)
    if found:
        return found
    local = dest / (name + (".exe" if sys.platform == "win32" else ""))
    return str(local) if local.is_file() else None


def download(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("refusing a non-https download URL")
    req = urllib.request.Request(url, headers={"User-Agent": "PortReveal-setup"})
    # https only (checked above), pinned URL from the manifest.
    with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("download larger than expected")
    return data


def install(name: str, spec: dict, key: str, dest: Path) -> bool:
    have = already_available(name, dest)
    if have:
        log(f"{name} already available ({have}) - skipping download")
        return True
    asset = (spec.get("assets") or {}).get(key)
    if not asset:
        log(f"{name}: no pinned release for {key}", "WARN")
        return False
    log(f"downloading {name} {spec['version']} ({key})")
    try:
        data = download(asset["url"])
    except (OSError, ValueError, http.client.HTTPException) as exc:  # reported, never fatal by default
        log(f"{name}: download failed: {exc}", "ERROR")
        return False
    digest = hashlib.sha256(data).hexdigest()
    if digest.lower() != str(asset["sha256"]).lower():
        log(f"{name}: sha256 mismatch (expected {asset['sha256']}, got {digest}) - NOT installed", "ERROR")
        return False
    exe = name + (".exe" if key.startswith("windows") else "")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            member = next((m for m in zf.namelist() if Path(m).name == exe and not m.endswith("/")), None)
            if member is None:
                log(f"{name}: {exe} not found in the archive", "ERROR")
                return False
            payload = zf.read(member)
    except zipfile.BadZipFile as exc:
        log(f"{name}: bad archive: {exc}", "ERROR")
        return False
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / exe
    tmp = target.with_name(target.name + ".part")
    tmp.write_bytes(payload)
    tmp.chmod(0o755)
    tmp.replace(target)
    log(f"{name} {spec['version']} installed at {target}")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dest", type=Path, default=None, help="install directory (default: <data dir>/tools/bin)")
    ap.add_argument("--manifest", type=Path, default=MANIFEST)
    ap.add_argument("--platform", default=None, help="override, e.g. linux-arm64")
    ap.add_argument("--strict", action="store_true", help="exit 1 when a tool could not be installed")
    args = ap.parse_args()
    key = args.platform or platform_key()
    dest = (args.dest or default_dest()).resolve()
    if key is None:
        log(f"unsupported platform {sys.platform}/{platform.machine()} - install subfinder and dnsx manually", "WARN")
        return 1 if args.strict else 0
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    failed = [name for name, spec in manifest["tools"].items() if not install(name, spec, key, dest)]
    if failed:
        log(f"not installed: {', '.join(failed)} - Domain scans skip the matching steps until they are", "WARN")
        return 1 if args.strict else 0
    log("subfinder and dnsx ready")
    return 0


if __name__ == "__main__":
    sys.exit(main())
