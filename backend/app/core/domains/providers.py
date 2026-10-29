"""Optional subfinder provider API keys: masking for the API, and a short-lived provider-config file.

Keys are stored Fernet-encrypted in the `domain_discovery` settings section. They never appear in
API responses (only a masked hint), logs or audit details. At run time they are written to a
provider-config YAML inside the job's private temp directory (mode 0600) and removed with it.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from ...security import decrypt_secret
from ...settings_store import DomainDiscoverySettings

# subfinder provider name -> settings field
FIXED_PROVIDERS = {
    "virustotal": "virustotal_key_enc",
    "securitytrails": "securitytrails_key_enc",
    "shodan": "shodan_key_enc",
}
MASK = "••••"


def mask_key(plain: str) -> str:
    """'' when unset; otherwise bullets plus at most the last 4 characters (only for long keys)."""
    if not plain:
        return ""
    return MASK + plain[-4:] if len(plain) >= 12 else MASK


def provider_keys(cfg: DomainDiscoverySettings) -> dict[str, str]:
    """Decrypted keys by subfinder provider name (only the ones that are set)."""
    out: dict[str, str] = {}
    for provider, attr in FIXED_PROVIDERS.items():
        key = decrypt_secret(getattr(cfg, attr))
        if key:
            out[provider] = key
    if cfg.other_provider:
        key = decrypt_secret(cfg.other_key_enc)
        if key:
            out[cfg.other_provider] = key
    return out


def keys_out(cfg: DomainDiscoverySettings) -> dict[str, dict]:
    """API view: {"virustotal": {"set": bool, "masked": "••••abcd"}, ...}. Never the plaintext."""
    out: dict[str, dict] = {}
    for provider, attr in FIXED_PROVIDERS.items():
        plain = decrypt_secret(getattr(cfg, attr))
        out[provider] = {"set": bool(getattr(cfg, attr)), "masked": mask_key(plain)}
    plain = decrypt_secret(cfg.other_key_enc)
    out["other"] = {"set": bool(cfg.other_key_enc), "masked": mask_key(plain), "provider": cfg.other_provider}
    return out


def render_provider_config(keys: dict[str, str]) -> str:
    # JSON strings are valid YAML double-quoted scalars: no escaping surprises in key values.
    lines = []
    for provider in sorted(keys):
        lines.append(f"{provider}:")
        lines.append(f"  - {json.dumps(keys[provider])}")
    return "\n".join(lines) + "\n"


def write_provider_config(directory: Path, keys: dict[str, str]) -> Path | None:
    """Create <directory>/provider-config.yaml readable by the app user only. None when no keys."""
    if not keys:
        return None
    path = directory / "provider-config.yaml"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render_provider_config(keys))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path
